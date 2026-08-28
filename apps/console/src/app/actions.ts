'use server';

import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { cookies } from 'next/headers';
import { api, ApiError } from '@/lib/api';
import { formText } from '@/lib/form';
import { currentSurface } from '@/lib/surface';

/**
 * Server actions.
 *
 * Every mutation goes through the API rather than touching the database directly, so the checks the
 * API enforces — the state machine, the scope guard, the release checklist — apply to the console
 * exactly as they do to anything else. A console that wrote to the database would be a second path
 * around every gate.
 */

function message(error: unknown): string {
  if (error instanceof ApiError) {
    const body = error.body as { error?: unknown } | null;
    if (typeof body?.error === 'string') return body.error;
    if (Array.isArray(body?.error)) return 'that request was not valid';
    return `the API refused the request (${error.status})`;
  }
  return error instanceof Error ? error.message : 'something went wrong';
}

export interface ActionResult {
  ok: boolean;
  error?: string;
  detail?: unknown;
}

/* Authentication ------------------------------------------------------------------------------ */

export async function signIn(unusedPrevious: ActionResult, form: FormData): Promise<ActionResult> {
  const email = formText(form, 'email');
  const password = formText(form, 'password');

  try {
    await api.post('/auth/login', { email, password });
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  redirect('/login/mfa');
}

export async function submitMfa(unusedPrevious: ActionResult, form: FormData): Promise<ActionResult> {
  const code = formText(form, 'code');

  try {
    await api.post('/auth/mfa', { code });
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  redirect('/');
}

export async function signOut(): Promise<void> {
  try {
    await api.post('/auth/logout');
  } catch {
    // A failed logout still clears the cookie locally; the session expires server-side anyway.
  }
  const store = await cookies();
  store.delete('attestor_session');
  redirect('/login');
}

/* Engagements --------------------------------------------------------------------------------- */

export async function changeState(
  engagementId: string,
  unusedPrevious: ActionResult,
  form: FormData,
): Promise<ActionResult> {
  const to = formText(form, 'to');
  const reason = formText(form, 'reason').trim();
  const override = formText(form, 'advanceGateOverrideReason').trim();

  try {
    await api.post(`/engagements/${engagementId}/state`, {
      to,
      ...(reason ? { reason } : {}),
      ...(override ? { advanceGateOverrideReason: override } : {}),
    });
  } catch (error) {
    return { ok: false, error: message(error) };
  }

  revalidatePath(`/engagements/${engagementId}`);
  return { ok: true };
}

export async function queueRun(
  engagementId: string,
  unusedPrevious: ActionResult,
  form: FormData,
): Promise<ActionResult> {
  const modules = form.getAll('modules').map(String);
  // Dry run is the default and the checkbox opts out of it, not into it. A run that sends packets
  // should take a deliberate action, not an omission.
  const dryRun = form.get('live') !== 'on';

  if (modules.length === 0) return { ok: false, error: 'choose at least one module' };

  try {
    const result = await api.post<{ queued: unknown[]; policyWarnings: string[] }>(
      `/engagements/${engagementId}/runs`,
      { modules, dryRun },
    );
    revalidatePath(`/engagements/${engagementId}`);
    return { ok: true, detail: result };
  } catch (error) {
    return { ok: false, error: message(error) };
  }
}

export async function pressPanicStop(
  engagementId: string,
  unusedPrevious: ActionResult,
  form: FormData,
): Promise<ActionResult> {
  const reason = formText(form, 'reason').trim();
  const scope = formText(form, 'scope', 'engagement');

  if (reason.length < 3) return { ok: false, error: 'a stop needs a reason' };

  try {
    const result = await api.post<{ containersKilled: number }>(
      `/engagements/${engagementId}/panic-stop`,
      { scope, reason },
    );
    revalidatePath(`/engagements/${engagementId}`);
    return { ok: true, detail: result };
  } catch (error) {
    return { ok: false, error: message(error) };
  }
}

export async function clearStop(
  engagementId: string,
  unusedPrevious: ActionResult,
  form: FormData,
): Promise<ActionResult> {
  const reason = formText(form, 'reason').trim();
  const scope = formText(form, 'scope', 'engagement');

  try {
    await api.delete(`/engagements/${engagementId}/panic-stop`, { scope, reason });
  } catch (error) {
    return { ok: false, error: message(error) };
  }

  revalidatePath(`/engagements/${engagementId}`);
  return { ok: true };
}

export async function addScopeItems(
  engagementId: string,
  unusedPrevious: ActionResult,
  form: FormData,
): Promise<ActionResult> {
  const kind = formText(form, 'kind', 'domain');
  const included = form.get('excluded') !== 'on';
  const values = formText(form, 'values')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);

  if (values.length === 0) return { ok: false, error: 'nothing to add' };

  try {
    await api.post(`/engagements/${engagementId}/scope`, {
      items: values.map((value) => ({ kind, value, included })),
    });
  } catch (error) {
    return { ok: false, error: message(error), detail: (error as ApiError).body };
  }

  revalidatePath(`/engagements/${engagementId}`);
  return { ok: true };
}

export async function savePolicy(
  engagementId: string,
  unusedPrevious: ActionResult,
  form: FormData,
): Promise<ActionResult> {
  try {
    const result = await api.put<{ warnings: string[] }>(`/engagements/${engagementId}/policy`, {
      yaml: formText(form, 'yaml'),
    });
    revalidatePath(`/engagements/${engagementId}`);
    return { ok: true, detail: result };
  } catch (error) {
    return { ok: false, error: message(error) };
  }
}

/* Triage --------------------------------------------------------------------------------------- */

export async function confirmFindings(
  engagementId: string,
  findingIds: string[],
): Promise<ActionResult> {
  try {
    await api.post(`/engagements/${engagementId}/findings/bulk`, { findingIds, action: 'confirm' });
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  revalidatePath(`/engagements/${engagementId}/triage`);
  return { ok: true };
}

export async function discardFindings(
  engagementId: string,
  findingIds: string[],
): Promise<ActionResult> {
  try {
    await api.post(`/engagements/${engagementId}/findings/bulk`, { findingIds, action: 'discard' });
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  revalidatePath(`/engagements/${engagementId}/triage`);
  return { ok: true };
}

export async function markFalsePositive(
  engagementId: string,
  findingId: string,
  reason: string,
): Promise<ActionResult> {
  try {
    await api.post(`/findings/${findingId}/false-positive`, { reason });
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  revalidatePath(`/engagements/${engagementId}/triage`);
  return { ok: true };
}

/* Reporting ------------------------------------------------------------------------------------ */

export async function saveSection(
  engagementId: string,
  key: string,
  markdown: string,
): Promise<ActionResult> {
  try {
    await api.put(`/engagements/${engagementId}/report/sections/${key}`, { markdown });
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  revalidatePath(`/engagements/${engagementId}/report`);
  return { ok: true };
}

export async function saveChecklist(
  engagementId: string,
  confirmations: Record<string, boolean>,
): Promise<ActionResult> {
  try {
    await api.put(`/engagements/${engagementId}/report/checklist`, confirmations);
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  revalidatePath(`/engagements/${engagementId}/report`);
  return { ok: true };
}

export async function generateReport(engagementId: string, kind: 'assessment' | 'retest') {
  try {
    const result = await api.post<{ report: { id: string; version: string } }>(
      `/engagements/${engagementId}/report`,
      { kind },
    );
    revalidatePath(`/engagements/${engagementId}/report`);
    return { ok: true, detail: result };
  } catch (error) {
    return { ok: false, error: message(error) };
  }
}

export async function releaseReport(
  engagementId: string,
  reportId: string,
  recipients: string[],
): Promise<ActionResult> {
  try {
    await api.post(`/reports/${reportId}/release`, { recipients });
  } catch (error) {
    return { ok: false, error: message(error), detail: (error as ApiError).body };
  }
  revalidatePath(`/engagements/${engagementId}/report`);
  return { ok: true };
}

/* Portal ---------------------------------------------------------------------------------------- */

export async function updateFindingStatus(
  findingId: string,
  status: string,
  justification?: string,
): Promise<ActionResult> {
  if (currentSurface() !== 'portal') return { ok: false, error: 'not available on this surface' };

  try {
    await api.post(`/findings/${findingId}/status`, { status, justification });
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  revalidatePath('/findings');
  return { ok: true };
}

export async function postComment(findingId: string, markdown: string): Promise<ActionResult> {
  if (currentSurface() !== 'portal') return { ok: false, error: 'not available on this surface' };

  try {
    await api.post(`/findings/${findingId}/comments`, { markdown });
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  revalidatePath(`/findings/${findingId}`);
  return { ok: true };
}

export async function requestRetest(engagementId: string, note: string): Promise<ActionResult> {
  if (currentSurface() !== 'portal') return { ok: false, error: 'not available on this surface' };

  try {
    const result = await api.post<{ withinFreeWindow: boolean; note: string }>(
      `/engagements/${engagementId}/retest-request`,
      { note },
    );
    revalidatePath('/');
    return { ok: true, detail: result };
  } catch (error) {
    return { ok: false, error: message(error) };
  }
}

export async function acceptPortalTerms(): Promise<ActionResult> {
  if (currentSurface() !== 'portal') return { ok: false, error: 'not available on this surface' };

  try {
    await api.post('/terms/accept');
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  revalidatePath('/account');
  return { ok: true };
}

export async function changePortalPassword(
  unusedPrevious: ActionResult,
  form: FormData,
): Promise<ActionResult> {
  if (currentSurface() !== 'portal') return { ok: false, error: 'not available on this surface' };

  const current = formText(form, 'current');
  const next = formText(form, 'next');
  const confirm = formText(form, 'confirm');

  if (next !== confirm) return { ok: false, error: 'the two new passwords do not match' };
  if (next.length < 12) return { ok: false, error: 'use at least twelve characters' };

  try {
    await api.put('/account/password', { current, next });
  } catch (error) {
    return { ok: false, error: message(error) };
  }

  // Changing the password revokes every session, including this one. Send them back to sign in
  // rather than leaving a screen that will 401 on its next request.
  const store = await cookies();
  store.delete('attestor_session');
  redirect('/login?changed=1');
}

export async function signOutEverywhere(): Promise<void> {
  try {
    await api.post('/auth/sign-out-everywhere');
  } catch {
    // Nothing useful to say: the local cookie is cleared either way and the server-side sessions
    // expire on their own.
  }
  const store = await cookies();
  store.delete('attestor_session');
  redirect('/login');
}

export async function deactivateTeamMember(userId: string): Promise<ActionResult> {
  if (currentSurface() !== 'portal') return { ok: false, error: 'not available on this surface' };

  try {
    await api.post(`/account/users/${userId}/deactivate`);
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  revalidatePath('/account');
  return { ok: true };
}

/* Clients and platform operations ---------------------------------------------------------------- */

export async function createClient(
  unusedPrevious: ActionResult,
  form: FormData,
): Promise<ActionResult> {
  const name = formText(form, 'name');
  const legalName = formText(form, 'legalName');
  if (name === '' || legalName === '') return { ok: false, error: 'a name and a legal name' };

  let created: { client: { id: string } };
  try {
    created = await api.post<{ client: { id: string } }>('/clients', {
      name,
      legalName,
      country: formText(form, 'country', 'IN'),
      notes: formText(form, 'notes'),
    });
  } catch (error) {
    return { ok: false, error: message(error) };
  }

  redirect(`/clients/${created.client.id}`);
}

export async function recordDpa(clientId: string): Promise<ActionResult> {
  try {
    await api.post(`/clients/${clientId}/dpa`);
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  revalidatePath(`/clients/${clientId}`);
  return { ok: true };
}

export async function inviteClientUser(
  clientId: string,
  email: string,
  role: string,
): Promise<ActionResult> {
  try {
    const result = await api.post<{ token: string; acceptUrl: string; note: string }>(
      `/clients/${clientId}/invitations`,
      { email, role },
    );
    revalidatePath(`/clients/${clientId}`);
    // The link is returned once and shown once. It is not stored anywhere it can be read back.
    return { ok: true, detail: result };
  } catch (error) {
    return { ok: false, error: message(error) };
  }
}

export async function revokeInvitation(
  clientId: string,
  invitationId: string,
): Promise<ActionResult> {
  try {
    await api.delete(`/clients/${clientId}/invitations/${invitationId}`);
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  revalidatePath(`/clients/${clientId}`);
  return { ok: true };
}

export async function setRetainerActive(
  clientId: string,
  retainerId: string,
  active: boolean,
): Promise<ActionResult> {
  try {
    await api.post(`/retainers/${retainerId}/pause`, { active });
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  revalidatePath(`/clients/${clientId}`);
  return { ok: true };
}

export async function retryScanJob(jobId: string): Promise<ActionResult> {
  try {
    await api.post(`/queue/scan/${jobId}/retry`);
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  revalidatePath('/queue');
  return { ok: true };
}

export async function approveNotification(notificationId: string): Promise<ActionResult> {
  try {
    await api.post(`/notifications/${notificationId}/approve`);
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  revalidatePath('/queue');
  return { ok: true };
}

export async function markNotificationSent(notificationId: string): Promise<ActionResult> {
  try {
    await api.post(`/notifications/${notificationId}/mark-sent`);
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  revalidatePath('/queue');
  return { ok: true };
}

export async function discardNotification(
  notificationId: string,
  reason: string,
): Promise<ActionResult> {
  try {
    await api.delete(`/notifications/${notificationId}`, { reason });
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  revalidatePath('/queue');
  return { ok: true };
}

/* Portal invitation acceptance --------------------------------------------------------------------- */

export async function acceptInvitation(
  token: string,
  unusedPrevious: ActionResult,
  form: FormData,
): Promise<ActionResult> {
  if (currentSurface() !== 'portal') return { ok: false, error: 'not available on this surface' };

  const name = formText(form, 'name');
  const password = formText(form, 'password');
  const confirm = formText(form, 'confirm');

  if (password !== confirm) return { ok: false, error: 'the two passwords do not match' };
  if (password.length < 12) return { ok: false, error: 'use at least twelve characters' };

  try {
    const result = await api.post<{ otpauthUrl: string; mustConfirm: boolean }>(
      '/invitations/accept',
      { token, password, name },
    );
    // The otpauth URL contains the shared secret. It is returned to the person enrolling, once,
    // and never stored by this app.
    return { ok: true, detail: result };
  } catch (error) {
    return { ok: false, error: message(error) };
  }
}

export async function confirmInvitationMfa(
  email: string,
  code: string,
): Promise<ActionResult> {
  if (currentSurface() !== 'portal') return { ok: false, error: 'not available on this surface' };

  try {
    await api.post('/invitations/confirm-mfa', { email, code });
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  return { ok: true };
}

export async function generateAttestationLetter(engagementId: string): Promise<ActionResult> {
  try {
    await api.post(`/engagements/${engagementId}/attestation-letter`);
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  revalidatePath(`/engagements/${engagementId}/report`);
  return { ok: true };
}

export async function generateDeletionConfirmation(
  engagementId: string,
  evidenceObjects: number,
  credentialSets: number,
): Promise<ActionResult> {
  try {
    await api.post(`/engagements/${engagementId}/deletion-confirmation`, {
      evidenceObjects,
      credentialSets,
    });
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  revalidatePath(`/engagements/${engagementId}/report`);
  return { ok: true };
}

/* AI assistance ------------------------------------------------------------------------------- */

export async function draftWithAi(
  engagementId: string,
  sectionKey: string,
  instruction: string,
): Promise<ActionResult> {
  try {
    const result = await api.post<{ draft: string; model: string; estimatedCostUsd: number }>(
      `/engagements/${engagementId}/ai/draft`,
      { purpose: 'executiveSummary', sectionKey, instruction },
    );
    revalidatePath(`/engagements/${engagementId}/report`);
    return { ok: true, detail: result };
  } catch (error) {
    return { ok: false, error: message(error) };
  }
}

export async function approveSection(
  engagementId: string,
  sectionKey: string,
  markdown: string,
): Promise<ActionResult> {
  try {
    // Approval and the current text go together: approving means approving what is on the screen,
    // not whatever happens to be in the database.
    await api.put(`/engagements/${engagementId}/report/sections/${sectionKey}`, {
      markdown,
      approve: true,
    });
  } catch (error) {
    return { ok: false, error: message(error) };
  }
  revalidatePath(`/engagements/${engagementId}/report`);
  return { ok: true };
}
