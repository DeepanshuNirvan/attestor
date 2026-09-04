import 'server-only';

/**
 * The one call the portal makes to the console API.
 *
 * `lib/api.ts` is bound to this deployment's own surface on purpose — a portal deployment cannot
 * reach the console API through it, and that is a property worth keeping. Credential intake is the
 * single exception, and it is deliberately a separate, narrow client rather than a flag on the
 * general one, so nothing else can quietly acquire the same reach.
 *
 * Why the exception exists: the client fills the form on the portal, because that is the only
 * surface they can reach, but the console is the only service holding the vault key. Sending the
 * credential to the portal API instead would mean giving the internet-facing service the ability to
 * write into the credential vault, which is exactly what the split exists to prevent.
 *
 * No session cookie is forwarded. The one-time token in the path is the whole of the authorisation.
 */

function intakeBaseUrl(): string {
  const url = process.env.ATTESTOR_INTAKE_API_URL ?? process.env.ATTESTOR_API_URL;
  if (!url) {
    throw new Error(
      'ATTESTOR_INTAKE_API_URL is not set. The credential intake page needs the console API address; ' +
        'on the portal deployment it is the only thing that address is used for.',
    );
  }
  return url.replace(/\/$/, '');
}

export interface IntakeField {
  name: string;
  label: string;
  input: 'text' | 'password' | 'email' | 'tel' | 'textarea';
  help: string;
  optional?: boolean;
}

export interface IntakeForm {
  slot: string;
  label: string;
  roleName: string;
  kind: string;
  kindLabel: string;
  description: string;
  fields: IntakeField[];
  alreadyProvided: boolean;
}

export interface IntakeDetails {
  engagementReference: string;
  engagementTitle: string;
  clientName: string;
  expiresAt: string;
  forms: IntakeForm[];
}

export type IntakeLookup =
  | { ok: true; details: IntakeDetails }
  | { ok: false; message: string };

export async function loadIntake(token: string): Promise<IntakeLookup> {
  const response = await fetch(`${intakeBaseUrl()}/credential-intake/${encodeURIComponent(token)}`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { error?: string } | null;
    return { ok: false, message: body?.error ?? 'That link is not valid. Ask your tester for a new one.' };
  }

  return { ok: true, details: (await response.json()) as IntakeDetails };
}

export type IntakeSubmission =
  | { ok: true; label: string }
  | { ok: false; problems: string[] };

export async function submitIntake(
  token: string,
  slot: string,
  values: Record<string, string>,
): Promise<IntakeSubmission> {
  const response = await fetch(`${intakeBaseUrl()}/credential-intake/${encodeURIComponent(token)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ slot, values }),
    cache: 'no-store',
  });

  const body = (await response.json().catch(() => null)) as
    | { label?: string; problems?: string[]; error?: string }
    | null;

  if (!response.ok) {
    return {
      ok: false,
      problems: body?.problems ?? [body?.error ?? 'That could not be saved. Please try again.'],
    };
  }

  return { ok: true, label: body?.label ?? '' };
}
