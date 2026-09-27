'use client';

import { useActionState, useState, useTransition } from 'react';
import { useRouter } from 'next/navigation';
import { markFalsePositive, saveFindingWriteUp, type ActionResult } from '@/app/actions';

/**
 * The text a finding needs before the report can be released: business impact, numbered steps and
 * a specific fix. Tools write little or none of it, so it is written here. The release checklist
 * still decides what is enough; this form only saves.
 */

const initial: ActionResult = { ok: false };

export function FindingWriteUp({
  engagementId,
  findingId,
  businessImpact,
  reproductionSteps,
  remediation,
}: {
  engagementId: string;
  findingId: string;
  businessImpact: string;
  reproductionSteps: string[];
  remediation: string;
}) {
  const router = useRouter();
  const [state, action, pending] = useActionState(
    saveFindingWriteUp.bind(null, engagementId, findingId),
    initial,
  );
  const [dismissing, startDismissing] = useTransition();
  const [dismissError, setDismissError] = useState<string | null>(null);

  function onNotReal() {
    const reason = window.prompt(
      'Why is this not a real issue? At least ten characters. It is recorded and the finding leaves the report.',
    );
    if (!reason) return;
    startDismissing(async () => {
      const result = await markFalsePositive(engagementId, findingId, reason);
      if (result.ok) router.push(`/engagements/${engagementId}/report`);
      else setDismissError(result.error ?? 'that was refused');
    });
  }

  return (
    <form action={action}>
      <div className="field">
        <label htmlFor="businessImpact">Business impact</label>
        <textarea id="businessImpact" name="businessImpact" rows={4} defaultValue={businessImpact} />
        <p className="small muted">What it means for the client's business, in plain words.</p>
      </div>

      <div className="field">
        <label htmlFor="reproductionSteps">Reproduction steps</label>
        <textarea
          id="reproductionSteps"
          name="reproductionSteps"
          rows={5}
          defaultValue={reproductionSteps.join('\n')}
        />
        <p className="small muted">One step per line, at least two. They are numbered in the report.</p>
      </div>

      <div className="field">
        <label htmlFor="remediation">Remediation</label>
        <textarea id="remediation" name="remediation" rows={4} defaultValue={remediation} />
        <p className="small muted">The specific fix for this application, not a general rule.</p>
      </div>

      {state.error ? (
        <p className="notice notice-danger" role="alert">
          {state.error}
        </p>
      ) : null}
      {state.ok ? (
        <p className="notice small" role="status">
          Saved.
        </p>
      ) : null}
      {dismissError ? (
        <p className="notice notice-danger" role="alert">
          {dismissError}
        </p>
      ) : null}

      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <button type="submit" disabled={pending || dismissing}>
          {pending ? 'Saving…' : 'Save'}
        </button>
        <button type="button" className="button-quiet" onClick={onNotReal} disabled={pending || dismissing}>
          Not a real issue
        </button>
      </div>
    </form>
  );
}
