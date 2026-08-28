'use client';

import { useActionState } from 'react';
import { changeState, type ActionResult } from '@/app/actions';

/**
 * The lifecycle control.
 *
 * The API enforces the state machine; this presents the options and surfaces the refusal. When a
 * transition is refused the reason is shown verbatim, because "the advance payment has not been
 * recorded" is more useful than "invalid transition".
 */

const STATES = [
  'draft',
  'scoped',
  'authorised',
  'advancePaid',
  'readyToRun',
  'running',
  'triage',
  'manualTesting',
  'reportDraft',
  'reportReview',
  'released',
  'retestPending',
  'retestComplete',
  'closed',
];

const initial: ActionResult = { ok: false };

export function StateControl({ engagementId, current }: { engagementId: string; current: string }) {
  const [state, action, pending] = useActionState(changeState.bind(null, engagementId), initial);
  const needsBackwardsReason = state.error?.includes('backwards') ?? false;
  const needsOverride = state.error?.includes('advance payment') ?? false;

  return (
    <form action={action}>
      <p className="small muted">
        Current stage: <strong>{current}</strong>
      </p>

      <div className="field">
        <label htmlFor="to">Move to</label>
        <select id="to" name="to" defaultValue={current}>
          {STATES.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
      </div>

      <div className="field">
        <label htmlFor="reason">Reason (required when moving backwards)</label>
        <input id="reason" name="reason" minLength={needsBackwardsReason ? 10 : 0} />
      </div>

      {needsOverride ? (
        <div className="field">
          <label htmlFor="advanceGateOverrideReason">
            Advance payment override — recorded against you in the audit log
          </label>
          <input id="advanceGateOverrideReason" name="advanceGateOverrideReason" minLength={10} />
        </div>
      ) : null}

      {state.error ? (
        <p className="notice notice-warning small" role="alert">
          {state.error}
        </p>
      ) : null}
      {state.ok ? <p className="notice small">Moved.</p> : null}

      <button type="submit" disabled={pending}>
        {pending ? 'Moving…' : 'Change stage'}
      </button>
    </form>
  );
}
