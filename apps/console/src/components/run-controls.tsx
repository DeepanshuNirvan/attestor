'use client';

import { useActionState } from 'react';
import { queueRun, type ActionResult } from '@/app/actions';

/**
 * Queue a run.
 *
 * Dry run is the default and the checkbox opts *out* of it. That is deliberate: sending packets at
 * a client's systems should be an action somebody took, not the consequence of leaving a box
 * unticked. The confirmation phrase on the live path is there for the same reason.
 */

const MODULES = [
  { id: 'recon', label: 'Recon and attack surface' },
  { id: 'web', label: 'Web application' },
  { id: 'api', label: 'API' },
  { id: 'cloud', label: 'Cloud posture' },
  { id: 'code', label: 'Code and supply chain' },
  { id: 'network', label: 'Network' },
  { id: 'mobile', label: 'Mobile' },
  { id: 'llm', label: 'LLM and AI' },
];

const initial: ActionResult = { ok: false };

export function RunControls({ engagementId, disabled }: { engagementId: string; disabled: boolean }) {
  const [state, action, pending] = useActionState(
    queueRun.bind(null, engagementId),
    initial,
  );

  const detail = state.detail as { queued?: unknown[]; policyWarnings?: string[] } | undefined;

  return (
    <form action={action}>
      <fieldset style={{ border: 0, padding: 0, margin: '0 0 0.75rem' }}>
        <legend className="label">Modules</legend>
        {MODULES.map((module) => (
          <label key={module.id} style={{ fontWeight: 400, display: 'flex', gap: '0.4rem' }}>
            <input type="checkbox" name="modules" value={module.id} style={{ width: 'auto' }} />
            {module.label}
          </label>
        ))}
      </fieldset>

      <label style={{ fontWeight: 400, display: 'flex', gap: '0.4rem', marginBottom: '0.5rem' }}>
        <input type="checkbox" name="live" style={{ width: 'auto' }} />
        Send packets. Leave unticked for a dry run, which performs every check and contacts nothing.
      </label>

      {state.error ? (
        <p className="notice notice-danger small" role="alert">
          {state.error}
        </p>
      ) : null}

      {state.ok && detail ? (
        <div className="notice small">
          <p>Queued {detail.queued?.length ?? 0} run(s).</p>
          {(detail.policyWarnings ?? []).map((warning) => (
            <p key={warning}>{warning}</p>
          ))}
        </div>
      ) : null}

      <button type="submit" disabled={pending || disabled}>
        {pending ? 'Queueing…' : 'Queue'}
      </button>

      {disabled ? (
        <p className="small muted" style={{ marginTop: '0.5rem' }}>
          Disabled: the engagement has no valid authorisation, or a stop is in force.
        </p>
      ) : null}
    </form>
  );
}
