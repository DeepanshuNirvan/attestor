'use client';

import { useActionState } from 'react';
import { addScopeItems, type ActionResult } from '@/app/actions';

/**
 * Adding scope.
 *
 * Values are validated by the API at entry, so a typo is a form error now rather than a refusal on
 * the morning of the test. The per-value problems come back and are shown against the value.
 */

const KINDS = [
  'domain',
  'wildcard',
  'ip',
  'cidr',
  'url',
  'repo',
  'cloudAccount',
  'mobilePackage',
  'llmEndpoint',
];

const initial: ActionResult = { ok: false };

export function ScopeEditor({ engagementId }: { engagementId: string }) {
  const [state, action, pending] = useActionState(addScopeItems.bind(null, engagementId), initial);
  const problems = (state.detail as { problems?: { value: string; problem: string }[] } | undefined)
    ?.problems;

  return (
    <form action={action} style={{ marginTop: '1rem' }}>
      <div className="field">
        <label htmlFor="kind">Kind</label>
        <select id="kind" name="kind" defaultValue="domain">
          {KINDS.map((kind) => (
            <option key={kind} value={kind}>
              {kind}
            </option>
          ))}
        </select>
      </div>

      <div className="field">
        <label htmlFor="values">Values, one per line</label>
        <textarea
          id="values"
          name="values"
          rows={4}
          placeholder={'app.client.example\n*.client.example'}
        />
      </div>

      <label style={{ fontWeight: 400, display: 'flex', gap: '0.4rem', marginBottom: '0.5rem' }}>
        <input type="checkbox" name="excluded" style={{ width: 'auto' }} />
        Add these as exclusions rather than inclusions
      </label>

      {state.error ? (
        <p className="notice notice-danger small" role="alert">
          {state.error}
        </p>
      ) : null}

      {problems ? (
        <ul className="small">
          {problems.map((problem) => (
            <li key={problem.value}>
              <code>{problem.value}</code> — {problem.problem}
            </li>
          ))}
        </ul>
      ) : null}

      <button type="submit" disabled={pending}>
        {pending ? 'Adding…' : 'Add to scope'}
      </button>
    </form>
  );
}
