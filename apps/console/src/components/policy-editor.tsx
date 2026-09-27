'use client';

import { useActionState } from 'react';
import { savePolicy, type ActionResult } from '@/app/actions';

/**
 * The engagement's policy, as YAML.
 *
 * Validation happens in the API: a rate above the ceiling is refused and nothing is saved, and
 * anything merely suspect comes back as a warning. Both are shown here, before a run rather than
 * during one.
 */
const LOGIN_EXAMPLE = `authProfiles:
  - id: user-a
    roleName: user
    type: formLogin
    loginUrl: http://192.168.29.249:5174/login
    apiLogin:
      url: http://192.168.29.249:5174/api/auth/login
      usernameField: email
      passwordField: password
      tokenPath: token`;

export function PolicyEditor({ engagementId, yaml }: { engagementId: string; yaml: string }) {
  const [state, action, pending] = useActionState<ActionResult, FormData>(
    savePolicy.bind(null, engagementId),
    { ok: false },
  );
  const warnings = (state.detail as { warnings?: string[] } | undefined)?.warnings ?? [];

  return (
    <form action={action}>
      <p className="small muted">
        Started from the profile you chose. Add how to log in to the application — without an{' '}
        <code>authProfiles</code> entry everything is tested as an anonymous visitor. Copy the field
        names from the application&apos;s login request in your browser&apos;s network tab. For example:
      </p>
      <pre className="small">{LOGIN_EXAMPLE}</pre>

      <div className="field">
        <label htmlFor="yaml">Policy</label>
        <textarea
          id="yaml"
          name="yaml"
          rows={18}
          defaultValue={yaml}
          spellCheck={false}
          style={{ fontFamily: 'var(--font-mono, monospace)' }}
        />
      </div>

      {state.error ? (
        <p className="notice notice-danger small" role="alert">
          {state.error}
        </p>
      ) : null}
      {state.ok ? (
        <div className={`notice ${warnings.length > 0 ? 'notice-warning' : ''} small`} role="status">
          <p>
            <strong>Saved.</strong>{' '}
            {warnings.length === 0 ? 'No warnings.' : 'Read these before running anything:'}
          </p>
          {warnings.length > 0 ? (
            <ul>
              {warnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}

      <button type="submit" disabled={pending}>
        {pending ? 'Saving…' : 'Save policy'}
      </button>
    </form>
  );
}
