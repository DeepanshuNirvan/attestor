'use client';

import { useState, useTransition } from 'react';
import { setAiAssist } from '@/app/actions';

/**
 * Whether AI may draft this engagement's report prose.
 *
 * Two switches have to agree: the deployment's (`AI_ENABLED` and a provider in `infra/.env`) and
 * this one. The deployment's state is shown alongside so a refused draft is never a mystery.
 */
export function AiAssistToggle({
  engagementId,
  enabled,
  deploymentProvider,
  deploymentEnabled,
}: {
  engagementId: string;
  enabled: boolean;
  deploymentProvider: string | null;
  deploymentEnabled: boolean | null;
}) {
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  const deploymentReady = deploymentEnabled === true && deploymentProvider !== null && deploymentProvider !== 'none';

  return (
    <div>
      <p className="small">
        AI drafting for this engagement: <strong>{enabled ? 'allowed' : 'not allowed'}</strong>
        {' · '}
        Deployment: <strong>{deploymentReady ? `on (${deploymentProvider})` : 'off'}</strong>
      </p>
      {!deploymentReady ? (
        <p className="small muted">
          Set <code>AI_ENABLED=true</code> and an <code>AI_PROVIDER</code> in <code>infra/.env</code>{' '}
          before drafting will work, whatever this switch says.
        </p>
      ) : null}
      <p className="small muted">
        Only confirmed findings are sent, redacted, and every draft still has to be approved by you.
        Turn this on only if the client has not objected to their findings being processed by the
        model you configured.
      </p>
      {error ? (
        <p className="notice notice-danger small" role="alert">
          {error}
        </p>
      ) : null}
      <button
        type="button"
        className={enabled ? 'button-quiet' : undefined}
        disabled={pending}
        onClick={() =>
          startTransition(async () => {
            const result = await setAiAssist(engagementId, !enabled);
            setError(result.ok ? null : (result.error ?? 'could not change the setting'));
          })
        }
      >
        {pending ? 'Saving…' : enabled ? 'Stop allowing AI drafting' : 'Allow AI drafting'}
      </button>
    </div>
  );
}
