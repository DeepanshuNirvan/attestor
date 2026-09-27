'use client';

import { useState, useTransition } from 'react';
import { recordRetest } from '@/app/actions';

/**
 * The retest verdict for one finding. The retest report prints it, and the attestation letter counts
 * a finding as re-verified only once a tester has recorded "fixed" here.
 */
export function RetestVerdict({
  engagementId,
  findingId,
  status,
  retestedAt,
}: {
  engagementId: string;
  findingId: string;
  status: string;
  retestedAt: string | null;
}) {
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  function record(outcome: 'fixed' | 'stillOpen') {
    startTransition(async () => {
      const result = await recordRetest(engagementId, findingId, outcome);
      setError(result.ok ? null : (result.error ?? 'that was refused'));
    });
  }

  return (
    <div>
      <p className="small muted">
        {retestedAt
          ? `Retested ${new Date(retestedAt).toLocaleString()}: ${status === 'fixed' ? 'verified fixed' : 'still open'}.`
          : 'Not retested yet. After the client says it is fixed, repeat the reproduction steps and record what you saw.'}
      </p>
      {error ? (
        <p className="notice notice-danger" role="alert">
          {error}
        </p>
      ) : null}
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <button type="button" disabled={pending} onClick={() => record('fixed')}>
          Verified fixed
        </button>
        <button type="button" className="button-quiet" disabled={pending} onClick={() => record('stillOpen')}>
          Still open
        </button>
      </div>
    </div>
  );
}
