'use client';

import { useActionState } from 'react';
import { clearStop, pressPanicStop, type ActionResult } from '@/app/actions';

/**
 * The stop control.
 *
 * Prominent, one field, one button. It kills every running container for the engagement and pauses
 * the queue, and who pressed it and why goes to the audit log. Clearing it needs a reason too.
 */

const initial: ActionResult = { ok: false };

export function StopControl({ engagementId, active }: { engagementId: string; active: boolean }) {
  const [stopState, stopAction, stopping] = useActionState(
    pressPanicStop.bind(null, engagementId),
    initial,
  );
  const [clearState, clearAction, clearing] = useActionState(
    clearStop.bind(null, engagementId),
    initial,
  );

  const killed = (stopState.detail as { containersKilled?: number } | undefined)?.containersKilled;

  if (active) {
    return (
      <form action={clearAction}>
        <p className="small">
          A stop is in force. Clearing it resumes the queue; running containers are not restarted.
        </p>
        <div className="field">
          <label htmlFor="clear-reason">Why is it safe to resume?</label>
          <input id="clear-reason" name="reason" required minLength={3} />
        </div>
        <input type="hidden" name="scope" value="engagement" />
        {clearState.error ? (
          <p className="notice notice-danger small" role="alert">
            {clearState.error}
          </p>
        ) : null}
        <button type="submit" disabled={clearing}>
          {clearing ? 'Clearing…' : 'Clear the stop'}
        </button>
      </form>
    );
  }

  return (
    <form action={stopAction}>
      <p className="small">
        Halts every running job for this engagement within seconds and pauses the queue.
      </p>
      <div className="field">
        <label htmlFor="stop-reason">Reason</label>
        <input
          id="stop-reason"
          name="reason"
          required
          minLength={3}
          placeholder="Client asked us to stop"
        />
      </div>
      <div className="field">
        <label htmlFor="stop-scope">Scope</label>
        <select id="stop-scope" name="scope" defaultValue="engagement">
          <option value="engagement">This engagement</option>
          <option value="platform">The whole platform</option>
        </select>
      </div>
      {stopState.error ? (
        <p className="notice notice-danger small" role="alert">
          {stopState.error}
        </p>
      ) : null}
      {stopState.ok ? (
        <p className="notice small">Stopped. {killed ?? 0} container(s) killed.</p>
      ) : null}
      <button type="submit" className="button-danger" disabled={stopping}>
        {stopping ? 'Stopping…' : 'Stop everything'}
      </button>
    </form>
  );
}
