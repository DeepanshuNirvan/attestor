'use client';

import { useActionState } from 'react';
import { savePreFlightChecklist, type ActionResult } from '@/app/actions';

/**
 * The pre-flight checklist.
 *
 * It gates `advancePaid → readyToRun` and, unlike the advance payment, it has no override — so this
 * panel is the only way an engagement becomes runnable. The list and the verdict both come from the
 * API; this renders them and shows what is still outstanding.
 */

export interface PreFlightItem {
  id: string;
  label: string;
  note: string;
}

const initial: ActionResult = { ok: false };

export function PreFlightChecklist({
  engagementId,
  items,
  confirmations,
  outstanding,
}: {
  engagementId: string;
  items: PreFlightItem[];
  confirmations: Record<string, boolean>;
  outstanding: string[];
}) {
  const [state, action, pending] = useActionState(
    savePreFlightChecklist.bind(
      null,
      engagementId,
      items.map((item) => item.id),
    ),
    initial,
  );

  return (
    <form action={action}>
      <p className="small muted">
        {outstanding.length === 0
          ? 'Complete. This engagement can move to ready to run.'
          : `${outstanding.length} of ${items.length} still outstanding.`}
      </p>

      {items.map((item) => (
        <div className="field" key={item.id}>
          <label htmlFor={item.id}>
            <input
              type="checkbox"
              id={item.id}
              name={item.id}
              defaultChecked={confirmations[item.id] === true}
            />{' '}
            {item.label}
          </label>
          <p className="small muted">{item.note}</p>
        </div>
      ))}

      {state.error ? (
        <p className="notice notice-warning small" role="alert">
          {state.error}
        </p>
      ) : null}
      {state.ok ? <p className="notice small">Saved.</p> : null}

      <button type="submit" disabled={pending}>
        {pending ? 'Saving…' : 'Save checklist'}
      </button>
    </form>
  );
}
