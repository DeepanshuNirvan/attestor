'use client';

import { useActionState } from 'react';
import { recordPayment, type ActionResult } from '@/app/actions';

/**
 * Recording a payment.
 *
 * Two gates read these dates: the advance before anything runs, the balance before a report is
 * released. The invoice reference is required because the question asked six months later is which
 * invoice this was against, not whether somebody once ticked a box.
 */

const initial: ActionResult = { ok: false };

export function PaymentControl({
  engagementId,
  advancePaidAt,
  finalPaidAt,
  currency,
}: {
  engagementId: string;
  advancePaidAt: string | null;
  finalPaidAt: string | null;
  currency: string;
}) {
  const [state, action, pending] = useActionState(recordPayment.bind(null, engagementId), initial);
  const asDate = (value: string | null) =>
    value === null ? 'not recorded' : new Date(value).toLocaleDateString('en-GB');

  return (
    <form action={action}>
      <p className="small muted">
        Advance: <strong>{asDate(advancePaidAt)}</strong> · Balance:{' '}
        <strong>{asDate(finalPaidAt)}</strong>
      </p>

      <div className="field">
        <label htmlFor="kind">Payment</label>
        <select id="kind" name="kind" defaultValue="advance">
          <option value="advance">Advance</option>
          <option value="final">Balance</option>
        </select>
      </div>

      <div className="field">
        <label htmlFor="reference">Invoice reference</label>
        <input id="reference" name="reference" required maxLength={120} />
      </div>

      <div className="field">
        <label htmlFor="amount">Amount received ({currency}), optional</label>
        <input id="amount" name="amount" type="number" min={0} step={1} />
      </div>

      {state.error ? (
        <p className="notice notice-warning small" role="alert">
          {state.error}
        </p>
      ) : null}
      {state.ok ? <p className="notice small">Recorded.</p> : null}

      <button type="submit" disabled={pending}>
        {pending ? 'Recording…' : 'Record payment'}
      </button>
    </form>
  );
}
