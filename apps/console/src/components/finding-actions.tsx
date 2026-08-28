'use client';

import { useState, useTransition } from 'react';
import { postComment, updateFindingStatus } from '@/app/actions';
import { formText } from '@/lib/form';

/**
 * What a client can do with a finding.
 *
 * Risk acceptance needs a written justification because it is their audit record, not ours. The API
 * refuses it without one; this asks for it up front so the refusal is not a surprise.
 */

const STATUSES = [
  { value: 'acknowledged', label: 'Acknowledged' },
  { value: 'inProgress', label: 'In progress' },
  { value: 'fixed', label: 'Fixed, ready for verification' },
  { value: 'riskAccepted', label: 'Risk accepted' },
];

export function FindingActions({
  findingId,
  status,
  justification,
}: {
  findingId: string;
  status: string;
  justification: string | null;
}) {
  const [pending, startTransition] = useTransition();
  const [message, setMessage] = useState<string | null>(null);
  const [chosen, setChosen] = useState(status === 'riskAccepted' ? 'riskAccepted' : 'acknowledged');

  return (
    <>
      <section className="panel">
        <h3>Status</h3>
        <p className="small muted">
          A finding is treated as verified only after we have retested it and recorded the result.
        </p>

        <form
          onSubmit={(event) => {
            event.preventDefault();
            const data = new FormData(event.currentTarget);
            const next = formText(data, 'status');
            const reason = formText(data, 'justification');

            startTransition(async () => {
              const result = await updateFindingStatus(findingId, next, reason || undefined);
              setMessage(result.ok ? 'Updated.' : (result.error ?? 'that did not work'));
            });
          }}
        >
          <div className="field">
            <label htmlFor="status">Set status</label>
            <select
              id="status"
              name="status"
              value={chosen}
              onChange={(event) => setChosen(event.target.value)}
            >
              {STATUSES.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>

          {chosen === 'riskAccepted' ? (
            <div className="field">
              <label htmlFor="justification">
                Why is this risk acceptable? Recorded with your name and the date.
              </label>
              <textarea
                id="justification"
                name="justification"
                rows={4}
                minLength={20}
                defaultValue={justification ?? ''}
                required
              />
            </div>
          ) : null}

          {message ? (
            <p className="notice small" role="status">
              {message}
            </p>
          ) : null}

          <button type="submit" disabled={pending}>
            {pending ? 'Saving…' : 'Update'}
          </button>
        </form>
      </section>

      <section className="panel">
        <h3>Ask us about this</h3>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            const form = event.currentTarget;
            const value = formText(new FormData(form), 'markdown');
            if (value.trim() === '') return;

            startTransition(async () => {
              const result = await postComment(findingId, value);
              setMessage(result.ok ? 'Sent. We will reply here.' : (result.error ?? 'that did not work'));
              if (result.ok) form.reset();
            });
          }}
        >
          <div className="field">
            <label htmlFor="markdown">Message</label>
            <textarea id="markdown" name="markdown" rows={4} />
          </div>
          <button type="submit" className="button-quiet" disabled={pending}>
            Send
          </button>
        </form>
      </section>
    </>
  );
}
