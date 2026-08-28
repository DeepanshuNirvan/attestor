'use client';

import { useState, useTransition } from 'react';
import { requestRetest } from '@/app/actions';
import { formText } from '@/lib/form';

/** The retest request form. Records a request; a person schedules the work. */
export function RetestRequest({ engagementId }: { engagementId: string }) {
  const [pending, startTransition] = useTransition();
  const [message, setMessage] = useState<string | null>(null);

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        const form = event.currentTarget;
        const note = formText(new FormData(form), 'note');

        startTransition(async () => {
          const result = await requestRetest(engagementId, note);
          if (result.ok) {
            const detail = result.detail as { note?: string } | undefined;
            setMessage(detail?.note ?? 'Recorded. We will confirm a date.');
            form.reset();
            return;
          }
          setMessage(result.error ?? 'that did not work');
        });
      }}
    >
      <div className="field">
        <label htmlFor={`note-${engagementId}`}>
          Anything we should know? Deploy dates, environments that have moved, changes we should
          expect.
        </label>
        <textarea id={`note-${engagementId}`} name="note" rows={3} />
      </div>
      {message ? (
        <p className="notice small" role="status">
          {message}
        </p>
      ) : null}
      <button type="submit" disabled={pending}>
        {pending ? 'Sending…' : 'Request a retest'}
      </button>
    </form>
  );
}
