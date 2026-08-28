'use client';

import { useState, useTransition } from 'react';
import {
  approveNotification,
  discardNotification,
  markNotificationSent,
  retryScanJob,
} from '@/app/actions';

/**
 * Failed jobs and the outbox.
 *
 * Retrying a job re-runs the scope guard: a run refused the first time is refused again. Retry is
 * for a tool that crashed, not a way past a refusal.
 */

export function QueueControls({
  failed,
  queues,
}: {
  failed: {
    id: string;
    name: string;
    attemptsMade: number;
    failedReason: string | null;
    engagementId: string | null;
    toolId: string | null;
  }[];
  queues: { name: string; counts: Record<string, number> }[];
}) {
  const [pending, startTransition] = useTransition();
  const [message, setMessage] = useState<string | null>(null);

  return (
    <>
      <section className="panel">
        <h2>Failed jobs</h2>
        {message ? (
          <p className="notice small" role="status">
            {message}
          </p>
        ) : null}

        {failed.length === 0 ? (
          <p className="muted small">Nothing has failed.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Tool</th>
                <th>Attempts</th>
                <th>Reason</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {failed.map((job) => (
                <tr key={job.id}>
                  <td className="small">{job.toolId ?? job.name}</td>
                  <td className="small muted">{job.attemptsMade}</td>
                  <td className="small">{job.failedReason ?? 'no reason recorded'}</td>
                  <td>
                    <button
                      type="button"
                      className="button-quiet"
                      disabled={pending}
                      onClick={() => {
                        startTransition(async () => {
                          const result = await retryScanJob(job.id);
                          setMessage(
                            result.ok
                              ? 'Requeued. Scope is checked again before it starts.'
                              : (result.error ?? 'that did not work'),
                          );
                        });
                      }}
                    >
                      Retry
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <h3>All queues</h3>
        <table>
          <thead>
            <tr>
              <th>Queue</th>
              <th>Waiting</th>
              <th>Active</th>
              <th>Delayed</th>
              <th>Failed</th>
              <th>Completed</th>
            </tr>
          </thead>
          <tbody>
            {queues.map((queue) => (
              <tr key={queue.name}>
                <td className="small">{queue.name}</td>
                <td className="small">{queue.counts.waiting ?? 0}</td>
                <td className="small">{queue.counts.active ?? 0}</td>
                <td className="small">{queue.counts.delayed ?? 0}</td>
                <td className="small">{queue.counts.failed ?? 0}</td>
                <td className="small muted">{queue.counts.completed ?? 0}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}

export function Outbox({
  notifications,
}: {
  notifications: {
    id: string;
    engagementReference: string | null;
    channel: string;
    template: string;
    subject: string;
    body: string;
    queuedAt: string;
    approvedAt: string | null;
    sentAt: string | null;
  }[];
}) {
  const [pending, startTransition] = useTransition();
  const [message, setMessage] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  if (notifications.length === 0) {
    return <p className="muted small">Nothing here.</p>;
  }

  return (
    <>
      {message ? (
        <p className="notice small" role="status">
          {message}
        </p>
      ) : null}

      {notifications.map((item) => (
        <div key={item.id} style={{ borderTop: '1px solid var(--rule)', padding: '0.75rem 0' }}>
          <p style={{ marginBottom: '0.25rem' }}>
            <strong>{item.subject}</strong>
          </p>
          <p className="small muted">
            {item.engagementReference ?? 'no engagement'} · {item.channel} · {item.template} ·{' '}
            {item.sentAt ? 'sent' : item.approvedAt ? 'approved, not sent' : 'awaiting approval'}
          </p>

          <button
            type="button"
            className="button-quiet"
            onClick={() => setOpen(open === item.id ? null : item.id)}
          >
            {open === item.id ? 'Hide' : 'Read'}
          </button>

          {open === item.id ? (
            // Rendered as text. A drafted message is content, not markup.
            <pre style={{ whiteSpace: 'pre-wrap', marginTop: '0.5rem' }}>{item.body}</pre>
          ) : null}

          <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
            {item.approvedAt ? null : (
              <button
                type="button"
                disabled={pending}
                onClick={() => {
                  startTransition(async () => {
                    const result = await approveNotification(item.id);
                    setMessage(result.ok ? 'Approved.' : (result.error ?? 'that did not work'));
                  });
                }}
              >
                Approve
              </button>
            )}

            {item.approvedAt && !item.sentAt ? (
              <button
                type="button"
                className="button-quiet"
                disabled={pending}
                onClick={() => {
                  startTransition(async () => {
                    const result = await markNotificationSent(item.id);
                    setMessage(
                      result.ok ? 'Recorded as sent.' : (result.error ?? 'that did not work'),
                    );
                  });
                }}
              >
                I have sent this
              </button>
            ) : null}

            {item.sentAt ? null : (
              <button
                type="button"
                className="button-quiet"
                disabled={pending}
                onClick={() => {
                  const reason = window.prompt('Why is this being discarded?');
                  if (!reason) return;
                  startTransition(async () => {
                    const result = await discardNotification(item.id, reason);
                    setMessage(result.ok ? 'Discarded.' : (result.error ?? 'that did not work'));
                  });
                }}
              >
                Discard
              </button>
            )}
          </div>
        </div>
      ))}
    </>
  );
}
