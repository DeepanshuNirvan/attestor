import { redirect } from 'next/navigation';
import Link from 'next/link';
import { PageHeader, Shell, Stat } from '@/components/shell';
import { Outbox, QueueControls } from '@/components/queue-controls';
import { tryGet } from '@/lib/api';

/**
 * The job queue and the outbox.
 *
 * A failed scan job is not a number: it is a tool that did not run against a client's asset, which
 * means the coverage matrix has a hole in it until somebody decides what to do. That is why this
 * page leads with failures rather than with throughput.
 */

interface QueueSnapshot {
  queues: { name: string; counts: Record<string, number> }[];
  running: {
    id: string;
    engagementId: string;
    engagementReference: string;
    module: string;
    toolName: string;
    startedAt: string | null;
  }[];
  failed: {
    id: string;
    name: string;
    attemptsMade: number;
    failedReason: string | null;
    engagementId: string | null;
    toolId: string | null;
  }[];
}

interface OutboxResponse {
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
  note: string;
}

function formatTime(value: string | null): string {
  if (!value) return '—';
  return new Intl.DateTimeFormat('en-GB', {
    day: 'numeric',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
    timeZone: 'UTC',
  }).format(new Date(value));
}

export default async function QueuePage({
  searchParams,
}: {
  searchParams: Promise<{ outbox?: string }>;
}) {
  const filters = await searchParams;
  const state = filters.outbox ?? 'pending';

  const [snapshot, outbox] = await Promise.all([
    tryGet<QueueSnapshot>('/queue'),
    tryGet<OutboxResponse>(`/notifications?state=${encodeURIComponent(state)}`),
  ]);
  if (!snapshot) redirect('/login');

  const scan = snapshot.queues.find((queue) => queue.name === 'scan')?.counts ?? {};

  return (
    <Shell>
      <PageHeader
        title="Job queue"
        subtitle={`${snapshot.running.length} running, ${snapshot.failed.length} failed`}
      />

      <div className="stats" style={{ marginBottom: '1.5rem' }}>
        <Stat label="Waiting" value={scan.waiting ?? 0} />
        <Stat label="Active" value={scan.active ?? 0} />
        <Stat label="Delayed" value={scan.delayed ?? 0} />
        <Stat label="Failed" value={scan.failed ?? 0} note="scan queue" />
      </div>

      <section className="panel" style={{ marginBottom: '1.5rem' }}>
        <h2>Running now</h2>
        {snapshot.running.length === 0 ? (
          <p className="muted small">Nothing is running.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Engagement</th>
                <th>Module</th>
                <th>Tool</th>
                <th>Started</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {snapshot.running.map((run) => (
                <tr key={run.id}>
                  <td className="mono small">
                    <Link href={`/engagements/${run.engagementId}`}>{run.engagementReference}</Link>
                  </td>
                  <td className="small">{run.module}</td>
                  <td className="small">{run.toolName}</td>
                  <td className="small muted">{formatTime(run.startedAt)}</td>
                  <td>
                    <Link className="button button-quiet" href={`/engagements/${run.engagementId}`}>
                      Stop
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <QueueControls failed={snapshot.failed} queues={snapshot.queues} />

      <section className="panel" style={{ marginTop: '1.5rem' }}>
        <h2>Outbox</h2>
        <p className="small muted">{outbox?.note ?? ''}</p>
        <p className="small">
          Show:{' '}
          <Link href="/queue?outbox=pending">Awaiting approval</Link>
          {' · '}
          <Link href="/queue?outbox=approved">Approved, not sent</Link>
          {' · '}
          <Link href="/queue?outbox=sent">Sent</Link>
          {' · '}
          <Link href="/queue?outbox=all">All</Link>
        </p>
        <Outbox notifications={outbox?.notifications ?? []} />
      </section>
    </Shell>
  );
}
