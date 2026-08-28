import { redirect } from 'next/navigation';
import Link from 'next/link';
import { PageHeader, Shell } from '@/components/shell';
import { TriageQueue, type Candidate } from '@/components/triage-queue';
import { tryGet } from '@/lib/api';

/**
 * The review queue.
 *
 * Everything a tool or an agent produced arrives here as a candidate and stays a candidate until a
 * person confirms it. This screen exists to make that person's afternoon survivable: keyboard
 * first, bulk actions, and enough of the finding visible that most decisions need no click.
 */

interface ReviewQueue {
  candidates: Candidate[];
  total: number;
  byTool: Record<string, number>;
}

export default async function TriagePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const queue = await tryGet<ReviewQueue>(`/engagements/${id}/review-queue`);
  if (!queue) redirect('/login');

  return (
    <Shell>
      <PageHeader
        title="Review queue"
        subtitle={`${queue.total} candidate${queue.total === 1 ? '' : 's'} awaiting a decision`}
        actions={
          <Link className="button button-quiet" href={`/engagements/${id}`}>
            Back to engagement
          </Link>
        }
      />

      {queue.total === 0 ? (
        <div className="panel">
          <p>
            Nothing to review. Candidates appear here after a run; nothing reaches a report without
            passing through this screen.
          </p>
        </div>
      ) : (
        <>
          <div className="panel" style={{ marginBottom: '1.5rem' }}>
            <h3>By tool</h3>
            <p className="small muted">
              {Object.entries(queue.byTool)
                .sort((a, b) => b[1] - a[1])
                .map(([tool, count]) => `${tool}: ${count}`)
                .join(' · ')}
            </p>
          </div>
          <TriageQueue engagementId={id} candidates={queue.candidates} />
        </>
      )}
    </Shell>
  );
}
