import Link from 'next/link';
import { redirect } from 'next/navigation';
import { PageHeader, Shell } from '@/components/shell';
import { tryGet } from '@/lib/api';

interface EngagementRow {
  id: string;
  reference: string;
  title: string;
  state: string;
  type: string;
  startsAt: string | null;
  endsAt: string | null;
  clientName: string;
}

function formatDate(value: string | null): string {
  if (!value) return '—';
  return new Intl.DateTimeFormat('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    timeZone: 'UTC',
  }).format(new Date(value));
}

export default async function EngagementsPage() {
  const data = await tryGet<{ engagements: EngagementRow[] }>('/engagements');
  if (!data) redirect('/login');

  return (
    <Shell>
      <PageHeader title="Engagements" subtitle={`${data.engagements.length} on record`} />

      <div className="panel">
        {data.engagements.length === 0 ? (
          <p className="muted small">
            Nothing yet. Seed the demo data with <code>pnpm --filter @attestor/api seed</code> to see
            the whole flow.
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Reference</th>
                <th>Client</th>
                <th>Engagement</th>
                <th>Type</th>
                <th>Stage</th>
                <th>Window</th>
              </tr>
            </thead>
            <tbody>
              {data.engagements.map((engagement) => (
                <tr key={engagement.id}>
                  <td>
                    <Link href={`/engagements/${engagement.id}`} className="mono">
                      {engagement.reference}
                    </Link>
                  </td>
                  <td>{engagement.clientName}</td>
                  <td>{engagement.title}</td>
                  <td className="small muted">{engagement.type}</td>
                  <td>{engagement.state}</td>
                  <td className="small muted">
                    {formatDate(engagement.startsAt)} – {formatDate(engagement.endsAt)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Shell>
  );
}
