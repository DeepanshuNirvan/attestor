import Link from 'next/link';
import { redirect } from 'next/navigation';
import { PageHeader, Severity, Shell } from '@/components/shell';
import { tryGet } from '@/lib/api';

/**
 * The client's findings list. Portal surface only; the middleware refuses this path on a console
 * deployment.
 */

interface FindingRow {
  id: string;
  reference: string | null;
  title: string;
  severity: string;
  status: string;
  cvssScore: number | null;
  owaspCategory: string | null;
  affectedAssets: { value: string; location?: string }[];
  firstSeenAt: string;
  fixedAt: string | null;
  engagementReference: string;
}

const STATUS_LABEL: Record<string, string> = {
  open: 'Open',
  fixed: 'Fixed, awaiting verification',
  riskAccepted: 'Risk accepted',
};

function formatDate(value: string | null): string {
  if (!value) return '—';
  return new Intl.DateTimeFormat('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    timeZone: 'UTC',
  }).format(new Date(value));
}

export default async function FindingsPage({
  searchParams,
}: {
  searchParams: Promise<{ severity?: string; status?: string }>;
}) {
  const filters = await searchParams;
  const query = new URLSearchParams();
  if (filters.severity) query.set('severity', filters.severity);
  if (filters.status) query.set('status', filters.status);

  const data = await tryGet<{ findings: FindingRow[] }>(
    `/findings${query.toString() ? `?${query.toString()}` : ''}`,
  );
  if (!data) redirect('/login');

  return (
    <Shell>
      <PageHeader
        title="Findings"
        subtitle={`${data.findings.length} finding${data.findings.length === 1 ? '' : 's'} across your engagements`}
      />

      <div className="panel" style={{ marginBottom: '1.5rem' }}>
        <p className="small">
          Filter:{' '}
          <Link href="/findings">All</Link>
          {' · '}
          <Link href="/findings?status=open">Open</Link>
          {' · '}
          <Link href="/findings?severity=critical">Critical</Link>
          {' · '}
          <Link href="/findings?severity=high">High</Link>
          {' · '}
          <Link href="/findings?status=riskAccepted">Risk accepted</Link>
        </p>
      </div>

      <div className="panel">
        {data.findings.length === 0 ? (
          <p className="muted small">Nothing here. That is a good result.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Reference</th>
                <th>Severity</th>
                <th>Finding</th>
                <th>Asset</th>
                <th>Status</th>
                <th>First seen</th>
              </tr>
            </thead>
            <tbody>
              {data.findings.map((finding) => (
                <tr key={finding.id}>
                  <td className="mono small">
                    <Link href={`/findings/${finding.id}`}>{finding.reference ?? '—'}</Link>
                  </td>
                  <td>
                    <Severity value={finding.severity} />
                  </td>
                  <td>
                    <Link href={`/findings/${finding.id}`}>{finding.title}</Link>
                  </td>
                  <td className="mono small">
                    {finding.affectedAssets[0]
                      ? `${finding.affectedAssets[0].value}${finding.affectedAssets[0].location ?? ''}`
                      : '—'}
                    {finding.affectedAssets.length > 1
                      ? ` +${finding.affectedAssets.length - 1}`
                      : ''}
                  </td>
                  <td className="small">{STATUS_LABEL[finding.status] ?? finding.status}</td>
                  <td className="small muted">{formatDate(finding.firstSeenAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Shell>
  );
}
