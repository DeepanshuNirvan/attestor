import Link from 'next/link';
import { redirect } from 'next/navigation';
import { PageHeader, Shell } from '@/components/shell';
import { tryGet } from '@/lib/api';

/**
 * Released documents.
 *
 * Only released reports appear: the API filters on releasedAt being set, so a draft cannot leak
 * through this list even if someone links to it directly.
 */

interface ReportRow {
  id: string;
  kind: string;
  version: string;
  releasedAt: string | null;
  engagementReference: string;
  engagementTitle: string;
  readableInBrowser: boolean;
}

const KIND_LABEL: Record<string, string> = {
  assessment: 'Assessment report',
  retest: 'Retest report',
  attestation: 'Attestation letter',
  deletionConfirmation: 'Evidence deletion confirmation',
  executiveSummary: 'Executive summary',
};

function formatDate(value: string | null): string {
  if (!value) return '—';
  return new Intl.DateTimeFormat('en-GB', {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    timeZone: 'UTC',
  }).format(new Date(value));
}

export default async function ReportsPage() {
  const data = await tryGet<{ reports: ReportRow[] }>('/reports');
  if (!data) redirect('/login');

  return (
    <Shell>
      <PageHeader
        title="Reports and documents"
        subtitle="Everything we have released to you, newest first"
      />

      <div className="panel">
        {data.reports.length === 0 ? (
          <p className="muted small">
            Nothing released yet. Reports appear here the moment they are released; we do not email
            them as attachments.
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Document</th>
                <th>Engagement</th>
                <th>Version</th>
                <th>Released</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.reports.map((report) => (
                <tr key={report.id}>
                  <td>
                    {report.readableInBrowser ? (
                      <Link href={`/reports/${report.id}`}>
                        {KIND_LABEL[report.kind] ?? report.kind}
                      </Link>
                    ) : (
                      (KIND_LABEL[report.kind] ?? report.kind)
                    )}
                  </td>
                  <td className="small">
                    {report.engagementReference} — {report.engagementTitle}
                  </td>
                  <td className="mono small">{report.version}</td>
                  <td className="small muted">{formatDate(report.releasedAt)}</td>
                  <td>
                    {report.readableInBrowser ? (
                      <Link className="button button-quiet" href={`/reports/${report.id}`}>
                        Read
                      </Link>
                    ) : (
                      // An attestation letter is a PDF and has nothing to show in a frame.
                      <a className="button button-quiet" href={`/reports/${report.id}/download`}>
                        Download
                      </a>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <p className="small muted" style={{ marginTop: '1rem' }}>
        Downloads are watermarked with your name, your email address and the time you took the copy.
        We keep a record of every download so that you can answer the question &ldquo;who has this
        document?&rdquo; if you are ever asked.
      </p>
    </Shell>
  );
}
