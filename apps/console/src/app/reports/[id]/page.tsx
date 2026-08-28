import Link from 'next/link';
import { notFound, redirect } from 'next/navigation';
import { Notice, PageHeader, Shell } from '@/components/shell';
import { fetchRaw, tryGet } from '@/lib/api';

/**
 * Reading a report in the browser.
 *
 * The report is rendered inside a fully sandboxed frame with `srcdoc`, which gives it an opaque
 * origin and no script execution. The document contains the client's own evidence, some of which
 * is attacker-supplied by definition — it is displayed, never trusted.
 */

interface ReportRow {
  id: string;
  kind: string;
  version: string;
  releasedAt: string | null;
  engagementReference: string;
  engagementTitle: string;
}

const KIND_LABEL: Record<string, string> = {
  assessment: 'Assessment report',
  retest: 'Retest report',
  attestation: 'Attestation letter',
  deletionConfirmation: 'Evidence deletion confirmation',
  executiveSummary: 'Executive summary',
};

export default async function ReportViewPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;

  const [list, account, response] = await Promise.all([
    tryGet<{ reports: ReportRow[] }>('/reports'),
    tryGet<{ account: { role: string } | undefined }>('/account'),
    fetchRaw(`/reports/${id}/view`),
  ]);

  if (!list || response.status === 401 || response.status === 403) redirect('/login');
  if (!response.ok) notFound();

  const report = list.reports.find((item) => item.id === id);
  const html = await response.text();
  const canDownload = account?.account?.role !== 'clientViewer';

  return (
    <Shell>
      <PageHeader
        title={report ? (KIND_LABEL[report.kind] ?? report.kind) : 'Report'}
        subtitle={report ? `${report.engagementReference} · version ${report.version}` : undefined}
        actions={
          <>
            <Link className="button button-quiet" href="/reports">
              All documents
            </Link>{' '}
            {canDownload ? (
              <a className="button" href={`/reports/${id}/download`}>
                Download PDF
              </a>
            ) : null}
          </>
        }
      />

      {canDownload ? (
        <Notice>
          <p>
            The PDF is watermarked with your name and email address, and the download is recorded.
            Read it here if you only need to look.
          </p>
        </Notice>
      ) : (
        <Notice>
          <p>
            Your account can read reports here but cannot download them. Ask your account owner if
            you need a copy.
          </p>
        </Notice>
      )}

      <div className="panel" style={{ padding: 0 }}>
        <iframe
          title="Report"
          sandbox=""
          srcDoc={html}
          style={{ width: '100%', height: '80vh', border: 0, display: 'block' }}
        />
      </div>
    </Shell>
  );
}
