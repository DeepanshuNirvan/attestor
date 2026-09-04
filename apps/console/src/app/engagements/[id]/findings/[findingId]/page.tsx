import Link from 'next/link';
import { notFound, redirect } from 'next/navigation';
import { PageHeader, Severity, Shell } from '@/components/shell';
import { RiskRating } from '@/components/risk-rating';
import { tryGet } from '@/lib/api';

/**
 * A finding, as the tester sees it.
 *
 * The triage queue is built for volume — confirm or discard, keyboard first. This is the other half:
 * one finding, everything about it, and the place a person does the work no tool does. Right now
 * that is the OWASP risk rating, which is sixteen questions about this client rather than about the
 * class of flaw, and is the half of the scoring a client can actually argue with.
 *
 * Evidence is rendered into a `<pre>` and never handed to the browser as a document. An evidence
 * body is attacker-controlled by definition, and an XSS here would be one delivered by the security
 * vendor to its own staff.
 */

interface FindingDetail {
  finding: {
    id: string;
    reference: string | null;
    title: string;
    description: string;
    severity: string;
    status: string;
    cvssVersion: string | null;
    cvssVector: string | null;
    cvssScore: number | null;
    owaspRiskScores: Record<string, number> | null;
    cweId: number | null;
    owaspCategory: string | null;
    wstgId: string | null;
    checkId: string | null;
    toolName: string | null;
    affectedAssets: { value: string; location?: string; parameter?: string; method?: string }[];
    remediation: string;
  };
  evidence: { id: string; kind: string; sha256: string; text?: string; unavailable?: boolean }[];
}

export default async function ConsoleFindingPage({
  params,
}: {
  params: Promise<{ id: string; findingId: string }>;
}) {
  const { id, findingId } = await params;
  const data = await tryGet<FindingDetail>(`/findings/${findingId}`);
  if (data === null) redirect('/login');
  if (!data.finding) notFound();

  const { finding } = data;

  return (
    <Shell>
      <PageHeader
        title={finding.title}
        subtitle={`${finding.reference ?? 'unreferenced'} · ${finding.status}`}
        actions={
          <Link className="button button-quiet" href={`/engagements/${id}/triage`}>
            Back to the queue
          </Link>
        }
      />

      <div className="panel" style={{ marginBottom: '1.5rem' }}>
        <p>
          <Severity value={finding.severity} />{' '}
          {finding.cvssScore !== null ? <span className="tag">{finding.cvssScore}</span> : null}
          {finding.cvssVector ? <span className="tag">{finding.cvssVector}</span> : null}
          {finding.cweId ? <span className="tag">CWE-{finding.cweId}</span> : null}
          {finding.owaspCategory ? <span className="tag">{finding.owaspCategory}</span> : null}
          {finding.wstgId ? <span className="tag">{finding.wstgId}</span> : null}
          {finding.toolName ? <span className="tag">{finding.toolName}</span> : null}
        </p>
        <p>{finding.description}</p>

        <h3>Affected</h3>
        <ul>
          {finding.affectedAssets.map((asset, index) => (
            <li key={`${asset.value}-${index}`}>
              <code>
                {asset.method ? `${asset.method} ` : ''}
                {asset.value}
                {asset.location ?? ''}
                {asset.parameter ? ` (${asset.parameter})` : ''}
              </code>
            </li>
          ))}
        </ul>

        <h3>Remediation</h3>
        <p>{finding.remediation}</p>
      </div>

      <div className="panel" style={{ marginBottom: '1.5rem' }}>
        <h3>OWASP risk rating</h3>
        <RiskRating
          engagementId={id}
          findingId={finding.id}
          saved={finding.owaspRiskScores}
        />
      </div>

      <div className="panel">
        <h3>Evidence</h3>
        {data.evidence.length === 0 ? (
          <p className="small muted">Nothing attached.</p>
        ) : (
          data.evidence.map((item) => (
            <figure key={item.id}>
              <figcaption className="small muted">
                {item.kind} · {item.sha256.slice(0, 16)}
              </figcaption>
              <pre>{item.unavailable ? '(evidence unavailable)' : (item.text ?? '')}</pre>
            </figure>
          ))
        )}
      </div>
    </Shell>
  );
}
