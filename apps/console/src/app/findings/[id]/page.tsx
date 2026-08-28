import Link from 'next/link';
import { notFound, redirect } from 'next/navigation';
import { PageHeader, Severity, Shell } from '@/components/shell';
import { FindingActions } from '@/components/finding-actions';
import { tryGet } from '@/lib/api';

/**
 * A finding, as the client sees it.
 *
 * Evidence arrives from the API as inert text or a data URI and is rendered into a `<pre>`. It is
 * never handed to the browser as a document to render: an evidence body is attacker-controlled by
 * definition, and an XSS here would be an XSS delivered by the security vendor.
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
    cweId: number | null;
    owaspCategory: string | null;
    wstgId: string | null;
    asvsRequirement: string | null;
    affectedAssets: { value: string; location?: string; parameter?: string; method?: string }[];
    businessImpact: string;
    likelihood: string;
    attackerPrerequisites: string;
    reproductionSteps: string[];
    remediation: string;
    references: { title: string; url: string }[];
    attackSuccessRate: number | null;
    attemptCount: number | null;
    riskAcceptanceJustification: string | null;
  };
  engagementReference: string;
  evidence: {
    id: string;
    kind: string;
    sha256: string;
    text?: string;
    imageDataUri?: string;
    unavailable?: boolean;
  }[];
  comments: { id: string; authorKind: string; markdown: string; createdAt: string }[];
}

export default async function FindingPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const data = await tryGet<FindingDetail>(`/findings/${id}`);
  if (data === null) redirect('/login');
  if (!data.finding) notFound();

  const { finding } = data;

  return (
    <Shell>
      <PageHeader
        title={finding.title}
        subtitle={`${finding.reference ?? ''} · ${data.engagementReference}`}
        actions={
          <Link className="button button-quiet" href="/findings">
            All findings
          </Link>
        }
      />

      <div className="columns" style={{ gridTemplateColumns: 'minmax(0, 2fr) minmax(16rem, 1fr)' }}>
        <div className="stack">
          <section className="panel">
            <p style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', alignItems: 'center' }}>
              <Severity value={finding.severity} />
              {finding.cvssScore !== null ? (
                <span className="tag">{finding.cvssScore.toFixed(1)}</span>
              ) : null}
              {finding.cvssVector ? <span className="tag">{finding.cvssVector}</span> : null}
              {finding.cweId ? <span className="tag">CWE-{finding.cweId}</span> : null}
              {finding.owaspCategory ? <span className="tag">{finding.owaspCategory}</span> : null}
              {finding.wstgId ? <span className="tag">{finding.wstgId}</span> : null}
              {finding.asvsRequirement ? (
                <span className="tag">ASVS {finding.asvsRequirement.replace('v5.0.0-', '')}</span>
              ) : null}
            </p>

            <h3>Affected</h3>
            <ul className="small">
              {finding.affectedAssets.map((asset) => (
                <li key={`${asset.value}${asset.location ?? ''}${asset.parameter ?? ''}`}>
                  <code>
                    {asset.method ? `${asset.method} ` : ''}
                    {asset.value}
                    {asset.location ?? ''}
                    {asset.parameter ? ` (${asset.parameter})` : ''}
                  </code>
                </li>
              ))}
            </ul>

            <h3>Business impact</h3>
            <p>{finding.businessImpact}</p>

            <h3>Likelihood</h3>
            <p>{finding.likelihood}</p>

            <h3>Attacker prerequisites</h3>
            <p>{finding.attackerPrerequisites}</p>

            <h3>Technical description</h3>
            <p>{finding.description}</p>

            {finding.attackSuccessRate !== null && finding.attemptCount ? (
              <>
                <h3>Attack success rate</h3>
                <p>
                  {Math.round(finding.attackSuccessRate * 100)}% over {finding.attemptCount}{' '}
                  attempts.
                </p>
              </>
            ) : null}

            <h3>Reproduction</h3>
            <ol className="small">
              {finding.reproductionSteps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>

            <h3>Remediation</h3>
            <p>{finding.remediation}</p>

            {finding.references.length > 0 ? (
              <>
                <h3>References</h3>
                <ul className="small">
                  {finding.references.map((reference) => (
                    <li key={reference.url}>
                      <a href={reference.url} rel="noopener noreferrer nofollow" target="_blank">
                        {reference.title}
                      </a>
                    </li>
                  ))}
                </ul>
              </>
            ) : null}
          </section>

          <section className="panel">
            <h3>Evidence</h3>
            <p className="small muted">
              Captured during testing, masked at capture. Rendered as text, never as a live document.
            </p>
            {data.evidence.length === 0 ? (
              <p className="small muted">No evidence attached, or it has passed its retention date.</p>
            ) : (
              data.evidence.map((item) => (
                <figure key={item.id} style={{ margin: '0 0 1rem' }}>
                  <figcaption className="small muted">
                    {item.kind} · sha256 {item.sha256.slice(0, 16)}…
                  </figcaption>
                  {item.unavailable ? (
                    <p className="small muted">This evidence has been deleted under our retention policy.</p>
                  ) : item.imageDataUri ? (
                    /* A data URI produced by our own capture, never a remote fetch. */
                    <img
                      src={item.imageDataUri}
                      alt={`${item.kind} evidence`}
                      style={{ maxWidth: '100%', border: '1px solid var(--rule)' }}
                    />
                  ) : (
                    <pre>{item.text}</pre>
                  )}
                </figure>
              ))
            )}
          </section>
        </div>

        <div className="stack">
          <FindingActions
            findingId={finding.id}
            status={finding.status}
            justification={finding.riskAcceptanceJustification}
          />

          <section className="panel">
            <h3>Conversation</h3>
            {data.comments.length === 0 ? (
              <p className="small muted">Nothing yet. Ask us anything about this finding.</p>
            ) : (
              data.comments.map((comment) => (
                <div key={comment.id} style={{ borderTop: '1px solid var(--rule)', padding: '0.5rem 0' }}>
                  <p className="small muted" style={{ marginBottom: '0.2rem' }}>
                    {comment.authorKind === 'client' ? 'Your team' : 'Attestor'} ·{' '}
                    {new Intl.DateTimeFormat('en-GB', {
                      day: 'numeric',
                      month: 'short',
                      timeZone: 'UTC',
                    }).format(new Date(comment.createdAt))}
                  </p>
                  {/* Rendered as text. Comment bodies are user input and never become markup. */}
                  <p style={{ whiteSpace: 'pre-wrap' }}>{comment.markdown}</p>
                </div>
              ))
            )}
          </section>
        </div>
      </div>
    </Shell>
  );
}
