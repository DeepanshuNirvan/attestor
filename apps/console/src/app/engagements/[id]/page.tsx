import Link from 'next/link';
import { notFound, redirect } from 'next/navigation';
import { Notice, PageHeader, Severity, Shell, Stat } from '@/components/shell';
import { RunControls } from '@/components/run-controls';
import { StopControl } from '@/components/stop-control';
import { StateControl } from '@/components/state-control';
import { ScopeEditor } from '@/components/scope-editor';
import { tryGet } from '@/lib/api';

interface EngagementDetail {
  engagement: {
    id: string;
    reference: string;
    title: string;
    state: string;
    type: string;
    testType: string;
    startsAt: string | null;
    endsAt: string | null;
    timezone: string;
    currency: string;
    quotedAmount: number;
    advancePaidAt: string | null;
    finalPaidAt: string | null;
    evidenceRetentionDays: number;
    legalHold: boolean;
    thirdPartyInfrastructureAcknowledgedAt: string | null;
    cloudTestingPolicyAcknowledgedAt: string | null;
    policyYaml: string;
  };
  scopeItems: { id: string; kind: string; value: string; included: boolean; notes: string }[];
  authorisations: {
    id: string;
    signedBy: string;
    signerEmail: string;
    signedAt: string | null;
    validFrom: string;
    validUntil: string;
    revokedAt: string | null;
    sourceAddresses: string[];
  }[];
  credentials: {
    id: string;
    label: string;
    roleName: string;
    authType: string;
    isSecondary: boolean;
    expiresAt: string;
    lastVerifiedAt: string | null;
    revokedAt: string | null;
    shreddedAt: string | null;
  }[];
  runs: {
    id: string;
    module: string;
    toolName: string;
    status: string;
    startedAt: string | null;
    finishedAt: string | null;
    abortReason: string | null;
    dryRun: boolean;
  }[];
  findingCounts: { status: string; severity: string; count: number }[];
  panicStop: { active: boolean; reason: string | null; pressedBy: string | null };
  policyWarnings: string[];
}

function formatDateTime(value: string | null): string {
  if (!value) return '—';
  return new Intl.DateTimeFormat('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZone: 'UTC',
  }).format(new Date(value));
}

export default async function EngagementPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const data = await tryGet<EngagementDetail>(`/engagements/${id}`);
  if (data === null) redirect('/login');
  if (!data.engagement) notFound();

  const { engagement, panicStop } = data;
  const candidates = data.findingCounts
    .filter((entry) => entry.status === 'candidate')
    .reduce((total, entry) => total + Number(entry.count), 0);
  const open = data.findingCounts.filter((entry) => entry.status === 'open');

  const activeAuthorisation = data.authorisations.find(
    (authorisation) => authorisation.signedAt && !authorisation.revokedAt,
  );
  const authorisationValid =
    activeAuthorisation !== undefined &&
    new Date(activeAuthorisation.validFrom) <= new Date() &&
    new Date(activeAuthorisation.validUntil) > new Date();

  return (
    <Shell>
      <PageHeader
        title={engagement.title}
        subtitle={`${engagement.reference} · ${engagement.state} · ${engagement.testType}`}
        actions={
          <>
            <Link className="button button-quiet" href={`/engagements/${id}/triage`}>
              Triage {candidates > 0 ? `(${candidates})` : ''}
            </Link>{' '}
            <Link className="button" href={`/engagements/${id}/report`}>
              Report
            </Link>
          </>
        }
      />

      {panicStop.active ? (
        <Notice tone="danger">
          <p>
            <strong>A panic stop is in force.</strong> Nothing will run until it is cleared.
            {panicStop.reason ? ` Reason: ${panicStop.reason}` : ''}
          </p>
        </Notice>
      ) : null}

      {!authorisationValid ? (
        <Notice tone="warning">
          <p>
            <strong>No valid authorisation.</strong> Every tool run will be refused until a signed
            authorisation exists and the current time is inside its window. This is a legal gate, not
            a workflow one, and it cannot be overridden.
          </p>
        </Notice>
      ) : null}

      {data.policyWarnings.length > 0 ? (
        <Notice tone="warning">
          <p>
            <strong>Policy warnings</strong>
          </p>
          <ul>
            {data.policyWarnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        </Notice>
      ) : null}

      <div className="stack">
        <section className="panel">
          <div className="stat-row">
            <Stat label="Candidates" value={candidates} note="awaiting your review" />
            {(['critical', 'high', 'medium', 'low'] as const).map((severity) => (
              <div className="stat" key={severity}>
                <span className="label">
                  <Severity value={severity} />
                </span>
                <span className="value">
                  {open.find((entry) => entry.severity === severity)?.count ?? 0}
                </span>
              </div>
            ))}
          </div>
        </section>

        <div className="columns">
          <section className="panel">
            <h2>Run</h2>
            <RunControls engagementId={id} disabled={panicStop.active || !authorisationValid} />
          </section>

          <section className="panel">
            <h2>Stop</h2>
            <StopControl engagementId={id} active={panicStop.active} />
          </section>
        </div>

        <section className="panel">
          <h2>Lifecycle</h2>
          <StateControl engagementId={id} current={engagement.state} />
        </section>

        <section className="panel">
          <h2>Authorisation</h2>
          {data.authorisations.length === 0 ? (
            <p className="muted small">
              None uploaded. Testing cannot start without one, and the scope guard will refuse every
              target until it exists.
            </p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Signed by</th>
                  <th>Email</th>
                  <th>Window</th>
                  <th>Source addresses</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {data.authorisations.map((authorisation) => (
                  <tr key={authorisation.id}>
                    <td>{authorisation.signedBy}</td>
                    <td className="small">{authorisation.signerEmail}</td>
                    <td className="small">
                      {formatDateTime(authorisation.validFrom)} – {formatDateTime(authorisation.validUntil)}
                    </td>
                    <td className="mono small">{authorisation.sourceAddresses.join(', ') || '—'}</td>
                    <td>
                      {authorisation.revokedAt
                        ? 'Revoked'
                        : authorisation.signedAt
                          ? 'Signed'
                          : 'Unsigned'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section className="panel">
          <h2>Scope</h2>
          <table>
            <thead>
              <tr>
                <th>Kind</th>
                <th>Value</th>
                <th>In scope</th>
                <th>Notes</th>
              </tr>
            </thead>
            <tbody>
              {data.scopeItems.map((item) => (
                <tr key={item.id}>
                  <td className="small">{item.kind}</td>
                  <td className="mono">{item.value}</td>
                  <td>{item.included ? 'Yes' : 'Excluded'}</td>
                  <td className="small muted">{item.notes}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <ScopeEditor engagementId={id} />
        </section>

        <section className="panel">
          <h2>Credentials</h2>
          <p className="muted small">
            Labels and roles only. No route in this platform returns a credential value, and adding
            one would defeat the vault.
          </p>
          {data.credentials.length === 0 ? (
            <p className="muted small">
              None submitted. Generate a one-time intake link so the client can submit them without
              sending them through email.
            </p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Label</th>
                  <th>Role</th>
                  <th>Type</th>
                  <th>Second account</th>
                  <th>Verified</th>
                  <th>Expires</th>
                </tr>
              </thead>
              <tbody>
                {data.credentials.map((credential) => (
                  <tr key={credential.id}>
                    <td>{credential.label}</td>
                    <td>{credential.roleName}</td>
                    <td className="small">{credential.authType}</td>
                    <td>{credential.isSecondary ? 'Yes' : 'No'}</td>
                    <td className="small">
                      {credential.shreddedAt
                        ? 'Shredded'
                        : credential.lastVerifiedAt
                          ? formatDateTime(credential.lastVerifiedAt)
                          : 'Not verified'}
                    </td>
                    <td className="small">{formatDateTime(credential.expiresAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section className="panel">
          <h2>Runs</h2>
          {data.runs.length === 0 ? (
            <p className="muted small">Nothing has run yet. Start with a dry run.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Module</th>
                  <th>Tool</th>
                  <th>Status</th>
                  <th>Started</th>
                  <th>Finished</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {data.runs.slice(0, 40).map((run) => (
                  <tr key={run.id}>
                    <td>{run.module}</td>
                    <td className="mono small">{run.toolName}</td>
                    <td>
                      {run.status}
                      {run.dryRun ? ' (dry run)' : ''}
                    </td>
                    <td className="small muted">{formatDateTime(run.startedAt)}</td>
                    <td className="small muted">{formatDateTime(run.finishedAt)}</td>
                    <td className="small muted">{run.abortReason ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>
    </Shell>
  );
}
