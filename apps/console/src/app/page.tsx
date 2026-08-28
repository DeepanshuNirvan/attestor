import Link from 'next/link';
import { redirect } from 'next/navigation';
import { Notice, PageHeader, Severity, Shell, Stat } from '@/components/shell';
import { tryGet } from '@/lib/api';
import { currentSurface } from '@/lib/surface';

/**
 * The dashboard.
 *
 * Two surfaces, two dashboards, one file. The console shows the engagement list and anything that
 * needs a person's attention; the portal shows the client their posture and the actions that are
 * theirs to take.
 */

interface ConsoleEngagement {
  id: string;
  reference: string;
  title: string;
  state: string;
  type: string;
  startsAt: string | null;
  endsAt: string | null;
  clientName: string;
}

interface PortalDashboard {
  engagements: {
    id: string;
    reference: string;
    title: string;
    status: string;
    startsAt: string | null;
    endsAt: string | null;
  }[];
  counts: { severity: string; status: string; count: number }[];
  oldestOpenCritical: { id: string; reference: string | null; title: string; firstSeenAt: string } | null;
  outstandingActions: string[];
}

interface LegalBlocks {
  allReviewed: boolean;
  blocks: { id: string; title: string; mandatory: boolean; lawyerReviewedAt: string | null }[];
}

const STATE_LABEL: Record<string, string> = {
  draft: 'Draft',
  scoped: 'Scoped',
  authorised: 'Authorised',
  advancePaid: 'Advance paid',
  readyToRun: 'Ready to run',
  running: 'Running',
  triage: 'Triage',
  manualTesting: 'Manual testing',
  reportDraft: 'Report draft',
  reportReview: 'Report review',
  released: 'Released',
  retestPending: 'Retest pending',
  retestComplete: 'Retest complete',
  closed: 'Closed',
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

export default function DashboardPage() {
  return currentSurface() === 'portal' ? <PortalDashboardPage /> : <ConsoleDashboardPage />;
}

async function ConsoleDashboardPage() {
  const data = await tryGet<{ engagements: ConsoleEngagement[] }>('/engagements');
  if (!data) redirect('/login');

  const legal = await tryGet<LegalBlocks>('/legal-blocks');

  const active = data.engagements.filter(
    (engagement) => !['closed', 'released', 'retestComplete'].includes(engagement.state),
  );
  const needsAttention = data.engagements.filter((engagement) =>
    ['triage', 'reportReview', 'retestPending'].includes(engagement.state),
  );

  return (
    <Shell>
      <PageHeader
        title="Dashboard"
        subtitle={`${data.engagements.length} engagement${data.engagements.length === 1 ? '' : 's'} on record`}
        actions={
          <Link className="button" href="/engagements">
            All engagements
          </Link>
        }
      />

      {legal && !legal.allReviewed ? (
        <Notice tone="warning">
          <p>
            <strong>Legal text is still in draft.</strong> The mandatory report blocks have not been
            reviewed by a lawyer, so every document generated carries a draft banner.{' '}
            <Link href="/legal">Review status</Link>
          </p>
        </Notice>
      ) : null}

      <div className="stack">
        <section className="panel">
          <div className="stat-row">
            <Stat label="Active" value={active.length} note="not released or closed" />
            <Stat label="Needs you" value={needsAttention.length} note="triage, review or retest" />
            <Stat
              label="Released"
              value={data.engagements.filter((engagement) => engagement.state === 'released').length}
            />
            <Stat
              label="Clients"
              value={new Set(data.engagements.map((engagement) => engagement.clientName)).size}
            />
          </div>
        </section>

        <section className="panel">
          <h2>Waiting on you</h2>
          {needsAttention.length === 0 ? (
            <p className="muted small">Nothing waiting. Everything is either running or finished.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Reference</th>
                  <th>Client</th>
                  <th>Engagement</th>
                  <th>Stage</th>
                  <th>Window</th>
                </tr>
              </thead>
              <tbody>
                {needsAttention.map((engagement) => (
                  <tr key={engagement.id}>
                    <td>
                      <Link href={`/engagements/${engagement.id}`} className="mono">
                        {engagement.reference}
                      </Link>
                    </td>
                    <td>{engagement.clientName}</td>
                    <td>{engagement.title}</td>
                    <td>{STATE_LABEL[engagement.state] ?? engagement.state}</td>
                    <td className="small muted">
                      {formatDate(engagement.startsAt)} – {formatDate(engagement.endsAt)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section className="panel">
          <h2>Active engagements</h2>
          {active.length === 0 ? (
            <p className="muted small">
              No active engagements. Create one from <Link href="/engagements">the list</Link>.
            </p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Reference</th>
                  <th>Client</th>
                  <th>Engagement</th>
                  <th>Stage</th>
                </tr>
              </thead>
              <tbody>
                {active.map((engagement) => (
                  <tr key={engagement.id}>
                    <td>
                      <Link href={`/engagements/${engagement.id}`} className="mono">
                        {engagement.reference}
                      </Link>
                    </td>
                    <td>{engagement.clientName}</td>
                    <td>{engagement.title}</td>
                    <td>{STATE_LABEL[engagement.state] ?? engagement.state}</td>
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

async function PortalDashboardPage() {
  const data = await tryGet<PortalDashboard>('/dashboard');
  if (!data) redirect('/login');

  const open = data.counts.filter((entry) => entry.status === 'open');
  const bySeverity = (severity: string) =>
    open.find((entry) => entry.severity === severity)?.count ?? 0;

  return (
    <Shell>
      <PageHeader title="Your security posture" subtitle="Open findings and what needs your attention" />

      {data.outstandingActions.length > 0 ? (
        <Notice tone="warning">
          <p>
            <strong>Waiting on you</strong>
          </p>
          <ul>
            {data.outstandingActions.map((action) => (
              <li key={action}>{action}</li>
            ))}
          </ul>
        </Notice>
      ) : null}

      <div className="stack">
        <section className="panel">
          <h2>Open findings</h2>
          <div className="stat-row">
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map((severity) => (
              <div className="stat" key={severity}>
                <span className="label">
                  <Severity value={severity} />
                </span>
                <span className="value">{bySeverity(severity)}</span>
              </div>
            ))}
          </div>
          {data.oldestOpenCritical ? (
            <p className="small muted" style={{ marginTop: '1rem' }}>
              Oldest unresolved critical: <strong>{data.oldestOpenCritical.title}</strong>, open since{' '}
              {formatDate(data.oldestOpenCritical.firstSeenAt)}.
            </p>
          ) : null}
          <p style={{ marginTop: '1rem' }}>
            <Link className="button" href="/findings">
              Go to findings
            </Link>
          </p>
        </section>

        <section className="panel">
          <h2>Engagements</h2>
          <table>
            <thead>
              <tr>
                <th>Reference</th>
                <th>Engagement</th>
                <th>Status</th>
                <th>Tested</th>
              </tr>
            </thead>
            <tbody>
              {data.engagements.map((engagement) => (
                <tr key={engagement.id}>
                  <td className="mono">{engagement.reference}</td>
                  <td>{engagement.title}</td>
                  <td>{engagement.status}</td>
                  <td className="small muted">
                    {formatDate(engagement.startsAt)} – {formatDate(engagement.endsAt)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </div>
    </Shell>
  );
}
