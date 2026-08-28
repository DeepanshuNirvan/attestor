import { redirect } from 'next/navigation';
import { PageHeader, Shell } from '@/components/shell';
import { RetestRequest } from '@/components/retest-request';
import { tryGet } from '@/lib/api';

/**
 * Asking for a retest.
 *
 * This records a request. Nothing runs from here: a person reads it, confirms the window and the
 * scope, and schedules it. An engagement that starts because a button was pressed is an engagement
 * nobody authorised.
 */

interface Engagement {
  id: string;
  reference: string;
  title: string;
  status: string;
}

interface Eligibility {
  releasedAt: string | null;
  freeRetestUntil: string | null;
  withinFreeWindow: boolean;
  willBeVerified: { id: string; reference: string | null; title: string }[];
}

function formatDate(value: string | null): string {
  if (!value) return '—';
  return new Intl.DateTimeFormat('en-GB', {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    timeZone: 'UTC',
  }).format(new Date(value));
}

export default async function RetestPage() {
  const dashboard = await tryGet<{ engagements: Engagement[] }>('/dashboard');
  if (!dashboard) redirect('/login');

  const eligibility = await Promise.all(
    dashboard.engagements.map(async (engagement) => ({
      engagement,
      detail: await tryGet<Eligibility>(`/engagements/${engagement.id}/retest-eligibility`),
    })),
  );

  const released = eligibility.filter((entry) => entry.detail?.releasedAt);

  return (
    <Shell>
      <PageHeader
        title="Retests"
        subtitle="One retest is included within thirty days of a report being released"
      />

      {released.length === 0 ? (
        <div className="panel">
          <p className="muted small">
            Nothing to retest yet. This page becomes useful once a report has been released.
          </p>
        </div>
      ) : (
        released.map((entry) => (
          <section className="panel" key={entry.engagement.id} style={{ marginBottom: '1.5rem' }}>
            <h2>
              {entry.engagement.reference} — {entry.engagement.title}
            </h2>
            <p className="small">
              Report released {formatDate(entry.detail?.releasedAt ?? null)}.{' '}
              {entry.detail?.withinFreeWindow ? (
                <>
                  Your included retest is available until{' '}
                  <strong>{formatDate(entry.detail.freeRetestUntil)}</strong>.
                </>
              ) : (
                <>
                  The included window closed on {formatDate(entry.detail?.freeRetestUntil ?? null)}.
                  We will quote this as a separate engagement before anything runs.
                </>
              )}
            </p>

            <h3>What we will verify</h3>
            {entry.detail && entry.detail.willBeVerified.length > 0 ? (
              <ul className="small">
                {entry.detail.willBeVerified.map((finding) => (
                  <li key={finding.id}>
                    {finding.reference ? `${finding.reference} — ` : ''}
                    {finding.title}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="small muted">
                Nothing is marked fixed yet. Mark a finding as fixed and it will appear here, so the
                retest covers exactly what you have changed.
              </p>
            )}

            <RetestRequest engagementId={entry.engagement.id} />
          </section>
        ))
      )}
    </Shell>
  );
}
