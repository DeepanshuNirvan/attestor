import Link from 'next/link';
import { redirect } from 'next/navigation';
import { Notice, PageHeader, Severity, Shell } from '@/components/shell';
import { ReportWorkbench, type ChecklistResult, type ReportRow, type SectionRow } from '@/components/report-workbench';
import { tryGet } from '@/lib/api';

/**
 * The report workbench.
 *
 * Prose on the left, the pre-release checklist on the right. The checklist is the gate, and it is
 * enforced by the API — this screen shows what is blocking release rather than deciding it.
 */

interface Preflight {
  results: ChecklistResult[];
  blocking: ChecklistResult[];
  awaitingHuman: ChecklistResult[];
  releasable: boolean;
  unreviewedLegal: string[];
  coverage?: {
    module: string;
    label: string;
    checks: number;
    tested: number;
    partiallyTested: number;
    notTested: number;
    notApplicable: number;
  }[];
  testingActivity?: {
    incompleteRuns: { tool: string; module: string; reason: string }[];
    untestedServices: string[];
  };
}

interface FindingRow {
  id: string;
  reference: string | null;
  title: string;
  severity: string;
  status: string;
}

/** The statuses the report includes. Anything else never reaches the client. */
const REPORTED_STATUSES = new Set(['open', 'fixed', 'riskAccepted']);

const SECTION_ORDER: { key: string; label: string; help: string }[] = [
  {
    key: 'executiveSummary',
    label: 'Executive summary',
    help: 'Two to four pages, no jargon. What was tested, the headline risks in business terms, and what changed since last time. Blank lines separate paragraphs.',
  },
  {
    key: 'headlineActions',
    label: 'The first things to do',
    help: 'Three items, ordered by what actually reduces risk rather than by severity.',
  },
  {
    key: 'attackNarrativeTitle',
    label: 'Attack narrative title',
    help: 'One line naming the outcome, e.g. "From an anonymous visitor to every customer record in four steps".',
  },
  {
    key: 'attackNarrative',
    label: 'Attack narrative steps',
    help: 'One step per paragraph. First line is the heading, the rest is the body.',
  },
  {
    key: 'attackNarrativeConclusion',
    label: 'Attack narrative conclusion',
    help: 'Why the chain matters more than the individual severities.',
  },
  {
    key: 'attackNarrativeDiagram',
    label: 'Attack narrative diagram',
    help: 'Plain monospace text. It prints, and it needs no image pipeline.',
  },
  { key: 'positiveObservations', label: 'Positive observations', help: 'Controls found working. Real ones.' },
  { key: 'roadmap30', label: 'Roadmap: first 30 days', help: 'Grouped by root cause, not by finding.' },
  { key: 'roadmap60', label: 'Roadmap: days 30 to 60', help: '' },
  { key: 'roadmap90', label: 'Roadmap: days 60 to 90', help: '' },
  { key: 'environments', label: 'Environments', help: 'What was actually tested against.' },
  { key: 'rolesTested', label: 'Roles and accounts used', help: 'One per line.' },
  { key: 'constraints', label: 'Client-imposed constraints', help: 'Windows, rate limits, anything that shaped coverage.' },
  {
    key: 'manualCoverage',
    label: 'Manual coverage',
    help: 'One line per check: "check-id: what you did". This is what makes the coverage matrix honest about manual work.',
  },
  { key: 'outOfScopeNotes', label: 'Out-of-scope notes', help: '' },
];

export default async function ReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;

  const [sections, preflight, reports, findings] = await Promise.all([
    tryGet<{ sections: SectionRow[] }>(`/engagements/${id}/report/sections`),
    tryGet<Preflight>(`/engagements/${id}/report/preflight`),
    tryGet<{ reports: ReportRow[] }>(`/engagements/${id}/reports`),
    tryGet<{ findings: FindingRow[] }>(`/engagements/${id}/findings`),
  ]);
  const reported = (findings?.findings ?? []).filter((finding) => REPORTED_STATUSES.has(finding.status));

  if (!sections || !preflight) redirect('/login');

  return (
    <Shell>
      <PageHeader
        title="Report"
        subtitle={
          preflight.releasable
            ? 'Every check passes. This can be released.'
            : `${preflight.blocking.length} blocking, ${preflight.awaitingHuman.length} awaiting you`
        }
        actions={
          <Link className="button button-quiet" href={`/engagements/${id}`}>
            Back to engagement
          </Link>
        }
      />

      {preflight.unreviewedLegal.length > 0 ? (
        <Notice tone="warning">
          <p>
            <strong>Legal text is in draft.</strong> {preflight.unreviewedLegal.join(', ')} have not
            been reviewed by a lawyer. Documents generated now carry a visible draft banner.
          </p>
        </Notice>
      ) : null}

      {preflight.coverage ? (
        <section className="panel" style={{ marginBottom: '1.5rem' }}>
          <h3>What was tested</h3>
          <p className="small muted">
            Checks per module, from what actually ran. Manual checks count as tested once you list
            them under Manual coverage below. The report prints the same table.
          </p>
          <table>
            <thead>
              <tr>
                <th>Module</th>
                <th className="numeric">Checks</th>
                <th className="numeric">Tested</th>
                <th className="numeric">Partly</th>
                <th className="numeric">Not tested</th>
                <th className="numeric">Not present</th>
              </tr>
            </thead>
            <tbody>
              {preflight.coverage.map((row) => (
                <tr key={row.module}>
                  <td>{row.label}</td>
                  <td className="numeric">{row.checks}</td>
                  <td className="numeric">{row.tested}</td>
                  <td className="numeric">{row.partiallyTested}</td>
                  <td className="numeric">{row.notTested}</td>
                  <td className="numeric">{row.notApplicable}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {preflight.testingActivity && preflight.testingActivity.incompleteRuns.length > 0 ? (
            <>
              <h4>Runs that did not complete</h4>
              <ul className="small">
                {preflight.testingActivity.incompleteRuns.map((run) => (
                  <li key={`${run.tool}-${run.module}-${run.reason}`}>
                    <strong>{run.tool}</strong> ({run.module}): {run.reason}
                  </li>
                ))}
              </ul>
            </>
          ) : null}

          {preflight.testingActivity && preflight.testingActivity.untestedServices.length > 0 ? (
            <Notice tone="warning">
              <p>
                <strong>Found but not tested:</strong>{' '}
                {preflight.testingActivity.untestedServices.join(', ')}. Recon found these web
                services on an in-scope host, but no run was pointed at them. To test one, add it to
                the scope as a URL, then run the web and API modules again.
              </p>
            </Notice>
          ) : null}
        </section>
      ) : null}

      <details className="panel" style={{ marginBottom: '1.5rem' }}>
        <summary>
          <strong>Findings in this report ({reported.length})</strong>
          <span className="small muted">
            {' '}
            — open one to write its business impact, steps and fix, or mark it not a real issue
          </span>
        </summary>
        <table style={{ marginTop: '0.75rem' }}>
          <tbody>
            {reported.map((finding) => (
              <tr key={finding.id}>
                <td className="mono small">{finding.reference ?? '—'}</td>
                <td>
                  <Severity value={finding.severity} />
                </td>
                <td>
                  <Link href={`/engagements/${id}/findings/${finding.id}`}>{finding.title}</Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>

      <ReportWorkbench
        engagementId={id}
        sectionOrder={SECTION_ORDER}
        sections={sections.sections}
        checklist={preflight.results}
        releasable={preflight.releasable}
        reports={reports?.reports ?? []}
      />
    </Shell>
  );
}
