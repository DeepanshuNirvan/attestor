import Link from 'next/link';
import { redirect } from 'next/navigation';
import { Notice, PageHeader, Shell } from '@/components/shell';
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
}

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

  const [sections, preflight, reports] = await Promise.all([
    tryGet<{ sections: SectionRow[] }>(`/engagements/${id}/report/sections`),
    tryGet<Preflight>(`/engagements/${id}/report/preflight`),
    tryGet<{ reports: ReportRow[] }>(`/engagements/${id}/reports`),
  ]);

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
