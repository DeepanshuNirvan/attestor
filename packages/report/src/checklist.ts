import { summariseCoverage } from '@attestor/findings';
import { unfilledPlaceholders, type ReportData } from './render.ts';

/**
 * The pre-release checklist.
 *
 * Release is blocked until every one of these passes. The last item is the only one a machine
 * cannot check, and it is deliberately worded as a claim the tester makes rather than a box that
 * happens to be ticked: "I have read every line of this report".
 */

/**
 * State that lives outside the rendered report but decides whether it may be released.
 *
 * Right now that is the AI-drafted sections: the draft marker is on the section row, not in the
 * report data, and an unapproved draft must not be able to reach a client.
 */
export interface ChecklistContext {
  /** Section keys that are AI drafts and have not been approved by a person. */
  unapprovedAiDrafts: string[];
  /**
   * Findings still sitting in the review queue as candidates.
   *
   * This has to come from outside the report because the report never contains a candidate: the
   * query that assembles it filters to confirmed statuses. The item below used to look for
   * candidates *in the report*, where by construction there are none, so it passed on every
   * engagement — including one released with a queue full of unreviewed tool output, which is the
   * exact situation it exists to stop.
   */
  outstandingCandidates: number;
}

const EMPTY_CONTEXT: ChecklistContext = { unapprovedAiDrafts: [], outstandingCandidates: 0 };

export interface ChecklistItem {
  id: string;
  label: string;
  /** Automated checks return a failure reason, or null when the item passes. */
  check: (data: ReportData, context: ChecklistContext) => string | null;
  /** Items a human confirms. The machine cannot decide these. */
  manual?: boolean;
}

const PLACEHOLDER_TEXT = /\b(TODO|TBD|FIXME|XXX|lorem ipsum|\[insert|placeholder)\b/i;

function everyFindingHas(
  data: ReportData,
  predicate: (finding: ReportData['findings'][number]) => boolean,
): string[] {
  return data.findings.filter((finding) => !predicate(finding)).map((finding) => finding.reference ?? finding.id);
}

export const CHECKLIST: ChecklistItem[] = [
  {
    id: 'findings-have-evidence',
    label: 'Every finding carries evidence',
    check: (data) => {
      const missing = everyFindingHas(data, (finding) => finding.evidence.length > 0);
      return missing.length === 0
        ? null
        : `no evidence attached to: ${missing.join(', ')}`;
    },
  },
  {
    id: 'findings-have-remediation',
    label: 'Every finding carries specific remediation',
    check: (data) => {
      const missing = everyFindingHas(data, (finding) => finding.remediation.trim().length > 40);
      return missing.length === 0
        ? null
        : `remediation missing or too thin on: ${missing.join(', ')}`;
    },
  },
  {
    id: 'findings-have-impact',
    label: 'Every finding states a business impact, not just a technical one',
    check: (data) => {
      const missing = everyFindingHas(data, (finding) => finding.businessImpact.trim().length > 40);
      return missing.length === 0 ? null : `business impact missing on: ${missing.join(', ')}`;
    },
  },
  {
    id: 'findings-have-repro',
    label: 'Every finding has numbered reproduction steps',
    check: (data) => {
      const missing = everyFindingHas(data, (finding) => finding.reproductionSteps.length >= 2);
      return missing.length === 0 ? null : `reproduction steps missing on: ${missing.join(', ')}`;
    },
  },
  {
    id: 'findings-have-reference',
    label: 'Every finding has a quotable reference',
    check: (data) => {
      const missing = everyFindingHas(data, (finding) => Boolean(finding.reference));
      return missing.length === 0 ? null : `${missing.length} finding(s) have no reference`;
    },
  },
  {
    id: 'no-candidates',
    label: 'Every candidate has been confirmed or discarded',
    check: (data, context) => {
      const inReport = data.findings.filter((finding) => finding.status === 'candidate').length;
      const outstanding = context.outstandingCandidates + inReport;
      return outstanding === 0
        ? null
        : `${outstanding} finding(s) are still candidates in the review queue and must be confirmed or discarded before this report goes out`;
    },
  },
  {
    id: 'cvss-vectors-present',
    label: 'Every finding carries a CVSS vector, not just a score',
    check: (data) => {
      const missing = everyFindingHas(data, (finding) => Boolean(finding.cvssVector));
      return missing.length === 0 ? null : `CVSS vector missing on: ${missing.join(', ')}`;
    },
  },
  {
    id: 'severity-overrides-justified',
    label: 'Every severity override carries a written justification',
    check: (data) => {
      const missing = data.findings
        .filter((finding) => finding.severityOverrideReason === '')
        .map((finding) => finding.reference ?? finding.id);
      return missing.length === 0 ? null : `override without justification on: ${missing.join(', ')}`;
    },
  },
  {
    id: 'coverage-complete',
    label: 'The coverage matrix explains everything not fully tested',
    check: (data) => {
      const summary = summariseCoverage(data.coverage);
      if (data.coverage.length === 0) return 'the coverage matrix is empty';
      return summary.missingReasons.length === 0
        ? null
        : `${summary.missingReasons.length} coverage entries have no reason: ${summary.missingReasons.slice(0, 5).join(', ')}`;
    },
  },
  {
    id: 'no-placeholders',
    label: 'No unfilled placeholder remains in the legal text',
    check: (data) => {
      const missing = unfilledPlaceholders(data);
      return missing.length === 0 ? null : `unfilled: ${missing.join(', ')}`;
    },
  },
  {
    id: 'no-draft-markers',
    label: 'No draft marker or placeholder prose remains in the body',
    check: (data) => {
      const haystack = [
        ...data.executiveSummary,
        ...data.headlineActions,
        ...data.positiveObservations,
        ...data.findings.flatMap((finding) => [
          finding.title,
          finding.description,
          finding.remediation,
          finding.businessImpact,
        ]),
      ].join('\n');
      const match = PLACEHOLDER_TEXT.exec(haystack);
      return match ? `found "${match[0]}" in the report body` : null;
    },
  },
  {
    id: 'client-name-correct',
    label: 'The client name appears and is not a leftover from another engagement',
    check: (data) => {
      if (data.clientLegalName.trim() === '') return 'the client legal name is empty';
      const body = JSON.stringify(data).toLowerCase();
      if (body.includes('sample retail') && !data.clientLegalName.toLowerCase().includes('sample')) {
        return 'the sample client name appears in a report for a different client';
      }
      return null;
    },
  },
  {
    id: 'executive-summary-written',
    label: 'The executive summary is written and is not a list of findings',
    check: (data) => {
      const words = data.executiveSummary.join(' ').split(/\s+/).filter(Boolean).length;
      if (words < 150) return `the executive summary is ${words} words; it needs to stand alone`;
      if (data.headlineActions.length < 1) return 'no headline actions are listed';
      return null;
    },
  },
  {
    id: 'positive-observations-present',
    label: 'Positive observations are recorded',
    check: (data) =>
      data.positiveObservations.length > 0
        ? null
        : 'no positive observations. If nothing was working, say so explicitly instead.',
  },
  {
    id: 'roadmap-present',
    label: 'A prioritised remediation roadmap is present',
    check: (data) => (data.roadmap.length > 0 ? null : 'no remediation roadmap'),
  },
  {
    id: 'ai-drafts-approved',
    label: 'Every AI-drafted section has been read and approved by a person',
    check: (unusedData, context) =>
      context.unapprovedAiDrafts.length === 0
        ? null
        : `still marked as an AI draft: ${context.unapprovedAiDrafts.join(', ')}. A model wrote it; a person has to own it.`,
  },
  {
    id: 'critical-notified',
    label: 'Every critical finding was notified out of band before the report',
    manual: true,
    check: () => null,
  },
  {
    id: 'evidence-masked',
    label: 'Evidence has been reviewed and contains no unmasked personal data',
    manual: true,
    check: () => null,
  },
  {
    id: 'read-every-line',
    label: 'I have read every line of this report',
    manual: true,
    check: () => null,
  },
];

export interface ChecklistResult {
  id: string;
  label: string;
  manual: boolean;
  passed: boolean;
  reason: string | null;
}

export interface ChecklistOutcome {
  results: ChecklistResult[];
  /** Automated failures. Release is impossible while this is non-empty. */
  blocking: ChecklistResult[];
  /** Manual items still unticked. Release is impossible while this is non-empty. */
  awaitingHuman: ChecklistResult[];
  releasable: boolean;
}

export function runChecklist(
  data: ReportData,
  manualConfirmations: Record<string, boolean> = {},
  context: ChecklistContext = EMPTY_CONTEXT,
): ChecklistOutcome {
  const results: ChecklistResult[] = CHECKLIST.map((item) => {
    if (item.manual) {
      const confirmed = manualConfirmations[item.id] === true;
      return {
        id: item.id,
        label: item.label,
        manual: true,
        passed: confirmed,
        reason: confirmed ? null : 'not yet confirmed by a person',
      };
    }
    const reason = item.check(data, context);
    return { id: item.id, label: item.label, manual: false, passed: reason === null, reason };
  });

  const blocking = results.filter((result) => !result.manual && !result.passed);
  const awaitingHuman = results.filter((result) => result.manual && !result.passed);

  return {
    results,
    blocking,
    awaitingHuman,
    releasable: blocking.length === 0 && awaitingHuman.length === 0,
  };
}
