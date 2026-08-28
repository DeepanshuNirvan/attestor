import type { ModuleName } from '@attestor/shared';
import { checkCatalogue, type Check } from './catalogue/index.ts';

/**
 * The coverage matrix.
 *
 * This is the section of the report that protects the firm when something is missed, and the one an
 * auditor reads first. It is generated from what actually ran, never asserted. A check is only
 * "tested" if the run that covers it completed; a run that aborted downgrades its checks to
 * "partially tested" with the abort reason attached.
 */

export type CoverageState = 'tested' | 'partiallyTested' | 'notTested';

export interface CoverageEntry {
  check: Check;
  state: CoverageState;
  /** Required whenever the state is not `tested`. The report refuses to render without it. */
  reason?: string;
  /** Which runs contributed, for traceability. */
  scanRunIds: string[];
  findingCount: number;
}

export interface CoverageInput {
  /** Modules the engagement policy selected. Anything outside them is `notTested` by design. */
  selectedModules: ModuleName[];
  /** Checks explicitly excluded by the policy, with the client's or tester's reason. */
  excludedCheckIds: Map<string, string>;
  /** Completed runs, by the check ids each covered. */
  completedRuns: { scanRunId: string; checkIds: string[] }[];
  /** Runs that started but aborted, with why. Their checks become partially tested. */
  abortedRuns: { scanRunId: string; checkIds: string[]; abortReason: string }[];
  /** Checks a human recorded as covered by manual work. */
  manuallyCovered: Map<string, string>;
  findingCountByCheckId: Map<string, number>;
}

export function buildCoverageMatrix(input: CoverageInput): CoverageEntry[] {
  const completedByCheck = new Map<string, string[]>();
  for (const run of input.completedRuns) {
    for (const checkId of run.checkIds) {
      const list = completedByCheck.get(checkId);
      if (list) list.push(run.scanRunId);
      else completedByCheck.set(checkId, [run.scanRunId]);
    }
  }

  const abortedByCheck = new Map<string, { runIds: string[]; reason: string }>();
  for (const run of input.abortedRuns) {
    for (const checkId of run.checkIds) {
      const entry = abortedByCheck.get(checkId);
      if (entry) entry.runIds.push(run.scanRunId);
      else abortedByCheck.set(checkId, { runIds: [run.scanRunId], reason: run.abortReason });
    }
  }

  const selected = new Set(input.selectedModules);

  return checkCatalogue.map((check) => {
    const findingCount = input.findingCountByCheckId.get(check.id) ?? 0;
    const inSelectedModule = check.modules.some((module) => selected.has(module));

    const excludedReason = input.excludedCheckIds.get(check.id);
    if (excludedReason) {
      return { check, state: 'notTested', reason: excludedReason, scanRunIds: [], findingCount };
    }

    if (!inSelectedModule) {
      return {
        check,
        state: 'notTested',
        reason: `The ${check.modules.join(' and ')} module was not in scope for this engagement.`,
        scanRunIds: [],
        findingCount,
      };
    }

    const manualNote = input.manuallyCovered.get(check.id);
    const completedRunIds = completedByCheck.get(check.id) ?? [];
    if (completedRunIds.length > 0 || manualNote) {
      return {
        check,
        state: 'tested',
        scanRunIds: completedRunIds,
        findingCount,
      };
    }

    const aborted = abortedByCheck.get(check.id);
    if (aborted) {
      return {
        check,
        state: 'partiallyTested',
        reason: `The run covering this check stopped early: ${aborted.reason}`,
        scanRunIds: aborted.runIds,
        findingCount,
      };
    }

    return {
      check,
      state: 'notTested',
      reason:
        check.automation === 'manual'
          ? 'Not reached within the agreed test window.'
          : 'No completed run covered this check.',
      scanRunIds: [],
      findingCount,
    };
  });
}

export interface CoverageSummary {
  tested: number;
  partiallyTested: number;
  notTested: number;
  total: number;
  /** Entries missing a reason. The pre-release checklist blocks on this being empty. */
  missingReasons: string[];
}

export function summariseCoverage(entries: CoverageEntry[]): CoverageSummary {
  const summary: CoverageSummary = {
    tested: 0,
    partiallyTested: 0,
    notTested: 0,
    total: entries.length,
    missingReasons: [],
  };
  for (const entry of entries) {
    if (entry.state === 'tested') summary.tested += 1;
    else {
      if (entry.state === 'partiallyTested') summary.partiallyTested += 1;
      else summary.notTested += 1;
      if (!entry.reason) summary.missingReasons.push(entry.check.id);
    }
  }
  return summary;
}
