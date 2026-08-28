import type { Finding } from './model.ts';

/**
 * Run-to-run diffing. Used by the retest report and by the retainer engine.
 *
 * A regression — a dedupe key that was fixed and has come back — is called out separately from a
 * new finding, because it means something in the client's release process is undoing fixes, and
 * that is a different conversation from "we found something new".
 */

export interface FindingDiff {
  newFindings: Finding[];
  stillOpen: Finding[];
  resolved: Finding[];
  regressions: Finding[];
}

export function diffFindings(previous: Finding[], current: Finding[]): FindingDiff {
  const previousByKey = new Map(previous.map((finding) => [finding.dedupeKey, finding]));
  const currentByKey = new Map(current.map((finding) => [finding.dedupeKey, finding]));

  const newFindings: Finding[] = [];
  const stillOpen: Finding[] = [];
  const regressions: Finding[] = [];

  for (const [key, finding] of currentByKey) {
    const before = previousByKey.get(key);
    if (!before) {
      newFindings.push(finding);
    } else if (before.status === 'fixed') {
      regressions.push(finding);
    } else {
      stillOpen.push(finding);
    }
  }

  const resolved = previous.filter(
    (finding) =>
      !currentByKey.has(finding.dedupeKey) &&
      finding.status !== 'falsePositive' &&
      finding.status !== 'duplicate',
  );

  return { newFindings, stillOpen, resolved, regressions };
}

export type RetestOutcome = 'verifiedFixed' | 'stillOpen' | 'regressed' | 'riskAccepted' | 'notRetested';

export interface RetestLine {
  finding: Finding;
  outcome: RetestOutcome;
}

/**
 * Build the retest report body. `retested` holds the keys that were actually re-verified; anything
 * outside that set is reported as not retested rather than silently assumed fixed.
 */
export function buildRetestLines(
  original: Finding[],
  current: Finding[],
  retestedKeys: Set<string>,
): RetestLine[] {
  const currentByKey = new Map(current.map((finding) => [finding.dedupeKey, finding]));

  return original.map((finding) => {
    if (finding.status === 'riskAccepted') return { finding, outcome: 'riskAccepted' as const };
    if (!retestedKeys.has(finding.dedupeKey)) return { finding, outcome: 'notRetested' as const };

    const now = currentByKey.get(finding.dedupeKey);
    if (!now) return { finding, outcome: 'verifiedFixed' as const };
    return {
      finding: now,
      outcome: finding.status === 'fixed' ? ('regressed' as const) : ('stillOpen' as const),
    };
  });
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export function countBySeverity(findings: Finding[]): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}
