import { createHash } from 'node:crypto';
import type { AffectedAsset, Finding, RawFinding } from './model.ts';

/**
 * Deduplication and correlation.
 *
 * Dedupe answers "is this the same issue we already have?" and must survive across runs and across
 * tools that find the same thing under different rule names.
 *
 * Correlation answers "is this the same root cause as those forty others?" — one missing header
 * across forty endpoints is one finding with forty affected assets, not forty findings. That single
 * behaviour is the difference between a report and a scanner export.
 */

/** Numbers, UUIDs and hashes in a path are instance data, not identity. */
function normaliseLocation(location: string | undefined): string {
  if (!location) return '';
  return location
    .toLowerCase()
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, '/{id}')
    .replace(/\/\d+\b/g, '/{id}')
    .replace(/\/[0-9a-f]{24,64}\b/g, '/{id}')
    .replace(/[?#].*$/, '')
    .replace(/\/+$/, '');
}

function normaliseAsset(asset: AffectedAsset): string {
  const host = asset.value.toLowerCase().replace(/^https?:\/\//, '').replace(/\/+$/, '');
  return `${host}${normaliseLocation(asset.location)}`;
}

export interface DedupeKeyParts {
  /** The catalogue check where one applies, otherwise the tool's rule identifier. */
  ruleId: string;
  asset: AffectedAsset;
  parameter?: string;
}

export function dedupeKey({ ruleId, asset, parameter }: DedupeKeyParts): string {
  const material = [ruleId.toLowerCase(), normaliseAsset(asset), (parameter ?? '').toLowerCase()].join(
    '|',
  );
  return createHash('sha256').update(material).digest('hex').slice(0, 32);
}

export function dedupeKeyForRaw(raw: RawFinding): string {
  const asset = raw.affectedAssets[0];
  if (!asset) throw new Error('finding has no affected asset');
  return dedupeKey({
    ruleId: raw.checkId ?? raw.toolFindingRef ?? raw.title,
    asset,
    parameter: asset.parameter,
  });
}

export interface DedupeResult<T> {
  /** One entry per distinct issue, with assets merged. */
  merged: T[];
  /** How many inputs collapsed into each key, for the run statistics. */
  collapsed: Map<string, number>;
}

/**
 * Merge findings that share a dedupe key. The highest severity wins, the longest description wins
 * (tools vary wildly in how much they say), and affected assets are unioned.
 */
export function dedupeFindings(findings: Finding[]): DedupeResult<Finding> {
  const byKey = new Map<string, Finding>();
  const collapsed = new Map<string, number>();

  for (const finding of findings) {
    collapsed.set(finding.dedupeKey, (collapsed.get(finding.dedupeKey) ?? 0) + 1);
    const existing = byKey.get(finding.dedupeKey);
    if (!existing) {
      byKey.set(finding.dedupeKey, { ...finding, affectedAssets: [...finding.affectedAssets] });
      continue;
    }
    byKey.set(finding.dedupeKey, mergeFindings(existing, finding));
  }

  return { merged: [...byKey.values()], collapsed };
}

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;

export function mergeFindings(left: Finding, right: Finding): Finding {
  const higher = SEVERITY_RANK[left.severity] <= SEVERITY_RANK[right.severity] ? left : right;
  const richer = left.description.length >= right.description.length ? left : right;

  return {
    ...higher,
    description: richer.description,
    remediation: left.remediation.length >= right.remediation.length ? left.remediation : right.remediation,
    reproductionSteps:
      left.reproductionSteps.length >= right.reproductionSteps.length
        ? left.reproductionSteps
        : right.reproductionSteps,
    references: dedupeReferences([...left.references, ...right.references]),
    affectedAssets: dedupeAssets([...left.affectedAssets, ...right.affectedAssets]),
    firstSeenAt: left.firstSeenAt < right.firstSeenAt ? left.firstSeenAt : right.firstSeenAt,
    lastSeenAt: left.lastSeenAt > right.lastSeenAt ? left.lastSeenAt : right.lastSeenAt,
    // A manual finding always outranks a tool finding as the record of authorship.
    source: left.source === 'manual' || right.source === 'manual' ? 'manual' : higher.source,
  };
}

export function dedupeAssets(assets: AffectedAsset[]): AffectedAsset[] {
  const seen = new Map<string, AffectedAsset>();
  for (const asset of assets) {
    const key = `${asset.value}|${asset.location ?? ''}|${asset.parameter ?? ''}|${asset.method ?? ''}`;
    if (!seen.has(key)) seen.set(key, asset);
  }
  return [...seen.values()];
}

function dedupeReferences(references: Finding['references']): Finding['references'] {
  const seen = new Map<string, Finding['references'][number]>();
  for (const reference of references) {
    if (!seen.has(reference.url)) seen.set(reference.url, reference);
  }
  return [...seen.values()];
}

/**
 * Correlation groups findings whose root cause is shared. Two findings correlate when they carry
 * the same rule identity and differ only in which asset they were seen on.
 *
 * Correlation is deliberately narrower than dedupe: a missing header on forty endpoints is one
 * cause, but an IDOR on forty endpoints is forty decisions a developer has to make, so those stay
 * separate unless a human groups them.
 */
const CORRELATABLE_CATEGORIES = new Set([
  'web-security-headers',
  'web-cookie-attributes',
  'web-error-handling',
  'web-browser-storage-of-secrets-in-source-maps',
  'web-clickjacking',
  'recon-tls-configuration',
  'web-cache-configuration',
  'api-error-verbosity',
  'cloud-encryption-at-rest',
  'cloud-logging-coverage',
  'code-dependency-vulnerabilities',
]);

export interface CorrelationGroup {
  /** The check id or rule identity all members share. */
  rootCause: string;
  primary: Finding;
  members: Finding[];
}

export function correlateFindings(findings: Finding[]): {
  correlated: Finding[];
  groups: CorrelationGroup[];
} {
  const groupsByCause = new Map<string, Finding[]>();
  const standalone: Finding[] = [];

  for (const finding of findings) {
    const cause = finding.checkId;
    if (cause && CORRELATABLE_CATEGORIES.has(cause)) {
      const bucket = groupsByCause.get(cause);
      if (bucket) bucket.push(finding);
      else groupsByCause.set(cause, [finding]);
    } else {
      standalone.push(finding);
    }
  }

  const groups: CorrelationGroup[] = [];
  const correlated: Finding[] = [...standalone];

  for (const [rootCause, members] of groupsByCause) {
    if (members.length === 1) {
      correlated.push(members[0]!);
      continue;
    }
    const sorted = [...members].sort(
      (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity],
    );
    const primary = sorted[0]!;
    const combined: Finding = {
      ...primary,
      affectedAssets: dedupeAssets(members.flatMap((member) => member.affectedAssets)),
      firstSeenAt: members.reduce(
        (earliest, member) => (member.firstSeenAt < earliest ? member.firstSeenAt : earliest),
        primary.firstSeenAt,
      ),
      lastSeenAt: members.reduce(
        (latest, member) => (member.lastSeenAt > latest ? member.lastSeenAt : latest),
        primary.lastSeenAt,
      ),
    };
    groups.push({ rootCause, primary: combined, members });
    correlated.push(combined);
  }

  return { correlated, groups };
}
