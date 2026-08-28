/** Vocabulary shared by every package. Kept flat and obvious on purpose. */

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const MODULES = [
  'recon',
  'web',
  'api',
  'mobile',
  'cloud',
  'code',
  'network',
  'llm',
  'agentic',
] as const;
export type ModuleName = (typeof MODULES)[number];

export const ENGAGEMENT_TYPES = [
  'webApplication',
  'api',
  'mobile',
  'cloud',
  'llm',
  'network',
  'codeReview',
  'retainer',
  'retest',
] as const;
export type EngagementType = (typeof ENGAGEMENT_TYPES)[number];

export const SCOPE_ITEM_KINDS = [
  'domain',
  'wildcard',
  'ip',
  'cidr',
  'url',
  'repo',
  'cloudAccount',
  'mobilePackage',
  'llmEndpoint',
] as const;
export type ScopeItemKind = (typeof SCOPE_ITEM_KINDS)[number];

export const FINDING_STATUSES = [
  'candidate',
  'open',
  'fixed',
  'riskAccepted',
  'falsePositive',
  'duplicate',
] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export const FINDING_SOURCES = ['tool', 'manual', 'ai'] as const;
export type FindingSource = (typeof FINDING_SOURCES)[number];

export const EVIDENCE_KINDS = [
  'request',
  'response',
  'screenshot',
  'log',
  'terminal',
  'file',
  'transcript',
] as const;
export type EvidenceKind = (typeof EVIDENCE_KINDS)[number];

export const CVSS_VERSIONS = ['3.1', '4.0'] as const;
export type CvssVersion = (typeof CVSS_VERSIONS)[number];

export const ENGAGEMENT_STATES = [
  'draft',
  'scoped',
  'authorised',
  'advancePaid',
  'readyToRun',
  'running',
  'triage',
  'manualTesting',
  'reportDraft',
  'reportReview',
  'released',
  'retestPending',
  'retestComplete',
  'closed',
] as const;
export type EngagementState = (typeof ENGAGEMENT_STATES)[number];

export const TEST_TYPES = ['blackBox', 'greyBox', 'whiteBox'] as const;
export type TestType = (typeof TEST_TYPES)[number];

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER[a] - SEVERITY_ORDER[b];
}

export function severityFromCvssScore(score: number): Severity {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}
