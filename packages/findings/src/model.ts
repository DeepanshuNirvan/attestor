import { z } from 'zod';
import {
  CVSS_VERSIONS,
  FINDING_SOURCES,
  FINDING_STATUSES,
  SEVERITIES,
  type Severity,
} from '@attestor/shared';

/**
 * The normalised finding. Every adapter converts its tool's output into this shape, and nothing
 * downstream — dedupe, correlation, the report, the portal — knows which tool produced it.
 *
 * Validation happens at the adapter boundary. Once a finding is in this shape the rest of the
 * system trusts it.
 */

export const affectedAssetSchema = z.object({
  /** Hostname, URL, cloud resource identifier, package name or mobile component. */
  value: z.string().min(1),
  /** Where in the asset: a path, a parameter, a header, a field, a resource property. */
  location: z.string().optional(),
  /** The parameter or property that carries the issue, where one applies. */
  parameter: z.string().optional(),
  method: z.string().optional(),
});

export type AffectedAsset = z.infer<typeof affectedAssetSchema>;

export const referenceSchema = z.object({
  title: z.string().min(1),
  url: z.string().url(),
});

export const findingSchema = z.object({
  id: z.string().min(1),
  engagementId: z.string().min(1),
  /** `ATT-2026-014-003`. Assigned when the finding is confirmed, not when it is created. */
  reference: z.string().optional(),
  source: z.enum(FINDING_SOURCES),
  /** Which scan run produced it, if any. Manual findings have none. */
  scanRunId: z.string().optional(),
  /** The tool's own identifier for the rule that fired, kept for traceability. */
  toolFindingRef: z.string().optional(),
  toolName: z.string().optional(),
  /** The catalogue check this finding satisfies, which drives the coverage matrix. */
  checkId: z.string().optional(),

  title: z.string().min(1),
  description: z.string(),
  severity: z.enum(SEVERITIES),
  /** Set when a human overrode the computed severity. Auditors ask for the reason. */
  severityOverrideReason: z.string().optional(),

  cvssVersion: z.enum(CVSS_VERSIONS).optional(),
  cvssVector: z.string().optional(),
  cvssScore: z.number().min(0).max(10).optional(),

  cweId: z.number().int().positive().optional(),
  owaspCategory: z.string().optional(),
  apiCategory: z.string().optional(),
  wstgId: z.string().optional(),
  asvsRequirement: z.string().optional(),
  masvsControl: z.string().optional(),
  llmCategory: z.string().optional(),

  affectedAssets: z.array(affectedAssetSchema).min(1),
  businessImpact: z.string().default(''),
  likelihood: z.string().default(''),
  attackerPrerequisites: z.string().default(''),
  reproductionSteps: z.array(z.string()).default([]),
  remediation: z.string().default(''),
  references: z.array(referenceSchema).default([]),

  status: z.enum(FINDING_STATUSES).default('candidate'),
  dedupeKey: z.string().min(1),
  /** Set when correlation folded this finding into another as one reportable issue. */
  correlatedIntoId: z.string().optional(),

  /** LLM findings need a success rate, not a boolean. Absent for everything else. */
  attackSuccessRate: z.number().min(0).max(1).optional(),
  attemptCount: z.number().int().nonnegative().optional(),

  firstSeenAt: z.coerce.date(),
  lastSeenAt: z.coerce.date(),
  confirmedAt: z.coerce.date().optional(),
  confirmedBy: z.string().optional(),
  fixedAt: z.coerce.date().optional(),
  retestedAt: z.coerce.date().optional(),
});

export type Finding = z.infer<typeof findingSchema>;

/** What an adapter produces. Ids, timestamps and the dedupe key are filled in by the pipeline. */
export const rawFindingSchema = findingSchema
  .omit({
    id: true,
    engagementId: true,
    dedupeKey: true,
    firstSeenAt: true,
    lastSeenAt: true,
    status: true,
  })
  .extend({
    /** Evidence captured alongside the finding, already masked by the capture layer. */
    evidence: z
      .array(
        z.object({
          kind: z.enum(['request', 'response', 'screenshot', 'log', 'terminal', 'file', 'transcript']),
          objectKey: z.string(),
          sha256: z.string(),
          redactionApplied: z.array(z.string()).default([]),
        }),
      )
      .default([]),
  });

export type RawFinding = z.infer<typeof rawFindingSchema>;

export function severityRank(severity: Severity): number {
  return SEVERITIES.indexOf(severity);
}
