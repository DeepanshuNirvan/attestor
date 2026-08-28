import { and, eq, inArray, sql } from 'drizzle-orm';
import {
  correlateFindings,
  dedupeFindings,
  dedupeKeyForRaw,
  derivedVectorForSeverity,
  isValidCvssVector,
  scoreCvss,
  type Finding,
  type RawFinding,
} from '@attestor/findings';
import { findingReference, severityFromCvssScore } from '@attestor/shared';
import type { Database } from '../db/client.ts';
import { engagement, falsePositiveMemo, finding as findingTable } from '../db/schema.ts';

/**
 * The findings pipeline.
 *
 * Raw adapter output goes in; normalised, deduplicated, correlated candidates come out. Three
 * behaviours in here are what separate a report from a scanner export:
 *
 *   1. Everything from a tool lands as `candidate`. A human confirms it or it never appears.
 *   2. One root cause across many assets becomes one finding with many affected assets.
 *   3. A dedupe key the client has already marked a false positive is suppressed on sight, with the
 *      reason recorded, so the same noise is not re-triaged every month.
 */

export interface IngestInput {
  engagementId: string;
  clientId: string;
  scanRunId: string;
  toolName: string;
  raw: RawFinding[];
  cvssVersion: '3.1' | '4.0';
  now?: Date;
}

export interface IngestResult {
  created: number;
  updated: number;
  suppressed: number;
  collapsed: number;
  correlatedGroups: number;
}

/**
 * Complete a raw finding into the normalised shape. Where a tool gave a severity but no vector, a
 * conservative vector is derived and marked so the human replaces it — a score with no vector
 * cannot be recomputed by anyone reading the report.
 */
function completeFinding(
  raw: RawFinding,
  input: IngestInput,
  now: Date,
): Omit<Finding, 'id'> & { evidence: RawFinding['evidence'] } {
  let cvssVector = raw.cvssVector;
  let cvssScore = raw.cvssScore;
  let severity = raw.severity;

  if (cvssVector && isValidCvssVector(cvssVector)) {
    const scored = scoreCvss(cvssVector);
    cvssScore = scored.score;
    severity = severityFromCvssScore(scored.score);
  } else if (cvssVector) {
    // The tool gave something that does not parse. Keep the severity it reported and drop the
    // vector rather than printing a vector nobody can verify.
    cvssVector = undefined;
    cvssScore = undefined;
  } else {
    cvssVector = derivedVectorForSeverity(severity, input.cvssVersion);
    cvssScore = scoreCvss(cvssVector).score;
  }

  return {
    ...raw,
    engagementId: input.engagementId,
    severity,
    cvssVersion: input.cvssVersion,
    cvssVector,
    cvssScore,
    status: 'candidate',
    dedupeKey: dedupeKeyForRaw(raw),
    firstSeenAt: now,
    lastSeenAt: now,
  };
}

export async function ingestFindings(
  database: Database,
  input: IngestInput,
): Promise<IngestResult> {
  const now = input.now ?? new Date();
  if (input.raw.length === 0) {
    return { created: 0, updated: 0, suppressed: 0, collapsed: 0, correlatedGroups: 0 };
  }

  const completed = input.raw.map((raw) => completeFinding(raw, input, now));

  // False-positive memory is per client, not per engagement: the same noisy rule against the same
  // asset should stay suppressed at the next quarterly run.
  const memos = await database
    .select({ dedupeKey: falsePositiveMemo.dedupeKey })
    .from(falsePositiveMemo)
    .where(eq(falsePositiveMemo.clientId, input.clientId));
  const suppressedKeys = new Set(memos.map((memo) => memo.dedupeKey));

  const kept = completed.filter((item) => !suppressedKeys.has(item.dedupeKey));
  const suppressed = completed.length - kept.length;

  const asFindings: Finding[] = kept.map((item, index) => ({ ...item, id: `pending-${index}` }));
  const { merged, collapsed } = dedupeFindings(asFindings);
  const { correlated, groups } = correlateFindings(merged);

  let created = 0;
  let updated = 0;

  for (const item of correlated) {
    const existing = await database
      .select({ id: findingTable.id, status: findingTable.status })
      .from(findingTable)
      .where(
        and(
          eq(findingTable.engagementId, input.engagementId),
          eq(findingTable.dedupeKey, item.dedupeKey),
        ),
      )
      .limit(1);

    const previous = existing[0];

    if (previous) {
      // A finding that was marked fixed and has come back is a regression, and it goes back to
      // candidate so a human confirms it rather than the status flipping silently.
      const status = previous.status === 'fixed' ? 'candidate' : previous.status;
      await database
        .update(findingTable)
        .set({
          lastSeenAt: now,
          status,
          affectedAssets: item.affectedAssets,
          updatedAt: now,
        })
        .where(eq(findingTable.id, previous.id));
      updated += 1;
      continue;
    }

    await database.insert(findingTable).values({
      engagementId: input.engagementId,
      scanRunId: input.scanRunId,
      source: item.source,
      toolName: input.toolName,
      toolFindingRef: item.toolFindingRef ?? null,
      checkId: item.checkId ?? null,
      title: item.title,
      description: item.description,
      severity: item.severity,
      cvssVersion: item.cvssVersion ?? null,
      cvssVector: item.cvssVector ?? null,
      cvssScore: item.cvssScore ?? null,
      cweId: item.cweId ?? null,
      owaspCategory: item.owaspCategory ?? null,
      apiCategory: item.apiCategory ?? null,
      wstgId: item.wstgId ?? null,
      asvsRequirement: item.asvsRequirement ?? null,
      masvsControl: item.masvsControl ?? null,
      llmCategory: item.llmCategory ?? null,
      affectedAssets: item.affectedAssets,
      businessImpact: item.businessImpact,
      likelihood: item.likelihood,
      attackerPrerequisites: item.attackerPrerequisites,
      reproductionSteps: item.reproductionSteps,
      remediation: item.remediation,
      references: item.references,
      status: 'candidate',
      dedupeKey: item.dedupeKey,
      attackSuccessRate: item.attackSuccessRate ?? null,
      attemptCount: item.attemptCount ?? null,
      firstSeenAt: now,
      lastSeenAt: now,
    });
    created += 1;
  }

  const collapsedCount = [...collapsed.values()].reduce(
    (total, count) => total + Math.max(0, count - 1),
    0,
  );

  return {
    created,
    updated,
    suppressed,
    collapsed: collapsedCount,
    correlatedGroups: groups.length,
  };
}

/**
 * Confirm a candidate. This is the moment a finding becomes something that can appear in a report,
 * so it is also the moment it gets its quotable reference.
 */
export async function confirmFinding(
  database: Database,
  input: { findingId: string; engagementId: string; confirmedBy: string; now?: Date },
): Promise<{ reference: string }> {
  const now = input.now ?? new Date();

  const engagements = await database
    .select({ reference: engagement.reference })
    .from(engagement)
    .where(eq(engagement.id, input.engagementId))
    .limit(1);
  const engagementReference = engagements[0]?.reference;
  if (!engagementReference) throw new Error('engagement not found');

  const maxRows = await database
    .select({ maximum: sql<number>`coalesce(max(${findingTable.referenceSequence}), 0)` })
    .from(findingTable)
    .where(eq(findingTable.engagementId, input.engagementId));

  const sequence = Number(maxRows[0]?.maximum ?? 0) + 1;
  const reference = findingReference(engagementReference, sequence);

  await database
    .update(findingTable)
    .set({
      status: 'open',
      reference,
      referenceSequence: sequence,
      confirmedAt: now,
      confirmedBy: input.confirmedBy,
      updatedAt: now,
    })
    .where(and(eq(findingTable.id, input.findingId), eq(findingTable.status, 'candidate')));

  return { reference };
}

export async function markFalsePositive(
  database: Database,
  input: {
    findingId: string;
    clientId: string;
    reason: string;
    createdBy: string;
  },
): Promise<void> {
  if (input.reason.trim().length < 10) {
    throw new Error('a false positive needs a written reason of at least 10 characters');
  }

  const rows = await database
    .select({ dedupeKey: findingTable.dedupeKey })
    .from(findingTable)
    .where(eq(findingTable.id, input.findingId))
    .limit(1);
  const dedupeKey = rows[0]?.dedupeKey;
  if (!dedupeKey) throw new Error('finding not found');

  await database.transaction(async (transaction) => {
    await transaction
      .update(findingTable)
      .set({ status: 'falsePositive', updatedAt: new Date() })
      .where(eq(findingTable.id, input.findingId));

    await transaction
      .insert(falsePositiveMemo)
      .values({
        clientId: input.clientId,
        dedupeKey,
        reason: input.reason,
        createdBy: input.createdBy,
      })
      .onConflictDoNothing();
  });
}

/**
 * A severity override without a written justification is exactly what an auditor asks about, so it
 * is refused here as well as by the database constraint.
 */
export async function overrideSeverity(
  database: Database,
  input: {
    findingId: string;
    severity: Finding['severity'];
    reason: string;
    overriddenBy: string;
  },
): Promise<void> {
  if (input.reason.trim().length < 20) {
    throw new Error(
      'a severity override needs a written justification of at least 20 characters; auditors ask for it',
    );
  }

  await database
    .update(findingTable)
    .set({
      severity: input.severity,
      severityOverrideReason: input.reason,
      severityOverriddenBy: input.overriddenBy,
      updatedAt: new Date(),
    })
    .where(eq(findingTable.id, input.findingId));
}

export async function bulkUpdateStatus(
  database: Database,
  input: {
    findingIds: string[];
    status: Finding['status'];
    engagementId: string;
  },
): Promise<number> {
  if (input.findingIds.length === 0) return 0;

  const updated = await database
    .update(findingTable)
    .set({
      status: input.status,
      fixedAt: input.status === 'fixed' ? new Date() : null,
      updatedAt: new Date(),
    })
    .where(
      and(
        eq(findingTable.engagementId, input.engagementId),
        inArray(findingTable.id, input.findingIds),
      ),
    )
    .returning({ id: findingTable.id });

  return updated.length;
}
