import { and, eq, isNull, lt, sql } from 'drizzle-orm';
import type { Job } from 'bullmq';
import type { ConsoleContext } from '../context.ts';
import {
  credentialSet,
  engagement as engagementTable,
  evidence as evidenceTable,
  report as reportTable,
} from '../db/schema.ts';
import type { RetentionJob } from '../queue.ts';

/**
 * Evidence retention.
 *
 * Runs daily. For every engagement whose retention window has expired, it deletes the evidence
 * objects, shreds the credentials, records the purge, and prepares the deletion confirmation the
 * client was promised.
 *
 * Two things it will not do:
 *
 *   - purge an engagement under legal hold, because a disputed engagement is the one case where the
 *     evidence has to survive the promise;
 *   - send the confirmation. Like every other client-facing message in v1, it is queued for a human.
 */

export interface PurgeOutcome {
  engagementId: string;
  reference: string;
  evidenceObjects: number;
  credentialSets: number;
  skippedForLegalHold: boolean;
}

export async function purgeExpiredEvidence(
  context: ConsoleContext,
  engagementId?: string,
): Promise<PurgeOutcome[]> {
  const logger = context.logger.child({ worker: 'retention' });

  // Retention runs from report release, not from the end of testing: the client's clock starts when
  // they receive the document.
  const releaseDates = context.database
    .select({
      engagementId: reportTable.engagementId,
      releasedAt: sql<Date>`max(${reportTable.releasedAt})`.as('released_at'),
    })
    .from(reportTable)
    .where(eq(reportTable.kind, 'assessment'))
    .groupBy(reportTable.engagementId)
    .as('release_dates');

  const candidates = await context.database
    .select({
      id: engagementTable.id,
      reference: engagementTable.reference,
      retentionDays: engagementTable.evidenceRetentionDays,
      legalHold: engagementTable.legalHold,
      releasedAt: releaseDates.releasedAt,
    })
    .from(engagementTable)
    .innerJoin(releaseDates, eq(releaseDates.engagementId, engagementTable.id))
    .where(
      engagementId
        ? eq(engagementTable.id, engagementId)
        : lt(
            releaseDates.releasedAt,
            sql`now() - (${engagementTable.evidenceRetentionDays} || ' days')::interval`,
          ),
    );

  const outcomes: PurgeOutcome[] = [];

  for (const candidate of candidates) {
    if (candidate.legalHold) {
      logger.info('skipping purge: engagement is under legal hold', {
        engagementId: candidate.id,
        reference: candidate.reference,
      });
      outcomes.push({
        engagementId: candidate.id,
        reference: candidate.reference,
        evidenceObjects: 0,
        credentialSets: 0,
        skippedForLegalHold: true,
      });
      continue;
    }

    const rows = await context.database
      .select({ id: evidenceTable.id, objectKey: evidenceTable.objectKey })
      .from(evidenceTable)
      .where(and(eq(evidenceTable.engagementId, candidate.id), isNull(evidenceTable.purgedAt)));

    const deleted = await context.evidence.purge(rows.map((row) => row.objectKey));

    // The rows stay, marked purged, so the report can still show that evidence existed and what its
    // hash was. Deleting the rows would erase the record of what was destroyed.
    await context.database
      .update(evidenceTable)
      .set({ purgedAt: new Date() })
      .where(and(eq(evidenceTable.engagementId, candidate.id), isNull(evidenceTable.purgedAt)));

    const credentials = await context.database
      .select({ id: credentialSet.id })
      .from(credentialSet)
      .where(and(eq(credentialSet.engagementId, candidate.id), isNull(credentialSet.shreddedAt)));

    if (credentials.length > 0) {
      // Cryptographic shredding: the salt goes, so the subkey is no longer derivable and the
      // ciphertext is unopenable. The row survives as the record that a credential existed.
      await context.database
        .update(credentialSet)
        .set(context.vault.shredPatch())
        .where(and(eq(credentialSet.engagementId, candidate.id), isNull(credentialSet.shreddedAt)));
    }

    await context.auditLog.record({
      actorId: 'system',
      actorKind: 'system',
      action: 'evidence.purged',
      subjectType: 'engagement',
      subjectId: candidate.id,
      metadata: {
        reference: candidate.reference,
        evidenceObjects: deleted,
        credentialSets: credentials.length,
        retentionDays: candidate.retentionDays,
      },
    });

    for (const credential of credentials) {
      await context.auditLog.record({
        actorId: 'system',
        actorKind: 'system',
        action: 'credentialSet.shredded',
        subjectType: 'credentialSet',
        subjectId: credential.id,
      });
    }

    logger.info('purged expired evidence', {
      engagementId: candidate.id,
      reference: candidate.reference,
      evidenceObjects: deleted,
      credentialSets: credentials.length,
    });

    outcomes.push({
      engagementId: candidate.id,
      reference: candidate.reference,
      evidenceObjects: deleted,
      credentialSets: credentials.length,
      skippedForLegalHold: false,
    });
  }

  return outcomes;
}

export async function handleRetentionJob(
  context: ConsoleContext,
  job: Job<RetentionJob>,
): Promise<void> {
  const outcomes = await purgeExpiredEvidence(context, job.data.engagementId);
  context.logger.info('retention sweep complete', {
    engagements: outcomes.length,
    purged: outcomes.filter((outcome) => !outcome.skippedForLegalHold).length,
    heldBack: outcomes.filter((outcome) => outcome.skippedForLegalHold).length,
  });
}
