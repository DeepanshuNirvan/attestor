import { and, asc, eq, inArray, sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { isValidCvssVector, scoreCvss } from '@attestor/findings';
import { SEVERITIES } from '@attestor/shared';
import type { ConsoleContext } from '../context.ts';
import {
  engagement as engagementTable,
  evidence as evidenceTable,
  finding as findingTable,
} from '../db/schema.ts';
import {
  bulkUpdateStatus,
  confirmFinding,
  markFalsePositive,
  overrideSeverity,
} from '../services/findings-service.ts';
import { actorIdOf, requestContext, requireSession } from './session-guard.ts';

/**
 * Triage.
 *
 * The review queue is the point of the whole pipeline: everything a tool or an agent produced is a
 * candidate, and this is where a person turns it into a finding or discards it. The routes are
 * shaped for keyboard-driven bulk work, because a tester triaging two hundred candidates one modal
 * at a time will stop doing it properly by candidate forty.
 */

export function registerFindingRoutes(app: FastifyInstance, context: ConsoleContext): void {
  const guard = requireSession({ database: context.database, expect: 'staff' });

  app.get('/engagements/:id/findings', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const query = z
      .object({
        status: z.enum(['candidate', 'open', 'fixed', 'riskAccepted', 'falsePositive', 'duplicate']).optional(),
        severity: z.enum(SEVERITIES).optional(),
        limit: z.coerce.number().int().min(1).max(500).default(200),
      })
      .parse(request.query);

    const conditions = [eq(findingTable.engagementId, id)];
    if (query.status) conditions.push(eq(findingTable.status, query.status));
    if (query.severity) conditions.push(eq(findingTable.severity, query.severity));

    const rows = await context.database
      .select()
      .from(findingTable)
      .where(and(...conditions))
      .orderBy(
        // Severity first, then age. `order by` on a text column needs the ordering spelled out.
        sql`case ${findingTable.severity}
              when 'critical' then 0 when 'high' then 1 when 'medium' then 2
              when 'low' then 3 else 4 end`,
        asc(findingTable.firstSeenAt),
      )
      .limit(query.limit);

    return reply.send({ findings: rows });
  });

  app.get('/findings/:findingId', { preHandler: guard }, async (request, reply) => {
    const { findingId } = request.params as { findingId: string };

    const rows = await context.database
      .select()
      .from(findingTable)
      .where(eq(findingTable.id, findingId))
      .limit(1);
    const record = rows[0];
    if (!record) return reply.code(404).send({ error: 'not found' });

    const evidenceRows = await context.database
      .select()
      .from(evidenceTable)
      .where(eq(evidenceTable.findingId, findingId));

    // Signed URLs are short-lived and issued only after this handler has established that the
    // requester is staff. The signature is delivery, not authorisation.
    const withUrls = await Promise.all(
      evidenceRows.map(async (item) => ({
        ...item,
        url: item.purgedAt ? null : await context.evidence.signedUrl(item.objectKey, 300),
      })),
    );

    for (const item of evidenceRows) {
      await context.auditLog.record({
        actorId: actorIdOf(request),
        actorKind: 'staff',
        action: 'evidence.accessed',
        subjectType: 'evidence',
        subjectId: item.id,
        ...requestContext(request),
      });
    }

    return reply.send({ finding: record, evidence: withUrls });
  });

  app.post('/findings/:findingId/confirm', { preHandler: guard }, async (request, reply) => {
    const { findingId } = request.params as { findingId: string };

    const rows = await context.database
      .select({ engagementId: findingTable.engagementId, status: findingTable.status })
      .from(findingTable)
      .where(eq(findingTable.id, findingId))
      .limit(1);
    const record = rows[0];
    if (!record) return reply.code(404).send({ error: 'not found' });
    if (record.status !== 'candidate') {
      return reply.code(409).send({ error: 'only a candidate can be confirmed' });
    }

    const { reference } = await confirmFinding(context.database, {
      findingId,
      engagementId: record.engagementId,
      confirmedBy: actorIdOf(request),
    });

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'finding.confirmed',
      subjectType: 'finding',
      subjectId: findingId,
      metadata: { reference },
      ...requestContext(request),
    });

    return reply.send({ ok: true, reference });
  });

  app.post('/findings/:findingId/false-positive', { preHandler: guard }, async (request, reply) => {
    const { findingId } = request.params as { findingId: string };
    const parsed = z.object({ reason: z.string().min(10).max(1000) }).safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: 'a false positive needs a written reason' });
    }

    const rows = await context.database
      .select({ engagementId: findingTable.engagementId })
      .from(findingTable)
      .where(eq(findingTable.id, findingId))
      .limit(1);
    if (!rows[0]) return reply.code(404).send({ error: 'not found' });

    const engagements = await context.database
      .select({ clientId: engagementTable.clientId })
      .from(engagementTable)
      .where(eq(engagementTable.id, rows[0].engagementId))
      .limit(1);
    const clientId = engagements[0]?.clientId;
    if (!clientId) return reply.code(404).send({ error: 'engagement not found' });

    await markFalsePositive(context.database, {
      findingId,
      clientId,
      reason: parsed.data.reason,
      createdBy: actorIdOf(request),
    });

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'finding.markedFalsePositive',
      subjectType: 'finding',
      subjectId: findingId,
      metadata: { reason: parsed.data.reason },
      ...requestContext(request),
    });

    return reply.send({ ok: true });
  });

  app.post('/findings/:findingId/severity', { preHandler: guard }, async (request, reply) => {
    const { findingId } = request.params as { findingId: string };
    const parsed = z
      .object({
        severity: z.enum(SEVERITIES),
        reason: z.string().min(20).max(1000),
      })
      .safeParse(request.body);
    if (!parsed.success) {
      return reply
        .code(400)
        .send({ error: 'a severity override needs a written justification of at least 20 characters' });
    }

    await overrideSeverity(context.database, {
      findingId,
      severity: parsed.data.severity,
      reason: parsed.data.reason,
      overriddenBy: actorIdOf(request),
    });

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'finding.severityOverridden',
      subjectType: 'finding',
      subjectId: findingId,
      metadata: { severity: parsed.data.severity, reason: parsed.data.reason },
      ...requestContext(request),
    });

    return reply.send({ ok: true });
  });

  app.put('/findings/:findingId', { preHandler: guard }, async (request, reply) => {
    const { findingId } = request.params as { findingId: string };
    const parsed = z
      .object({
        title: z.string().min(5).max(300).optional(),
        description: z.string().max(20_000).optional(),
        businessImpact: z.string().max(10_000).optional(),
        likelihood: z.string().max(4_000).optional(),
        attackerPrerequisites: z.string().max(4_000).optional(),
        reproductionSteps: z.array(z.string().max(2_000)).max(40).optional(),
        remediation: z.string().max(20_000).optional(),
        references: z
          .array(z.object({ title: z.string().max(200), url: z.string().url() }))
          .max(20)
          .optional(),
        cvssVector: z.string().max(200).optional(),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const update: Record<string, unknown> = { ...parsed.data, updatedAt: new Date() };

    if (parsed.data.cvssVector !== undefined) {
      if (!isValidCvssVector(parsed.data.cvssVector)) {
        return reply.code(400).send({ error: 'that CVSS vector does not parse' });
      }
      const scored = scoreCvss(parsed.data.cvssVector);
      update.cvssVersion = scored.version;
      update.cvssScore = scored.score;
      // The severity follows the vector unless a human has explicitly overridden it, which is
      // recorded separately.
      update.severity = scored.severity;
    }

    await context.database.update(findingTable).set(update).where(eq(findingTable.id, findingId));
    return reply.send({ ok: true });
  });

  /** Manual findings are the valuable ones, so creating one is a first-class route, not an import. */
  app.post('/engagements/:id/findings', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({
        title: z.string().min(5).max(300),
        description: z.string().min(20).max(20_000),
        severity: z.enum(SEVERITIES),
        cvssVector: z.string().max(200),
        checkId: z.string().max(100).optional(),
        cweId: z.number().int().positive().optional(),
        owaspCategory: z.string().max(20).optional(),
        wstgId: z.string().max(20).optional(),
        asvsRequirement: z.string().max(30).optional(),
        affectedAssets: z
          .array(
            z.object({
              value: z.string().min(1).max(300),
              location: z.string().max(500).optional(),
              parameter: z.string().max(200).optional(),
              method: z.string().max(10).optional(),
            }),
          )
          .min(1),
        businessImpact: z.string().min(20).max(10_000),
        likelihood: z.string().max(4_000).default(''),
        attackerPrerequisites: z.string().max(4_000).default(''),
        reproductionSteps: z.array(z.string().max(2_000)).min(1).max(40),
        remediation: z.string().min(20).max(20_000),
        references: z
          .array(z.object({ title: z.string().max(200), url: z.string().url() }))
          .max(20)
          .default([]),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    if (!isValidCvssVector(parsed.data.cvssVector)) {
      return reply.code(400).send({ error: 'that CVSS vector does not parse' });
    }
    const scored = scoreCvss(parsed.data.cvssVector);

    const [created] = await context.database
      .insert(findingTable)
      .values({
        engagementId: id,
        source: 'manual',
        checkId: parsed.data.checkId ?? null,
        title: parsed.data.title,
        description: parsed.data.description,
        severity: parsed.data.severity,
        cvssVersion: scored.version,
        cvssVector: scored.vector,
        cvssScore: scored.score,
        cweId: parsed.data.cweId ?? null,
        owaspCategory: parsed.data.owaspCategory ?? null,
        wstgId: parsed.data.wstgId ?? null,
        asvsRequirement: parsed.data.asvsRequirement ?? null,
        affectedAssets: parsed.data.affectedAssets,
        businessImpact: parsed.data.businessImpact,
        likelihood: parsed.data.likelihood,
        attackerPrerequisites: parsed.data.attackerPrerequisites,
        reproductionSteps: parsed.data.reproductionSteps,
        remediation: parsed.data.remediation,
        references: parsed.data.references,
        status: 'candidate',
        dedupeKey: `manual:${Date.now()}:${Math.random().toString(36).slice(2, 10)}`,
      })
      .returning();

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'finding.created',
      subjectType: 'finding',
      subjectId: created?.id ?? '',
      metadata: { source: 'manual', title: parsed.data.title },
      ...requestContext(request),
    });

    return reply.code(201).send({ finding: created });
  });

  app.post('/engagements/:id/findings/bulk', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({
        findingIds: z.array(z.string().uuid()).min(1).max(500),
        action: z.enum(['confirm', 'discard', 'markFixed', 'reopen']),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    if (parsed.data.action === 'confirm') {
      let confirmed = 0;
      for (const findingId of parsed.data.findingIds) {
        await confirmFinding(context.database, {
          findingId,
          engagementId: id,
          confirmedBy: actorIdOf(request),
        });
        confirmed += 1;
      }
      return reply.send({ ok: true, confirmed });
    }

    const status =
      parsed.data.action === 'discard'
        ? 'duplicate'
        : parsed.data.action === 'markFixed'
          ? 'fixed'
          : 'open';

    const updated = await bulkUpdateStatus(context.database, {
      findingIds: parsed.data.findingIds,
      status,
      engagementId: id,
    });

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'finding.statusChanged',
      subjectType: 'engagement',
      subjectId: id,
      metadata: { action: parsed.data.action, count: updated },
      ...requestContext(request),
    });

    return reply.send({ ok: true, updated });
  });

  /** Attach evidence to a finding. Masking and redaction happen inside the store, not here. */
  app.post('/findings/:findingId/evidence', { preHandler: guard }, async (request, reply) => {
    const { findingId } = request.params as { findingId: string };
    const parsed = z
      .object({
        kind: z.enum(['request', 'response', 'screenshot', 'log', 'terminal', 'file', 'transcript']),
        text: z.string().max(2_000_000).optional(),
        base64: z.string().max(20_000_000).optional(),
        contentType: z.string().max(100).optional(),
        filename: z.string().max(200).optional(),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const rows = await context.database
      .select({ engagementId: findingTable.engagementId })
      .from(findingTable)
      .where(eq(findingTable.id, findingId))
      .limit(1);
    const engagementId = rows[0]?.engagementId;
    if (!engagementId) return reply.code(404).send({ error: 'not found' });

    const stored = await context.evidence.capture({
      engagementId,
      kind: parsed.data.kind,
      text: parsed.data.text,
      binary: parsed.data.base64 ? Buffer.from(parsed.data.base64, 'base64') : undefined,
      contentType: parsed.data.contentType,
      filename: parsed.data.filename,
    });

    const [created] = await context.database
      .insert(evidenceTable)
      .values({
        findingId,
        engagementId,
        kind: parsed.data.kind,
        objectKey: stored.objectKey,
        contentType: stored.contentType,
        byteSize: stored.byteSize,
        sha256: stored.sha256,
        redactionApplied: stored.redactionApplied,
      })
      .returning();

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'evidence.captured',
      subjectType: 'finding',
      subjectId: findingId,
      metadata: { kind: parsed.data.kind, sha256: stored.sha256, masked: stored.redactionApplied },
      ...requestContext(request),
    });

    return reply.code(201).send({ evidence: created });
  });

  app.get('/engagements/:id/review-queue', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };

    const candidates = await context.database
      .select({
        id: findingTable.id,
        title: findingTable.title,
        severity: findingTable.severity,
        toolName: findingTable.toolName,
        checkId: findingTable.checkId,
        affectedAssets: findingTable.affectedAssets,
        firstSeenAt: findingTable.firstSeenAt,
        attackSuccessRate: findingTable.attackSuccessRate,
      })
      .from(findingTable)
      .where(and(eq(findingTable.engagementId, id), eq(findingTable.status, 'candidate')))
      .orderBy(
        sql`case ${findingTable.severity}
              when 'critical' then 0 when 'high' then 1 when 'medium' then 2
              when 'low' then 3 else 4 end`,
        asc(findingTable.firstSeenAt),
      );

    const byTool = new Map<string, number>();
    for (const candidate of candidates) {
      const tool = candidate.toolName ?? 'manual';
      byTool.set(tool, (byTool.get(tool) ?? 0) + 1);
    }

    return reply.send({
      candidates,
      total: candidates.length,
      byTool: Object.fromEntries(byTool),
    });
  });

  app.get('/findings/by-reference/:reference', { preHandler: guard }, async (request, reply) => {
    const { reference } = request.params as { reference: string };
    const rows = await context.database
      .select()
      .from(findingTable)
      .where(eq(findingTable.reference, reference))
      .limit(1);
    return rows[0] ? reply.send({ finding: rows[0] }) : reply.code(404).send({ error: 'not found' });
  });

  app.post('/engagements/:id/findings/import-status', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({ references: z.array(z.string()).min(1).max(500), status: z.enum(SEVERITIES).optional() })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const rows = await context.database
      .select({ id: findingTable.id, reference: findingTable.reference })
      .from(findingTable)
      .where(
        and(eq(findingTable.engagementId, id), inArray(findingTable.reference, parsed.data.references)),
      );

    return reply.send({ matched: rows });
  });
}
