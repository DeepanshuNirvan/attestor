import { and, desc, eq, gte, isNull, sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { LEGAL_BLOCKS } from '@attestor/report';
import { DENIAL_OF_SERVICE_CAPABILITY, RATE_CEILINGS } from '@attestor/policy';
import { TOOL_IMAGES } from '@attestor/core';
import type { ConsoleContext } from '../context.ts';
import type { Queues } from '../queue.ts';
import {
  aiUsage,
  auditLog as auditLogTable,
  engagement as engagementTable,
  notification,
  scanRun as scanRunTable,
} from '../db/schema.ts';
import { loadToolDigests } from '../services/tool-digests.ts';
import { actorIdOf, requestContext, requireSession } from './session-guard.ts';

/**
 * Platform operations: the job queue, the outbox, the audit log, and what this deployment is
 * actually configured to do.
 *
 * The outbox is the part worth reading. Client-facing messages are drafted by the platform and
 * released by a person: approving one records who approved it, and marking it sent records that a
 * human sent it. There is no SMTP client in this file, and that is deliberate — a code path that
 * can email a client is a code path that will eventually email a client by accident.
 */

export function registerPlatformRoutes(
  app: FastifyInstance,
  context: ConsoleContext,
  queues: Queues,
): void {
  const guard = requireSession({ database: context.database, expect: 'staff' });

  /* Queue --------------------------------------------------------------------------------------- */

  app.get('/queue', { preHandler: guard }, async (unusedRequest, reply) => {
    const counts = await Promise.all(
      (['scan', 'report', 'retention', 'retainer', 'notification'] as const).map(async (name) => ({
        name,
        counts: await queues[name].getJobCounts(
          'waiting',
          'active',
          'delayed',
          'failed',
          'completed',
        ),
      })),
    );

    // Failed scan jobs matter more than the number: each one is a tool that did not run against a
    // client's asset, and somebody has to decide whether that leaves a hole in the coverage matrix.
    const failedScans = await queues.scan.getFailed(0, 24);

    const running = await context.database
      .select({
        id: scanRunTable.id,
        engagementId: scanRunTable.engagementId,
        engagementReference: engagementTable.reference,
        module: scanRunTable.module,
        toolName: scanRunTable.toolName,
        status: scanRunTable.status,
        startedAt: scanRunTable.startedAt,
      })
      .from(scanRunTable)
      .innerJoin(engagementTable, eq(engagementTable.id, scanRunTable.engagementId))
      .where(eq(scanRunTable.status, 'running'))
      .orderBy(desc(scanRunTable.startedAt));

    return reply.send({
      queues: counts,
      running,
      failed: failedScans.map((job) => ({
        id: job.id,
        name: job.name,
        attemptsMade: job.attemptsMade,
        failedReason: job.failedReason,
        // The payload names targets, which is engagement data; only the ids are surfaced here.
        engagementId: (job.data as { engagementId?: string }).engagementId ?? null,
        toolId: (job.data as { toolId?: string }).toolId ?? null,
      })),
    });
  });

  app.post('/queue/scan/:jobId/retry', { preHandler: guard }, async (request, reply) => {
    const { jobId } = request.params as { jobId: string };
    const job = await queues.scan.getJob(jobId);
    if (!job) return reply.code(404).send({ error: 'not found' });

    await job.retry();

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'queue.jobRetried',
      subjectType: 'scanRun',
      subjectId: (job.data as { scanRunId?: string }).scanRunId ?? jobId,
      ...requestContext(request),
    });

    // The scope guard runs again on the retry. A job that was refused the first time is refused
    // again; retrying is not a way past it.
    return reply.send({ ok: true });
  });

  /* The outbox ---------------------------------------------------------------------------------- */

  app.get('/notifications', { preHandler: guard }, async (request, reply) => {
    const query = z
      .object({ state: z.enum(['pending', 'approved', 'sent', 'all']).default('pending') })
      .safeParse(request.query);
    if (!query.success) return reply.code(400).send({ error: query.error.issues });

    const condition =
      query.data.state === 'pending'
        ? isNull(notification.approvedAt)
        : query.data.state === 'approved'
          ? and(sql`${notification.approvedAt} is not null`, isNull(notification.sentAt))
          : query.data.state === 'sent'
            ? sql`${notification.sentAt} is not null`
            : undefined;

    const rows = await context.database
      .select({
        id: notification.id,
        engagementId: notification.engagementId,
        engagementReference: engagementTable.reference,
        channel: notification.channel,
        template: notification.template,
        subject: notification.subject,
        body: notification.body,
        queuedAt: notification.queuedAt,
        approvedAt: notification.approvedAt,
        sentAt: notification.sentAt,
      })
      .from(notification)
      .leftJoin(engagementTable, eq(engagementTable.id, notification.engagementId))
      .where(condition)
      .orderBy(desc(notification.queuedAt))
      .limit(200);

    return reply.send({
      notifications: rows,
      note: 'Nothing here is sent by the platform. Approving records the decision; sending is done by a person, who then marks it sent.',
    });
  });

  app.post('/notifications/:id/approve', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };

    const [updated] = await context.database
      .update(notification)
      .set({ approvedAt: new Date(), approvedBy: actorIdOf(request) })
      .where(and(eq(notification.id, id), isNull(notification.approvedAt)))
      .returning({ id: notification.id, subject: notification.subject });
    if (!updated) return reply.code(404).send({ error: 'not found, or already approved' });

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'notification.approved',
      subjectType: 'notification',
      subjectId: id,
      metadata: { subject: updated.subject },
      ...requestContext(request),
    });

    return reply.send({ ok: true });
  });

  app.post('/notifications/:id/mark-sent', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };

    const [updated] = await context.database
      .update(notification)
      .set({ sentAt: new Date() })
      .where(and(eq(notification.id, id), sql`${notification.approvedAt} is not null`))
      .returning({ id: notification.id });
    if (!updated) return reply.code(409).send({ error: 'approve it before marking it sent' });

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'notification.sent',
      subjectType: 'notification',
      subjectId: id,
      ...requestContext(request),
    });

    return reply.send({ ok: true });
  });

  app.delete('/notifications/:id', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z.object({ reason: z.string().min(3).max(500) }).safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const deleted = await context.database
      .delete(notification)
      .where(and(eq(notification.id, id), isNull(notification.sentAt)))
      .returning({ id: notification.id, subject: notification.subject });
    if (deleted.length === 0) return reply.code(404).send({ error: 'not found, or already sent' });

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'notification.discarded',
      subjectType: 'notification',
      subjectId: id,
      metadata: { reason: parsed.data.reason, subject: deleted[0]?.subject },
      ...requestContext(request),
    });

    return reply.send({ ok: true });
  });

  /* The audit log ------------------------------------------------------------------------------- */

  app.get('/audit', { preHandler: guard }, async (request, reply) => {
    const query = z
      .object({
        action: z.string().max(80).optional(),
        subjectId: z.string().max(80).optional(),
        sinceDays: z.coerce.number().int().min(1).max(365).default(7),
        limit: z.coerce.number().int().min(1).max(500).default(100),
      })
      .safeParse(request.query);
    if (!query.success) return reply.code(400).send({ error: query.error.issues });

    const since = new Date(Date.now() - query.data.sinceDays * 24 * 60 * 60 * 1000);
    const filters = [gte(auditLogTable.createdAt, since)];
    if (query.data.action) filters.push(eq(auditLogTable.action, query.data.action));
    if (query.data.subjectId) filters.push(eq(auditLogTable.subjectId, query.data.subjectId));

    const entries = await context.database
      .select()
      .from(auditLogTable)
      .where(and(...filters))
      .orderBy(desc(auditLogTable.createdAt))
      .limit(query.data.limit);

    return reply.send({ entries });
  });

  /**
   * Refusals, on their own. A single refusal is the system working; a repeated one means a scope
   * item is wrong and somebody is arguing with the guard, which is a person's problem to solve.
   */
  app.get('/audit/refusals', { preHandler: guard }, async (request, reply) => {
    const query = z
      .object({ sinceDays: z.coerce.number().int().min(1).max(90).default(7) })
      .safeParse(request.query);
    if (!query.success) return reply.code(400).send({ error: query.error.issues });

    const since = new Date(Date.now() - query.data.sinceDays * 24 * 60 * 60 * 1000);
    const entries = await context.database
      .select()
      .from(auditLogTable)
      .where(and(gte(auditLogTable.createdAt, since), eq(auditLogTable.action, 'scanRun.refused')))
      .orderBy(desc(auditLogTable.createdAt))
      .limit(200);

    return reply.send({ entries });
  });

  /* What this deployment is configured to do ------------------------------------------------------ */

  app.get('/settings', { preHandler: guard }, async (unusedRequest, reply) => {
    const digests = await loadToolDigests();

    const unreviewedLegal = LEGAL_BLOCKS.filter((block) => block.lawyerReviewedAt === null).map(
      (block) => block.id,
    );

    const usage = await context.database
      .select({
        model: aiUsage.model,
        purpose: aiUsage.purpose,
        inputTokens: sql<number>`sum(${aiUsage.inputTokens})`,
        outputTokens: sql<number>`sum(${aiUsage.outputTokens})`,
        cost: sql<number>`sum(${aiUsage.estimatedCostUsd})`,
      })
      .from(aiUsage)
      .groupBy(aiUsage.model, aiUsage.purpose);

    return reply.send({
      // Never the values. A settings screen that shows a secret is a screenshot away from a leak.
      configuration: {
        aiEnabled: context.config.AI_ENABLED,
        aiProvider: context.config.AI_PROVIDER,
        aiMonthlyBudgetUsd: context.config.AI_MONTHLY_BUDGET_USD,
        egressIp: context.config.EGRESS_IP,
        portalOrigin: context.config.PORTAL_ORIGIN,
        consoleOrigin: context.config.CONSOLE_ORIGIN,
        evidenceBucket: context.config.S3_BUCKET_EVIDENCE,
        reportBucket: context.config.S3_BUCKET_REPORTS,
      },
      capabilities: {
        denialOfService: DENIAL_OF_SERVICE_CAPABILITY,
        rateCeilings: RATE_CEILINGS,
      },
      tools: TOOL_IMAGES.map((tool) => ({
        id: tool.id,
        displayName: tool.displayName,
        image: `${tool.image}:${tool.tag}`,
        modules: tool.modules,
        purpose: tool.purpose,
        digest: digests[tool.id] ?? null,
        runnable: Boolean(digests[tool.id]),
      })),
      legal: {
        blocks: LEGAL_BLOCKS.map((block) => ({
          id: block.id,
          version: block.version,
          lawyerReviewedAt: block.lawyerReviewedAt,
        })),
        unreviewed: unreviewedLegal,
      },
      aiUsage: usage,
    });
  });
}
