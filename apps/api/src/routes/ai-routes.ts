import { and, eq, gte, sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { AiAssist, agenticRun, type AiPurpose } from '@attestor/core';
import type { ConsoleContext } from '../context.ts';
import {
  aiUsage,
  engagement as engagementTable,
  evidence as evidenceTable,
  finding as findingTable,
  reportSection as reportSectionTable,
} from '../db/schema.ts';
import { transportFor } from '../services/ai-transport.ts';
import { actorIdOf, requestContext, requireSession } from './session-guard.ts';

/**
 * AI assistance, per engagement.
 *
 * The evidence handed to the model is read here, from the finding it belongs to, rather than
 * accepted from the caller. A route that let the console post arbitrary text to a third-party model
 * would be a way around every control in `AiAssist`, and the console is not the trust boundary.
 *
 * Everything this returns is a draft. Storing it marks it as one, and the pre-release checklist
 * refuses to release a report with an unapproved AI block in it.
 */

const PURPOSES = [
  'findingProse',
  'executiveSummary',
  'toolOutputExplanation',
  'cvssRationale',
  'deduplicationProposal',
] as const satisfies readonly AiPurpose[];

export function registerAiRoutes(app: FastifyInstance, context: ConsoleContext): void {
  const guard = requireSession({ database: context.database, expect: 'staff' });

  const assist = new AiAssist({
    config: {
      enabled: context.config.AI_ENABLED,
      provider: context.config.AI_PROVIDER,
      modelDrafting: context.config.AI_MODEL_DRAFTING,
      modelTriage: context.config.AI_MODEL_TRIAGE,
      monthlyBudgetUsd: context.config.AI_MONTHLY_BUDGET_USD,
      inputCostPerMillionUsd: context.config.AI_INPUT_COST_PER_MILLION_USD,
      outputCostPerMillionUsd: context.config.AI_OUTPUT_COST_PER_MILLION_USD,
    },
    transport: transportFor(context.config.AI_PROVIDER, context.config.AI_API_KEY),

    engagementEnabled: async (engagementId) => {
      const rows = await context.database
        .select({ enabled: engagementTable.aiAssistEnabled })
        .from(engagementTable)
        .where(eq(engagementTable.id, engagementId))
        .limit(1);
      return rows[0]?.enabled === true;
    },

    spentThisMonthUsd: async (engagementId) => {
      // The ceiling is per engagement per calendar month. A shared pool would mean one noisy
      // engagement silently spending another's budget.
      const monthStart = new Date();
      monthStart.setUTCDate(1);
      monthStart.setUTCHours(0, 0, 0, 0);

      const rows = await context.database
        .select({ total: sql<number>`coalesce(sum(${aiUsage.estimatedCostUsd}), 0)` })
        .from(aiUsage)
        .where(and(eq(aiUsage.engagementId, engagementId), gte(aiUsage.createdAt, monthStart)));
      return Number(rows[0]?.total ?? 0);
    },

    record: async (entry) => {
      await context.database.insert(aiUsage).values({
        engagementId: entry.engagementId,
        model: entry.model,
        purpose: entry.purpose,
        inputTokens: entry.inputTokens,
        outputTokens: entry.outputTokens,
        estimatedCostUsd: entry.estimatedCostUsd,
      });

      await context.auditLog.record({
        actorId: 'system',
        actorKind: 'system',
        action: 'ai.requestSent',
        subjectType: 'engagement',
        subjectId: entry.engagementId,
        // The prompt hash, not the prompt: enough to prove which text produced which draft, without
        // keeping a second copy of the evidence in the audit log.
        metadata: {
          model: entry.model,
          purpose: entry.purpose,
          promptSha256: entry.promptSha256,
          inputTokens: entry.inputTokens,
          outputTokens: entry.outputTokens,
          estimatedCostUsd: entry.estimatedCostUsd,
        },
      });
    },
  });

  app.post('/engagements/:id/ai/draft', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({
        purpose: z.enum(PURPOSES),
        /** Present for the per-finding purposes. Its evidence is what grounds the draft. */
        findingId: z.string().uuid().optional(),
        instruction: z.string().min(3).max(2_000),
        /** When set, the draft is stored in this report section, marked as a draft. */
        sectionKey: z.string().min(1).max(80).optional(),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const evidenceText: string[] = [];

    if (parsed.data.findingId) {
      const rows = await context.database
        .select({ finding: findingTable })
        .from(findingTable)
        .where(and(eq(findingTable.id, parsed.data.findingId), eq(findingTable.engagementId, id)))
        .limit(1);
      const record = rows[0]?.finding;
      if (!record) return reply.code(404).send({ error: 'not found' });

      evidenceText.push(
        `Title: ${record.title}`,
        `Affected: ${JSON.stringify(record.affectedAssets)}`,
        `Tool: ${record.toolName ?? 'manual testing'}`,
        `Raw tool output: ${record.toolFindingRef ?? ''}`,
        record.description,
      );

      const captured = await context.database
        .select({
          kind: evidenceTable.kind,
          objectKey: evidenceTable.objectKey,
          contentType: evidenceTable.contentType,
          purgedAt: evidenceTable.purgedAt,
        })
        .from(evidenceTable)
        .where(eq(evidenceTable.findingId, parsed.data.findingId));

      for (const item of captured) {
        // Evidence past its retention date is gone, and a draft grounded in what used to be there
        // would be grounded in nothing.
        if (item.purgedAt) continue;
        // Text is read from the store; an image is named, not sent. There is no reason to put a
        // client's screen in front of a third-party model.
        if (!item.contentType.startsWith('text/') && !item.contentType.includes('json')) {
          evidenceText.push(`${item.kind} evidence was captured and is not included here.`);
          continue;
        }
        const body = await context.evidence.read(item.objectKey).catch(() => null);
        if (body) evidenceText.push(`${item.kind}:\n${body.toString('utf8').slice(0, 8_000)}`);
      }
    } else {
      const findings = await context.database
        .select({
          title: findingTable.title,
          severity: findingTable.severity,
          businessImpact: findingTable.businessImpact,
        })
        .from(findingTable)
        .where(and(eq(findingTable.engagementId, id), eq(findingTable.status, 'open')));

      for (const item of findings) {
        evidenceText.push(`${item.severity}: ${item.title} — ${item.businessImpact}`);
      }
    }

    const outcome = await assist.draft({
      engagementId: id,
      purpose: parsed.data.purpose,
      evidence: evidenceText,
      instruction: parsed.data.instruction,
    });

    if (outcome.status === 'refused') {
      return reply.code(409).send({ error: outcome.detail, rule: outcome.rule });
    }

    if (parsed.data.sectionKey) {
      // Stored with `isAiDraft` set and no approval. The pre-release checklist refuses to release a
      // report while any section is still in that state, so approval is a step somebody has to take
      // rather than a default the UI can quietly skip.
      await context.database
        .insert(reportSectionTable)
        .values({
          engagementId: id,
          sectionKey: parsed.data.sectionKey,
          markdown: outcome.markdown,
          isAiDraft: true,
          approvedAt: null,
        })
        .onConflictDoUpdate({
          target: [reportSectionTable.engagementId, reportSectionTable.sectionKey],
          set: {
            markdown: outcome.markdown,
            isAiDraft: true,
            approvedAt: null,
            approvedBy: null,
            updatedAt: new Date(),
          },
        });
    }

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'ai.requestSent',
      subjectType: 'engagement',
      subjectId: id,
      metadata: {
        purpose: parsed.data.purpose,
        model: outcome.model,
        requestedByPerson: true,
        sectionKey: parsed.data.sectionKey ?? null,
      },
      ...requestContext(request),
    });

    return reply.send({
      draft: outcome.markdown,
      isDraft: true,
      model: outcome.model,
      promptSha256: outcome.promptSha256,
      estimatedCostUsd: outcome.estimatedCostUsd,
      note: 'This is a draft. Read every line against the evidence before it goes anywhere near a report.',
    });
  });

  /** Present so that the engagement flag cannot be mistaken for a working feature. */
  app.post('/engagements/:id/agentic/run', { preHandler: guard }, (unusedRequest, reply) => {
    const outcome = agenticRun();
    return reply.code(501).send({ error: outcome.detail, rule: outcome.rule });
  });
}
