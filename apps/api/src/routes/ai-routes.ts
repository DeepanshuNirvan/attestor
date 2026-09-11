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

/**
 * Should autodraft leave this section alone?
 *
 * Returns the reason to skip, or null to draft it. Two rules, and the first one is the important
 * one: a section a person has approved is never overwritten by a machine, force or not. Approval is
 * the moment somebody put their name to the words, and an autodraft that could undo it would make
 * the release checklist meaningless.
 */
export function autodraftSkipReason(
  current: { markdown: string; approvedAt: Date | null } | undefined,
  force: boolean,
): string | null {
  if (current?.approvedAt) {
    return 'a person has approved this section; autodraft never overwrites that';
  }
  if (!force && current && current.markdown.trim() !== '') {
    return 'already written; send force: true to replace it';
  }
  return null;
}

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
  /**
   * Draft every prose section the findings can support, in one call.
   *
   * The per-section route above is the deliberate version: one section, one instruction typed by
   * the person who will sign the report. This is the same machinery run over a fixed list, because
   * typing sixteen instructions to get a first draft is the reason reports were being written from
   * a blank page instead.
   *
   * Three rules keep it from being a way to publish a report nobody wrote:
   *
   *   1. **It never overwrites human work.** A section a person has approved is left alone, and so
   *      is one with text in it, unless `force` is set.
   *   2. **Everything it writes is still a draft.** `isAiDraft` is set and `approvedAt` is null, so
   *      the release checklist blocks exactly as it does for a hand-requested draft.
   *   3. **It only drafts what the evidence can ground.** The sections listed in
   *      `UNDRAFTABLE_SECTIONS` are records of what a tester did — which environment, which
   *      accounts, which constraints the client imposed. A model writing those is a model making
   *      them up, and the coverage matrix would then be quoting fiction.
   */
  const AUTODRAFT_SECTIONS: { key: string; instruction: string }[] = [
    {
      key: 'executiveSummary',
      instruction:
        'Write the executive summary for this assessment: what was tested, the headline risks in ' +
        'business terms rather than vulnerability names, and what an executive should conclude. ' +
        'Plain words, short sentences, no jargon. Separate paragraphs with a blank line.',
    },
    {
      key: 'headlineActions',
      instruction:
        'List the first three things to fix, ordered by how much risk each one actually removes ' +
        'rather than by severity label. One line each, starting with the action verb.',
    },
    {
      key: 'attackNarrativeTitle',
      instruction:
        'Write one line naming the worst realistic outcome these findings chain into, in the form ' +
        '"From an anonymous visitor to every customer record in four steps". One line only.',
    },
    {
      key: 'attackNarrative',
      instruction:
        'Write the attack narrative as ordered steps, one step per paragraph. The first line of ' +
        'each paragraph is a short heading, the rest is the body. Only use findings that exist.',
    },
    {
      key: 'attackNarrativeConclusion',
      instruction:
        'Write why the chain above matters more than the individual severities do. Two or three ' +
        'sentences.',
    },
    {
      key: 'positiveObservations',
      instruction:
        'List the controls these findings show were working — a control that stopped something, ' +
        'or one whose absence would have appeared here and did not. One line each. If the evidence ' +
        'does not support any, say so in one line rather than inventing one.',
    },
    {
      key: 'roadmap30',
      instruction:
        'The first thirty days of remediation, grouped by root cause rather than by finding. One ' +
        'line per item.',
    },
    {
      key: 'roadmap60',
      instruction: 'Days thirty to sixty of remediation, grouped by root cause. One line per item.',
    },
    {
      key: 'roadmap90',
      instruction: 'Days sixty to ninety of remediation, grouped by root cause. One line per item.',
    },
  ];

  /** Records of what a person did. A model has no way to know these and must not guess them. */
  const UNDRAFTABLE_SECTIONS = [
    'environments',
    'rolesTested',
    'constraints',
    'manualCoverage',
    'attackNarrativeDiagram',
    'outOfScopeNotes',
  ];

  app.post('/engagements/:id/report/autodraft', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({ force: z.boolean().default(false) })
      .safeParse(request.body ?? {});
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const existing = await context.database
      .select({
        sectionKey: reportSectionTable.sectionKey,
        markdown: reportSectionTable.markdown,
        approvedAt: reportSectionTable.approvedAt,
      })
      .from(reportSectionTable)
      .where(eq(reportSectionTable.engagementId, id));
    const stored = new Map(existing.map((row) => [row.sectionKey, row]));

    const findings = await context.database
      .select({
        title: findingTable.title,
        severity: findingTable.severity,
        description: findingTable.description,
        businessImpact: findingTable.businessImpact,
        remediation: findingTable.remediation,
        affectedAssets: findingTable.affectedAssets,
      })
      .from(findingTable)
      .where(and(eq(findingTable.engagementId, id), eq(findingTable.status, 'open')));

    // One evidence set, built once and reused for every section. Each section is a different
    // question asked of the same confirmed findings, so re-reading them per section would cost
    // nine round trips to say the same thing.
    const evidence = findings.map(
      (item) =>
        `${item.severity}: ${item.title}\n${item.description}\nAffected: ${JSON.stringify(
          item.affectedAssets,
        )}\nBusiness impact: ${item.businessImpact}\nRemediation: ${item.remediation}`,
    );

    const results: {
      sectionKey: string;
      status: 'drafted' | 'skipped' | 'refused';
      detail?: string;
      rule?: string;
    }[] = [];
    let totalCostUsd = 0;

    for (const section of AUTODRAFT_SECTIONS) {
      const skip = autodraftSkipReason(stored.get(section.key), parsed.data.force);
      if (skip !== null) {
        results.push({ sectionKey: section.key, status: 'skipped', detail: skip });
        continue;
      }

      const outcome = await assist.draft({
        engagementId: id,
        // Every one of these is summary prose over confirmed findings, which is what this purpose
        // is budgeted and grounded for.
        purpose: 'executiveSummary',
        evidence,
        instruction: section.instruction,
      });

      if (outcome.status === 'refused') {
        results.push({
          sectionKey: section.key,
          status: 'refused',
          detail: outcome.detail,
          rule: outcome.rule,
        });
        // A refusal that is about the deployment rather than this section — AI switched off, no
        // provider, budget gone — will refuse every remaining section identically. Stop rather
        // than spend nine identical failures.
        if (outcome.rule !== 'ungrounded' && outcome.rule !== 'noEvidence') break;
        continue;
      }

      totalCostUsd += outcome.estimatedCostUsd;

      await context.database
        .insert(reportSectionTable)
        .values({
          engagementId: id,
          sectionKey: section.key,
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

      results.push({ sectionKey: section.key, status: 'drafted' });
    }

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'ai.requestSent',
      subjectType: 'engagement',
      subjectId: id,
      metadata: {
        purpose: 'reportAutodraft',
        sections: results.map((item) => `${item.sectionKey}:${item.status}`),
        estimatedCostUsd: totalCostUsd,
        findingsUsed: findings.length,
      },
      ...requestContext(request),
    });

    return reply.send({
      results,
      estimatedCostUsd: totalCostUsd,
      stillYours: UNDRAFTABLE_SECTIONS,
      note:
        'Every section written here is a draft and none of them is approved. Release stays blocked ' +
        'until a person reads each one against the evidence and approves it. The sections in ' +
        '`stillYours` are records of what you did and are not drafted at all.',
    });
  });

  app.post('/engagements/:id/agentic/run', { preHandler: guard }, (unusedRequest, reply) => {
    const outcome = agenticRun();
    return reply.code(501).send({ error: outcome.detail, rule: outcome.rule });
  });
}
