import { and, desc, eq, sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  canTransition,
  clearPanicStop,
  engagePanicStop,
  missingPreFlightItems,
  unknownPreFlightItems,
  validateScopeItem,
  PRE_FLIGHT_CHECKLIST,
  type TransitionContext,
} from '@attestor/core';
import { PROFILE_IDS, loadProfileYaml, resolvePolicy, CLOUD_TESTING_POLICIES } from '@attestor/policy';
import { engagementReference, type EngagementState } from '@attestor/shared';
import type { ConsoleContext } from '../context.ts';
import type { Queues } from '../queue.ts';
import {
  acknowledgement,
  authorisation as authorisationTable,
  client as clientTable,
  credentialIntakeLink,
  credentialSet,
  engagement as engagementTable,
  evidence as evidenceTable,
  finding as findingTable,
  scanRun as scanRunTable,
  scopeItem as scopeItemTable,
} from '../db/schema.ts';
import { createRunsForModule, loadRunContext } from '../services/run-service.ts';
import { actorIdOf, requestContext, requireSession } from './session-guard.ts';
import { hashToken, newSessionToken } from '../services/auth.ts';

/**
 * Engagement management.
 *
 * The state machine is enforced here rather than left to the console UI: a request that would skip
 * the authorisation gate is refused with the reason, whatever the client sends.
 */

const MODULE_VALUES = ['recon', 'web', 'api', 'mobile', 'cloud', 'code', 'network', 'llm', 'agentic'] as const;

export function registerEngagementRoutes(
  app: FastifyInstance,
  context: ConsoleContext,
  queues: Queues,
): void {
  const guard = requireSession({ database: context.database, expect: 'staff' });

  app.get('/engagements', { preHandler: guard }, async (unusedRequest, reply) => {
    const rows = await context.database
      .select({
        id: engagementTable.id,
        reference: engagementTable.reference,
        title: engagementTable.title,
        state: engagementTable.state,
        type: engagementTable.type,
        startsAt: engagementTable.startsAt,
        endsAt: engagementTable.endsAt,
        clientId: engagementTable.clientId,
        clientName: clientTable.name,
      })
      .from(engagementTable)
      .innerJoin(clientTable, eq(clientTable.id, engagementTable.clientId))
      .orderBy(desc(engagementTable.createdAt));
    return reply.send({ engagements: rows });
  });

  app.post('/engagements', { preHandler: guard }, async (request, reply) => {
    const parsed = z
      .object({
        clientId: z.string().uuid(),
        title: z.string().min(3).max(200),
        type: z.string().min(2).max(40),
        // The report prints all three, and the pre-release checklist blocks on the dates because
        // the legal blocks quote them. Until these were accepted here nothing could set them, so
        // every engagement was greyBox with no test window and no report could pass the gate.
        testType: z.enum(['blackBox', 'greyBox', 'whiteBox']).default('greyBox'),
        startsAt: z.coerce.date().optional(),
        endsAt: z.coerce.date().optional(),
        timezone: z.string().default('Asia/Kolkata'),
        currency: z.enum(['INR', 'USD']).default('INR'),
        quotedAmount: z.number().int().nonnegative().default(0),
        profileId: z.enum(PROFILE_IDS).optional(),
      })
      .refine(
        (value) => !value.startsAt || !value.endsAt || value.endsAt > value.startsAt,
        { message: 'the test window ends before it begins' },
      )
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const year = new Date().getFullYear();
    const maxRows = await context.database
      .select({ maximum: sql<number>`coalesce(max(${engagementTable.referenceSequence}), 0)` })
      .from(engagementTable)
      .where(eq(engagementTable.referenceYear, year));
    const sequence = Number(maxRows[0]?.maximum ?? 0) + 1;

    const policyYaml = parsed.data.profileId ? await loadProfileYaml(parsed.data.profileId) : '';

    const [created] = await context.database
      .insert(engagementTable)
      .values({
        clientId: parsed.data.clientId,
        reference: engagementReference({ year, sequence }),
        referenceYear: year,
        referenceSequence: sequence,
        type: parsed.data.type,
        title: parsed.data.title,
        testType: parsed.data.testType,
        startsAt: parsed.data.startsAt,
        endsAt: parsed.data.endsAt,
        timezone: parsed.data.timezone,
        currency: parsed.data.currency,
        quotedAmount: parsed.data.quotedAmount,
        policyYaml,
      })
      .returning();

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'engagement.created',
      subjectType: 'engagement',
      subjectId: created?.id ?? '',
      metadata: { reference: created?.reference, profileId: parsed.data.profileId },
      ...requestContext(request),
    });

    return reply.code(201).send({ engagement: created });
  });

  /**
   * Revising an engagement.
   *
   * Test windows move, and the assessment type is often settled after the scoping call rather than
   * at creation. Only the fields an operator legitimately revises are here: the reference, the
   * client and the state are not editable, because the first is quoted by the client for years, the
   * second would move work between tenants, and the third belongs to the state machine.
   */
  app.patch('/engagements/:id', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({
        title: z.string().min(3).max(200).optional(),
        testType: z.enum(['blackBox', 'greyBox', 'whiteBox']).optional(),
        startsAt: z.coerce.date().optional(),
        endsAt: z.coerce.date().optional(),
        timezone: z.string().min(1).max(60).optional(),
        quotedAmount: z.number().int().nonnegative().optional(),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const rows = await context.database
      .select()
      .from(engagementTable)
      .where(eq(engagementTable.id, id))
      .limit(1);
    const record = rows[0];
    if (!record) return reply.code(404).send({ error: 'not found' });

    const startsAt = parsed.data.startsAt ?? record.startsAt;
    const endsAt = parsed.data.endsAt ?? record.endsAt;
    if (startsAt && endsAt && endsAt <= startsAt) {
      return reply.code(400).send({ error: 'the test window ends before it begins' });
    }

    const [updated] = await context.database
      .update(engagementTable)
      .set({ ...parsed.data, updatedAt: new Date() })
      .where(eq(engagementTable.id, id))
      .returning();

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'engagement.updated',
      subjectType: 'engagement',
      subjectId: id,
      metadata: { changed: Object.keys(parsed.data) },
      ...requestContext(request),
    });

    return reply.send({ engagement: updated });
  });

  app.get('/engagements/:id', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };

    const rows = await context.database
      .select()
      .from(engagementTable)
      .where(eq(engagementTable.id, id))
      .limit(1);
    const record = rows[0];
    if (!record) return reply.code(404).send({ error: 'not found' });

    const [scopeItems, authorisations, credentials, runs, findingCounts] = await Promise.all([
      context.database.select().from(scopeItemTable).where(eq(scopeItemTable.engagementId, id)),
      context.database
        .select()
        .from(authorisationTable)
        .where(eq(authorisationTable.engagementId, id))
        .orderBy(desc(authorisationTable.createdAt)),
      context.database
        .select({
          id: credentialSet.id,
          label: credentialSet.label,
          roleName: credentialSet.roleName,
          authType: credentialSet.authType,
          isSecondary: credentialSet.isSecondary,
          expiresAt: credentialSet.expiresAt,
          lastVerifiedAt: credentialSet.lastVerifiedAt,
          revokedAt: credentialSet.revokedAt,
          shreddedAt: credentialSet.shreddedAt,
        })
        .from(credentialSet)
        .where(eq(credentialSet.engagementId, id)),
      context.database
        .select()
        .from(scanRunTable)
        .where(eq(scanRunTable.engagementId, id))
        .orderBy(desc(scanRunTable.createdAt))
        .limit(100),
      context.database
        .select({ status: findingTable.status, severity: findingTable.severity, count: sql<number>`count(*)` })
        .from(findingTable)
        .where(eq(findingTable.engagementId, id))
        .groupBy(findingTable.status, findingTable.severity),
    ]);

    const panicStopState = await context.panicStop.state(id);
    const { policy, warnings } = resolvePolicy([
      { name: 'engagement', yamlSource: record.policyYaml },
    ]);

    // Credentials are listed by label and role only. There is no route that returns a value, and
    // adding one would defeat the vault.
    return reply.send({
      engagement: record,
      scopeItems,
      authorisations,
      credentials,
      runs,
      findingCounts,
      panicStop: panicStopState,
      policy,
      policyWarnings: warnings,
    });
  });

  app.post('/engagements/:id/scope', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({
        items: z
          .array(
            z.object({
              kind: z.enum([
                'domain',
                'wildcard',
                'ip',
                'cidr',
                'url',
                'repo',
                'cloudAccount',
                'mobilePackage',
                'llmEndpoint',
              ]),
              value: z.string().min(1).max(500),
              included: z.boolean().default(true),
              notes: z.string().max(500).default(''),
            }),
          )
          .min(1),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    // Validate at entry so a typo — or a forbidden target — is a form error now rather than a
    // refusal on the morning of the test, when one bad item refuses the whole run.
    //
    // A private address is only legitimate inside a range the client has declared as their own, so
    // the ranges already recorded and the ones arriving in this request both count.
    const declaredRanges = await context.database
      .select({ value: scopeItemTable.value })
      .from(scopeItemTable)
      .where(and(eq(scopeItemTable.engagementId, id), eq(scopeItemTable.kind, 'cidr')));
    const ownedPrivateRanges = [
      ...declaredRanges.map((row) => row.value),
      ...parsed.data.items.filter((item) => item.kind === 'cidr').map((item) => item.value),
    ];

    const problems = parsed.data.items
      .map((item) => ({ item, problem: validateScopeItem(item, { ownedPrivateRanges }) }))
      .filter((entry) => entry.problem !== null);
    if (problems.length > 0) {
      return reply.code(400).send({
        error: 'some scope items are not valid',
        problems: problems.map((entry) => ({ value: entry.item.value, problem: entry.problem })),
      });
    }

    const inserted = await context.database
      .insert(scopeItemTable)
      .values(parsed.data.items.map((item) => ({ ...item, engagementId: id })))
      .onConflictDoNothing()
      .returning();

    for (const item of inserted) {
      await context.auditLog.record({
        actorId: actorIdOf(request),
        actorKind: 'staff',
        action: 'scopeItem.added',
        subjectType: 'engagement',
        subjectId: id,
        metadata: { kind: item.kind, value: item.value, included: item.included },
        ...requestContext(request),
      });
    }

    return reply.code(201).send({ scopeItems: inserted });
  });

  app.delete('/engagements/:id/scope/:scopeItemId', { preHandler: guard }, async (request, reply) => {
    const { id, scopeItemId } = request.params as { id: string; scopeItemId: string };
    await context.database
      .delete(scopeItemTable)
      .where(and(eq(scopeItemTable.id, scopeItemId), eq(scopeItemTable.engagementId, id)));

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'scopeItem.removed',
      subjectType: 'engagement',
      subjectId: id,
      metadata: { scopeItemId },
      ...requestContext(request),
    });

    return reply.send({ ok: true });
  });

  /**
   * Authorisation upload. The asset list from the signed document is diffed against the entered
   * scope, and any mismatch is returned for a human to resolve before the engagement can advance.
   */
  app.post('/engagements/:id/authorisation', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({
        signedBy: z.string().min(2).max(150),
        signerRole: z.string().min(2).max(150),
        signerEmail: z.string().email(),
        signedAt: z.coerce.date(),
        documentObjectKey: z.string().min(1),
        documentSha256: z.string().length(64),
        assetList: z.array(z.string()).min(1),
        exclusionList: z.array(z.string()).default([]),
        sourceAddresses: z.array(z.string()).default([]),
        emergencyContact: z.object({
          name: z.string().min(1),
          role: z.string().min(1),
          phone: z.string().min(5),
          email: z.string().email(),
        }),
        criticalNotificationHours: z.number().int().positive().max(168).default(24),
        validFrom: z.coerce.date(),
        validUntil: z.coerce.date(),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    if (parsed.data.validUntil <= parsed.data.validFrom) {
      return reply.code(400).send({ error: 'the testing window ends before it begins' });
    }

    const [created] = await context.database
      .insert(authorisationTable)
      .values({ ...parsed.data, engagementId: id })
      .returning();

    const scopeItems = await context.database
      .select()
      .from(scopeItemTable)
      .where(eq(scopeItemTable.engagementId, id));

    const enteredValues = new Set(scopeItems.filter((item) => item.included).map((item) => item.value.toLowerCase()));
    const authorisedValues = new Set(parsed.data.assetList.map((value) => value.toLowerCase()));

    const inDocumentNotEntered = [...authorisedValues].filter((value) => !enteredValues.has(value));
    const enteredNotInDocument = [...enteredValues].filter((value) => !authorisedValues.has(value));

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'authorisation.uploaded',
      subjectType: 'engagement',
      subjectId: id,
      metadata: {
        authorisationId: created?.id,
        signerEmail: parsed.data.signerEmail,
        documentSha256: parsed.data.documentSha256,
        validFrom: parsed.data.validFrom,
        validUntil: parsed.data.validUntil,
      },
      ...requestContext(request),
    });

    if (inDocumentNotEntered.length > 0 || enteredNotInDocument.length > 0) {
      await context.auditLog.record({
        actorId: actorIdOf(request),
        actorKind: 'staff',
        action: 'authorisation.assetListDiffed',
        subjectType: 'engagement',
        subjectId: id,
        metadata: { inDocumentNotEntered, enteredNotInDocument },
        ...requestContext(request),
      });
    }

    return reply.code(201).send({
      authorisation: created,
      diff: { inDocumentNotEntered, enteredNotInDocument },
      // A mismatch does not block the upload; it blocks the state transition, which is where a
      // human has to look at it.
      requiresResolution: inDocumentNotEntered.length > 0 || enteredNotInDocument.length > 0,
    });
  });

  app.post('/engagements/:id/authorisation/:authorisationId/revoke', { preHandler: guard }, async (request, reply) => {
    const { id, authorisationId } = request.params as { id: string; authorisationId: string };
    const parsed = z.object({ reason: z.string().min(5).max(500) }).safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'a revocation needs a reason' });

    await context.database
      .update(authorisationTable)
      .set({ revokedAt: new Date(), revokedReason: parsed.data.reason })
      .where(and(eq(authorisationTable.id, authorisationId), eq(authorisationTable.engagementId, id)));

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'authorisation.revoked',
      subjectType: 'engagement',
      subjectId: id,
      metadata: { authorisationId, reason: parsed.data.reason },
      ...requestContext(request),
    });

    return reply.send({ ok: true });
  });

  app.post('/engagements/:id/state', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({
        to: z.string().min(2).max(40),
        reason: z.string().max(1000).optional(),
        advanceGateOverrideReason: z.string().min(10).max(500).optional(),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const rows = await context.database
      .select()
      .from(engagementTable)
      .where(eq(engagementTable.id, id))
      .limit(1);
    const record = rows[0];
    if (!record) return reply.code(404).send({ error: 'not found' });

    const [authorisations, credentials, evidenceRows] = await Promise.all([
      context.database
        .select()
        .from(authorisationTable)
        .where(eq(authorisationTable.engagementId, id))
        .orderBy(desc(authorisationTable.createdAt))
        .limit(1),
      context.database.select().from(credentialSet).where(eq(credentialSet.engagementId, id)),
      context.database
        .select({ id: evidenceTable.id, purgedAt: evidenceTable.purgedAt })
        .from(evidenceTable)
        .where(eq(evidenceTable.engagementId, id)),
    ]);

    const scopeCount = await context.database
      .select({ count: sql<number>`count(*)` })
      .from(scopeItemTable)
      .where(eq(scopeItemTable.engagementId, id));

    const checklist = record.preFlightChecklist as Record<string, boolean>;
    const reviewChecklist = record.reviewChecklist as Record<string, boolean>;

    const transitionContext: TransitionContext = {
      scopeItemCount: Number(scopeCount[0]?.count ?? 0),
      hasSignedAuthorisation: Boolean(authorisations[0]?.signedAt && !authorisations[0]?.revokedAt),
      authorisationValidUntil: authorisations[0]?.validUntil ?? null,
      advancePaymentReceived: record.advancePaidAt !== null,
      advanceGateOverride: parsed.data.advanceGateOverrideReason
        ? { by: actorIdOf(request), reason: parsed.data.advanceGateOverrideReason }
        : (record.advanceGateOverride as { by: string; reason: string } | null),
      credentialsVerified:
        credentials.length === 0 ||
        credentials.every((credential) => credential.lastVerifiedAt !== null || credential.revokedAt !== null),
      preFlightChecklistComplete: missingPreFlightItems(checklist).length === 0,
      reviewChecklistComplete:
        Object.values(reviewChecklist).length > 0 && Object.values(reviewChecklist).every(Boolean),
      finalPaymentReceived: record.finalPaidAt !== null,
      evidencePurged: evidenceRows.every((row) => row.purgedAt !== null),
      now: new Date(),
    };

    const outcome = canTransition(
      record.state as EngagementState,
      parsed.data.to as EngagementState,
      transitionContext,
      parsed.data.reason,
    );

    if (!outcome.allowed) {
      return reply.code(409).send({
        error: outcome.reason,
        requiresBackwardsReason: outcome.requiresBackwardsReason ?? false,
      });
    }

    await context.database
      .update(engagementTable)
      .set({
        state: parsed.data.to,
        updatedAt: new Date(),
        ...(parsed.data.advanceGateOverrideReason
          ? {
              advanceGateOverride: {
                by: actorIdOf(request),
                reason: parsed.data.advanceGateOverrideReason,
                at: new Date().toISOString(),
              },
            }
          : {}),
      })
      .where(eq(engagementTable.id, id));

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'engagement.stateChanged',
      subjectType: 'engagement',
      subjectId: id,
      metadata: {
        from: record.state,
        to: parsed.data.to,
        reason: parsed.data.reason ?? null,
        advanceGateOverrideReason: parsed.data.advanceGateOverrideReason ?? null,
      },
      ...requestContext(request),
    });

    return reply.send({ ok: true, state: parsed.data.to });
  });

  /**
   * The pre-flight checklist, which gates `advancePaid → readyToRun`.
   *
   * The required ids come from the catalogue rather than from the request, so the gate cannot be
   * satisfied by inventing a key. Unknown ids are refused rather than ignored: a typo that silently
   * does nothing is how a checklist becomes decoration.
   */
  app.put('/engagements/:id/pre-flight-checklist', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z.record(z.string(), z.boolean()).safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const unknown = unknownPreFlightItems(parsed.data);
    if (unknown.length > 0) {
      return reply.code(400).send({ error: 'unknown checklist items', unknown });
    }

    await context.database
      .update(engagementTable)
      .set({ preFlightChecklist: parsed.data, updatedAt: new Date() })
      .where(eq(engagementTable.id, id));

    const outstanding = missingPreFlightItems(parsed.data);

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'engagement.preFlightChecklistUpdated',
      subjectType: 'engagement',
      subjectId: id,
      metadata: { confirmed: Object.keys(parsed.data).filter((key) => parsed.data[key]), outstanding },
      ...requestContext(request),
    });

    return reply.send({ ok: true, items: PRE_FLIGHT_CHECKLIST, outstanding });
  });

  app.get('/engagements/:id/pre-flight-checklist', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const rows = await context.database
      .select({ checklist: engagementTable.preFlightChecklist })
      .from(engagementTable)
      .where(eq(engagementTable.id, id))
      .limit(1);
    if (!rows[0]) return reply.code(404).send({ error: 'not found' });
    const confirmations = rows[0].checklist as Record<string, boolean>;
    return reply.send({
      items: PRE_FLIGHT_CHECKLIST,
      confirmations,
      outstanding: missingPreFlightItems(confirmations),
    });
  });

  /**
   * Recording a payment.
   *
   * Both gates that read these dates — the advance before a run, the balance before release — had
   * no way to be satisfied except the seed, so an engagement created through the API could not
   * reach `readyToRun` and its report could not be released. The amount and reference are recorded
   * because "who said this was paid, and against which invoice" is the question asked later.
   */
  app.post('/engagements/:id/payment', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({
        kind: z.enum(['advance', 'final']),
        reference: z.string().min(1).max(120),
        amount: z.number().int().nonnegative().optional(),
        receivedAt: z.coerce.date().default(() => new Date()),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const rows = await context.database
      .select({ id: engagementTable.id })
      .from(engagementTable)
      .where(eq(engagementTable.id, id))
      .limit(1);
    if (!rows[0]) return reply.code(404).send({ error: 'not found' });

    await context.database
      .update(engagementTable)
      .set({
        ...(parsed.data.kind === 'advance'
          ? { advancePaidAt: parsed.data.receivedAt }
          : { finalPaidAt: parsed.data.receivedAt }),
        updatedAt: new Date(),
      })
      .where(eq(engagementTable.id, id));

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'engagement.paymentRecorded',
      subjectType: 'engagement',
      subjectId: id,
      metadata: {
        kind: parsed.data.kind,
        reference: parsed.data.reference,
        amount: parsed.data.amount ?? null,
        receivedAt: parsed.data.receivedAt.toISOString(),
      },
      ...requestContext(request),
    });

    return reply.send({ ok: true, kind: parsed.data.kind, receivedAt: parsed.data.receivedAt });
  });

  /** A one-time link the client uses to submit credentials without them travelling through email. */
  app.post('/engagements/:id/credential-link', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const token = newSessionToken();
    const expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000);

    await context.database.insert(credentialIntakeLink).values({
      engagementId: id,
      tokenHash: hashToken(token),
      expiresAt,
      createdBy: actorIdOf(request),
    });

    // Returned once, here. The hash is what is stored, so this link cannot be recovered later.
    return reply.send({
      url: `${context.config.PORTAL_ORIGIN}/credentials/${token}`,
      expiresAt,
    });
  });

  app.post('/engagements/:id/acknowledge', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({
        kind: z.enum(['thirdPartyInfrastructure', 'cloudTestingPolicy', 'productionTesting']),
        note: z.string().max(1000).default(''),
        provider: z.enum(['aws', 'azure', 'gcp']).optional(),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const acknowledgedText =
      parsed.data.kind === 'cloudTestingPolicy'
        ? JSON.stringify(
            CLOUD_TESTING_POLICIES.find((policy) => policy.provider === (parsed.data.provider ?? 'aws')),
          )
        : parsed.data.kind === 'thirdPartyInfrastructure'
          ? "The client's authorisation may not cover shared or third-party infrastructure that the in-scope names resolve to. The tester has confirmed that it does."
          : 'Testing will run against a production environment. Backups are confirmed and an emergency contact is reachable throughout the window.';

    await context.database.insert(acknowledgement).values({
      engagementId: id,
      kind: parsed.data.kind,
      acknowledgedText,
      acknowledgedBy: actorIdOf(request),
      note: parsed.data.note,
    });

    if (parsed.data.kind === 'thirdPartyInfrastructure') {
      await context.database
        .update(engagementTable)
        .set({ thirdPartyInfrastructureAcknowledgedAt: new Date() })
        .where(eq(engagementTable.id, id));
    }
    if (parsed.data.kind === 'cloudTestingPolicy') {
      await context.database
        .update(engagementTable)
        .set({ cloudTestingPolicyAcknowledgedAt: new Date() })
        .where(eq(engagementTable.id, id));
    }

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'acknowledgement.recorded',
      subjectType: 'engagement',
      subjectId: id,
      metadata: { kind: parsed.data.kind, note: parsed.data.note },
      ...requestContext(request),
    });

    return reply.send({ ok: true });
  });

  /**
   * Queue a module. `dryRun` performs every check and sends nothing, and is the recommended first
   * action on any new engagement.
   */
  app.post('/engagements/:id/runs', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({
        modules: z.array(z.enum(MODULE_VALUES)).min(1),
        dryRun: z.boolean().default(true),
        targets: z.array(z.string()).optional(),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const panicStopActive = await context.panicStop.isActive(id);
    const runContext = await loadRunContext(context.database, id, panicStopActive);

    if (panicStopActive) {
      return reply.code(409).send({ error: 'a panic stop is in force for this engagement' });
    }

    const targets = parsed.data.targets ?? runContext.targets;
    if (targets.length === 0) {
      return reply.code(400).send({ error: 'the engagement has no network targets in scope' });
    }

    const queued: unknown[] = [];
    for (const module of parsed.data.modules) {
      const runs = await createRunsForModule(context.database, {
        engagementId: id,
        module,
        targets,
        policy: runContext.policy,
        dryRun: parsed.data.dryRun,
      });

      for (const run of runs) {
        await queues.scan.add('scan', {
          engagementId: id,
          scanRunId: run.scanRunId,
          module: run.module,
          toolId: run.toolId,
          targets: run.targets,
          dryRun: parsed.data.dryRun,
          requestedBy: actorIdOf(request),
        });
        queued.push(run);
      }
    }

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'scanRun.requested',
      subjectType: 'engagement',
      subjectId: id,
      metadata: { modules: parsed.data.modules, dryRun: parsed.data.dryRun, queued: queued.length },
      ...requestContext(request),
    });

    return reply.code(202).send({
      queued,
      dryRun: parsed.data.dryRun,
      policyWarnings: runContext.policyWarnings,
    });
  });

  app.post('/engagements/:id/panic-stop', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({
        scope: z.enum(['platform', 'engagement']).default('engagement'),
        reason: z.string().min(3).max(500),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'a stop needs a reason' });

    const result = await engagePanicStop(
      {
        scope: parsed.data.scope,
        engagementId: parsed.data.scope === 'platform' ? null : id,
        pressedBy: actorIdOf(request),
        reason: parsed.data.reason,
      },
      {
        store: context.panicStop,
        auditLog: context.auditLog,
        killRunningContainers: (engagementId) =>
          context.containerRunner.killAllRunContainers(engagementId),
      },
    );

    // Drain the queue too: a stop that kills running containers but lets the next queued job start
    // is not a stop. If the queue cannot be reached, the stop still stands — every worker checks
    // the flag before it starts — so say so rather than failing the request.
    let queuePaused = true;
    let queuePauseError: string | undefined;
    try {
      await queues.scan.pause();
    } catch (error) {
      queuePaused = false;
      queuePauseError = error instanceof Error ? error.message : 'the queue could not be paused';
    }

    return reply.send({ ...result, queuePaused, ...(queuePauseError === undefined ? {} : { queuePauseError }) });
  });

  app.delete('/engagements/:id/panic-stop', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({
        scope: z.enum(['platform', 'engagement']).default('engagement'),
        reason: z.string().min(3).max(500),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'clearing a stop needs a reason' });

    await clearPanicStop(
      {
        scope: parsed.data.scope,
        engagementId: parsed.data.scope === 'platform' ? null : id,
        clearedBy: actorIdOf(request),
        reason: parsed.data.reason,
      },
      { store: context.panicStop, auditLog: context.auditLog },
    );

    await queues.scan.resume();
    return reply.send({ ok: true });
  });

  app.put('/engagements/:id/policy', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z.object({ yaml: z.string().max(60_000) }).safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    // Validate before storing, so an unparseable policy is a form error rather than a run failure.
    try {
      const { warnings } = resolvePolicy([{ name: 'engagement', yamlSource: parsed.data.yaml }]);
      await context.database
        .update(engagementTable)
        .set({ policyYaml: parsed.data.yaml, updatedAt: new Date() })
        .where(eq(engagementTable.id, id));

      await context.auditLog.record({
        actorId: actorIdOf(request),
        actorKind: 'staff',
        action: 'policy.changed',
        subjectType: 'engagement',
        subjectId: id,
        metadata: { bytes: parsed.data.yaml.length },
        ...requestContext(request),
      });

      return reply.send({ ok: true, warnings });
    } catch (error) {
      return reply
        .code(400)
        .send({ error: error instanceof Error ? error.message : 'policy is not valid' });
    }
  });

  app.get('/profiles', { preHandler: guard }, async (unusedRequest, reply) => {
    const profiles = await Promise.all(
      PROFILE_IDS.map(async (id) => ({ id, yaml: await loadProfileYaml(id) })),
    );
    return reply.send({ profiles });
  });

  app.get('/cloud-policies', { preHandler: guard }, (unusedRequest, reply) =>
    reply.send({ policies: CLOUD_TESTING_POLICIES }),
  );
}
