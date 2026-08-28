import { randomBytes, createHash } from 'node:crypto';
import { and, desc, eq, isNull } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { ConsoleContext } from '../context.ts';
import {
  client as clientTable,
  clientInvitation,
  clientUser,
  engagement as engagementTable,
  retainerSchedule,
} from '../db/schema.ts';
import { actorIdOf, requestContext, requireSession } from './session-guard.ts';

/**
 * Clients, the people who work for them, and retainers.
 *
 * Two things here are worth reading carefully:
 *
 *   1. An invitation token is generated once, returned once, and stored only as a hash. There is no
 *      endpoint that reads it back. If it is lost, issue another — that is cheaper than a table of
 *      live credentials waiting to be read by whoever gets database access.
 *   2. Creating a retainer schedule schedules nothing by itself. The retainer worker creates a
 *      draft engagement at the due date; a person still has to check the authorisation is current
 *      and start it. A recurring test that starts itself is a recurring unauthorised test the first
 *      time an authorisation lapses.
 */

const contactSchema = z.object({
  name: z.string().min(1).max(200),
  email: z.string().email().max(320),
  role: z.string().max(120).default(''),
  phone: z.string().max(40).default(''),
  isEmergencyContact: z.boolean().default(false),
});

const clientBodySchema = z.object({
  name: z.string().min(1).max(200),
  legalName: z.string().min(1).max(300),
  country: z.string().length(2).default('IN'),
  contacts: z.array(contactSchema).default([]),
  billingDetails: z
    .object({
      gstin: z.string().max(20).default(''),
      address: z.string().max(600).default(''),
      currency: z.enum(['INR', 'USD', 'EUR', 'GBP', 'AED', 'SGD']).default('INR'),
      paymentTermsDays: z.number().int().min(0).max(120).default(15),
    })
    .prefault({}),
  policyYaml: z.string().max(40_000).default(''),
  notes: z.string().max(20_000).default(''),
});

const INVITATION_TTL_DAYS = 7;

export function registerClientRoutes(app: FastifyInstance, context: ConsoleContext): void {
  const guard = requireSession({ database: context.database, expect: 'staff' });

  /* Clients ------------------------------------------------------------------------------------ */

  app.get('/clients', { preHandler: guard }, async (unusedRequest, reply) => {
    const clients = await context.database
      .select()
      .from(clientTable)
      .orderBy(desc(clientTable.createdAt));

    const engagements = await context.database
      .select({
        id: engagementTable.id,
        clientId: engagementTable.clientId,
        reference: engagementTable.reference,
        title: engagementTable.title,
        state: engagementTable.state,
      })
      .from(engagementTable);

    return reply.send({
      clients: clients.map((record) => ({
        ...record,
        engagements: engagements.filter((item) => item.clientId === record.id),
      })),
    });
  });

  app.post('/clients', { preHandler: guard }, async (request, reply) => {
    const parsed = clientBodySchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const [created] = await context.database.insert(clientTable).values(parsed.data).returning();

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'client.created',
      subjectType: 'client',
      subjectId: created?.id ?? '',
      metadata: { name: parsed.data.name },
      ...requestContext(request),
    });

    return reply.code(201).send({ client: created });
  });

  app.get('/clients/:id', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };

    const rows = await context.database
      .select()
      .from(clientTable)
      .where(eq(clientTable.id, id))
      .limit(1);
    const record = rows[0];
    if (!record) return reply.code(404).send({ error: 'not found' });

    const [engagements, users, invitations, retainers] = await Promise.all([
      context.database
        .select()
        .from(engagementTable)
        .where(eq(engagementTable.clientId, id))
        .orderBy(desc(engagementTable.createdAt)),
      context.database
        .select({
          id: clientUser.id,
          email: clientUser.email,
          name: clientUser.name,
          role: clientUser.role,
          activatedAt: clientUser.activatedAt,
          deactivatedAt: clientUser.deactivatedAt,
          lastLoginAt: clientUser.lastLoginAt,
          totpEnrolledAt: clientUser.totpEnrolledAt,
        })
        .from(clientUser)
        .where(eq(clientUser.clientId, id)),
      context.database
        .select({
          id: clientInvitation.id,
          email: clientInvitation.email,
          role: clientInvitation.role,
          expiresAt: clientInvitation.expiresAt,
          acceptedAt: clientInvitation.acceptedAt,
          createdAt: clientInvitation.createdAt,
        })
        .from(clientInvitation)
        .where(eq(clientInvitation.clientId, id))
        .orderBy(desc(clientInvitation.createdAt)),
      context.database
        .select()
        .from(retainerSchedule)
        .where(eq(retainerSchedule.clientId, id)),
    ]);

    return reply.send({ client: record, engagements, users, invitations, retainers });
  });

  app.put('/clients/:id', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = clientBodySchema.partial().safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const [updated] = await context.database
      .update(clientTable)
      .set({ ...parsed.data, updatedAt: new Date() })
      .where(eq(clientTable.id, id))
      .returning();
    if (!updated) return reply.code(404).send({ error: 'not found' });

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'client.updated',
      subjectType: 'client',
      subjectId: id,
      metadata: { fields: Object.keys(parsed.data) },
      ...requestContext(request),
    });

    return reply.send({ client: updated });
  });

  app.post('/clients/:id/dpa', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const [updated] = await context.database
      .update(clientTable)
      .set({ dataProcessingAgreementSignedAt: new Date(), updatedAt: new Date() })
      .where(eq(clientTable.id, id))
      .returning({ id: clientTable.id, signedAt: clientTable.dataProcessingAgreementSignedAt });
    if (!updated) return reply.code(404).send({ error: 'not found' });

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'client.dpaRecorded',
      subjectType: 'client',
      subjectId: id,
      ...requestContext(request),
    });

    return reply.send({ ok: true, signedAt: updated.signedAt });
  });

  /* Portal invitations -------------------------------------------------------------------------- */

  app.post('/clients/:id/invitations', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({
        email: z.string().email().max(320),
        role: z.enum(['clientOwner', 'clientMember', 'clientViewer']).default('clientMember'),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const exists = await context.database
      .select({ id: clientTable.id })
      .from(clientTable)
      .where(eq(clientTable.id, id))
      .limit(1);
    if (!exists[0]) return reply.code(404).send({ error: 'not found' });

    const alreadyInvited = await context.database
      .select({ id: clientInvitation.id })
      .from(clientInvitation)
      .where(
        and(
          eq(clientInvitation.clientId, id),
          eq(clientInvitation.email, parsed.data.email.toLowerCase()),
          isNull(clientInvitation.acceptedAt),
        ),
      )
      .limit(1);
    if (alreadyInvited[0]) {
      return reply
        .code(409)
        .send({ error: 'an unaccepted invitation for that address already exists' });
    }

    // 32 bytes from the CSPRNG, shown once. Only the hash is stored: an invitation table that can
    // be read back is a table of live portal credentials.
    const token = randomBytes(32).toString('base64url');
    const tokenHash = createHash('sha256').update(token).digest('hex');
    const expiresAt = new Date(Date.now() + INVITATION_TTL_DAYS * 24 * 60 * 60 * 1000);

    const [created] = await context.database
      .insert(clientInvitation)
      .values({
        clientId: id,
        email: parsed.data.email.toLowerCase(),
        role: parsed.data.role,
        tokenHash,
        expiresAt,
        invitedBy: actorIdOf(request),
      })
      .returning({ id: clientInvitation.id, expiresAt: clientInvitation.expiresAt });

    // No account row is created here. The portal creates it when the invitation is accepted, with
    // the password and the enrolled authenticator in the same step — a half-made account with no
    // credential is an account somebody will eventually find a way to sign in to.

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'client.invitationIssued',
      subjectType: 'client',
      subjectId: id,
      // The address is recorded; the token is not, here or anywhere else.
      metadata: { email: parsed.data.email.toLowerCase(), role: parsed.data.role },
      ...requestContext(request),
    });

    return reply.code(201).send({
      invitation: created,
      // Returned exactly once, for a person to send through a channel they choose. The platform
      // does not send it: nothing here reaches a client without a human in between.
      token,
      acceptUrl: `${context.config.PORTAL_ORIGIN}/invitation/${token}`,
      note: 'This link is shown once and expires in seven days. Send it yourself; nothing has been emailed.',
    });
  });

  app.delete('/clients/:id/invitations/:invitationId', { preHandler: guard }, async (request, reply) => {
    const { id, invitationId } = request.params as { id: string; invitationId: string };

    const deleted = await context.database
      .delete(clientInvitation)
      .where(
        and(
          eq(clientInvitation.id, invitationId),
          eq(clientInvitation.clientId, id),
          isNull(clientInvitation.acceptedAt),
        ),
      )
      .returning({ id: clientInvitation.id });
    if (deleted.length === 0) return reply.code(404).send({ error: 'not found' });

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'client.invitationRevoked',
      subjectType: 'client',
      subjectId: id,
      metadata: { invitationId },
      ...requestContext(request),
    });

    return reply.send({ ok: true });
  });

  /* Retainers ----------------------------------------------------------------------------------- */

  app.get('/retainers', { preHandler: guard }, async (unusedRequest, reply) => {
    const schedules = await context.database
      .select({
        id: retainerSchedule.id,
        clientId: retainerSchedule.clientId,
        clientName: clientTable.name,
        cadence: retainerSchedule.cadence,
        modules: retainerSchedule.modules,
        nextRunAt: retainerSchedule.nextRunAt,
        lastRunAt: retainerSchedule.lastRunAt,
        active: retainerSchedule.active,
      })
      .from(retainerSchedule)
      .innerJoin(clientTable, eq(clientTable.id, retainerSchedule.clientId))
      .orderBy(retainerSchedule.nextRunAt);

    return reply.send({ retainers: schedules });
  });

  app.post('/clients/:id/retainers', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({
        cadence: z.enum(['monthly', 'quarterly']).default('monthly'),
        modules: z.array(z.string()).min(1),
        startsAt: z.coerce.date(),
        windowRule: z
          .object({
            daysOfWeek: z.array(z.number().int().min(0).max(6)).default([]),
            startMinute: z.number().int().min(0).max(1439).default(0),
            endMinute: z.number().int().min(0).max(1439).default(1439),
          })
          .prefault({}),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const [created] = await context.database
      .insert(retainerSchedule)
      .values({
        clientId: id,
        cadence: parsed.data.cadence,
        modules: parsed.data.modules,
        windowRule: parsed.data.windowRule,
        nextRunAt: parsed.data.startsAt,
      })
      .returning();

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'retainer.created',
      subjectType: 'client',
      subjectId: id,
      metadata: { cadence: parsed.data.cadence, modules: parsed.data.modules },
      ...requestContext(request),
    });

    return reply.code(201).send({
      retainer: created,
      note: 'At the due date this creates a draft engagement. Nothing runs until someone confirms the authorisation is current and starts it.',
    });
  });

  app.post('/retainers/:retainerId/pause', { preHandler: guard }, async (request, reply) => {
    const { retainerId } = request.params as { retainerId: string };
    const parsed = z.object({ active: z.boolean() }).safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const [updated] = await context.database
      .update(retainerSchedule)
      .set({ active: parsed.data.active })
      .where(eq(retainerSchedule.id, retainerId))
      .returning({ id: retainerSchedule.id, active: retainerSchedule.active });
    if (!updated) return reply.code(404).send({ error: 'not found' });

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: parsed.data.active ? 'retainer.resumed' : 'retainer.paused',
      subjectType: 'retainer',
      subjectId: retainerId,
      ...requestContext(request),
    });

    return reply.send({ retainer: updated });
  });

  /* Client users -------------------------------------------------------------------------------- */

  app.post('/clients/:id/users/:userId/deactivate', { preHandler: guard }, async (request, reply) => {
    const { id, userId } = request.params as { id: string; userId: string };

    const [updated] = await context.database
      .update(clientUser)
      .set({ deactivatedAt: new Date() })
      .where(and(eq(clientUser.id, userId), eq(clientUser.clientId, id)))
      .returning({ id: clientUser.id, email: clientUser.email });
    if (!updated) return reply.code(404).send({ error: 'not found' });

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'staff',
      action: 'client.userDeactivated',
      subjectType: 'clientUser',
      subjectId: userId,
      metadata: { clientId: id },
      ...requestContext(request),
    });

    return reply.send({ ok: true });
  });

  /* A single view of everything owed to a client, for the weekly review. --------------------------- */

  app.get('/clients/:id/summary', { preHandler: guard }, async (request, reply) => {
    const { id } = request.params as { id: string };

    const engagements = await context.database
      .select({
        id: engagementTable.id,
        reference: engagementTable.reference,
        state: engagementTable.state,
        endsAt: engagementTable.endsAt,
        invoiceState: engagementTable.invoiceState,
      })
      .from(engagementTable)
      .where(eq(engagementTable.clientId, id));

    const open = engagements.filter(
      (item) => !['closed', 'cancelled', 'archived'].includes(item.state),
    );
    const unpaid = engagements.filter(
      (item) => item.invoiceState === 'issued' || item.invoiceState === 'overdue',
    );

    return reply.send({
      openEngagements: open,
      unpaidInvoices: unpaid.map((item) => ({ reference: item.reference, state: item.invoiceState })),
    });
  });
}
