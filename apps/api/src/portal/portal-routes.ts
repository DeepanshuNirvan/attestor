import { and, asc, desc, eq, inArray, isNull, sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { CLIENT_FACING_STATUS } from '@attestor/core';
import { renderPdf, watermarkFor, legalBlock } from '@attestor/report';
import type { EngagementState } from '@attestor/shared';
import type { PortalContext } from '../context.ts';
import {
  clientEngagementAccess,
  clientInvitation,
  clientUser,
  engagement as engagementTable,
  evidence as evidenceTable,
  finding as findingTable,
  findingComment,
  questionnaireAnswer,
  report as reportTable,
  reportDownload,
  retestRequest,
  scanRun as scanRunTable,
} from '../db/schema.ts';
import {
  beginTotpEnrolment,
  createSession,
  hashPassword,
  hashToken,
  LoginThrottle,
  revokeAllSessionsFor,
  revokeSession,
  verifyPassword,
  verifyTotp,
} from '../services/auth.ts';
import {
  SESSION_COOKIE,
  actorIdOf,
  clientIdOf,
  cookieOptions,
  requestContext,
  requireSession,
} from '../routes/session-guard.ts';

/**
 * The client portal.
 *
 * This is the only publicly reachable surface of the platform, and it holds records of other
 * companies' unfixed vulnerabilities. Three rules are absolute here:
 *
 *   1. Scoping comes from the session. Every query filters by the client id derived from the
 *      session cookie, and no handler reads a client id from a parameter. This is the exact bug
 *      class the firm sells testing for.
 *   2. MFA is mandatory. There is no route that works for a client user who has not enrolled.
 *   3. Nothing here can start a tool, read the credential vault, or edit a policy. A retest request
 *      creates a record; a human starts the job.
 */

const throttle = new LoginThrottle();
const GENERIC_FAILURE = { error: 'those details did not work' };

/** The terms version a client must have accepted. Bumping it forces re-acceptance. */
const PORTAL_TERMS_VERSION = '1.0.0-draft';

/**
 * Authenticator secrets are sealed under the portal's own key, so a stolen database or backup does
 * not hand an attacker every client's second factor alongside their password hashes.
 */
const TOTP_CONTEXT = 'portal-totp';

async function openTotpSecret(context: PortalContext, stored: string): Promise<string | null> {
  try {
    return await context.totpVault.open(
      TOTP_CONTEXT,
      JSON.parse(stored) as { sealedValue: string; keySalt: string; nonce: string },
    );
  } catch {
    // Unparseable or undecryptable. Treated as a failed second factor rather than as an error, so
    // the response says nothing about which of the two it was.
    return null;
  }
}

export function registerPortalRoutes(app: FastifyInstance, context: PortalContext): void {
  const secure = context.config.NODE_ENV === 'production';
  const guard = requireSession({ database: context.database, expect: 'client' });
  const ownerGuard = requireSession({
    database: context.database,
    expect: 'client',
    allowRoles: ['clientOwner'],
  });

  /* Invitation and sign-in ------------------------------------------------------------------ */

  app.post('/invitations/accept', async (request, reply) => {
    const parsed = z
      .object({
        token: z.string().min(20).max(200),
        password: z.string().min(12).max(400),
        name: z.string().min(1).max(120),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid details' });

    const invitations = await context.database
      .select()
      .from(clientInvitation)
      .where(
        and(
          eq(clientInvitation.tokenHash, hashToken(parsed.data.token)),
          isNull(clientInvitation.acceptedAt),
        ),
      )
      .limit(1);
    const invitation = invitations[0];

    if (!invitation || invitation.expiresAt < new Date()) {
      return reply.code(400).send({ error: 'that invitation is not valid' });
    }

    const enrolment = beginTotpEnrolment(invitation.email);

    // The account is created without `activatedAt`. It cannot sign in until the authenticator is
    // confirmed, so MFA is not something a client can decline.
    const [created] = await context.database
      .insert(clientUser)
      .values({
        clientId: invitation.clientId,
        email: invitation.email.toLowerCase(),
        name: parsed.data.name,
        passwordHash: await hashPassword(parsed.data.password),
        role: invitation.role,
        totpSecretSealed: JSON.stringify(await context.totpVault.seal(TOTP_CONTEXT, enrolment.secretBase32)),
        invitedBy: invitation.invitedBy,
        invitedAt: invitation.createdAt,
      })
      .onConflictDoNothing()
      .returning({ id: clientUser.id });

    await context.database
      .update(clientInvitation)
      .set({ acceptedAt: new Date() })
      .where(eq(clientInvitation.id, invitation.id));

    await context.auditLog.record({
      actorId: created?.id ?? invitation.email,
      actorKind: 'client',
      action: 'client.userInvited',
      subjectType: 'clientUser',
      subjectId: created?.id ?? invitation.email,
      ...requestContext(request),
    });

    return reply.send({ otpauthUrl: enrolment.otpauthUrl, mustConfirm: true });
  });

  app.post('/invitations/confirm-mfa', async (request, reply) => {
    const parsed = z
      .object({ email: z.string().email(), code: z.string().min(6).max(10) })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send(GENERIC_FAILURE);

    const users = await context.database
      .select()
      .from(clientUser)
      .where(eq(clientUser.email, parsed.data.email.toLowerCase()))
      .limit(1);
    const user = users[0];
    if (!user?.totpSecretSealed || user.totpEnrolledAt) return reply.code(409).send(GENERIC_FAILURE);

    const enrolling = await openTotpSecret(context, user.totpSecretSealed);
    if (!enrolling || !verifyTotp(enrolling, parsed.data.code)) {
      return reply.code(401).send(GENERIC_FAILURE);
    }

    await context.database
      .update(clientUser)
      .set({ totpEnrolledAt: new Date(), activatedAt: new Date() })
      .where(eq(clientUser.id, user.id));

    await context.auditLog.record({
      actorId: user.id,
      actorKind: 'client',
      action: 'client.userActivated',
      subjectType: 'clientUser',
      subjectId: user.id,
      ...requestContext(request),
    });

    return reply.send({ ok: true });
  });

  app.post('/auth/login', async (request, reply) => {
    const parsed = z
      .object({ email: z.string().email().max(200), password: z.string().min(1).max(400) })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send(GENERIC_FAILURE);

    const email = parsed.data.email.toLowerCase();
    const key = `${request.ip}|${email}`;
    const waitMs = throttle.check(key);
    if (waitMs > 0) {
      return reply
        .code(429)
        .header('Retry-After', String(Math.ceil(waitMs / 1000)))
        .send({ error: 'too many attempts, try again shortly' });
    }

    const users = await context.database
      .select()
      .from(clientUser)
      .where(eq(clientUser.email, email))
      .limit(1);
    const user = users[0];

    const referenceHash =
      user?.passwordHash ??
      '$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const passwordOk = await verifyPassword(referenceHash, parsed.data.password);

    // The same response and the same work whether the account exists, is deactivated, or the
    // password is wrong. A portal that enumerates its users is a portal that lists a security
    // firm's clients.
    if (!user || user.deactivatedAt || !user.totpEnrolledAt || !passwordOk) {
      throttle.recordFailure(key);
      return reply.code(401).send(GENERIC_FAILURE);
    }

    const { token, expiresAt } = await createSession(
      context.database,
      { kind: 'client', clientUserId: user.id, clientId: user.clientId, role: user.role },
      { ...requestContext(request), mfaSatisfied: false },
    );
    throttle.recordSuccess(key);

    return reply
      .setCookie(SESSION_COOKIE, token, { ...cookieOptions(secure), expires: expiresAt })
      .send({ mfaRequired: true });
  });

  app.post(
    '/auth/mfa',
    { preHandler: requireSession({ database: context.database, expect: 'client', allowWithoutMfa: true }) },
    async (request, reply) => {
      const parsed = z.object({ code: z.string().min(6).max(10) }).safeParse(request.body);
      const subject = request.subject;
      if (!parsed.success || subject?.kind !== 'client') return reply.code(400).send(GENERIC_FAILURE);

      const key = `mfa|${request.ip}|${subject.clientUserId}`;
      if (throttle.check(key) > 0) {
        return reply.code(429).send({ error: 'too many attempts, try again shortly' });
      }

      const users = await context.database
        .select()
        .from(clientUser)
        .where(eq(clientUser.id, subject.clientUserId))
        .limit(1);
      const user = users[0];
      if (!user?.totpSecretSealed) {
        throttle.recordFailure(key);
        return reply.code(401).send(GENERIC_FAILURE);
      }
      const secret = await openTotpSecret(context, user.totpSecretSealed);
      if (!secret || !verifyTotp(secret, parsed.data.code)) {
        throttle.recordFailure(key);
        return reply.code(401).send(GENERIC_FAILURE);
      }
      throttle.recordSuccess(key);

      await revokeSession(context.database, request.sessionId ?? '');
      const { token, expiresAt } = await createSession(context.database, subject, {
        ...requestContext(request),
        mfaSatisfied: true,
      });

      await context.database
        .update(clientUser)
        .set({ lastLoginAt: new Date() })
        .where(eq(clientUser.id, subject.clientUserId));

      await context.auditLog.record({
        actorId: subject.clientUserId,
        actorKind: 'client',
        action: 'client.loggedIn',
        subjectType: 'clientUser',
        subjectId: subject.clientUserId,
        ...requestContext(request),
      });

      return reply
        .setCookie(SESSION_COOKIE, token, { ...cookieOptions(secure), expires: expiresAt })
        .send({
          ok: true,
          role: user.role,
          termsAcceptanceRequired: user.portalTermsVersion !== PORTAL_TERMS_VERSION,
        });
    },
  );

  app.post('/auth/logout', { preHandler: guard }, async (request, reply) => {
    await revokeSession(context.database, request.sessionId ?? '');
    return reply.clearCookie(SESSION_COOKIE, { path: '/' }).send({ ok: true });
  });

  app.post('/auth/sign-out-everywhere', { preHandler: guard }, async (request, reply) => {
    const subject = request.subject;
    if (subject?.kind !== 'client') return reply.code(403).send(GENERIC_FAILURE);
    const revoked = await revokeAllSessionsFor(context.database, {
      clientUserId: subject.clientUserId,
    });
    return reply.clearCookie(SESSION_COOKIE, { path: '/' }).send({ ok: true, revoked });
  });

  app.get('/terms', { preHandler: guard }, (unusedRequest, reply) =>
    reply.send({
      version: PORTAL_TERMS_VERSION,
      text: legalBlock('portal-terms-of-access').text,
    }),
  );

  app.post('/terms/accept', { preHandler: guard }, async (request, reply) => {
    const subject = request.subject;
    if (subject?.kind !== 'client') return reply.code(403).send(GENERIC_FAILURE);
    await context.database
      .update(clientUser)
      .set({ portalTermsVersion: PORTAL_TERMS_VERSION, portalTermsAcceptedAt: new Date() })
      .where(eq(clientUser.id, subject.clientUserId));
    return reply.send({ ok: true });
  });

  /* Dashboard and engagements ---------------------------------------------------------------- */

  app.get('/dashboard', { preHandler: guard }, async (request, reply) => {
    const clientId = clientIdOf(request);

    const engagements = await context.database
      .select()
      .from(engagementTable)
      .where(eq(engagementTable.clientId, clientId))
      .orderBy(desc(engagementTable.createdAt));

    const engagementIds = engagements.map((item) => item.id);

    const counts =
      engagementIds.length > 0
        ? await context.database
            .select({
              severity: findingTable.severity,
              status: findingTable.status,
              count: sql<number>`count(*)`,
            })
            .from(findingTable)
            .where(
              and(
                inArray(findingTable.engagementId, engagementIds),
                inArray(findingTable.status, ['open', 'fixed', 'riskAccepted']),
              ),
            )
            .groupBy(findingTable.severity, findingTable.status)
        : [];

    const oldestCritical =
      engagementIds.length > 0
        ? await context.database
            .select({
              id: findingTable.id,
              reference: findingTable.reference,
              title: findingTable.title,
              firstSeenAt: findingTable.firstSeenAt,
            })
            .from(findingTable)
            .where(
              and(
                inArray(findingTable.engagementId, engagementIds),
                eq(findingTable.severity, 'critical'),
                eq(findingTable.status, 'open'),
              ),
            )
            .orderBy(asc(findingTable.firstSeenAt))
            .limit(1)
        : [];

    const outstandingActions: string[] = [];
    for (const item of engagements) {
      if (item.state === 'retestPending') {
        outstandingActions.push(
          `${item.reference}: request your retest once the fixes are deployed. One is included within 30 days of release.`,
        );
      }
    }

    return reply.send({
      // Internal state names never reach a client; they see plain language.
      engagements: engagements.map((item) => ({
        id: item.id,
        reference: item.reference,
        title: item.title,
        status: CLIENT_FACING_STATUS[item.state as EngagementState],
        startsAt: item.startsAt,
        endsAt: item.endsAt,
      })),
      counts,
      oldestOpenCritical: oldestCritical[0] ?? null,
      outstandingActions,
    });
  });

  app.get('/engagements/:id', { preHandler: guard }, async (request, reply) => {
    const clientId = clientIdOf(request);
    const { id } = request.params as { id: string };

    const rows = await context.database
      .select()
      .from(engagementTable)
      // The client id comes from the session and is part of the WHERE, so a request for another
      // client's engagement is a 404 rather than a permission check that might be forgotten.
      .where(and(eq(engagementTable.id, id), eq(engagementTable.clientId, clientId)))
      .limit(1);
    const record = rows[0];
    if (!record) return reply.code(404).send({ error: 'not found' });

    const runs = await context.database
      .select({
        module: scanRunTable.module,
        toolName: scanRunTable.toolName,
        status: scanRunTable.status,
        startedAt: scanRunTable.startedAt,
        finishedAt: scanRunTable.finishedAt,
      })
      .from(scanRunTable)
      .where(eq(scanRunTable.engagementId, id));

    return reply.send({
      engagement: {
        id: record.id,
        reference: record.reference,
        title: record.title,
        status: CLIENT_FACING_STATUS[record.state as EngagementState],
        startsAt: record.startsAt,
        endsAt: record.endsAt,
        testType: record.testType,
        evidenceRetentionDays: record.evidenceRetentionDays,
      },
      coverageSummary: {
        modulesRun: [...new Set(runs.map((run) => run.module))],
        runs: runs.length,
        completed: runs.filter((run) => run.status === 'completed').length,
      },
    });
  });

  /* Findings ---------------------------------------------------------------------------------- */

  app.get('/findings', { preHandler: guard }, async (request, reply) => {
    const clientId = clientIdOf(request);
    const query = z
      .object({
        engagementId: z.string().uuid().optional(),
        status: z.enum(['open', 'fixed', 'riskAccepted']).optional(),
        severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
      })
      .parse(request.query);

    const conditions = [
      eq(engagementTable.clientId, clientId),
      // Candidates and false positives never reach a client. A finding they can see is one a human
      // confirmed.
      inArray(findingTable.status, ['open', 'fixed', 'riskAccepted']),
    ];
    if (query.engagementId) conditions.push(eq(findingTable.engagementId, query.engagementId));
    if (query.status) conditions.push(eq(findingTable.status, query.status));
    if (query.severity) conditions.push(eq(findingTable.severity, query.severity));

    const rows = await context.database
      .select({
        id: findingTable.id,
        reference: findingTable.reference,
        title: findingTable.title,
        severity: findingTable.severity,
        status: findingTable.status,
        cvssScore: findingTable.cvssScore,
        owaspCategory: findingTable.owaspCategory,
        affectedAssets: findingTable.affectedAssets,
        firstSeenAt: findingTable.firstSeenAt,
        fixedAt: findingTable.fixedAt,
        engagementReference: engagementTable.reference,
      })
      .from(findingTable)
      .innerJoin(engagementTable, eq(engagementTable.id, findingTable.engagementId))
      .where(and(...conditions))
      .orderBy(
        sql`case ${findingTable.severity}
              when 'critical' then 0 when 'high' then 1 when 'medium' then 2
              when 'low' then 3 else 4 end`,
        asc(findingTable.firstSeenAt),
      );

    return reply.send({ findings: rows });
  });

  app.get('/findings/:findingId', { preHandler: guard }, async (request, reply) => {
    const clientId = clientIdOf(request);
    const { findingId } = request.params as { findingId: string };

    const rows = await context.database
      .select({ finding: findingTable, engagementReference: engagementTable.reference })
      .from(findingTable)
      .innerJoin(engagementTable, eq(engagementTable.id, findingTable.engagementId))
      .where(
        and(
          eq(findingTable.id, findingId),
          eq(engagementTable.clientId, clientId),
          inArray(findingTable.status, ['open', 'fixed', 'riskAccepted']),
        ),
      )
      .limit(1);
    const record = rows[0];
    if (!record) return reply.code(404).send({ error: 'not found' });

    const evidenceRows = await context.database
      .select()
      .from(evidenceTable)
      .where(and(eq(evidenceTable.findingId, findingId), isNull(evidenceTable.purgedAt)));

    // Evidence is returned as inert text and as data URIs for images. It is never a URL the browser
    // will render as a document, because an evidence body is attacker-controlled by definition and
    // an XSS here would be an XSS delivered by the security vendor.
    const evidence = await Promise.all(
      evidenceRows.map(async (item) => {
        const body = await context.evidence.read(item.objectKey).catch(() => null);
        if (!body) return { id: item.id, kind: item.kind, sha256: item.sha256, unavailable: true };
        return item.contentType.startsWith('image/')
          ? {
              id: item.id,
              kind: item.kind,
              sha256: item.sha256,
              imageDataUri: `data:${item.contentType};base64,${body.toString('base64')}`,
            }
          : {
              id: item.id,
              kind: item.kind,
              sha256: item.sha256,
              // Plain text. The client renders it into a <pre>; there is no HTML in this payload.
              text: body.toString('utf8').slice(0, 200_000),
            };
      }),
    );

    const comments = await context.database
      .select()
      .from(findingComment)
      .where(eq(findingComment.findingId, findingId))
      .orderBy(asc(findingComment.createdAt));

    for (const item of evidenceRows) {
      await context.auditLog.record({
        actorId: actorIdOf(request),
        actorKind: 'client',
        action: 'evidence.accessed',
        subjectType: 'evidence',
        subjectId: item.id,
        ...requestContext(request),
      });
    }

    return reply.send({
      finding: record.finding,
      engagementReference: record.engagementReference,
      evidence,
      comments,
    });
  });

  app.post('/findings/:findingId/status', { preHandler: guard }, async (request, reply) => {
    const clientId = clientIdOf(request);
    const subject = request.subject;
    if (subject?.kind !== 'client' || subject.role === 'clientViewer') {
      return reply.code(403).send({ error: 'your role is read-only' });
    }

    const { findingId } = request.params as { findingId: string };
    const parsed = z
      .object({
        status: z.enum(['acknowledged', 'inProgress', 'fixed', 'riskAccepted']),
        justification: z.string().max(4_000).optional(),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    // Risk acceptance is the client's own audit record. Without who and why it is worthless to them
    // later, so it is refused rather than stored incomplete.
    if (parsed.data.status === 'riskAccepted' && (parsed.data.justification ?? '').trim().length < 20) {
      return reply.code(400).send({
        error:
          'accepting a risk needs a written justification of at least 20 characters. Your auditor will ask for it.',
      });
    }

    // Confirmed findings only. A candidate is unconfirmed by definition, and letting a client
    // change its status would both leak its existence and corrupt the review queue.
    const owned = await context.database
      .select({ id: findingTable.id })
      .from(findingTable)
      .innerJoin(engagementTable, eq(engagementTable.id, findingTable.engagementId))
      .where(
        and(
          eq(findingTable.id, findingId),
          eq(engagementTable.clientId, clientId),
          inArray(findingTable.status, ['open', 'fixed', 'riskAccepted']),
        ),
      )
      .limit(1);
    if (!owned[0]) return reply.code(404).send({ error: 'not found' });

    const now = new Date();
    const update =
      parsed.data.status === 'riskAccepted'
        ? {
            status: 'riskAccepted' as const,
            riskAcceptedAt: now,
            riskAcceptedBy: actorIdOf(request),
            riskAcceptanceJustification: parsed.data.justification ?? '',
            updatedAt: now,
          }
        : parsed.data.status === 'fixed'
          ? { status: 'fixed' as const, fixedAt: now, updatedAt: now }
          : { updatedAt: now };

    await context.database.update(findingTable).set(update).where(eq(findingTable.id, findingId));

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'client',
      action: parsed.data.status === 'riskAccepted' ? 'client.riskAccepted' : 'finding.statusChanged',
      subjectType: 'finding',
      subjectId: findingId,
      metadata: { status: parsed.data.status, justification: parsed.data.justification ?? null },
      ...requestContext(request),
    });

    return reply.send({ ok: true });
  });

  app.post('/findings/:findingId/comments', { preHandler: guard }, async (request, reply) => {
    const clientId = clientIdOf(request);
    const subject = request.subject;
    if (subject?.kind !== 'client' || subject.role === 'clientViewer') {
      return reply.code(403).send({ error: 'your role is read-only' });
    }

    const { findingId } = request.params as { findingId: string };
    const parsed = z
      .object({ markdown: z.string().min(1).max(10_000), parentId: z.string().uuid().optional() })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    // Same rule as the status route: a client can only comment on a finding they can see.
    const owned = await context.database
      .select({ id: findingTable.id })
      .from(findingTable)
      .innerJoin(engagementTable, eq(engagementTable.id, findingTable.engagementId))
      .where(
        and(
          eq(findingTable.id, findingId),
          eq(engagementTable.clientId, clientId),
          inArray(findingTable.status, ['open', 'fixed', 'riskAccepted']),
        ),
      )
      .limit(1);
    if (!owned[0]) return reply.code(404).send({ error: 'not found' });

    const [created] = await context.database
      .insert(findingComment)
      .values({
        findingId,
        authorKind: 'client',
        clientUserId: subject.clientUserId,
        parentId: parsed.data.parentId ?? null,
        // Stored as written. Sanitising happens at render, in one place, rather than at every
        // write path where it can be forgotten.
        markdown: parsed.data.markdown,
      })
      .returning();

    return reply.code(201).send({ comment: created });
  });

  /* Retest ------------------------------------------------------------------------------------ */

  app.post('/engagements/:id/retest-request', { preHandler: guard }, async (request, reply) => {
    const clientId = clientIdOf(request);
    const subject = request.subject;
    if (subject?.kind !== 'client' || subject.role === 'clientViewer') {
      return reply.code(403).send({ error: 'your role is read-only' });
    }

    const { id } = request.params as { id: string };
    const parsed = z
      .object({ note: z.string().max(2_000).default(''), findingIds: z.array(z.string().uuid()).default([]) })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const rows = await context.database
      .select()
      .from(engagementTable)
      .where(and(eq(engagementTable.id, id), eq(engagementTable.clientId, clientId)))
      .limit(1);
    const record = rows[0];
    if (!record) return reply.code(404).send({ error: 'not found' });

    const releases = await context.database
      .select({ releasedAt: reportTable.releasedAt })
      .from(reportTable)
      .where(and(eq(reportTable.engagementId, id), eq(reportTable.kind, 'assessment')))
      .orderBy(desc(reportTable.releasedAt))
      .limit(1);
    const releasedAt = releases[0]?.releasedAt;

    const freeRetestUntil = releasedAt
      ? new Date(releasedAt.getTime() + 30 * 24 * 60 * 60 * 1000)
      : null;
    const withinFreeWindow = freeRetestUntil !== null && new Date() <= freeRetestUntil;

    const [created] = await context.database
      .insert(retestRequest)
      .values({
        engagementId: id,
        requestedBy: subject.clientUserId,
        findingIds: parsed.data.findingIds,
        note: parsed.data.note,
      })
      .returning();

    await context.auditLog.record({
      actorId: subject.clientUserId,
      actorKind: 'client',
      action: 'client.retestRequested',
      subjectType: 'engagement',
      subjectId: id,
      metadata: { retestRequestId: created?.id, withinFreeWindow },
      ...requestContext(request),
    });

    // A request is a record. Nothing starts here; a human schedules it.
    return reply.code(201).send({
      request: created,
      withinFreeWindow,
      freeRetestUntil,
      note: withinFreeWindow
        ? 'This retest is included at no cost. We will confirm a date.'
        : 'The free retest window has passed, so this will be quoted as a separate engagement before anything runs.',
    });
  });

  app.get('/engagements/:id/retest-eligibility', { preHandler: guard }, async (request, reply) => {
    const clientId = clientIdOf(request);
    const { id } = request.params as { id: string };

    const owned = await context.database
      .select({ id: engagementTable.id })
      .from(engagementTable)
      .where(and(eq(engagementTable.id, id), eq(engagementTable.clientId, clientId)))
      .limit(1);
    if (!owned[0]) return reply.code(404).send({ error: 'not found' });

    const releases = await context.database
      .select({ releasedAt: reportTable.releasedAt })
      .from(reportTable)
      .where(and(eq(reportTable.engagementId, id), eq(reportTable.kind, 'assessment')))
      .orderBy(desc(reportTable.releasedAt))
      .limit(1);
    const releasedAt = releases[0]?.releasedAt ?? null;
    const freeRetestUntil = releasedAt
      ? new Date(releasedAt.getTime() + 30 * 24 * 60 * 60 * 1000)
      : null;

    const openFindings = await context.database
      .select({ id: findingTable.id, reference: findingTable.reference, title: findingTable.title })
      .from(findingTable)
      .where(and(eq(findingTable.engagementId, id), eq(findingTable.status, 'fixed')));

    return reply.send({
      releasedAt,
      freeRetestUntil,
      withinFreeWindow: freeRetestUntil !== null && new Date() <= freeRetestUntil,
      willBeVerified: openFindings,
    });
  });

  /* Documents --------------------------------------------------------------------------------- */

  app.get('/reports', { preHandler: guard }, async (request, reply) => {
    const clientId = clientIdOf(request);

    const rows = await context.database
      .select({
        id: reportTable.id,
        kind: reportTable.kind,
        version: reportTable.version,
        releasedAt: reportTable.releasedAt,
        engagementReference: engagementTable.reference,
        engagementTitle: engagementTable.title,
        renderedHtmlKey: reportTable.renderedHtmlKey,
      })
      .from(reportTable)
      .innerJoin(engagementTable, eq(engagementTable.id, reportTable.engagementId))
      .where(and(eq(engagementTable.clientId, clientId), sql`${reportTable.releasedAt} is not null`))
      .orderBy(desc(reportTable.releasedAt));

    // The object key itself never leaves the server; the portal only needs to know whether there is
    // a readable version, because an attestation letter is a PDF and has nothing to show in a frame.
    return reply.send({
      reports: rows.map(({ renderedHtmlKey, ...rest }) => ({
        ...rest,
        readableInBrowser: renderedHtmlKey !== null,
      })),
    });
  });

  app.get('/reports/:reportId/view', { preHandler: guard }, async (request, reply) => {
    const clientId = clientIdOf(request);
    const { reportId } = request.params as { reportId: string };

    const rows = await context.database
      .select({ report: reportTable })
      .from(reportTable)
      .innerJoin(engagementTable, eq(engagementTable.id, reportTable.engagementId))
      .where(
        and(
          eq(reportTable.id, reportId),
          eq(engagementTable.clientId, clientId),
          sql`${reportTable.releasedAt} is not null`,
        ),
      )
      .limit(1);
    const record = rows[0]?.report;
    if (!record?.renderedHtmlKey) return reply.code(404).send({ error: 'not found' });

    const html = await context.reports.read(record.renderedHtmlKey);

    // Served with a restrictive CSP of its own: the report contains client evidence, and the
    // portal renders it in a sandboxed frame.
    return reply
      .header('Content-Type', 'text/html; charset=utf-8')
      .header(
        'Content-Security-Policy',
        "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; sandbox",
      )
      .header('X-Content-Type-Options', 'nosniff')
      .send(html.toString('utf8'));
  });

  app.get('/reports/:reportId/download', { preHandler: guard }, async (request, reply) => {
    const clientId = clientIdOf(request);
    const subject = request.subject;
    if (subject?.kind !== 'client') return reply.code(403).send(GENERIC_FAILURE);

    if (subject.role === 'clientViewer') {
      return reply
        .code(403)
        .send({ error: 'your role can read reports in the browser but cannot download them' });
    }

    const { reportId } = request.params as { reportId: string };

    const rows = await context.database
      .select({ report: reportTable, clientName: engagementTable.title })
      .from(reportTable)
      .innerJoin(engagementTable, eq(engagementTable.id, reportTable.engagementId))
      .where(
        and(
          eq(reportTable.id, reportId),
          eq(engagementTable.clientId, clientId),
          sql`${reportTable.releasedAt} is not null`,
        ),
      )
      .limit(1);
    const record = rows[0]?.report;
    if (!record?.pdfKey) return reply.code(404).send({ error: 'not found' });

    const users = await context.database
      .select({ name: clientUser.name, email: clientUser.email })
      .from(clientUser)
      .where(eq(clientUser.id, subject.clientUserId))
      .limit(1);

    // Watermarking happens at download time, server-side, so the stored PDF is one document and
    // every copy that leaves carries the identity of whoever took it.
    const watermark = watermarkFor({
      name: users[0]?.name ?? 'Unknown',
      email: users[0]?.email ?? 'unknown',
      organisation: rows[0]?.clientName ?? 'client',
      at: new Date(),
    });

    const html = record.renderedHtmlKey
      ? (await context.reports.read(record.renderedHtmlKey)).toString('utf8')
      : null;
    const pdf = html
      ? await renderPdf(html, { format: 'A4', watermarkText: watermark })
      : await context.reports.read(record.pdfKey);

    await context.database.insert(reportDownload).values({
      reportId,
      clientUserId: subject.clientUserId,
      watermarkText: watermark,
      ...requestContext(request),
    });

    await context.auditLog.record({
      actorId: subject.clientUserId,
      actorKind: 'client',
      action: 'report.downloaded',
      subjectType: 'report',
      subjectId: reportId,
      metadata: { version: record.version, kind: record.kind },
      ...requestContext(request),
    });

    return reply
      .header('Content-Type', 'application/pdf')
      .header('Content-Disposition', `attachment; filename="report-${record.version}.pdf"`)
      .send(pdf);
  });

  /* Questionnaire helper ---------------------------------------------------------------------- */

  app.get('/questionnaire', { preHandler: guard }, async (unusedRequest, reply) => {
    const answers = await context.database
      .select()
      .from(questionnaireAnswer)
      .orderBy(asc(questionnaireAnswer.category), asc(questionnaireAnswer.sortOrder));

    const byCategory = new Map<string, typeof answers>();
    for (const answer of answers) {
      const list = byCategory.get(answer.category) ?? [];
      list.push(answer);
      byCategory.set(answer.category, list);
    }

    return reply.send({
      categories: [...byCategory.entries()].map(([category, items]) => ({ category, items })),
      note: 'These answers describe how we work. Paste them into your buyer questionnaires and edit anything that is specific to your own environment.',
    });
  });

  /* Account ----------------------------------------------------------------------------------- */

  app.get('/account', { preHandler: guard }, async (request, reply) => {
    const subject = request.subject;
    if (subject?.kind !== 'client') return reply.code(403).send(GENERIC_FAILURE);

    const users = await context.database
      .select({
        id: clientUser.id,
        email: clientUser.email,
        name: clientUser.name,
        role: clientUser.role,
        totpEnrolledAt: clientUser.totpEnrolledAt,
        notificationPreferences: clientUser.notificationPreferences,
        portalTermsVersion: clientUser.portalTermsVersion,
      })
      .from(clientUser)
      .where(eq(clientUser.id, subject.clientUserId))
      .limit(1);

    return reply.send({
      account: users[0],
      termsAcceptanceRequired: users[0]?.portalTermsVersion !== PORTAL_TERMS_VERSION,
    });
  });

  app.put('/account/password', { preHandler: guard }, async (request, reply) => {
    const subject = request.subject;
    if (subject?.kind !== 'client') return reply.code(403).send(GENERIC_FAILURE);

    const parsed = z
      .object({ current: z.string().min(1).max(400), next: z.string().min(12).max(400) })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues });

    const users = await context.database
      .select()
      .from(clientUser)
      .where(eq(clientUser.id, subject.clientUserId))
      .limit(1);
    const user = users[0];
    if (!user?.passwordHash || !(await verifyPassword(user.passwordHash, parsed.data.current))) {
      return reply.code(401).send(GENERIC_FAILURE);
    }

    // Password change and session revocation in one transaction: there must be no window where the
    // old session still works after the password has changed.
    await context.database.transaction(async (transaction) => {
      await transaction
        .update(clientUser)
        .set({ passwordHash: await hashPassword(parsed.data.next) })
        .where(eq(clientUser.id, subject.clientUserId));
      await revokeAllSessionsFor(transaction, { clientUserId: subject.clientUserId });
    });

    return reply.clearCookie(SESSION_COOKIE, { path: '/' }).send({ ok: true, signedOutEverywhere: true });
  });

  app.get('/account/users', { preHandler: ownerGuard }, async (request, reply) => {
    const clientId = clientIdOf(request);
    const users = await context.database
      .select({
        id: clientUser.id,
        email: clientUser.email,
        name: clientUser.name,
        role: clientUser.role,
        activatedAt: clientUser.activatedAt,
        deactivatedAt: clientUser.deactivatedAt,
        lastLoginAt: clientUser.lastLoginAt,
      })
      .from(clientUser)
      .where(eq(clientUser.clientId, clientId));
    return reply.send({ users });
  });

  app.post('/account/users/:userId/deactivate', { preHandler: ownerGuard }, async (request, reply) => {
    const clientId = clientIdOf(request);
    const { userId } = request.params as { userId: string };

    // Deactivation and session revocation in one transaction, so access ends immediately rather
    // than when the session happens to expire.
    const revoked = await context.database.transaction(async (transaction) => {
      const updated = await transaction
        .update(clientUser)
        .set({ deactivatedAt: new Date() })
        .where(and(eq(clientUser.id, userId), eq(clientUser.clientId, clientId)))
        .returning({ id: clientUser.id });
      if (updated.length === 0) return 0;
      return revokeAllSessionsFor(transaction, { clientUserId: userId });
    });

    await context.auditLog.record({
      actorId: actorIdOf(request),
      actorKind: 'client',
      action: 'client.userDeactivated',
      subjectType: 'clientUser',
      subjectId: userId,
      metadata: { sessionsRevoked: revoked },
      ...requestContext(request),
    });

    return reply.send({ ok: true, sessionsRevoked: revoked });
  });

  /** Engagement access rows exist so a clientMember can be scoped to a subset of engagements. */
  app.get('/account/access', { preHandler: ownerGuard }, async (request, reply) => {
    const clientId = clientIdOf(request);
    const rows = await context.database
      .select({
        clientUserId: clientEngagementAccess.clientUserId,
        engagementId: clientEngagementAccess.engagementId,
      })
      .from(clientEngagementAccess)
      .innerJoin(clientUser, eq(clientUser.id, clientEngagementAccess.clientUserId))
      .where(eq(clientUser.clientId, clientId));
    return reply.send({ access: rows });
  });
}
