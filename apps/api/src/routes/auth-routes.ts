import { eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { ConsoleContext } from '../context.ts';
import { staffUser } from '../db/schema.ts';
import {
  beginTotpEnrolment,
  createSession,
  hashPassword,
  LoginThrottle,
  revokeAllSessionsFor,
  revokeSession,
  verifyPassword,
  verifyTotp,
} from '../services/auth.ts';
import { SESSION_COOKIE, cookieOptions, requestContext, requireSession } from './session-guard.ts';

/**
 * Staff authentication.
 *
 * Password then TOTP, in two steps, with the session created after the password and marked as
 * MFA-unsatisfied until the code is verified. That ordering means a stolen password gets an
 * inert session rather than an authenticated one.
 *
 * Failures are deliberately indistinguishable: the same message and roughly the same timing
 * whether the account exists, the password was wrong, or the account is inactive.
 */

const throttle = new LoginThrottle();

const loginSchema = z.object({
  email: z.string().email().max(200),
  password: z.string().min(1).max(400),
});

const totpSchema = z.object({ code: z.string().min(6).max(10) });

const GENERIC_FAILURE = { error: 'those details did not work' };

export function registerAuthRoutes(app: FastifyInstance, context: ConsoleContext): void {
  const secure = context.config.NODE_ENV === 'production';

  app.post('/auth/login', async (request, reply) => {
    const parsed = loginSchema.safeParse(request.body);
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
      .from(staffUser)
      .where(eq(staffUser.email, email))
      .limit(1);
    const user = users[0];

    // Always do the hash comparison, even when the account does not exist, so the response time
    // does not tell an attacker which addresses are staff accounts.
    const referenceHash =
      user?.passwordHash ??
      '$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const passwordOk = await verifyPassword(referenceHash, parsed.data.password);

    if (!user || !user.active || !passwordOk) {
      throttle.recordFailure(key);
      return reply.code(401).send(GENERIC_FAILURE);
    }

    if (!user.totpEnrolledAt) {
      // An account without a second factor cannot sign in. Enrolment happens through the invite
      // flow, not by skipping the requirement.
      throttle.recordFailure(key);
      return reply.code(403).send({
        error: 'this account has no second factor enrolled; ask the owner to re-issue the invitation',
      });
    }

    const { token, expiresAt } = await createSession(
      context.database,
      { kind: 'staff', staffUserId: user.id, role: user.role },
      { ...requestContext(request), mfaSatisfied: false },
    );

    throttle.recordSuccess(key);

    return reply
      .setCookie(SESSION_COOKIE, token, { ...cookieOptions(secure), expires: expiresAt })
      .send({ mfaRequired: true });
  });

  app.post(
    '/auth/mfa',
    { preHandler: requireSession({ database: context.database, expect: 'staff', allowWithoutMfa: true }) },
    async (request, reply) => {
      const parsed = totpSchema.safeParse(request.body);
      const subject = request.subject;
      if (!parsed.success || subject?.kind !== 'staff') {
        return reply.code(400).send(GENERIC_FAILURE);
      }

      const key = `mfa|${request.ip}|${subject.staffUserId}`;
      if (throttle.check(key) > 0) {
        return reply.code(429).send({ error: 'too many attempts, try again shortly' });
      }

      const users = await context.database
        .select()
        .from(staffUser)
        .where(eq(staffUser.id, subject.staffUserId))
        .limit(1);
      const user = users[0];
      if (!user?.totpSecretSealed) return reply.code(403).send(GENERIC_FAILURE);

      const secret = await context.vault.open('staff-mfa', JSON.parse(user.totpSecretSealed) as never);
      if (!verifyTotp(secret, parsed.data.code)) {
        throttle.recordFailure(key);
        return reply.code(401).send(GENERIC_FAILURE);
      }
      throttle.recordSuccess(key);

      // Rotate on privilege change: the pre-MFA token must not be the post-MFA token.
      await revokeSession(context.database, request.sessionId ?? '');
      const { token, expiresAt } = await createSession(
        context.database,
        subject,
        { ...requestContext(request), mfaSatisfied: true },
      );

      await context.database
        .update(staffUser)
        .set({ lastLoginAt: new Date() })
        .where(eq(staffUser.id, subject.staffUserId));

      await context.auditLog.record({
        actorId: subject.staffUserId,
        actorKind: 'staff',
        action: 'staff.loggedIn',
        subjectType: 'staffUser',
        subjectId: subject.staffUserId,
        ...requestContext(request),
      });

      return reply
        .setCookie(SESSION_COOKIE, token, { ...cookieOptions(secure), expires: expiresAt })
        .send({ ok: true, role: user.role });
    },
  );

  app.post(
    '/auth/logout',
    { preHandler: requireSession({ database: context.database, expect: 'staff', allowWithoutMfa: true }) },
    async (request, reply) => {
      await revokeSession(context.database, request.sessionId ?? '');
      return reply.clearCookie(SESSION_COOKIE, { path: '/' }).send({ ok: true });
    },
  );

  app.post(
    '/auth/sign-out-everywhere',
    { preHandler: requireSession({ database: context.database, expect: 'staff' }) },
    async (request, reply) => {
      const subject = request.subject;
      if (subject?.kind !== 'staff') return reply.code(403).send(GENERIC_FAILURE);
      const revoked = await revokeAllSessionsFor(context.database, {
        staffUserId: subject.staffUserId,
      });
      return reply.clearCookie(SESSION_COOKIE, { path: '/' }).send({ ok: true, revoked });
    },
  );

  app.get(
    '/auth/me',
    { preHandler: requireSession({ database: context.database, expect: 'staff' }) },
    (request, reply) => reply.send({ subject: request.subject }),
  );

  /**
   * First-run enrolment. Available only while no staff account exists, which is the one moment
   * where there is nobody to authorise the request.
   */
  app.post('/auth/bootstrap', async (request, reply) => {
    const existing = await context.database.select({ id: staffUser.id }).from(staffUser).limit(1);
    if (existing.length > 0) {
      return reply.code(409).send({ error: 'a staff account already exists; use an invitation' });
    }

    const parsed = z
      .object({
        email: z.string().email(),
        name: z.string().min(1).max(120),
        password: z.string().min(12).max(400),
      })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid details' });

    const enrolment = beginTotpEnrolment(parsed.data.email);
    const sealed = await context.vault.seal('staff-mfa', enrolment.secretBase32);

    const [created] = await context.database
      .insert(staffUser)
      .values({
        email: parsed.data.email.toLowerCase(),
        name: parsed.data.name,
        passwordHash: await hashPassword(parsed.data.password),
        role: 'owner',
        totpSecretSealed: JSON.stringify(sealed),
      })
      .returning({ id: staffUser.id });

    await context.auditLog.record({
      actorId: created?.id ?? 'bootstrap',
      actorKind: 'staff',
      action: 'staff.mfaEnrolled',
      subjectType: 'staffUser',
      subjectId: created?.id ?? 'bootstrap',
      ...requestContext(request),
    });

    // The secret is returned exactly once, at enrolment. It is never readable afterwards.
    return reply.send({ otpauthUrl: enrolment.otpauthUrl, mustConfirm: true });
  });

  /** Confirms enrolment by proving the authenticator works before the account is usable. */
  app.post('/auth/bootstrap/confirm', async (request, reply) => {
    const parsed = z
      .object({ email: z.string().email(), code: z.string().min(6).max(10) })
      .safeParse(request.body);
    if (!parsed.success) return reply.code(400).send(GENERIC_FAILURE);

    const users = await context.database
      .select()
      .from(staffUser)
      .where(eq(staffUser.email, parsed.data.email.toLowerCase()))
      .limit(1);
    const user = users[0];
    if (!user?.totpSecretSealed || user.totpEnrolledAt) {
      return reply.code(409).send(GENERIC_FAILURE);
    }

    const secret = await context.vault.open('staff-mfa', JSON.parse(user.totpSecretSealed) as never);
    if (!verifyTotp(secret, parsed.data.code)) return reply.code(401).send(GENERIC_FAILURE);

    await context.database
      .update(staffUser)
      .set({ totpEnrolledAt: new Date() })
      .where(eq(staffUser.id, user.id));

    return reply.send({ ok: true });
  });
}
