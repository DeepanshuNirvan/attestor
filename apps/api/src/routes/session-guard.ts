import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Database } from '../db/client.ts';
import { resolveSession, type SessionSubject } from '../services/auth.ts';

/**
 * The session guard.
 *
 * Applied as a preHandler on every route that is not explicitly public. Two properties matter:
 *
 *   1. MFA is checked here, not at login. A session that authenticated but has not satisfied its
 *      second factor is a session that can do nothing.
 *   2. The client scope comes from the session, never from a request parameter. That is the whole
 *      defence against the bug class this firm sells testing for, and it is why no handler is
 *      allowed to read a `clientId` from the body or the query.
 */

declare module 'fastify' {
  interface FastifyRequest {
    subject?: SessionSubject;
    sessionId?: string;
  }
}

export const SESSION_COOKIE = 'attestor_session';

export function cookieOptions(secure: boolean): {
  httpOnly: true;
  secure: boolean;
  sameSite: 'strict';
  path: string;
} {
  return { httpOnly: true, secure, sameSite: 'strict', path: '/' };
}

export interface GuardOptions {
  database: Database;
  /** Roles permitted on this route. Empty means any authenticated subject. */
  allowRoles?: string[];
  /** Set for routes that are reachable before the second factor, such as the MFA challenge. */
  allowWithoutMfa?: boolean;
  expect: 'staff' | 'client';
}

export function requireSession(options: GuardOptions) {
  return async function guard(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const token = request.cookies[SESSION_COOKIE];
    if (!token) {
      await reply.code(401).send({ error: 'not signed in' });
      return;
    }

    const resolved = await resolveSession(options.database, token);
    if (!resolved) {
      // The cookie is stale or the account was deactivated. Clear it so the browser stops sending
      // a token that will never work again.
      void reply.clearCookie(SESSION_COOKIE, { path: '/' });
      await reply.code(401).send({ error: 'session is no longer valid' });
      return;
    }

    if (resolved.subject.kind !== options.expect) {
      await reply.code(403).send({ error: 'wrong surface for this account' });
      return;
    }

    if (!resolved.mfaSatisfied && options.allowWithoutMfa !== true) {
      await reply.code(403).send({ error: 'multi-factor authentication is required', mfaRequired: true });
      return;
    }

    if (options.allowRoles && !options.allowRoles.includes(resolved.subject.role)) {
      await reply.code(403).send({ error: 'your role does not permit this' });
      return;
    }

    request.subject = resolved.subject;
    request.sessionId = resolved.sessionId;
  };
}

/** The client id for the current request. Derived from the session, never from user input. */
export function clientIdOf(request: FastifyRequest): string {
  const subject = request.subject;
  if (!subject || subject.kind !== 'client') {
    throw new Error('clientIdOf called outside a client session');
  }
  return subject.clientId;
}

export function actorIdOf(request: FastifyRequest): string {
  const subject = request.subject;
  if (!subject) return 'anonymous';
  return subject.kind === 'staff' ? subject.staffUserId : subject.clientUserId;
}

export function requestContext(request: FastifyRequest): { ipAddress: string; userAgent: string } {
  return {
    ipAddress: request.ip,
    userAgent: String(request.headers['user-agent'] ?? ''),
  };
}
