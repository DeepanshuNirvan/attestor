import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { CREDENTIAL_KINDS, credentialKind } from '@attestor/core';
import type { ConsoleContext } from '../context.ts';
import {
  intakeContextFor,
  resolveIntakeLink,
  submitCredential,
  type IntakeLink,
} from '../services/credential-intake.ts';
import { requestContext, requireSession } from './session-guard.ts';

/**
 * Credential intake.
 *
 * The one part of the console API a client touches, and the only one reached without a staff
 * session. The one-time token **is** the authorisation: it was generated once, handed to the client
 * through a channel the tester chose, and only its hash is stored — so there is no session to have,
 * and demanding one would mean the client needed an account before they could give us a password.
 *
 * The page lives on the portal, which is the surface a client can reach; it submits here, because
 * the console is the only service holding the vault key. The portal never touches the credential
 * tables and is granted nothing on them.
 *
 * Everything is deliberately narrow: two routes, both keyed on one token, neither returning a
 * credential, and a rate limit tighter than the rest of the API.
 */

/**
 * Tighter than the API's 300 a minute, because these two routes are the only ones an unauthenticated
 * caller can reach. Thirty is far above what filling in a form takes and far below what guessing at
 * a token would need.
 *
 * The limit is per source address, and every real submission arrives from the portal's Next server,
 * so all clients share one bucket. That is affordable at this volume — a handful of submissions per
 * engagement — and a caller guessing tokens comes through the same door.
 */
const INTAKE_RATE_LIMIT = { rateLimit: { max: 30, timeWindow: '1 minute' } };

declare module 'fastify' {
  interface FastifyRequest {
    intakeLink?: IntakeLink;
  }
}

const REFUSALS = {
  notFound: 'That link is not valid. Ask your tester for a new one.',
  expired: 'That link has expired. Ask your tester for a new one.',
} as const;

export function registerCredentialIntakeRoutes(app: FastifyInstance, context: ConsoleContext): void {
  /**
   * The token guard. It plays the part a session guard plays elsewhere: nothing below it runs until
   * the token has been resolved to a live link, and the handlers read the link off the request
   * rather than looking it up again.
   */
  const requireIntakeToken = async (request: FastifyRequest, reply: { code: (status: number) => { send: (body: unknown) => unknown } }) => {
    const { token } = request.params as { token?: string };
    if (typeof token !== 'string' || token.length < 20 || token.length > 200) {
      reply.code(404).send({ error: REFUSALS.notFound });
      return;
    }

    const resolved = await resolveIntakeLink(context.database, token);
    if (!resolved.ok) {
      reply.code(resolved.reason === 'expired' ? 410 : 404).send({
        error: REFUSALS[resolved.reason],
      });
      return;
    }

    request.intakeLink = resolved.link;
  };

  /** What the client's page renders: who it is for, and which boxes to show. */
  app.get(
    '/credential-intake/:token',
    { preHandler: requireIntakeToken, config: INTAKE_RATE_LIMIT },
    async (request, reply) => {
      const link = request.intakeLink;
      if (!link) return reply.code(404).send({ error: REFUSALS.notFound });

      const details = await intakeContextFor(context.database, link);
      if (!details) return reply.code(404).send({ error: REFUSALS.notFound });

      // The field definitions travel with the response so the page has nothing of its own to keep in
      // step with the catalogue.
      const forms = link.requested.map((entry) => {
        const kind = credentialKind(entry.kind);
        return {
          slot: entry.slot,
          label: entry.label,
          roleName: entry.roleName,
          kind: entry.kind,
          kindLabel: kind?.label ?? entry.kind,
          description: kind?.description ?? '',
          fields: kind?.fields ?? [],
          alreadyProvided: details.filledSlots.includes(entry.slot),
        };
      });

      return reply.send({
        engagementReference: details.engagementReference,
        engagementTitle: details.engagementTitle,
        clientName: details.clientName,
        expiresAt: link.expiresAt,
        forms,
      });
    },
  );

  app.post(
    '/credential-intake/:token',
    { preHandler: requireIntakeToken, config: INTAKE_RATE_LIMIT },
    async (request, reply) => {
      const link = request.intakeLink;
      if (!link) return reply.code(404).send({ error: REFUSALS.notFound });

      const parsed = z
        .object({
          slot: z.string().min(1).max(64),
          // One level deep, strings only. A credential is a set of fields, never a structure.
          values: z.record(z.string().min(1).max(64), z.string().max(8000)),
        })
        .safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: 'That submission was not in the expected shape.' });
      }

      const outcome = await submitCredential(context.database, {
        link,
        slot: parsed.data.slot,
        values: parsed.data.values,
        vault: context.vault,
      });

      if (!outcome.ok) return reply.code(400).send({ problems: outcome.problems });

      // The values themselves are never logged, here or anywhere. What is recorded is that a
      // credential arrived, for which account, and from where.
      await context.auditLog.record({
        actorId: link.id,
        actorKind: 'client',
        action: 'credentialSet.submitted',
        subjectType: 'engagement',
        subjectId: link.engagementId,
        metadata: { slot: parsed.data.slot, label: outcome.label },
        ...requestContext(request),
      });

      return reply.send({
        ok: true,
        label: outcome.label,
        note: 'Stored and encrypted. Nobody at Attestor can display this value, including us.',
      });
    },
  );

  /** The catalogue, so the console can offer the kinds without keeping its own copy in step. */
  app.get(
    '/credential-kinds',
    { preHandler: requireSession({ database: context.database, expect: 'staff' }) },
    (unusedRequest, reply) => reply.send({ kinds: CREDENTIAL_KINDS }),
  );
}
