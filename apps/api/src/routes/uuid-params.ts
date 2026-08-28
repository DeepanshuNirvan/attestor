import type { FastifyInstance } from 'fastify';

/**
 * Path parameters that name a row are uuids.
 *
 * Postgres refuses anything else with a type error rather than an empty result, so a mistyped id
 * in a URL arrives as a 500 from whichever handler ran the first query — an unhandled error on a
 * request that was never valid, and on the portal that is a public surface. Checking the shape once
 * before any handler turns it into the 400 it always was.
 *
 * Named explicitly rather than matched by suffix because not every id is a uuid: `jobId` is a
 * queue's own counter, and `token`, `reference` and `key` are not ids at all.
 */
const UUID_PARAMETERS = new Set([
  'id',
  'authorisationId',
  'findingId',
  'invitationId',
  'reportId',
  'retainerId',
  'scopeItemId',
  'userId',
]);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function registerUuidParamGuard(app: FastifyInstance): void {
  app.addHook('preValidation', async (request, reply) => {
    const params = request.params as Record<string, unknown> | undefined;
    if (!params) return;

    for (const [name, value] of Object.entries(params)) {
      if (!UUID_PARAMETERS.has(name)) continue;
      if (typeof value === 'string' && UUID.test(value)) continue;
      // The same body a handler sends for a row that does not exist. A malformed id and an unknown
      // id should not be distinguishable.
      await reply.code(400).send({ error: 'not found' });
      return;
    }
  });
}
