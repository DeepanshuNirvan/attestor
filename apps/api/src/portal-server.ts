import cookie from '@fastify/cookie';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyInstance } from 'fastify';
import { redactValue } from '@attestor/shared';
import { buildPortalContext, type PortalContext } from './context.ts';
import { registerPortalRoutes } from './portal/portal-routes.ts';
import { registerOriginGuard } from './routes/origin-guard.ts';
import { registerUuidParamGuard } from './routes/uuid-params.ts';

/**
 * The client portal API.
 *
 * A separate process, a separate port, a separate database role, and a route table that contains
 * only what a client needs. It does not import the console's route modules, and an architecture
 * test asserts that.
 *
 * File uploads are disabled outright: the body parser has no multipart handler registered and the
 * body limit is small. A client cannot upload anything in v1.
 */

export async function buildPortalServer(
  context: PortalContext = buildPortalContext(),
): Promise<{ app: FastifyInstance; context: PortalContext }> {
  const app = Fastify({
    logger: false,
    // Deliberately small. The largest legitimate portal request is a comment.
    bodyLimit: 256 * 1024,
    trustProxy: true,
  });

  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        connectSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        styleSrc: ["'self'"],
        scriptSrc: ["'self'"],
        fontSrc: ["'self'"],
        frameSrc: ["'self'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
        baseUri: ["'none'"],
        objectSrc: ["'none'"],
      },
    },
    hsts: { maxAge: 63_072_000, includeSubDomains: true, preload: true },
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  });

  await app.register(cors, {
    origin: context.config.PORTAL_ORIGIN,
    credentials: true,
    methods: ['GET', 'POST', 'PUT'],
  });

  await app.register(cookie, { secret: context.config.SESSION_SECRET });

  // Every state-changing method is checked against the portal's own origin. GET is exempt because
  // it changes nothing. See routes/origin-guard.ts for why this is an origin check and not a token.
  registerOriginGuard(app, context.config.PORTAL_ORIGIN);

  // Authentication routes get their own tighter limit on top of the global one, because they are
  // the routes worth attacking.
  await app.register(rateLimit, {
    max: 120,
    timeWindow: '1 minute',
    keyGenerator: (request) => request.ip,
  });

  app.setErrorHandler((error: Error & { statusCode?: number }, request, reply) => {
    context.logger.error('portal request failed', {
      method: request.method,
      url: request.url,
      error: redactValue(error),
    });
    const status = typeof error.statusCode === 'number' && error.statusCode >= 400 ? error.statusCode : 500;
    // Never echo an internal message to a public surface.
    void reply.code(status).send({ error: status === 500 ? 'internal error' : error.message });
  });

  app.addHook('onRequest', async (request, reply) => {
    // There is no upload path in v1, and a request that tries one should be refused before it
    // reaches a handler rather than by a handler that happens not to read the body.
    const contentType = String(request.headers['content-type'] ?? '');
    if (contentType.startsWith('multipart/')) {
      await reply.code(415).send({ error: 'file uploads are not accepted' });
    }
  });

  app.get('/health', () => ({ ok: true }));

  registerUuidParamGuard(app);

  registerPortalRoutes(app, context);

  return { app, context };
}

const isEntryPoint = process.argv[1]?.endsWith('portal-server.ts') === true;
if (isEntryPoint) {
  const { app, context } = await buildPortalServer();
  const port = context.config.PORTAL_API_PORT;
  // The portal is the public surface, so it binds to all interfaces behind the reverse proxy.
  await app.listen({ host: '0.0.0.0', port });
  context.logger.info('portal api listening', { port });
}
