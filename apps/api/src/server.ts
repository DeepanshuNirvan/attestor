import cookie from '@fastify/cookie';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyInstance } from 'fastify';
import { redactValue } from '@attestor/shared';
import { buildConsoleContext, type ConsoleContext } from './context.ts';
import { buildQueues, type Queues } from './queue.ts';
import { registerAiRoutes } from './routes/ai-routes.ts';
import { registerAuthRoutes } from './routes/auth-routes.ts';
import { registerClientRoutes } from './routes/client-routes.ts';
import { registerCredentialIntakeRoutes } from './routes/credential-intake-routes.ts';
import { registerEngagementRoutes } from './routes/engagement-routes.ts';
import { registerFindingRoutes } from './routes/finding-routes.ts';
import { registerPlatformRoutes } from './routes/platform-routes.ts';
import { registerReportRoutes } from './routes/report-routes.ts';
import { registerOriginGuard } from './routes/origin-guard.ts';
import { registerUuidParamGuard } from './routes/uuid-params.ts';

/**
 * The console API.
 *
 * Bound to a private interface. It is reached over WireGuard or Tailscale and is never published:
 * the client portal is the only public surface, and it is a separate process with a separate
 * database role. If this process is ever reachable from the internet, that is a deployment bug and
 * the runbook says so.
 */

export async function buildConsoleServer(
  context: ConsoleContext = buildConsoleContext(),
  queues: Queues = buildQueues(context.config.REDIS_URL),
): Promise<{ app: FastifyInstance; context: ConsoleContext; queues: Queues }> {
  const app = Fastify({
    logger: false,
    bodyLimit: 25 * 1024 * 1024,
    trustProxy: false,
  });

  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'none'"],
      },
    },
    hsts: { maxAge: 63_072_000, includeSubDomains: true, preload: true },
  });

  await app.register(cors, {
    origin: context.config.CONSOLE_ORIGIN,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
  });

  await app.register(cookie, { secret: context.config.SESSION_SECRET });

  // Enforced, unlike the token plugin this replaces. See routes/origin-guard.ts.
  registerOriginGuard(app, context.config.CONSOLE_ORIGIN);

  await app.register(rateLimit, {
    max: 300,
    timeWindow: '1 minute',
    keyGenerator: (request) => request.ip,
  });

  // Errors are logged through the redaction filter and returned without internals. A stack trace in
  // an API response is an information disclosure finding in our own product.
  app.setErrorHandler((error: Error & { statusCode?: number }, request, reply) => {
    context.logger.error('request failed', {
      method: request.method,
      url: request.url,
      error: redactValue(error),
    });
    const status = typeof error.statusCode === 'number' && error.statusCode >= 400 ? error.statusCode : 500;
    void reply.code(status).send({ error: status === 500 ? 'internal error' : error.message });
  });

  app.get('/health', () => {
    // Deliberately shallow: a health endpoint that reports the database version is a health
    // endpoint that fingerprints the stack.
    return { ok: true };
  });

  registerUuidParamGuard(app);

  registerAiRoutes(app, context);
  registerAuthRoutes(app, context);
  registerClientRoutes(app, context);
  registerCredentialIntakeRoutes(app, context);
  registerEngagementRoutes(app, context, queues);
  registerFindingRoutes(app, context);
  registerReportRoutes(app, context);
  registerPlatformRoutes(app, context, queues);

  return { app, context, queues };
}

const isEntryPoint = process.argv[1]?.endsWith('server.ts') === true;
if (isEntryPoint) {
  const { app, context } = await buildConsoleServer();
  const address = context.config.API_BIND_ADDRESS;
  const port = context.config.API_PORT;

  if (address === '0.0.0.0' && context.config.NODE_ENV === 'production') {
    // Refusing to start is the right behaviour: the console holds the credential vault and the
    // container runner, and a misconfigured bind address would publish both.
    throw new Error(
      'the console API must not bind to 0.0.0.0 in production; reach it over WireGuard or Tailscale',
    );
  }

  await app.listen({ host: address, port });
  context.logger.info('console api listening', { address, port });
}
