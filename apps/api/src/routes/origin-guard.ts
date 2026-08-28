import type { FastifyInstance } from 'fastify';

/**
 * Cross-site request forgery, actually enforced.
 *
 * `@fastify/csrf-protection` was registered on both servers and never applied: the plugin only adds
 * `reply.generateCsrf()` and an `app.csrfProtection` handler, and neither was used by any route, so
 * nothing checked a token on any request. Registering it was the whole of the protection.
 *
 * A token flow is not the right replacement here. The console and portal talk to these APIs from
 * their Next server, forwarding the session cookie, so there is no browser page to carry a token
 * and no place to put one. What a browser can do is send a cross-site request directly to the API,
 * and the defence against that is an origin check — which needs no plumbing and cannot be forgotten
 * by a route author.
 *
 * A request with no `Origin` is allowed: server-to-server callers do not send one, and a browser
 * always does on a cross-origin state-changing request, which is the case being defended against.
 * The session cookie is `SameSite=strict` as well, so this is the second lock rather than the only
 * one.
 */
export function registerOriginGuard(app: FastifyInstance, allowedOrigin: string): void {
  const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

  app.addHook('onRequest', async (request, reply) => {
    if (SAFE_METHODS.has(request.method)) return;

    const origin = request.headers.origin;
    if (origin === undefined || origin === '' || origin === 'null') {
      // Not a browser, or a browser that sends nothing to forge with.
      return;
    }

    if (origin === allowedOrigin) return;

    await reply.code(403).send({ error: 'cross-origin request refused' });
  });
}
