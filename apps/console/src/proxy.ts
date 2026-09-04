import { NextResponse, type NextRequest } from 'next/server';
import { contentSecurityPolicy, newNonce } from '@/lib/csp';

/**
 * Surface gating and the Content-Security-Policy, at the edge (Next 16 calls this file the proxy;
 * it was the middleware).
 *
 * Two jobs:
 *
 *   1. The console and the portal are the same codebase deployed twice. This refuses the other
 *      surface's routes, so a misconfigured deployment serves a 404 rather than a staff console to
 *      a client — failing closed rather than open. The separation that actually protects data is at
 *      the API and the database role; this is the layer that makes a configuration mistake visible
 *      immediately.
 *
 *   2. The policy is issued here rather than as a static header because Next emits inline scripts —
 *      the bootstrap and the streamed flight payload — and the only way to allow exactly those
 *      without allowing every inline script is a per-request nonce. Next reads the nonce out of the
 *      policy on the request and stamps it onto its own tags. A static `script-src 'self'` blocks
 *      them, which produces a page that renders and then does nothing.
 */

const CONSOLE_PREFIXES = ['/engagements', '/clients', '/queue', '/legal', '/settings'];
const PORTAL_PREFIXES = [
  '/findings',
  '/reports',
  '/retest',
  '/questionnaire',
  '/account',
  '/invitation',
  // Public on the portal: a client fills this in before they have an account. It must 404 on the
  // console, where a staff member has no reason to open it and a stray link should not resolve.
  '/credentials',
];

export default function proxy(request: NextRequest): NextResponse {
  const surface = process.env.ATTESTOR_SURFACE === 'portal' ? 'portal' : 'console';
  const { pathname } = request.nextUrl;

  const forbidden =
    surface === 'portal'
      ? CONSOLE_PREFIXES.some((prefix) => pathname.startsWith(prefix))
      : PORTAL_PREFIXES.some((prefix) => pathname.startsWith(prefix));

  if (forbidden) {
    return new NextResponse('Not found', { status: 404, headers: { 'Content-Type': 'text/plain' } });
  }

  const nonce = newNonce();
  const policy = contentSecurityPolicy(nonce, {
    development: process.env.NODE_ENV !== 'production',
  });

  // On the request so Next can find the nonce; on the response so the browser enforces it.
  const headers = new Headers(request.headers);
  headers.set('x-nonce', nonce);
  headers.set('Content-Security-Policy', policy);

  const response = NextResponse.next({ request: { headers } });
  response.headers.set('Content-Security-Policy', policy);
  return response;
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|fonts|favicon.ico).*)'],
};
