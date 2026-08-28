/**
 * Which surface this deployment is.
 *
 * It lives on its own, away from the API client, because client components need it too and the API
 * client imports `next/headers` — which exists only on the server. The value is inlined at build
 * time by next.config.ts, so a deployment cannot change surface without a rebuild.
 */

export type Surface = 'console' | 'portal';

export function currentSurface(): Surface {
  return process.env.ATTESTOR_SURFACE === 'portal' ? 'portal' : 'console';
}
