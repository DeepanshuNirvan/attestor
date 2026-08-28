import type { NextConfig } from 'next';

/**
 * The console and the portal are the same codebase deployed twice, gated by ATTESTOR_SURFACE.
 *
 * They are separate deployments talking to separate APIs with separate database roles — the
 * separation that matters is at the API and the database, not in the rendering layer, which holds
 * no data of its own. The middleware refuses the other surface's routes at the edge so a
 * misconfigured deployment fails closed rather than serving both.
 */
const surface = process.env.ATTESTOR_SURFACE ?? 'console';

const config: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  env: { ATTESTOR_SURFACE: surface },
  // No images are loaded from anywhere but this origin, and no fonts from a CDN.
  images: { remotePatterns: [] },
  // The Content-Security-Policy is NOT here. It carries a per-request nonce and is issued by
  // src/proxy.ts; a second static policy at this layer would intersect with it and strip the nonce,
  // which breaks every script on the page. Only headers that are the same on every response belong
  // in this list.
  //
  // Not `async`: there is nothing to await, and Next only asks for a promise.
  headers: () =>
    Promise.resolve([
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
          { key: 'X-Frame-Options', value: 'DENY' },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
          },
        ],
      },
    ]),
};

export default config;
