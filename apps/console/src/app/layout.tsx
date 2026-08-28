import type { Metadata } from 'next';
import { currentSurface } from '@/lib/surface';
import './globals.css';

export const metadata: Metadata = {
  title: 'Attestor',
  // The console is not reachable from the internet and the portal must not be indexed either.
  robots: { index: false, follow: false },
};

/**
 * Every page is rendered per request, because every page needs that request's CSP nonce.
 *
 * A statically prerendered page is built once, before any request exists, so Next has no nonce to
 * stamp onto its script tags. The policy uses 'strict-dynamic', which tells the browser to ignore
 * the 'self' allowlist and trust only nonced scripts — so on a prerendered page every script,
 * including Next's own bootstrap, is blocked and the page renders and then does nothing. It is the
 * same failure as a static `script-src 'self'`, arriving by a different route, and it is invisible
 * in development because the dev policy is looser.
 *
 * Nothing here is cacheable anyway: both surfaces are behind a session and show one tenant's data.
 */
export const dynamic = 'force-dynamic';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const surface = currentSurface();

  return (
    <html lang="en-GB">
      <body data-surface={surface}>{children}</body>
    </html>
  );
}
