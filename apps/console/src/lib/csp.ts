/**
 * The Content-Security-Policy.
 *
 * It lives here rather than in next.config.ts because it carries a per-request nonce: Next emits
 * inline scripts — the bootstrap and the streamed flight payload — and the only way to allow
 * exactly those without allowing every inline script is a nonce. A static `script-src 'self'`
 * blocks them, which produces a page that renders and then does nothing at all.
 *
 * Kept out of proxy.ts so it can be tested without loading the edge runtime.
 */

export function newNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

export interface PolicyOptions {
  /** The dev server compiles with eval. Production gets no such allowance. */
  development: boolean;
}

export function contentSecurityPolicy(nonce: string, options: PolicyOptions): string {
  return [
    "default-src 'none'",
    // 'strict-dynamic' lets the nonced bootstrap load the chunks it needs without naming each one.
    // Browsers that honour it ignore 'self' here; older ones fall back to it.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${options.development ? " 'unsafe-eval'" : ''}`,
    // Server-rendered inline styles. Removing this needs nonces threaded through every style
    // attribute, for a benefit that style injection does not deliver once script-src is locked down.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    // data: is for the sandboxed report frame: a released report embeds its fonts so the PDF and
    // the browser view are identical and neither fetches anything. A srcdoc frame inherits this
    // policy, so the allowance has to live here.
    "font-src 'self' data:",
    "connect-src 'self'",
    "form-action 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    // The in-portal report view is a sandboxed frame served from this origin.
    "frame-src 'self'",
  ].join('; ');
}
