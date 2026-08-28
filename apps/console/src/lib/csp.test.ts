import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { contentSecurityPolicy, newNonce } from './csp.ts';

/**
 * The policy, and the two ways it has already been got wrong.
 *
 * It was first written as a static header in next.config.ts with `script-src 'self'`, which blocks
 * Next's own inline bootstrap: the page rendered and then did nothing, on every route. The fix is a
 * per-request nonce, and these tests exist so the static version cannot come back — including the
 * subtler version of the mistake, where a second static policy is added alongside this one and the
 * browser intersects the two, silently dropping the nonce.
 */

function directives(policy: string): Map<string, string> {
  return new Map(
    policy.split('; ').map((entry) => {
      const [name, ...rest] = entry.split(' ');
      return [name ?? '', rest.join(' ')];
    }),
  );
}

describe('the content security policy', () => {
  const production = contentSecurityPolicy('TESTNONCE', { development: false });
  const development = contentSecurityPolicy('TESTNONCE', { development: true });

  it('denies everything by default', () => {
    expect(directives(production).get('default-src')).toBe("'none'");
  });

  it('carries the nonce so Next can stamp it on its own scripts', () => {
    expect(directives(production).get('script-src')).toContain("'nonce-TESTNONCE'");
  });

  it('never allows inline scripts wholesale', () => {
    expect(directives(production).get('script-src')).not.toContain("'unsafe-inline'");
    expect(directives(development).get('script-src')).not.toContain("'unsafe-inline'");
  });

  it('allows eval only in development, where the dev server needs it', () => {
    expect(directives(development).get('script-src')).toContain("'unsafe-eval'");
    expect(directives(production).get('script-src')).not.toContain("'unsafe-eval'");
  });

  it('refuses to be framed and refuses plugins', () => {
    expect(directives(production).get('frame-ancestors')).toBe("'none'");
    expect(directives(production).get('object-src')).toBe("'none'");
    expect(directives(production).get('base-uri')).toBe("'none'");
  });

  it('allows data: fonts, which the sandboxed report frame inherits', () => {
    // A released report embeds its fonts so the PDF and the browser view match and neither fetches
    // anything. A srcdoc frame inherits the embedder's policy, so the allowance has to be here.
    expect(directives(production).get('font-src')).toContain('data:');
  });

  it('does not allow a remote origin anywhere', () => {
    expect(production).not.toMatch(/https?:\/\//);
  });
});

describe('the nonce', () => {
  it('is different every time', () => {
    const values = new Set(Array.from({ length: 200 }, () => newNonce()));
    expect(values.size).toBe(200);
  });

  it('is long enough to be unguessable', () => {
    // 16 bytes, base64. Anything shorter is a nonce an attacker can brute-force offline against a
    // cached page.
    expect(atob(newNonce()).length).toBe(16);
  });
});

describe('there is exactly one policy', () => {
  it('is not also set statically in next.config.ts', async () => {
    const config = await readFile(
      fileURLToPath(new URL('../../next.config.ts', import.meta.url)),
      'utf8',
    );
    // Two policies intersect. A static one without the nonce would strip the nonce from the
    // effective policy and break every script on the page — the exact bug this file documents.
    expect(config).not.toContain("key: 'Content-Security-Policy'");
  });

  it('is issued by the proxy on every response', async () => {
    const proxy = await readFile(fileURLToPath(new URL('../proxy.ts', import.meta.url)), 'utf8');
    expect(proxy).toContain("headers.set('Content-Security-Policy', policy)");
    expect(proxy).toContain("response.headers.set('Content-Security-Policy', policy)");
  });
});
