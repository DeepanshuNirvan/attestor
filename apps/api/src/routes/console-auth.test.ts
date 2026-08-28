import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * Structural proof that no console route is reachable without a session.
 *
 * The console API is bound to a private interface and reached over WireGuard, which is a network
 * control. This is the application-layer one, and it exists because the two protect against
 * different mistakes: the network control fails the day somebody binds the API to 0.0.0.0, and the
 * moment that happens an unguarded route is a public route.
 *
 * It parses the route files rather than exercising them, so it runs on every commit without a
 * database and catches the omission at the moment it is written.
 */

const routesDirectory = fileURLToPath(new URL('.', import.meta.url));

/** Routes that must work before a session exists. Nothing else may be added without a reason. */
const PUBLIC_ROUTES = new Set([
  'POST /auth/login',
  'POST /auth/mfa',
  'POST /auth/bootstrap',
  'POST /auth/bootstrap/confirm',
]);

interface RouteBlock {
  file: string;
  method: string;
  path: string;
  signature: string;
  body: string;
}

function parseRoutes(file: string, text: string): RouteBlock[] {
  const pattern = /app\.(get|post|put|delete)\(\s*'([^']+)'/g;
  const starts: { method: string; path: string; index: number }[] = [];

  for (const match of text.matchAll(pattern)) {
    starts.push({ method: match[1]!.toUpperCase(), path: match[2]!, index: match.index });
  }

  return starts.map((start, position) => {
    const end = starts[position + 1]?.index ?? text.length;
    const block = text.slice(start.index, end);
    const signatureEnd = block.indexOf('=>');
    return {
      file,
      method: start.method,
      path: start.path,
      signature: block.slice(0, signatureEnd === -1 ? 200 : signatureEnd),
      body: block,
    };
  });
}

const files = (await readdir(routesDirectory)).filter(
  (name) => name.endsWith('-routes.ts') && !name.endsWith('.test.ts'),
);

const routes: RouteBlock[] = [];
for (const file of files) {
  const text = await readFile(`${routesDirectory}${file}`, 'utf8');
  routes.push(...parseRoutes(file, text));
}

describe('console route registration', () => {
  it('finds every route file, so a rename fails loudly here rather than silently skipping', () => {
    expect(files).toContain('auth-routes.ts');
    expect(files).toContain('client-routes.ts');
    expect(files).toContain('engagement-routes.ts');
    expect(files).toContain('finding-routes.ts');
    expect(files).toContain('platform-routes.ts');
    expect(files).toContain('report-routes.ts');
    expect(routes.length).toBeGreaterThan(40);
  });

  it('requires a session on every route that is not explicitly public', () => {
    for (const route of routes) {
      const label = `${route.method} ${route.path}`;
      if (PUBLIC_ROUTES.has(label)) continue;

      expect(
        route.signature.includes('preHandler'),
        `${route.file}: ${label} has no preHandler. Every console route needs a session guard.`,
      ).toBe(true);
    }
  });

  it('keeps the public list small and deliberate', () => {
    // Sign-in and first-run bootstrap. If this number grows, somebody has opened a hole and should
    // have to explain it in a diff.
    expect(PUBLIC_ROUTES.size).toBe(4);
  });
});

describe('the console never becomes a second path around a control', () => {
  it('does not start containers outside the runner', async () => {
    for (const file of files) {
      const text = await readFile(`${routesDirectory}${file}`, 'utf8');
      expect(text).not.toContain('dockerode');
      expect(text).not.toContain('containerRunner.run(');
    }
  });

  it('only opens the vault for the staff authenticator, never for a client credential', async () => {
    // Opening a client credential belongs in the worker, at run time, in memory. A route that does
    // it is a route that can put a client's password on somebody's screen. The one legitimate use
    // is verifying a staff TOTP code, which is sealed under the fixed 'staff-mfa' context.
    for (const file of files) {
      const text = await readFile(`${routesDirectory}${file}`, 'utf8');
      for (const match of text.matchAll(/vault\.(open|seal)\(\s*([^,]+),/g)) {
        expect(
          match[2]?.trim(),
          `${file} calls vault.${match[1]} with something other than 'staff-mfa'`,
        ).toBe("'staff-mfa'");
      }
    }
  });
});
