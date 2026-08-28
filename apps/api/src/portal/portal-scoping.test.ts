import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * Structural proof that the portal cannot leak across tenants.
 *
 * The integration suite exercises this against a real database with two clients. This test is the
 * one that runs on every commit, and it catches the mistake at the moment it is written rather than
 * when somebody remembers to stand up Postgres.
 *
 * The rule it enforces: every authenticated portal route derives its client scope from the session,
 * and no portal route reads a client identifier out of a parameter, a query or a body.
 */

const portalRoutesPath = fileURLToPath(new URL('./portal-routes.ts', import.meta.url));
const source = await readFile(portalRoutesPath, 'utf8');

/** Routes reachable before a session exists. Everything else must be scoped. */
const PUBLIC_ROUTES = new Set([
  'POST /invitations/accept',
  'POST /invitations/confirm-mfa',
  'POST /auth/login',
]);

/**
 * Authenticated routes that legitimately act on the signed-in user rather than on client-owned
 * data. They still require a session; they just have no row to scope.
 */
const SELF_SCOPED_ROUTES = new Set([
  'POST /auth/mfa',
  'POST /auth/logout',
  'POST /auth/sign-out-everywhere',
  'GET /terms',
  'POST /terms/accept',
  'GET /account',
  'PUT /account/password',
  'GET /questionnaire',
]);

interface RouteBlock {
  method: string;
  path: string;
  signature: string;
  body: string;
}

/** Split the route file into one block per `app.<method>('<path>', …)` registration. */
function parseRoutes(text: string): RouteBlock[] {
  const pattern = /app\.(get|post|put|delete)\(\s*'([^']+)'/g;
  const starts: { method: string; path: string; index: number }[] = [];

  for (const match of text.matchAll(pattern)) {
    starts.push({
      method: match[1]!.toUpperCase(),
      path: match[2]!,
      index: match.index,
    });
  }

  return starts.map((start, position) => {
    const end = starts[position + 1]?.index ?? text.length;
    const block = text.slice(start.index, end);
    const signatureEnd = block.indexOf('=>');
    return {
      method: start.method,
      path: start.path,
      signature: block.slice(0, signatureEnd === -1 ? 200 : signatureEnd),
      body: block,
    };
  });
}

const routes = parseRoutes(source);

describe('portal route registration', () => {
  it('finds the routes, so a rename of the registration style fails loudly here', () => {
    expect(routes.length).toBeGreaterThan(15);
    expect(routes.map((route) => `${route.method} ${route.path}`)).toContain('GET /findings');
  });
});

describe('every authenticated portal route is scoped by the session', () => {
  const authenticated = routes.filter(
    (route) => !PUBLIC_ROUTES.has(`${route.method} ${route.path}`),
  );

  it('requires a session on every route that is not explicitly public', () => {
    for (const route of authenticated) {
      const label = `${route.method} ${route.path}`;
      expect(
        route.signature.includes('preHandler'),
        `${label} has no preHandler; every non-public portal route needs a session guard`,
      ).toBe(true);
    }
  });

  it('derives the client scope from the session on every data route', () => {
    const dataRoutes = authenticated.filter(
      (route) => !SELF_SCOPED_ROUTES.has(`${route.method} ${route.path}`),
    );

    expect(dataRoutes.length).toBeGreaterThan(8);

    for (const route of dataRoutes) {
      const label = `${route.method} ${route.path}`;
      expect(
        route.body.includes('clientIdOf(request)'),
        `${label} does not call clientIdOf(request). Client scope must come from the session, never from a parameter.`,
      ).toBe(true);
    }
  });

  it('never reads a client identifier from a parameter, query or body', () => {
    // The pattern that would break tenancy: pulling clientId out of anything the caller controls.
    const forbidden = [
      /request\.params\s+as\s+\{[^}]*clientId/,
      /request\.query[^;]*clientId/,
      /request\.body[^;]*clientId/,
      /params\.clientId/,
      /query\.clientId/,
      /body\.clientId/,
    ];

    for (const pattern of forbidden) {
      expect(pattern.test(source), `portal-routes.ts matches forbidden pattern ${String(pattern)}`).toBe(
        false,
      );
    }
  });

  it('scopes every query that touches an engagement-owned table through the engagement join', () => {
    // Findings, reports, evidence and comments all belong to a client through their engagement.
    // A query on those tables that does not also constrain the engagement's client is the bug.
    const ownedTables = ['findingTable', 'reportTable', 'evidenceTable', 'retestRequest'];

    for (const route of routes) {
      const label = `${route.method} ${route.path}`;
      if (PUBLIC_ROUTES.has(label) || SELF_SCOPED_ROUTES.has(label)) continue;

      const touchesOwnedTable = ownedTables.some((table) => route.body.includes(`.from(${table})`));
      if (!touchesOwnedTable) continue;

      const constrained =
        route.body.includes('eq(engagementTable.clientId, clientId)') ||
        route.body.includes('eq(findingTable.engagementId, id)') ||
        route.body.includes('eq(evidenceTable.findingId, findingId)');

      expect(
        constrained,
        `${label} selects from an engagement-owned table without constraining it to the session's client`,
      ).toBe(true);
    }
  });
});

describe('the portal cannot do the things only the console may do', () => {
  it('never imports the credential vault', () => {
    expect(source).not.toContain('credential-vault');
    expect(source).not.toContain('CredentialVault');
    expect(source).not.toContain('credentialSet');
  });

  it('never imports the container runner or the scope guard runner', () => {
    expect(source).not.toContain('ContainerRunner');
    expect(source).not.toContain('runToolForEngagement');
    expect(source).not.toContain('createRunsForModule');
  });

  it('never touches the panic stop, the policy or the audit log beyond appending', () => {
    expect(source).not.toContain('engagePanicStop');
    expect(source).not.toContain('resolvePolicy');
    // The audit log is append-only from here: `record` is the only method used.
    expect(source).not.toMatch(/auditLog\.(?!record)/);
  });

  it('does not import any console route module', () => {
    const consoleModules = ['engagement-routes', 'finding-routes', 'report-routes', 'auth-routes'];
    for (const module of consoleModules) {
      expect(source, `portal must not import ${module}`).not.toContain(`/${module}.ts`);
    }
  });

  it('never returns a candidate or a false positive to a client', () => {
    // Only these three statuses may reach a client. A candidate is unconfirmed by definition.
    const findingQueries = routes.filter((route) => route.body.includes('.from(findingTable)'));
    expect(findingQueries.length).toBeGreaterThan(0);

    for (const route of findingQueries) {
      const label = `${route.method} ${route.path}`;
      // The dashboard aggregates and the finding routes list; both must filter on status.
      expect(
        route.body.includes("['open', 'fixed', 'riskAccepted']") ||
          route.body.includes("eq(findingTable.status, 'fixed')"),
        `${label} queries findings without restricting the status to confirmed ones`,
      ).toBe(true);
    }
  });

  it('refuses downloads for the read-only role', () => {
    const download = routes.find((route) => route.path === '/reports/:reportId/download');
    expect(download).toBeDefined();
    expect(download?.body).toContain("subject.role === 'clientViewer'");
  });

  it('watermarks every report download server-side', () => {
    const download = routes.find((route) => route.path === '/reports/:reportId/download');
    expect(download?.body).toContain('watermarkFor(');
    expect(download?.body).toContain('reportDownload');
  });

  it('requires a written justification before a risk can be accepted', () => {
    const status = routes.find((route) => route.path === '/findings/:findingId/status');
    expect(status?.body).toContain('justification');
    expect(status?.body).toMatch(/length\s*<\s*20/);
  });
});

describe('evidence rendering', () => {
  it('returns evidence as inert text or a data URI, never as a URL the browser will render', () => {
    const detail = routes.find(
      (route) => route.method === 'GET' && route.path === '/findings/:findingId',
    );
    expect(detail).toBeDefined();
    // A signed URL here would be a URL the browser fetches and may render as HTML. The portal
    // reads the object server-side and hands back text or a data URI instead.
    expect(detail?.body).not.toContain('signedUrl');
    expect(detail?.body).toContain('imageDataUri');
    expect(detail?.body).toContain("toString('utf8')");
  });

  it('serves the in-portal report view under its own restrictive policy and a sandbox', () => {
    const view = routes.find((route) => route.path === '/reports/:reportId/view');
    expect(view?.body).toContain('Content-Security-Policy');
    expect(view?.body).toContain('sandbox');
    expect(view?.body).toContain('nosniff');
  });
});

describe('client authenticator secrets', () => {
  it('is never stored in the clear', () => {
    // The column is called `totpSecretSealed`. Writing a bare base32 secret into it would make the
    // name a lie and hand every client's second factor to whoever gets a database backup.
    expect(source).not.toMatch(/totpSecretSealed:\s*enrolment\.secretBase32/);
    expect(source).toContain('totpVault.seal(TOTP_CONTEXT');
  });

  it('is never verified straight out of the column', () => {
    // Verifying straight out of the column only works if the column holds plaintext. It must go
    // through the vault first, so either of these patterns reappearing is the regression.
    expect(source).not.toMatch(/verifyTotp\(\s*(?:user|enrolling)\.totpSecretSealed/);
    expect(source).not.toMatch(/totpSecretSealed\s*,\s*parsed\.data\.code/);
  });

  it('uses a different key from the credential vault', () => {
    // The portal must be able to decrypt a second factor and must never be able to decrypt a
    // client credential. Two keys is what makes that structural.
    expect(source).not.toContain('VAULT_MASTER_KEY');
    expect(source).not.toMatch(/context\.vault\b/);
  });
});
