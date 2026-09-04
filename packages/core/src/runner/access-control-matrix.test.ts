import { describe, expect, it } from 'vitest';
import { createLogger } from '@attestor/shared';
import { resolvePolicy } from '@attestor/policy';
import {
  accessControlMatrixProbe,
  bodyIsSubstantive,
  responseSimilarity,
  sameHostUrlsIn,
  sessionHeadersFrom,
  type AccessControlOptions,
  type AccessIdentity,
} from './access-control-matrix.ts';
import type { ProbeContext, ProbeRequest, ProbeResponse } from './run-probe-for-engagement.ts';

const { policy } = resolvePolicy([{ name: 'global', yamlSource: 'modules: [web, api]' }]);

const ALICE_BASKET =
  '{"id":41,"user":{"id":41,"email":"alice@example.com","name":"Alice Turner"},"items":[{"sku":"A-1","name":"Widget","price":1299},{"sku":"A-2","name":"Gadget","price":4599}],"total":5898}';
const BOB_BASKET =
  '{"id":77,"user":{"id":77,"email":"bob@example.com","name":"Bob Merrick"},"items":[{"sku":"B-9","name":"Sprocket","price":250}],"total":250}';
const PUBLIC_CATALOGUE =
  '{"products":[{"sku":"A-1","name":"Widget","price":1299},{"sku":"B-9","name":"Sprocket","price":250},{"sku":"C-3","name":"Flange","price":700}]}';

const alice: AccessIdentity = {
  name: 'user (primary)',
  roleName: 'user',
  isSecondary: false,
  headers: { authorization: 'Bearer alice-token' },
};
const bob: AccessIdentity = {
  name: 'user (second account)',
  roleName: 'user',
  isSecondary: true,
  headers: { authorization: 'Bearer bob-token' },
};

/** A fake application. `respond` decides what each identity sees for each URL. */
function contextWith(
  respond: (request: ProbeRequest) => Partial<ProbeResponse>,
): { context: ProbeContext; sent: ProbeRequest[] } {
  const sent: ProbeRequest[] = [];
  const context: ProbeContext = {
    policy,
    targets: ['app.example.com'],
    logger: createLogger({ service: 'test', write: () => undefined }),
    readOnly: true,
    request: (request) => {
      sent.push(request);
      const partial = respond(request);
      return Promise.resolve({
        status: 200,
        headers: {},
        body: '',
        latencyMs: 5,
        failed: false,
        ...partial,
      });
    },
  };
  return { context, sent };
}

function options(overrides: Partial<AccessControlOptions> = {}): AccessControlOptions {
  return {
    identities: [alice, bob],
    templates: [
      { method: 'GET', url: 'https://app.example.com/api/basket/41', owner: 'user (primary)' },
    ],
    similarityThreshold: 0.9,
    maxReplayRequests: 100,
    testUnauthenticated: true,
    rolePairs: [],
    ...overrides,
  };
}

describe('response similarity', () => {
  it('is 1 for identical bodies', () => {
    expect(responseSimilarity(ALICE_BASKET, ALICE_BASKET)).toBe(1);
  });

  it('is low for two users looking at their own data', () => {
    // The whole engine rests on this number. Two baskets share their JSON keys and little else, and
    // if that scored as "substantially the same" every per-user endpoint would be reported as broken.
    expect(responseSimilarity(ALICE_BASKET, BOB_BASKET)).toBeLessThan(0.5);
  });

  it('does not call a short response the same as a long one that contains it', () => {
    const summary = '{"id":41}';
    expect(responseSimilarity(ALICE_BASKET, summary)).toBeLessThan(0.3);
  });

  it('treats two empty bodies as identical, which is why substance is checked separately', () => {
    expect(responseSimilarity('', '')).toBe(1);
    expect(bodyIsSubstantive('')).toBe(false);
    expect(bodyIsSubstantive('{}')).toBe(false);
    expect(bodyIsSubstantive(ALICE_BASKET)).toBe(true);
  });
});

describe('establishing a session, whatever the application uses', () => {
  const login = {
    url: 'https://app.example.com/rest/user/login',
    usernameField: 'email',
    passwordField: 'password',
    username: 'alice@example.com',
    password: 'a-password',
    tokenHeader: 'authorization',
    tokenTemplate: 'Bearer {token}',
  };

  it('reads a token out of a JSON body at the configured path', () => {
    const resolved = sessionHeadersFrom(
      {
        status: 200,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ authentication: { token: 'jwt-value' } }),
      },
      { ...login, tokenPath: 'authentication.token' },
    );
    expect(resolved).toEqual({ authorization: 'Bearer jwt-value' });
  });

  it('uses a session cookie when that is what the application issues', () => {
    const resolved = sessionHeadersFrom(
      {
        status: 200,
        headers: { 'set-cookie': 'sid=abc123; Path=/; HttpOnly; SameSite=Lax' },
        body: 'ok',
      },
      login,
    );
    // Attributes are instructions to a browser and are never sent back on a request.
    expect(resolved).toEqual({ cookie: 'sid=abc123' });
  });

  it('takes both when the application expects both', () => {
    const resolved = sessionHeadersFrom(
      {
        status: 200,
        headers: { 'set-cookie': 'sid=abc123; Path=/' },
        body: JSON.stringify({ token: 'jwt-value' }),
      },
      { ...login, tokenPath: 'token' },
    );
    expect(resolved).toEqual({ cookie: 'sid=abc123', authorization: 'Bearer jwt-value' });
  });

  it('honours a custom header and format, not just bearer', () => {
    const resolved = sessionHeadersFrom(
      { status: 200, headers: {}, body: JSON.stringify({ key: 'k-1' }) },
      { ...login, tokenPath: 'key', tokenHeader: 'X-Api-Key', tokenTemplate: '{token}' },
    );
    expect(resolved).toEqual({ 'x-api-key': 'k-1' });
  });

  it('falls back to a token returned in a response header', () => {
    const resolved = sessionHeadersFrom(
      { status: 200, headers: { 'x-auth-token': 'header-token' }, body: 'ok' },
      login,
    );
    expect(resolved).toEqual({ 'x-auth-token': 'header-token' });
  });

  it('says why rather than guessing when the login gives nothing back', () => {
    expect(sessionHeadersFrom({ status: 401, headers: {}, body: 'no' }, login)).toEqual({
      error: 'the login endpoint answered 401',
    });
    const empty = sessionHeadersFrom({ status: 200, headers: {}, body: 'ok' }, login);
    expect('error' in empty && empty.error).toContain('no session to present');
  });

  it('marks the login as the one request that is not a test', async () => {
    // Read-only mode refuses every verb but GET and HEAD. Signing in is a POST, so without this
    // marking an engagement in read-only mode — the recommended setting against production — could
    // never run an authenticated test at all. Verified for real: it aborted before sending one.
    const { context, sent } = contextWith((request) =>
      request.url.endsWith('/login')
        ? { status: 200, body: JSON.stringify({ authentication: { token: 't' } }) }
        : { body: ALICE_BASKET },
    );

    await accessControlMatrixProbe(
      options({
        identities: [
          { ...alice, headers: {}, login: { ...login, tokenPath: 'authentication.token' } },
          bob,
        ],
      }),
    ).run(context);

    const loginRequest = sent.find((request) => request.url.endsWith('/login'));
    expect(loginRequest?.method).toBe('POST');
    expect(loginRequest?.purpose).toBe('authenticate');
    // Nothing else claims the exemption.
    expect(sent.filter((request) => request.purpose === 'authenticate')).toHaveLength(1);
  });

  it('leaves an identity out, with a reason, when its login fails', async () => {
    const { context } = contextWith((request) =>
      request.url.endsWith('/login') ? { status: 401, body: 'nope' } : { body: ALICE_BASKET },
    );

    const result = await accessControlMatrixProbe(
      options({
        identities: [
          { ...alice, headers: {}, login: { ...login, tokenPath: 'authentication.token' } },
          bob,
        ],
      }),
    ).run(context);

    expect(result.unavailableIdentities).toHaveLength(1);
    expect(result.unavailableIdentities[0]?.reason).toContain('401');
    expect(result.skipped).toContain('two accounts');
  });

  it('signs in and then compares, for a password credential', async () => {
    const { context } = contextWith((request) => {
      if (request.url.endsWith('/login')) {
        return { status: 200, body: JSON.stringify({ authentication: { token: 't' } }) };
      }
      if (request.identity === 'anonymous') return { status: 401, body: 'no' };
      return { body: ALICE_BASKET };
    });

    const result = await accessControlMatrixProbe(
      options({
        identities: [
          { ...alice, headers: {}, login: { ...login, tokenPath: 'authentication.token' } },
          bob,
        ],
      }),
    ).run(context);

    expect(result.unavailableIdentities).toHaveLength(0);
    expect(result.observations.some((entry) => entry.kind === 'crossUserAccess')).toBe(true);
  });
});

describe('finding the owner own object URLs', () => {
  it('picks up account-specific URLs out of what the owner is told', () => {
    const body = JSON.stringify({ user: { id: 6 }, links: ['/rest/basket/6', '/api/orders/91'] });
    const urls = sameHostUrlsIn(body, 'https://app.example.com/account');
    expect(urls).toContain('https://app.example.com/rest/basket/6');
    expect(urls).toContain('https://app.example.com/api/orders/91');
  });

  it('ignores another host, which nobody authorised us to touch', () => {
    const body = '<a href="https://cdn.other.example/asset/12">x</a><a href="/orders/7">y</a>';
    const urls = sameHostUrlsIn(body, 'https://app.example.com/');
    expect(urls).toEqual(['https://app.example.com/orders/7']);
  });

  it('ignores plain pages, which the crawl already found', () => {
    const body = '<a href="/about">about</a><a href="/contact">contact</a>';
    expect(sameHostUrlsIn(body, 'https://app.example.com/')).toEqual([]);
  });
});

describe('the access control matrix', () => {
  it('reports one account reading another account data', async () => {
    const { context } = contextWith((request) =>
      request.identity === 'anonymous' ? { status: 401, body: 'unauthorised' } : { body: ALICE_BASKET },
    );

    const result = await accessControlMatrixProbe(options()).run(context);
    const finding = result.observations.find((entry) => entry.kind === 'crossUserAccess');
    expect(finding).toBeDefined();
    expect(finding?.actor).toBe('user (second account)');
    expect(finding?.similarity).toBe(1);
  });

  it('does not report an endpoint that serves each account its own data', async () => {
    const { context } = contextWith((request) => {
      if (request.identity === 'anonymous') return { status: 401, body: 'unauthorised' };
      return { body: request.identity === 'user (primary)' ? ALICE_BASKET : BOB_BASKET };
    });

    const result = await accessControlMatrixProbe(options()).run(context);
    expect(result.observations.filter((entry) => entry.kind === 'crossUserAccess')).toHaveLength(0);
  });

  it('does not report a resource the whole world can already read', async () => {
    // Everybody gets the same catalogue, including an anonymous caller. Two users matching each
    // other says nothing about access control, and reporting it would be a false finding.
    const { context } = contextWith(() => ({ body: PUBLIC_CATALOGUE }));

    const result = await accessControlMatrixProbe(options()).run(context);
    expect(result.observations.filter((entry) => entry.kind === 'crossUserAccess')).toHaveLength(0);
    // The crawl found this URL while signed out, so anonymous access to it is what public means.
    expect(result.observations.some((entry) => entry.kind === 'publicResource')).toBe(true);
    expect(result.observations.some((entry) => entry.kind === 'unauthenticatedAccess')).toBe(false);
  });

  it('reports anonymous access to a URL that only the owner was told about', async () => {
    // The other half of the same rule. This URL was never linked publicly — it came out of the
    // owner's own response — so an unauthenticated caller getting it is worth a tester's attention.
    const { context } = contextWith(() => ({ body: ALICE_BASKET }));

    const result = await accessControlMatrixProbe(
      options({
        templates: [
          {
            method: 'GET',
            url: 'https://app.example.com/api/basket/41',
            owner: 'user (primary)',
            ownerDiscovered: true,
          },
        ],
      }),
    ).run(context);

    expect(result.observations.some((entry) => entry.kind === 'unauthenticatedAccess')).toBe(true);
  });

  it('does not draw a conclusion from an empty response', async () => {
    const { context } = contextWith((request) =>
      request.identity === 'anonymous' ? { status: 401, body: '' } : { status: 204, body: '' },
    );

    const result = await accessControlMatrixProbe(options()).run(context);
    expect(result.observations.filter((entry) => entry.kind === 'crossUserAccess')).toHaveLength(0);
  });

  it('records a refusal as the control working, not as an absence of evidence', async () => {
    const { context } = contextWith((request) =>
      request.identity === 'user (primary)' ? { body: ALICE_BASKET } : { status: 403, body: 'forbidden' },
    );

    const result = await accessControlMatrixProbe(options()).run(context);
    const denied = result.observations.filter((entry) => entry.kind === 'correctlyDenied');
    expect(denied.length).toBeGreaterThanOrEqual(2);
  });

  it('calls a match on an empty body inconclusive rather than a pass', async () => {
    // Observed against a real application: an endpoint that answers 200 with a near-empty body for
    // everybody. Nothing was learned about it. Recording that as "correctly denied" would put a
    // green tick beside a control nobody exercised, which is worse than leaving it blank.
    const { context } = contextWith(() => ({ status: 200, body: '{"user":{}}' }));

    const result = await accessControlMatrixProbe(options()).run(context);
    expect(result.observations.every((entry) => entry.kind === 'inconclusive')).toBe(true);
    expect(result.observations.some((entry) => entry.kind === 'correctlyDenied')).toBe(false);
  });

  it('says nothing at all when the owner request itself failed', async () => {
    const { context } = contextWith(() => ({ status: 500, body: 'server error' }));

    const result = await accessControlMatrixProbe(options()).run(context);
    expect(result.observations).toHaveLength(1);
    expect(result.observations[0]?.kind).toBe('inconclusive');
  });

  it('reports a role that reaches another role endpoint', async () => {
    const admin: AccessIdentity = {
      name: 'admin',
      roleName: 'admin',
      isSecondary: false,
      headers: { authorization: 'Bearer admin-token' },
    };
    const { context } = contextWith((request) =>
      request.identity === 'anonymous' ? { status: 401, body: 'unauthorised' } : { body: ALICE_BASKET },
    );

    const result = await accessControlMatrixProbe(
      options({
        identities: [admin, alice],
        templates: [
          { method: 'GET', url: 'https://app.example.com/admin/users', owner: 'admin' },
        ],
      }),
    ).run(context);

    expect(result.observations.some((entry) => entry.kind === 'crossRoleAccess')).toBe(true);
  });

  /* Applications differ. None of the following is an error. ------------------------------------ */

  it('stops cleanly when the engagement holds only one account', async () => {
    const { context, sent } = contextWith(() => ({ body: ALICE_BASKET }));

    const result = await accessControlMatrixProbe(options({ identities: [alice] })).run(context);
    expect(result.skipped).toContain('at least two accounts');
    expect(result.observations).toHaveLength(0);
    expect(sent).toHaveLength(0);
  });

  it('stops cleanly when the crawl discovered nothing to replay', async () => {
    const { context } = contextWith(() => ({ body: ALICE_BASKET }));

    const result = await accessControlMatrixProbe(options({ templates: [] })).run(context);
    expect(result.skipped).toContain('No replayable requests');
    expect(result.observations).toHaveLength(0);
  });

  it('leaves state-changing requests alone unless asked, and never in read-only mode', async () => {
    const { context, sent } = contextWith(() => ({ body: ALICE_BASKET }));

    const result = await accessControlMatrixProbe(
      options({
        templates: [
          { method: 'POST', url: 'https://app.example.com/api/orders', owner: 'user (primary)' },
        ],
      }),
    ).run(context);

    expect(sent).toHaveLength(0);
    expect(result.skipped).toContain('No replayable requests');
  });

  it('honours the replay budget rather than crawling a client forever', async () => {
    const templates = Array.from({ length: 50 }, (unused, index) => ({
      method: 'GET',
      url: `https://app.example.com/api/basket/${index}`,
      owner: 'user (primary)',
    }));
    const { context, sent } = contextWith(() => ({ body: ALICE_BASKET }));

    await accessControlMatrixProbe(options({ templates, maxReplayRequests: 10 })).run(context);
    expect(sent.length).toBeLessThanOrEqual(13);
  });

  it('only compares the role pairs the policy names', async () => {
    const { context } = contextWith((request) =>
      request.identity === 'anonymous' ? { status: 401, body: 'x' } : { body: ALICE_BASKET },
    );

    const result = await accessControlMatrixProbe(
      options({ rolePairs: [['admin', 'auditor']] }),
    ).run(context);

    expect(result.observations.some((entry) => entry.actor === 'user (second account)')).toBe(false);
  });
});
