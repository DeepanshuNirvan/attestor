import { describe, expect, it } from 'vitest';
import { createLogger } from '@attestor/shared';
import { resolvePolicy } from '@attestor/policy';
import {
  advertisedMethods,
  requestManipulationProbe,
  sameAnswer,
} from './request-manipulation-probe.ts';
import type { ProbeContext, ProbeRequest, ProbeResponse } from './run-probe-for-engagement.ts';

const { policy } = resolvePolicy([{ name: 'global', yamlSource: 'modules: [web]' }]);

function contextWith(
  respond: (request: ProbeRequest) => Partial<ProbeResponse>,
  readOnly = false,
): { context: ProbeContext; sent: ProbeRequest[] } {
  const sent: ProbeRequest[] = [];
  const context: ProbeContext = {
    policy,
    targets: ['app.example.com'],
    logger: createLogger({ service: 'test', write: () => undefined }),
    readOnly,
    request: (request) => {
      sent.push(request);
      return Promise.resolve({
        status: 200,
        headers: {},
        body: 'ok',
        latencyMs: 2,
        failed: false,
        ...respond(request),
      });
    },
  };
  return { context, sent };
}

const URL_WITH_PARAM = 'https://app.example.com/search?q=shoes';
const PLAIN_URL = 'https://app.example.com/account';

describe('reading an Allow header', () => {
  it('takes the methods from either header the server might use', () => {
    expect(advertisedMethods({ allow: 'GET, HEAD, PUT ' })).toEqual(['GET', 'HEAD', 'PUT']);
    expect(advertisedMethods({ 'access-control-allow-methods': 'get,post' })).toEqual([
      'GET',
      'POST',
    ]);
    expect(advertisedMethods({})).toEqual([]);
  });
});

describe('deciding whether two responses are the same answer', () => {
  it('separates a different status from a different body', () => {
    expect(sameAnswer({ status: 200, body: 'a' }, { status: 200, body: 'a' })).toBe(true);
    expect(sameAnswer({ status: 200, body: 'a' }, { status: 404, body: 'a' })).toBe(false);
    expect(sameAnswer({ status: 200, body: 'a' }, { status: 200, body: 'b' })).toBe(false);
  });
});

describe('the request manipulation probe', () => {
  it('says what it needs rather than reporting nothing when no URL is available', async () => {
    const { context, sent } = contextWith(() => ({}));
    const result = await requestManipulationProbe({ urls: [], maxUrls: 10 }).run(context);
    expect(result.skipped).toContain('No URL was available');
    expect(sent).toHaveLength(0);
  });

  it('sends nothing that could change the client data', async () => {
    const { context, sent } = contextWith(() => ({}));
    await requestManipulationProbe({ urls: [URL_WITH_PARAM], maxUrls: 10 }).run(context);
    // The whole point of the design: it runs unchanged in read-only mode, which is where an
    // authorisation bypass matters most.
    expect([...new Set(sent.map((request) => request.method))].sort()).toEqual([
      'GET',
      'HEAD',
      'OPTIONS',
    ]);
  });

  it('records the methods the server advertises without sending the dangerous ones', async () => {
    const { context, sent } = contextWith((request) =>
      request.method === 'OPTIONS' ? { headers: { allow: 'GET, HEAD, OPTIONS, PUT, DELETE' } } : {},
    );

    const result = await requestManipulationProbe({ urls: [PLAIN_URL], maxUrls: 10 }).run(context);
    expect(result.methods[0]?.notable).toEqual(['PUT', 'DELETE']);
    expect(sent.some((request) => request.method === 'PUT')).toBe(false);
    expect(sent.some((request) => request.method === 'DELETE')).toBe(false);
  });

  it('reports a resource that refuses GET and serves HEAD', async () => {
    const { context } = contextWith((request) =>
      request.method === 'GET' ? { status: 403 } : { status: 200 },
    );

    const result = await requestManipulationProbe({ urls: [PLAIN_URL], maxUrls: 10 }).run(context);
    expect(result.methods[0]?.verbBypass).toEqual({
      restrictedWith: 'GET',
      allowedWith: 'HEAD',
      restrictedStatus: 403,
    });
  });

  it('does not call an unimplemented HEAD an authorisation bypass', async () => {
    // The ordinary case: the resource is public and simply does not implement HEAD. Reporting that
    // as a bypass is how a scanner earns its reputation.
    const { context } = contextWith((request) =>
      request.method === 'HEAD' ? { status: 405 } : { status: 200 },
    );

    const result = await requestManipulationProbe({ urls: [PLAIN_URL], maxUrls: 10 }).run(context);
    expect(result.methods[0]?.verbBypass).toBeUndefined();
  });

  it('records which of two duplicated values the application acted on', async () => {
    const { context } = contextWith((request) => ({
      body: request.url.includes('attestor2') ? 'result-for-2' : 'result-for-1',
    }));

    const result = await requestManipulationProbe({ urls: [URL_WITH_PARAM], maxUrls: 10 }).run(
      context,
    );
    // Both values present, and the body matched the second one: last-wins parsing.
    expect(result.pollution[0]).toMatchObject({ parameter: 'q', resolvedAs: 'last' });
  });

  it('reports first-value parsing, which is the shape a front-end filter misses', async () => {
    const { context } = contextWith((request) => {
      const url = new URL(request.url);
      const first = url.searchParams.get('q');
      return { body: `result-for-${first}` };
    });

    const result = await requestManipulationProbe({ urls: [URL_WITH_PARAM], maxUrls: 10 }).run(
      context,
    );
    expect(result.pollution[0]?.resolvedAs).toBe('first');
  });

  it('finds a client-controlled host header in a redirect target', async () => {
    const { context } = contextWith((request) =>
      request.headers?.['x-forwarded-host']
        ? { status: 302, headers: { location: 'https://attestor-probe.invalid/login' } }
        : {},
    );

    const result = await requestManipulationProbe({ urls: [PLAIN_URL], maxUrls: 10 }).run(context);
    expect(result.hostHeader[0]).toEqual({
      url: PLAIN_URL,
      reflectedVia: 'x-forwarded-host',
      reflectedIn: 'location',
    });
  });

  it('records the header as not reflected rather than saying nothing', async () => {
    const { context } = contextWith(() => ({}));
    const result = await requestManipulationProbe({ urls: [PLAIN_URL], maxUrls: 10 }).run(context);
    expect(result.hostHeader[0]).toEqual({ url: PLAIN_URL });
  });

  it('never uses a marker host that could resolve to a real destination', async () => {
    const { context, sent } = contextWith(() => ({}));
    await requestManipulationProbe({ urls: [PLAIN_URL], maxUrls: 10 }).run(context);
    const marker = sent.find((request) => request.headers?.['x-forwarded-host'])?.headers?.[
      'x-forwarded-host'
    ];
    // RFC 2606 reserves `.invalid`. If the application mails a link built from this, the link is
    // inert, so proving the flaw cannot create a destination somebody could actually receive.
    expect(marker?.endsWith('.invalid')).toBe(true);
  });

  it('honours its own url budget', async () => {
    const { context } = contextWith(() => ({}));
    const urls = Array.from({ length: 20 }, (unused, index) => `${PLAIN_URL}/${index}`);
    const result = await requestManipulationProbe({ urls, maxUrls: 3 }).run(context);
    expect(result.methods).toHaveLength(3);
  });
});
