import { describe, expect, it } from 'vitest';
import { createLogger } from '@attestor/shared';
import { resolvePolicy } from '@attestor/policy';
import { isThrottleResponse, rateLimitProbe } from './rate-limit-probe.ts';
import type { ProbeContext, ProbeRequest, ProbeResponse } from './run-probe-for-engagement.ts';

const { policy } = resolvePolicy([{ name: 'global', yamlSource: 'modules: [web]' }]);

function contextWith(
  respond: (request: ProbeRequest, attempt: number) => Partial<ProbeResponse>,
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
        latencyMs: 3,
        failed: false,
        ...respond(request, sent.length),
      });
    },
  };
  return { context, sent };
}

const login = {
  url: 'https://app.example.com/rest/user/login',
  method: 'POST' as const,
  description: 'the sign-in endpoint',
  body: { email: 'nobody.attestor-probe@invalid.test', password: 'not-a-real-password' },
};

describe('recognising a throttle', () => {
  it('accepts the statuses that mean it, and a Retry-After on any status', () => {
    expect(isThrottleResponse(429, {})).toBe(true);
    expect(isThrottleResponse(503, {})).toBe(true);
    expect(isThrottleResponse(200, { 'retry-after': '30' })).toBe(true);
    expect(isThrottleResponse(401, {})).toBe(false);
    expect(isThrottleResponse(200, {})).toBe(false);
  });
});

describe('the rate limit probe', () => {
  it('stops at the request where throttling appears', async () => {
    const { context, sent } = contextWith((unusedRequest, attempt) =>
      attempt >= 8 ? { status: 429 } : { status: 401 },
    );

    const result = await rateLimitProbe({ targets: [login], burst: 30 }).run(context);
    expect(result.observations[0]?.throttledAfter).toBe(8);
    expect(result.observations[0]?.throttleStatus).toBe(429);
    // It stops as soon as it has its answer rather than finishing the burst out of habit.
    expect(sent).toHaveLength(8);
  });

  it('reports the burst it managed rather than claiming there is no limit', async () => {
    const { context } = contextWith(() => ({ status: 401 }));

    const result = await rateLimitProbe({ targets: [login], burst: 30 }).run(context);
    expect(result.observations[0]?.throttledAfter).toBeNull();
    expect(result.observations[0]?.requestsSent).toBe(30);
  });

  it('never sends more than the burst it was given', async () => {
    const { context, sent } = contextWith(() => ({ status: 200 }));
    await rateLimitProbe({ targets: [login], burst: 10 }).run(context);
    expect(sent).toHaveLength(10);
  });

  it('uses an address that cannot belong to anybody', () => {
    // The whole safety case. A burst of failed logins against a real account locks that account,
    // which turns a test into an incident on the client's side.
    expect(login.body.email).toContain('invalid.test');
  });

  it('leaves a state-changing endpoint alone in read-only mode, and says so', async () => {
    const { context, sent } = contextWith(() => ({ status: 200 }), true);

    const result = await rateLimitProbe({ targets: [login], burst: 30 }).run(context);
    expect(sent).toHaveLength(0);
    expect(result.observations[0]?.skipped).toContain('read-only');
  });

  it('still probes a GET endpoint in read-only mode', async () => {
    const { context, sent } = contextWith(() => ({ status: 200 }), true);

    await rateLimitProbe({
      targets: [{ url: 'https://app.example.com/search?q=a', method: 'GET', description: 'search' }],
      burst: 5,
    }).run(context);
    expect(sent).toHaveLength(5);
  });

  it('stops cleanly when nothing was named to probe', async () => {
    const { context, sent } = contextWith(() => ({ status: 200 }));
    const result = await rateLimitProbe({ targets: [], burst: 30 }).run(context);
    expect(result.skipped).toContain('No endpoint was named');
    expect(sent).toHaveLength(0);
  });

  it('does not read a target falling over as a rate limit', async () => {
    const { context } = contextWith((unusedRequest, attempt) =>
      attempt >= 4 ? { failed: true, status: 0 } : { status: 401 },
    );

    const result = await rateLimitProbe({ targets: [login], burst: 30 }).run(context);
    expect(result.observations[0]?.throttledAfter).toBeNull();
  });

  it('reports a burst that could not be completed as unmeasured, not as an absent limit', async () => {
    // The whole finding rests on "we asked thirty times and nobody stopped us". A connection that
    // was refused is not an answer, and against a live target that had fallen over this wrote a
    // medium-severity "no throttling within 1 requests" from a single refused connection.
    const { context } = contextWith(() => ({ failed: true, status: 0 }));

    const result = await rateLimitProbe({ targets: [login], burst: 30 }).run(context);
    expect(result.observations[0]?.skipped).toContain('stopped answering');
    expect(result.observations[0]?.throttledAfter).toBeNull();
  });
});
