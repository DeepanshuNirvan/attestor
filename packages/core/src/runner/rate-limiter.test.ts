import { describe, expect, it } from 'vitest';
import { resolvePolicy } from '@attestor/policy';
import { OutboundRateLimiter, RunAborted, median, type Clock } from './rate-limiter.ts';

/** A clock that advances only when something sleeps, so tests are fast and deterministic. */
function fakeClock(): Clock & { advance: (ms: number) => void; elapsed: () => number } {
  let current = 0;
  return {
    now: () => current,
    sleep: (milliseconds) => {
      current += milliseconds;
      return Promise.resolve();
    },
    advance: (milliseconds) => {
      current += milliseconds;
    },
    elapsed: () => current,
  };
}

function limitsFrom(yamlFragment: string) {
  const { policy } = resolvePolicy([
    { name: 'global', yamlSource: `modules: [web]\n${yamlFragment}` },
  ]);
  return policy.rateLimits;
}

const fast = 'rateLimits:\n  globalRequestsPerSecond: 10\n  perTargetRequestsPerSecond: 4\n  concurrency: 4\n  jitterMs: 0';

describe('OutboundRateLimiter — pacing', () => {
  it('holds the global rate over a burst', async () => {
    const clock = fakeClock();
    const limiter = new OutboundRateLimiter({ limits: limitsFrom(fast), clock });

    for (let index = 0; index < 30; index += 1) {
      await limiter.acquire(`host-${index % 5}.example`);
      limiter.release({ latencyMs: 100, status: 200 });
    }

    // 30 requests at 10 per second, with a one-second burst allowance, cannot finish faster than
    // roughly two seconds of simulated time.
    expect(clock.elapsed()).toBeGreaterThanOrEqual(1900);
  });

  it('holds a per-target rate even when other targets are idle', async () => {
    const clock = fakeClock();
    const limiter = new OutboundRateLimiter({ limits: limitsFrom(fast), clock });

    for (let index = 0; index < 20; index += 1) {
      await limiter.acquire('one.example');
      limiter.release({ latencyMs: 50, status: 200 });
    }

    // 20 requests at 4 per second to one host: at least four seconds minus the burst allowance.
    expect(clock.elapsed()).toBeGreaterThanOrEqual(3700);
  });
});

describe('OutboundRateLimiter — adaptive behaviour', () => {
  const adaptive = `${fast}\n  adaptive:\n    backOffLatencyIncreasePercent: 50\n    abortLatencyIncreasePercent: 200\n    abortErrorRatePercent: 15\n    abortConsecutiveServerErrors: 20`;

  it('backs off when the target slows down', async () => {
    const clock = fakeClock();
    const backOffs: number[] = [];
    const limiter = new OutboundRateLimiter({
      limits: limitsFrom(adaptive),
      clock,
      onBackOff: (factor) => backOffs.push(factor),
    });

    for (let index = 0; index < 20; index += 1) {
      await limiter.acquire('slow.example');
      limiter.release({ latencyMs: 100, status: 200 });
    }
    for (let index = 0; index < 15; index += 1) {
      await limiter.acquire('slow.example');
      limiter.release({ latencyMs: 180, status: 200 });
    }

    expect(backOffs.length).toBeGreaterThan(0);
    expect(limiter.currentBackOffFactor).toBeLessThan(1);
  });

  it('aborts when latency degrades past the threshold', async () => {
    const clock = fakeClock();
    const limiter = new OutboundRateLimiter({ limits: limitsFrom(adaptive), clock });

    for (let index = 0; index < 20; index += 1) {
      await limiter.acquire('dying.example');
      limiter.release({ latencyMs: 100, status: 200 });
    }

    expect(() => {
      for (let index = 0; index < 15; index += 1) {
        limiter.release({ latencyMs: 600, status: 200 });
      }
    }).toThrow(RunAborted);
  });

  it('aborts on a run of server errors rather than hammering a broken target', () => {
    const clock = fakeClock();
    const limiter = new OutboundRateLimiter({ limits: limitsFrom(adaptive), clock });

    expect(() => {
      for (let index = 0; index < 25; index += 1) {
        limiter.release({ latencyMs: 40, status: 503 });
      }
    }).toThrow(/consecutive server errors/);
  });

  it('resets the consecutive-error count on a good response', () => {
    // The error-rate rule is disabled here so the consecutive-error rule is what is under test;
    // with both live, a run of 500s trips the rate rule first, which is also correct.
    const consecutiveOnly = `${fast}\n  adaptive:\n    abortErrorRatePercent: 100\n    abortConsecutiveServerErrors: 20`;
    const limiter = new OutboundRateLimiter({
      limits: limitsFrom(consecutiveOnly),
      clock: fakeClock(),
    });

    for (let index = 0; index < 19; index += 1) limiter.release({ latencyMs: 40, status: 500 });
    limiter.release({ latencyMs: 40, status: 200 });
    expect(() => {
      for (let index = 0; index < 19; index += 1) limiter.release({ latencyMs: 40, status: 500 });
    }).not.toThrow();

    // The twentieth in the new run does trip it.
    expect(() => limiter.release({ latencyMs: 40, status: 500 })).toThrow(RunAborted);
  });

  it('counts a transport failure as a server error', () => {
    const limiter = new OutboundRateLimiter({ limits: limitsFrom(adaptive), clock: fakeClock() });
    expect(() => {
      for (let index = 0; index < 25; index += 1) {
        limiter.release({ latencyMs: 0, status: 0, failed: true });
      }
    }).toThrow(RunAborted);
  });
});

describe('OutboundRateLimiter — the stop control', () => {
  it('refuses to acquire once a panic stop is signalled', async () => {
    const limiter = new OutboundRateLimiter({
      limits: limitsFrom(fast),
      clock: fakeClock(),
      shouldAbort: () => 'panicStop',
    });
    await expect(limiter.acquire('any.example')).rejects.toThrow(RunAborted);
  });

  it('refuses once the test window closes mid-run', async () => {
    let open = true;
    const limiter = new OutboundRateLimiter({
      limits: limitsFrom(fast),
      clock: fakeClock(),
      shouldAbort: () => (open ? null : 'outOfWindow'),
    });
    await limiter.acquire('any.example');
    limiter.release({ latencyMs: 10, status: 200 });
    open = false;
    await expect(limiter.acquire('any.example')).rejects.toThrow(/outOfWindow/);
  });
});

describe('median', () => {
  it('handles odd, even and empty inputs', () => {
    expect(median([3, 1, 2])).toBe(2);
    expect(median([4, 1, 2, 3])).toBe(2.5);
    expect(median([])).toBe(0);
  });
});
