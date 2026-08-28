import type { RateLimits } from '@attestor/policy';

/**
 * Outbound rate limiting and adaptive abort.
 *
 * Every request the platform makes passes through here. The limits come from the resolved policy,
 * which cannot express a value above the ceilings in the policy schema, so there is no combination
 * of settings that produces flood-shaped traffic.
 *
 * The adaptive half watches what the target is doing back: if latency climbs or errors appear, the
 * rate drops; if it gets worse, the run aborts and the tester is told. A client's site going slow
 * during a test is our problem to notice, not theirs to report.
 */

export interface Clock {
  now(): number;
  sleep(milliseconds: number): Promise<void>;
}

export const systemClock: Clock = {
  now: () => Date.now(),
  sleep: (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
};

/** Refills continuously rather than in ticks, so a burst cannot accumulate across an idle period. */
class TokenBucket {
  private tokens: number;
  private lastRefillAt: number;
  private readonly ratePerSecond: number;
  private readonly clock: Clock;
  /** At most one second of burst, so a paused run does not resume with a spike. */
  private readonly capacity: number;

  constructor(ratePerSecond: number, clock: Clock, capacity = Math.max(1, ratePerSecond)) {
    this.ratePerSecond = ratePerSecond;
    this.clock = clock;
    this.capacity = capacity;
    this.tokens = capacity;
    this.lastRefillAt = clock.now();
  }

  /** Milliseconds to wait before a token is available. Zero when one is available now. */
  waitMs(): number {
    this.refill();
    if (this.tokens >= 1) return 0;
    return Math.ceil(((1 - this.tokens) / this.ratePerSecond) * 1000);
  }

  take(): void {
    this.refill();
    this.tokens -= 1;
  }

  private refill(): void {
    const now = this.clock.now();
    const elapsedSeconds = (now - this.lastRefillAt) / 1000;
    if (elapsedSeconds <= 0) return;
    this.tokens = Math.min(this.capacity, this.tokens + elapsedSeconds * this.ratePerSecond);
    this.lastRefillAt = now;
  }
}

export type AbortReason =
  | 'latencyDegradation'
  | 'errorRate'
  | 'consecutiveServerErrors'
  | 'panicStop'
  | 'outOfWindow';

export class RunAborted extends Error {
  readonly reason: AbortReason;

  constructor(reason: AbortReason, message: string) {
    super(message);
    this.name = 'RunAborted';
    this.reason = reason;
  }
}

export interface RequestOutcome {
  latencyMs: number;
  status: number;
  /** Transport-level failure, as distinct from an HTTP error status. */
  failed?: boolean;
}

export interface RateLimiterOptions {
  limits: RateLimits;
  clock?: Clock;
  /** Called when the limiter throttles itself, so the console can show why a run slowed down. */
  onBackOff?: (factor: number, reason: string) => void;
  /** Consulted before every request. Returning a reason aborts the run. */
  shouldAbort?: () => AbortReason | null;
}

/**
 * Baseline latency is the median of the first `BASELINE_SAMPLE` responses. Median rather than mean
 * because one slow response during warm-up would otherwise set an unusable baseline.
 */
const BASELINE_SAMPLE = 20;
const RECENT_WINDOW = 50;

export class OutboundRateLimiter {
  private readonly globalBucket: TokenBucket;
  private readonly perTargetBuckets = new Map<string, TokenBucket>();
  private readonly clock: Clock;
  private readonly baselineSamples: number[] = [];
  private readonly recentLatencies: number[] = [];
  private readonly recentStatuses: number[] = [];
  private consecutiveServerErrors = 0;
  private baselineMedian: number | null = null;
  private backOffFactor = 1;
  private inFlight = 0;

  private readonly options: RateLimiterOptions;

  constructor(options: RateLimiterOptions) {
    this.options = options;
    this.clock = options.clock ?? systemClock;
    this.globalBucket = new TokenBucket(options.limits.globalRequestsPerSecond, this.clock);
  }

  get currentBackOffFactor(): number {
    return this.backOffFactor;
  }

  /** Waits until it is this request's turn. Throws RunAborted when the run must stop. */
  async acquire(target: string): Promise<void> {
    const abortReason = this.options.shouldAbort?.();
    if (abortReason) {
      throw new RunAborted(abortReason, `run aborted before request to ${target}: ${abortReason}`);
    }

    while (this.inFlight >= this.effectiveConcurrency()) {
      await this.clock.sleep(25);
    }

    let bucket = this.perTargetBuckets.get(target);
    if (!bucket) {
      bucket = new TokenBucket(this.effectivePerTargetRate(), this.clock);
      this.perTargetBuckets.set(target, bucket);
    }

    for (;;) {
      const wait = Math.max(this.globalBucket.waitMs(), bucket.waitMs());
      if (wait === 0) break;
      await this.clock.sleep(wait);
    }

    this.globalBucket.take();
    bucket.take();
    this.inFlight += 1;

    const jitter = this.options.limits.jitterMs;
    if (jitter > 0) await this.clock.sleep(Math.floor(Math.random() * jitter));
  }

  /** Called after every request, whatever the outcome. */
  release(outcome: RequestOutcome): void {
    this.inFlight = Math.max(0, this.inFlight - 1);
    this.record(outcome);
  }

  private effectiveConcurrency(): number {
    return Math.max(1, Math.floor(this.options.limits.concurrency * this.backOffFactor));
  }

  private effectivePerTargetRate(): number {
    return Math.max(0.2, this.options.limits.perTargetRequestsPerSecond * this.backOffFactor);
  }

  private record(outcome: RequestOutcome): void {
    const { adaptive } = this.options.limits;

    if (outcome.failed || outcome.status >= 500) {
      this.consecutiveServerErrors += 1;
      if (this.consecutiveServerErrors >= adaptive.abortConsecutiveServerErrors) {
        throw new RunAborted(
          'consecutiveServerErrors',
          `${this.consecutiveServerErrors} consecutive server errors or transport failures. The target is not healthy; stopping.`,
        );
      }
    } else {
      this.consecutiveServerErrors = 0;
    }

    this.recentStatuses.push(outcome.status);
    if (this.recentStatuses.length > RECENT_WINDOW) this.recentStatuses.shift();

    if (this.baselineMedian === null) {
      this.baselineSamples.push(outcome.latencyMs);
      if (this.baselineSamples.length >= BASELINE_SAMPLE) {
        this.baselineMedian = median(this.baselineSamples);
      }
      return;
    }

    this.recentLatencies.push(outcome.latencyMs);
    if (this.recentLatencies.length > RECENT_WINDOW) this.recentLatencies.shift();
    if (this.recentLatencies.length < 10) return;

    const errorRate =
      (this.recentStatuses.filter((status) => status >= 500).length / this.recentStatuses.length) *
      100;
    if (errorRate > adaptive.abortErrorRatePercent) {
      throw new RunAborted(
        'errorRate',
        `${errorRate.toFixed(0)}% of recent responses were server errors, above the ${adaptive.abortErrorRatePercent}% abort threshold.`,
      );
    }

    const currentMedian = median(this.recentLatencies);
    const increasePercent = ((currentMedian - this.baselineMedian) / this.baselineMedian) * 100;

    if (increasePercent >= adaptive.abortLatencyIncreasePercent) {
      throw new RunAborted(
        'latencyDegradation',
        `Median latency rose ${increasePercent.toFixed(0)}% above baseline (${this.baselineMedian.toFixed(0)}ms to ${currentMedian.toFixed(0)}ms). Stopping rather than degrading the target further.`,
      );
    }

    if (increasePercent >= adaptive.backOffLatencyIncreasePercent) {
      if (this.backOffFactor > 0.25) {
        this.backOffFactor = Math.max(0.25, this.backOffFactor / 2);
        this.options.onBackOff?.(
          this.backOffFactor,
          `median latency up ${increasePercent.toFixed(0)}% on baseline`,
        );
      }
    } else if (increasePercent < adaptive.backOffLatencyIncreasePercent / 2 && this.backOffFactor < 1) {
      // Recover slowly. A target that has just stopped struggling should not be hit at full rate.
      this.backOffFactor = Math.min(1, this.backOffFactor * 1.25);
    }
  }
}

export function median(values: readonly number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? ((sorted[middle - 1] ?? 0) + (sorted[middle] ?? 0)) / 2
    : (sorted[middle] ?? 0);
}
