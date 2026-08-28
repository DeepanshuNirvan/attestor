import { Redis } from 'ioredis';
import type { PanicStopState, PanicStopStore } from '@attestor/core';

/**
 * The panic stop, backed by Redis.
 *
 * Redis rather than the database because the check runs before every outbound request inside a
 * long job, and a stop has to take effect in seconds across every worker process. A key read is the
 * right cost for that; a database round trip per request is not.
 *
 * The stop is also written to the `panic_stop` table by the route that presses it, so the record
 * survives a Redis restart and appears in the engagement's history.
 */

const PLATFORM_KEY = 'attestor:panic-stop:platform';
const engagementKey = (engagementId: string) => `attestor:panic-stop:engagement:${engagementId}`;

interface StoredState {
  scope: 'platform' | 'engagement';
  engagementId: string | null;
  pressedBy: string;
  pressedAt: string;
  reason: string;
}

const INACTIVE: PanicStopState = {
  active: false,
  scope: 'engagement',
  engagementId: null,
  pressedBy: null,
  pressedAt: null,
  reason: null,
};

export class RedisPanicStopStore implements PanicStopStore {
  private readonly redis: Redis;

  constructor(redisUrl: string) {
    this.redis = new Redis(redisUrl, { maxRetriesPerRequest: 2, lazyConnect: false });
  }

  async isActive(engagementId: string): Promise<boolean> {
    const [platform, engagement] = await this.redis.mget(PLATFORM_KEY, engagementKey(engagementId));
    return platform !== null || engagement !== null;
  }

  async state(engagementId: string): Promise<PanicStopState> {
    const [platform, engagement] = await this.redis.mget(PLATFORM_KEY, engagementKey(engagementId));
    const raw = platform ?? engagement;
    if (!raw) return INACTIVE;

    const stored = JSON.parse(raw) as StoredState;
    return {
      active: true,
      scope: stored.scope,
      engagementId: stored.engagementId,
      pressedBy: stored.pressedBy,
      pressedAt: new Date(stored.pressedAt),
      reason: stored.reason,
    };
  }

  async engage(input: {
    scope: 'platform' | 'engagement';
    engagementId: string | null;
    pressedBy: string;
    reason: string;
  }): Promise<void> {
    const stored: StoredState = {
      scope: input.scope,
      engagementId: input.engagementId,
      pressedBy: input.pressedBy,
      pressedAt: new Date().toISOString(),
      reason: input.reason,
    };
    const key =
      input.scope === 'platform' ? PLATFORM_KEY : engagementKey(input.engagementId ?? 'unknown');
    // No expiry. A stop stays in force until a person clears it, which is the whole point.
    await this.redis.set(key, JSON.stringify(stored));
  }

  async clear(input: {
    scope: 'platform' | 'engagement';
    engagementId: string | null;
  }): Promise<void> {
    const key =
      input.scope === 'platform' ? PLATFORM_KEY : engagementKey(input.engagementId ?? 'unknown');
    await this.redis.del(key);
  }

  async close(): Promise<void> {
    await this.redis.quit();
  }
}
