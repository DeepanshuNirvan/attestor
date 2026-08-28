import type { AuditLog } from './audit/audit-log.ts';

/**
 * The stop control.
 *
 * One action halts every running job for an engagement, or for the whole platform, within seconds.
 * It is a prominent button in the console and a CLI command, and who pressed it is recorded.
 *
 * The flag is checked in three places, not one: before a tool is launched, before every outbound
 * request inside a long-running job, and by the worker loop between jobs. A single check point
 * would leave an in-flight scan running for as long as the tool takes to finish.
 */

export interface PanicStopState {
  active: boolean;
  scope: 'platform' | 'engagement';
  engagementId: string | null;
  pressedBy: string | null;
  pressedAt: Date | null;
  reason: string | null;
}

export interface PanicStopStore {
  isActive(engagementId: string): Promise<boolean>;
  state(engagementId: string): Promise<PanicStopState>;
  engage(input: {
    scope: 'platform' | 'engagement';
    engagementId: string | null;
    pressedBy: string;
    reason: string;
  }): Promise<void>;
  clear(input: {
    scope: 'platform' | 'engagement';
    engagementId: string | null;
    clearedBy: string;
    reason: string;
  }): Promise<void>;
}

const INACTIVE: PanicStopState = {
  active: false,
  scope: 'engagement',
  engagementId: null,
  pressedBy: null,
  pressedAt: null,
  reason: null,
};

/** Used by tests and by a single-process development setup. Production uses the Redis-backed store. */
export class InMemoryPanicStopStore implements PanicStopStore {
  private platformStop: PanicStopState = INACTIVE;
  private readonly engagementStops = new Map<string, PanicStopState>();

  isActive(engagementId: string): Promise<boolean> {
    return Promise.resolve(
      this.platformStop.active || (this.engagementStops.get(engagementId)?.active ?? false),
    );
  }

  state(engagementId: string): Promise<PanicStopState> {
    if (this.platformStop.active) return Promise.resolve(this.platformStop);
    return Promise.resolve(this.engagementStops.get(engagementId) ?? INACTIVE);
  }

  engage(input: {
    scope: 'platform' | 'engagement';
    engagementId: string | null;
    pressedBy: string;
    reason: string;
  }): Promise<void> {
    const state: PanicStopState = {
      active: true,
      scope: input.scope,
      engagementId: input.engagementId,
      pressedBy: input.pressedBy,
      pressedAt: new Date(),
      reason: input.reason,
    };
    if (input.scope === 'platform') this.platformStop = state;
    else if (input.engagementId) this.engagementStops.set(input.engagementId, state);
    return Promise.resolve();
  }

  clear(input: {
    scope: 'platform' | 'engagement';
    engagementId: string | null;
  }): Promise<void> {
    if (input.scope === 'platform') this.platformStop = INACTIVE;
    else if (input.engagementId) this.engagementStops.delete(input.engagementId);
    return Promise.resolve();
  }
}

export interface PanicStopDependencies {
  store: PanicStopStore;
  auditLog: AuditLog;
  /** Kills running containers. Returns how many it stopped. */
  killRunningContainers: (engagementId?: string) => Promise<number>;
}

export interface PanicStopResult {
  containersKilled: number;
  state: PanicStopState;
}

export async function engagePanicStop(
  input: {
    scope: 'platform' | 'engagement';
    engagementId: string | null;
    pressedBy: string;
    reason: string;
  },
  dependencies: PanicStopDependencies,
): Promise<PanicStopResult> {
  if (input.scope === 'engagement' && !input.engagementId) {
    throw new Error('an engagement-scoped stop needs an engagement id');
  }
  if (input.reason.trim().length < 3) {
    throw new Error('a stop must carry a reason, however short');
  }

  // Set the flag before killing anything: a job that starts during the kill sweep must still find
  // the stop in force.
  await dependencies.store.engage(input);
  const containersKilled = await dependencies.killRunningContainers(input.engagementId ?? undefined);

  await dependencies.auditLog.record({
    actorId: input.pressedBy,
    actorKind: 'staff',
    action: 'engagement.panicStopped',
    subjectType: input.scope === 'platform' ? 'platform' : 'engagement',
    subjectId: input.engagementId ?? 'platform',
    metadata: { reason: input.reason, containersKilled, scope: input.scope },
  });

  return {
    containersKilled,
    state: await dependencies.store.state(input.engagementId ?? 'platform'),
  };
}

export async function clearPanicStop(
  input: {
    scope: 'platform' | 'engagement';
    engagementId: string | null;
    clearedBy: string;
    reason: string;
  },
  dependencies: Pick<PanicStopDependencies, 'store' | 'auditLog'>,
): Promise<void> {
  await dependencies.store.clear(input);
  await dependencies.auditLog.record({
    actorId: input.clearedBy,
    actorKind: 'staff',
    action: 'engagement.panicStopCleared',
    subjectType: input.scope === 'platform' ? 'platform' : 'engagement',
    subjectId: input.engagementId ?? 'platform',
    metadata: { reason: input.reason, scope: input.scope },
  });
}
