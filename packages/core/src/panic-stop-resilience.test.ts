import { describe, expect, it } from 'vitest';
import { engagePanicStop, InMemoryPanicStopStore } from './index.ts';

/**
 * The kill sweep talks to the container daemon, and the moment a stop is most needed is exactly
 * when that daemon may be unreachable. It used to throw straight out of the route: the flag was
 * set, so testing really had stopped, but the operator was answered with "internal error" and no
 * audit entry was written. In an emergency that is the one thing that must not happen — the person
 * pressing the button could not tell whether it had worked.
 */

function recordingAuditLog() {
  const entries: { action: string; metadata?: Record<string, unknown> }[] = [];
  return {
    entries,
    record: (entry: { action: string; metadata?: Record<string, unknown> }) => {
      entries.push(entry);
      return Promise.resolve();
    },
  };
}

describe('panic stop when the container daemon is unreachable', () => {
  const input = {
    scope: 'engagement' as const,
    engagementId: '11111111-1111-4111-8111-111111111111',
    pressedBy: 'tester',
    reason: 'the client asked us to stop',
  };

  it('still engages the stop', async () => {
    const store = new InMemoryPanicStopStore();
    const result = await engagePanicStop(input, {
      store,
      auditLog: recordingAuditLog(),
      killRunningContainers: () => Promise.reject(new Error('connect ENOENT /var/run/docker.sock')),
    });

    expect(result.state.active).toBe(true);
    expect(await store.isActive(input.engagementId)).toBe(true);
  });

  it('reports that the sweep failed rather than claiming success', async () => {
    const result = await engagePanicStop(input, {
      store: new InMemoryPanicStopStore(),
      auditLog: recordingAuditLog(),
      killRunningContainers: () => Promise.reject(new Error('connect ENOENT /var/run/docker.sock')),
    });

    expect(result.containersKilled).toBe(0);
    expect(result.containerKillError).toMatch(/docker\.sock/);
  });

  it('still writes the audit entry, with the failure recorded on it', async () => {
    const auditLog = recordingAuditLog();
    await engagePanicStop(input, {
      store: new InMemoryPanicStopStore(),
      auditLog,
      killRunningContainers: () => Promise.reject(new Error('daemon is wedged')),
    });

    const entry = auditLog.entries.find((item) => item.action === 'engagement.panicStopped');
    expect(entry).toBeDefined();
    expect(entry?.metadata?.containerKillError).toBe('daemon is wedged');
  });

  it('says nothing about a failure when the sweep worked', async () => {
    const result = await engagePanicStop(input, {
      store: new InMemoryPanicStopStore(),
      auditLog: recordingAuditLog(),
      killRunningContainers: () => Promise.resolve(3),
    });

    expect(result.containersKilled).toBe(3);
    expect(result.containerKillError).toBeUndefined();
  });
});
