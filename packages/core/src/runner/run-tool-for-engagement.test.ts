import { describe, expect, it, vi } from 'vitest';
import { createLogger, secretRegistry } from '@attestor/shared';
import { resolvePolicy } from '@attestor/policy';
import { InMemoryAuditLog } from '../audit/audit-log.ts';
import type { EngagementScopeContext } from '../scope/scope-guard.ts';
import type { ContainerRunner, ContainerRunResult } from './container-runner.ts';
import { runToolForEngagement, type ToolRunDependencies } from './run-tool-for-engagement.ts';

const NOW = new Date('2026-08-19T09:00:00Z');
const { policy } = resolvePolicy([{ name: 'global', yamlSource: 'modules: [recon, web]' }]);

function silentLogger() {
  return createLogger({ service: 'test', write: () => undefined });
}

function scopeContext(overrides: Partial<EngagementScopeContext> = {}): EngagementScopeContext {
  return {
    engagementId: 'eng-1',
    state: 'running',
    authorisation: {
      id: 'auth-1',
      signedAt: new Date('2026-08-01T00:00:00Z'),
      revokedAt: null,
      validFrom: new Date('2026-08-17T00:00:00Z'),
      validUntil: new Date('2026-08-24T00:00:00Z'),
    },
    scopeItems: [
      { id: 'scope-1', kind: 'wildcard', value: '*.client.example', included: true },
    ],
    testWindows: [],
    timezone: 'UTC',
    ownedPrivateRanges: [],
    thirdPartyInfrastructureAcknowledged: true,
    cloudTestingPolicyAcknowledged: false,
    panicStopActive: false,
    ...overrides,
  };
}

/** A container runner that records what it was asked to do and never starts anything. */
function fakeContainerRunner(result?: Partial<ContainerRunResult>) {
  const runs: unknown[] = [];
  const runner = {
    run: vi.fn((request: unknown) => {
      runs.push(request);
      return Promise.resolve({
        exitCode: 0,
        stdout: '{"findings":[]}',
        stderr: '',
        durationMs: 1200,
        timedOut: false,
        ...result,
      });
    }),
    createRunNetwork: vi.fn(() => Promise.resolve()),
    removeRunNetwork: vi.fn(() => Promise.resolve()),
    killAllRunContainers: vi.fn(() => Promise.resolve(0)),
    imageDigestFor: vi.fn(() => Promise.resolve(null)),
  };
  return { runner: runner as unknown as ContainerRunner, runs, spies: runner };
}

function dependencies(
  overrides: Partial<ToolRunDependencies> = {},
): ToolRunDependencies & { auditLog: InMemoryAuditLog } {
  const { runner } = fakeContainerRunner();
  const auditLog = (overrides.auditLog as InMemoryAuditLog | undefined) ?? new InMemoryAuditLog();
  return {
    scopeContext: scopeContext(),
    policy,
    logger: silentLogger(),
    containerRunner: runner,
    digests: { httpx: 'sha256:'.padEnd(71, 'a'), nuclei: 'sha256:'.padEnd(71, 'b') },
    actorId: 'tester-1',
    now: NOW,
    resolve: () => Promise.resolve(['93.184.216.34']),
    ...overrides,
    auditLog,
  };
}

describe('runToolForEngagement — refusals', () => {
  it('refuses the whole run when any single target is out of scope', async () => {
    const { runner, spies } = fakeContainerRunner();
    const deps = dependencies({ containerRunner: runner });

    const outcome = await runToolForEngagement(
      {
        engagementId: 'eng-1',
        scanRunId: 'run-1',
        toolId: 'httpx',
        targets: ['app.client.example', 'app.someoneelse.example'],
        command: ['-silent'],
        outputDirectory: '/tmp/out',
      },
      deps,
    );

    expect(outcome.status).toBe('refused');
    if (outcome.status === 'refused') {
      expect(outcome.rule).toBe('targetNotInScope');
      expect(outcome.target).toBe('app.someoneelse.example');
    }
    // Nothing ran. Not "the good one ran" — nothing.
    expect(spies.run).not.toHaveBeenCalled();
  });

  it('writes the refusal to the audit log with the rule that stopped it', async () => {
    const deps = dependencies();
    await runToolForEngagement(
      {
        engagementId: 'eng-1',
        scanRunId: 'run-1',
        toolId: 'httpx',
        targets: ['portal.gov.in'],
        command: [],
        outputDirectory: '/tmp/out',
      },
      deps,
    );

    const refusals = deps.auditLog.find('scanRun.refused');
    expect(refusals).toHaveLength(1);
    expect(refusals[0]!.metadata?.rule).toBe('neverTouchHost');
  });

  it('refuses a run with no targets rather than launching a tool with none', async () => {
    const outcome = await runToolForEngagement(
      {
        engagementId: 'eng-1',
        scanRunId: 'run-1',
        toolId: 'httpx',
        targets: [],
        command: [],
        outputDirectory: '/tmp/out',
      },
      dependencies(),
    );
    expect(outcome.status).toBe('refused');
  });

  it('refuses while a panic stop is in force', async () => {
    const { runner, spies } = fakeContainerRunner();
    const outcome = await runToolForEngagement(
      {
        engagementId: 'eng-1',
        scanRunId: 'run-1',
        toolId: 'httpx',
        targets: ['app.client.example'],
        command: [],
        outputDirectory: '/tmp/out',
      },
      dependencies({
        containerRunner: runner,
        scopeContext: scopeContext({ panicStopActive: true }),
      }),
    );
    expect(outcome.status).toBe('refused');
    expect(spies.run).not.toHaveBeenCalled();
  });

  it('refuses an unknown tool loudly', async () => {
    await expect(
      runToolForEngagement(
        {
          engagementId: 'eng-1',
          scanRunId: 'run-1',
          toolId: 'definitely-not-a-tool',
          targets: ['app.client.example'],
          command: [],
          outputDirectory: '/tmp/out',
        },
        dependencies(),
      ),
    ).rejects.toThrow(/unknown tool/);
  });
});

describe('runToolForEngagement — dry run', () => {
  it('performs every check and sends nothing', async () => {
    const { runner, spies } = fakeContainerRunner();
    const outcome = await runToolForEngagement(
      {
        engagementId: 'eng-1',
        scanRunId: 'run-1',
        toolId: 'httpx',
        targets: ['app.client.example', 'api.client.example'],
        command: ['-silent'],
        outputDirectory: '/tmp/out',
      },
      dependencies({ containerRunner: runner, dryRun: true }),
    );

    expect(outcome.status).toBe('dryRun');
    if (outcome.status === 'dryRun') {
      expect(outcome.approvedTargets).toHaveLength(2);
      expect(outcome.approvedTargets[0]!.resolvedAddresses).toEqual(['93.184.216.34']);
    }
    expect(spies.run).not.toHaveBeenCalled();
    expect(spies.createRunNetwork).not.toHaveBeenCalled();
  });

  it('still refuses in dry run, so the preview is honest', async () => {
    const outcome = await runToolForEngagement(
      {
        engagementId: 'eng-1',
        scanRunId: 'run-1',
        toolId: 'httpx',
        targets: ['app.elsewhere.example'],
        command: [],
        outputDirectory: '/tmp/out',
      },
      dependencies({ dryRun: true }),
    );
    expect(outcome.status).toBe('refused');
  });
});

describe('runToolForEngagement — execution', () => {
  it('runs the tool with the pinned digest and a per-run network', async () => {
    const { runner, runs, spies } = fakeContainerRunner();
    const outcome = await runToolForEngagement(
      {
        engagementId: 'eng-1',
        scanRunId: 'run-abc',
        toolId: 'httpx',
        targets: ['app.client.example'],
        command: ['-silent', '-json'],
        outputDirectory: '/tmp/out',
      },
      dependencies({ containerRunner: runner }),
    );

    expect(outcome.status).toBe('completed');
    expect(spies.createRunNetwork).toHaveBeenCalledWith('attestor-run-run-abc');
    expect(spies.removeRunNetwork).toHaveBeenCalledWith('attestor-run-run-abc');
    const [first] = runs as { digest: string; networkName: string; labels: Record<string, string> }[];
    expect(first!.digest.startsWith('sha256:')).toBe(true);
    // The panic stop finds containers by these labels. Without them it kills nothing.
    expect(first!.labels).toEqual({ engagementId: 'eng-1', scanRunId: 'run-abc' });
  });

  it('records launch and exit in the audit log with the resolved addresses', async () => {
    const deps = dependencies();
    await runToolForEngagement(
      {
        engagementId: 'eng-1',
        scanRunId: 'run-1',
        toolId: 'httpx',
        targets: ['app.client.example'],
        command: [],
        outputDirectory: '/tmp/out',
      },
      deps,
    );

    const launched = deps.auditLog.find('tool.launched');
    expect(launched).toHaveLength(1);
    expect(launched[0]!.metadata?.resolvedAddresses).toEqual(['93.184.216.34']);
    expect(deps.auditLog.find('tool.exited')).toHaveLength(1);
  });

  it('redacts tool output before returning it, because it gets persisted', async () => {
    const { runner } = fakeContainerRunner({
      stdout: 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345\nfound 3 hosts',
      stderr: 'password=supersecretvalue',
    });
    const outcome = await runToolForEngagement(
      {
        engagementId: 'eng-1',
        scanRunId: 'run-1',
        toolId: 'httpx',
        targets: ['app.client.example'],
        command: [],
        outputDirectory: '/tmp/out',
      },
      dependencies({ containerRunner: runner }),
    );

    expect(outcome.status).toBe('completed');
    if (outcome.status === 'completed') {
      expect(outcome.result.stdout).not.toContain('abcdefghijklmnopqrstuvwxyz012345');
      expect(outcome.result.stdout).toContain('found 3 hosts');
      expect(outcome.result.stderr).not.toContain('supersecretvalue');
    }
  });

  it('clears registered secrets once the run finishes', async () => {
    const { runner } = fakeContainerRunner();
    await runToolForEngagement(
      {
        engagementId: 'eng-1',
        scanRunId: 'run-1',
        toolId: 'httpx',
        targets: ['app.client.example'],
        command: [],
        secrets: { API_TOKEN: 'a-long-enough-secret-value' },
        outputDirectory: '/tmp/out',
      },
      dependencies({ containerRunner: runner }),
    );
    expect(secretRegistry.size).toBe(0);
  });

  it('refuses a cloud run until the provider policy is acknowledged', async () => {
    const { runner, spies } = fakeContainerRunner();
    const outcome = await runToolForEngagement(
      {
        engagementId: 'eng-1',
        scanRunId: 'run-1',
        toolId: 'httpx',
        targets: ['app.client.example'],
        command: [],
        outputDirectory: '/tmp/out',
        requiresCloudPolicyAcknowledgement: true,
      },
      dependencies({ containerRunner: runner }),
    );
    expect(outcome.status).toBe('refused');
    if (outcome.status === 'refused') {
      expect(outcome.rule).toBe('cloudTestingPolicyUnacknowledged');
    }
    expect(spies.run).not.toHaveBeenCalled();
  });
});
