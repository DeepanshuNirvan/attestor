import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import { ContainerRunner, runToolForEngagement } from '@attestor/core';
import type { EngagementScopeContext } from '@attestor/core';
import { loadProfile } from '@attestor/policy';
import { adapterFor } from '@attestor/scanners';
import { createLogger } from '@attestor/shared';

/**
 * The end-to-end run, against a target we own.
 *
 * Everything here goes through the real choke point: real scope guard, real container runner, real
 * tool image, real output, real adapter. The target is a deliberately vulnerable application on a
 * Docker network with `internal: true`, so nothing in this test can reach an internet host even if
 * every other control failed.
 *
 * Prerequisites:
 *   docker compose -f infra/docker-compose.test.yml up -d --wait
 *   ATTESTOR_TEST_NETWORK_ONLY=1 pnpm test:integration
 */

const run = promisify(execFile);

const httpx = adapterFor('httpx');
const nuclei = adapterFor('nuclei');

const TARGET_NETWORK = 'attestor-test_targets';
const TARGET_CONTAINER = 'attestor-test-juice-shop-1';

async function containerAddress(container: string): Promise<string> {
  const template = '{{(index .NetworkSettings.Networks "' + TARGET_NETWORK + '").IPAddress}}';
  const { stdout } = await run('docker', ['inspect', '-f', template, container]);
  const address = stdout.trim();
  if (address === '') throw new Error(`${container} has no address on ${TARGET_NETWORK}`);
  return address;
}

const logger = createLogger({ level: 'error', service: 'integration' });

function auditSink() {
  const records: { action: string; metadata?: Record<string, unknown> }[] = [];
  return {
    log: {
      record: (entry: { action: string; metadata?: Record<string, unknown> }) => {
        records.push(entry);
        return Promise.resolve();
      },
    },
    records,
  };
}

describe('an engagement run against the vulnerable stack', () => {
  let runner: ContainerRunner;
  let targetIp: string;
  let outputDirectory: string;
  let scopeContext: EngagementScopeContext;
  let digests: Record<string, string>;

  beforeAll(async () => {
    runner = new ContainerRunner();
    targetIp = await containerAddress(TARGET_CONTAINER);
    outputDirectory = await mkdtemp(path.join(tmpdir(), 'attestor-run-'));

    // The images are pulled here rather than assumed, and pinned to the digest the daemon
    // resolved. A tool with no digest does not run; that is enforced in the runner, not here.
    for (const image of ['projectdiscovery/httpx:latest', 'projectdiscovery/nuclei:latest']) {
      await run('docker', ['pull', image], { maxBuffer: 32 * 1024 * 1024 });
    }
    const httpxDigest = await runner.imageDigestFor('projectdiscovery/httpx:latest');
    const nucleiDigest = await runner.imageDigestFor('projectdiscovery/nuclei:latest');
    digests = { httpx: httpxDigest ?? '', nuclei: nucleiDigest ?? '' };

    scopeContext = {
      engagementId: 'integration-engagement',
      state: 'running',
      authorisation: {
        id: 'integration-authorisation',
        signedAt: new Date(Date.now() - 86_400_000),
        revokedAt: null,
        validFrom: new Date(Date.now() - 86_400_000),
        validUntil: new Date(Date.now() + 86_400_000),
      },
      scopeItems: [{ id: 'scope-1', kind: 'ip', value: targetIp, included: true }],
      testWindows: [],
      timezone: 'UTC',
      // The Docker bridge is RFC1918, which the guard refuses by default. Authorising it here is
      // the same deliberate act an internal engagement requires, and it is the only reason this
      // run is allowed to touch the target at all.
      ownedPrivateRanges: [`${targetIp}/32`],
      thirdPartyInfrastructureAcknowledged: false,
      cloudTestingPolicyAcknowledged: false,
      panicStopActive: false,
    };
  }, 600_000);

  afterAll(async () => {
    if (outputDirectory) await rm(outputDirectory, { recursive: true, force: true });
  });

  it('refuses a target that is not in scope, and starts nothing', async () => {
    const audit = auditSink();
    const { policy } = await loadProfile('quick-external');

    const outcome = await runToolForEngagement(
      {
        engagementId: scopeContext.engagementId,
        scanRunId: 'integration-refused',
        toolId: 'httpx',
        targets: [targetIp, 'example.com'],
        command: ['-silent'],
        outputDirectory,
      },
      {
        scopeContext,
        policy,
        auditLog: audit.log,
        logger,
        containerRunner: runner,
        digests,
        actorId: 'integration',
        // Resolution is stubbed rather than performed: asking a real resolver about a real domain
        // from a test is itself a small piece of reconnaissance against somebody else's name.
        resolve: () => Promise.resolve(['93.184.216.34']),
      },
    );

    expect(outcome.status).toBe('refused');
    expect(audit.records.some((entry) => entry.action === 'tool.launched')).toBe(false);
  });

  it('performs every check and sends nothing on a dry run', async () => {
    const audit = auditSink();
    const { policy } = await loadProfile('quick-external');
    const invocation = httpx.buildInvocation({
      policy,
      targets: [targetIp],
      outputPath: '/out',
    });

    const outcome = await runToolForEngagement(
      {
        engagementId: scopeContext.engagementId,
        scanRunId: 'integration-dry',
        toolId: 'httpx',
        targets: [targetIp],
        command: invocation.command,
        outputDirectory,
      },
      {
        scopeContext,
        policy,
        auditLog: audit.log,
        logger,
        containerRunner: runner,
        digests,
        actorId: 'integration',
        dryRun: true,
      },
    );

    expect(outcome.status).toBe('dryRun');
    expect(audit.records.some((entry) => entry.action === 'tool.launched')).toBe(false);
  });

  it('probes the target with httpx and turns the output into assets and findings', async () => {
    const audit = auditSink();
    const { policy } = await loadProfile('quick-external');
    const invocation = httpx.buildInvocation({
      policy,
      targets: [`${targetIp}:3000`],
      outputPath: '/out',
    });

    for (const file of invocation.inputFiles ?? []) {
      await writeFile(path.join(outputDirectory, file.name), file.contents, 'utf8');
    }

    const outcome = await runToolForEngagement(
      {
        engagementId: scopeContext.engagementId,
        scanRunId: 'integration-httpx',
        toolId: 'httpx',
        targets: [targetIp],
        command: invocation.command,
        outputDirectory,
      },
      {
        scopeContext,
        policy,
        auditLog: audit.log,
        logger,
        containerRunner: runner,
        digests,
        actorId: 'integration',
        additionalNetworks: [TARGET_NETWORK],
      },
    );

    expect(outcome.status).toBe('completed');
    if (outcome.status !== 'completed') return;
    expect(outcome.result.timedOut).toBe(false);

    const raw = await readFile(path.join(outputDirectory, invocation.outputFile), 'utf8');
    const assets = httpx.parseAssets?.(raw) ?? [];
    expect(assets.length).toBeGreaterThan(0);

    // Juice Shop answers over plain HTTP and does not redirect, which is a finding rather than
    // inventory. This is the whole pipeline in one assertion: tool output became a typed finding.
    const findings = httpx.parse(raw, { defaultAsset: targetIp, cvssVersion: '4.0' });
    expect(
      findings.some((finding) => finding.checkId === 'web-credentials-over-encrypted-channel'),
    ).toBe(true);

    // Every launch is on the record, with the digest that actually ran.
    const launch = audit.records.find((entry) => entry.action === 'tool.launched');
    expect(launch?.metadata?.digest).toMatch(/^sha256:/);
  }, 900_000);

  it('runs nuclei against the target and produces findings the model accepts', async () => {
    const audit = auditSink();
    const { policy } = await loadProfile('quick-external');
    const invocation = nuclei.buildInvocation({
      policy,
      targets: [`http://${targetIp}:3000`],
      outputPath: '/out',
    });

    for (const file of invocation.inputFiles ?? []) {
      await writeFile(path.join(outputDirectory, file.name), file.contents, 'utf8');
    }

    const outcome = await runToolForEngagement(
      {
        engagementId: scopeContext.engagementId,
        scanRunId: 'integration-nuclei',
        toolId: 'nuclei',
        targets: [targetIp],
        command: invocation.command,
        outputDirectory,
      },
      {
        scopeContext,
        policy,
        auditLog: audit.log,
        logger,
        containerRunner: runner,
        digests,
        actorId: 'integration',
        additionalNetworks: [TARGET_NETWORK],
      },
    );

    expect(outcome.status).toBe('completed');
    if (outcome.status !== 'completed') return;

    const raw = await readFile(path.join(outputDirectory, invocation.outputFile), 'utf8').catch(
      () => '',
    );
    const findings = nuclei.parse(raw, { defaultAsset: targetIp, cvssVersion: '4.0' });
    // A deliberately vulnerable application produces something; asserting on a specific template
    // id would be asserting on somebody else's release notes.
    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) {
      expect(finding.title.length).toBeGreaterThan(0);
      expect(finding.source).toBe('tool');
    }
  }, 1_800_000);

  it('leaves no container behind and no run network', async () => {
    const { stdout: containers } = await run('docker', [
      'ps',
      '-a',
      '--filter',
      'label=com.attestor.purpose=engagement-run',
      '--format',
      '{{.Names}}',
    ]);
    expect(containers.trim()).toBe('');

    const { stdout: networks } = await run('docker', [
      'network',
      'ls',
      '--filter',
      'label=com.attestor.purpose=engagement-run',
      '--format',
      '{{.Name}}',
    ]);
    expect(networks.trim()).toBe('');
  });
});
