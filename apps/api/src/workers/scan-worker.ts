import { chmod, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { eq, sql } from 'drizzle-orm';
import type { Job } from 'bullmq';
import { runToolForEngagement } from '@attestor/core';
import { adapterFor } from '@attestor/scanners';
import type { ConsoleContext } from '../context.ts';
import {
  discoveredAsset as discoveredAssetTable,
  evidence as evidenceTable,
  scanRun as scanRunTable,
} from '../db/schema.ts';
import { ingestFindings } from '../services/findings-service.ts';
import { loadRunContext } from '../services/run-service.ts';
import { loadToolDigests } from '../services/tool-digests.ts';
import type { ScanJob } from '../queue.ts';

/**
 * The scan worker.
 *
 * One job is one tool run. It builds the scope context fresh from the database rather than trusting
 * anything on the job payload, because the payload was written when the job was queued and the
 * authorisation may have been revoked since.
 *
 * The job is idempotent: it refuses to run a scan row that is not `queued`, so a retry after a
 * crash during ingestion does not run the tool twice.
 */

/**
 * nuclei is the one tool that needs data it does not ship with: its template repository, which the
 * image omits and which `-disable-update-check` stops it fetching at run time. The pack is
 * provisioned once into the shared workspace and mounted read-only here.
 *
 * The path is under `tmpdir()/attestor` because that directory means the same thing to this process
 * and to the daemon that will resolve the bind — see the workspace note in the compose file. One
 * named tool rather than a general mechanism: when a second tool needs a data pack, generalise then.
 */
const NUCLEI_TEMPLATE_MOUNT: Record<string, { hostPath: string; containerPath: string }[]> = {
  nuclei: [
    { hostPath: join(tmpdir(), 'attestor', 'nuclei-templates'), containerPath: '/templates' },
  ],
};

/**
 * Tools colour their output. The codes are meaningless once the text is in a database column, and
 * they arrive verbatim in the console's run table and in anything that quotes a failure reason —
 * `[[34mINF[0m] Targets loaded` rather than `[INF] Targets loaded`.
 */
// eslint-disable-next-line no-control-regex
const ANSI_ESCAPE = /\[[0-9;]*m/g;

function stripAnsi(value: string): string {
  return value.replace(ANSI_ESCAPE, '');
}

export async function handleScanJob(context: ConsoleContext, job: Job<ScanJob>): Promise<void> {
  const { engagementId, scanRunId, toolId, targets, dryRun, requestedBy } = job.data;
  const logger = context.logger.child({ engagementId, scanRunId, tool: toolId });

  const rows = await context.database
    .select()
    .from(scanRunTable)
    .where(eq(scanRunTable.id, scanRunId))
    .limit(1);
  const run = rows[0];

  if (!run) {
    logger.error('scan run row is missing; refusing to run a tool with nowhere to record it');
    return;
  }
  if (run.status !== 'queued') {
    logger.warn('scan run is not queued; treating this as a duplicate delivery and stopping', {
      status: run.status,
    });
    return;
  }

  const panicStopActive = await context.panicStop.isActive(engagementId);
  const runContext = await loadRunContext(context.database, engagementId, panicStopActive);
  const adapter = adapterFor(toolId);
  const digests = await loadToolDigests();

  const invocation = adapter.buildInvocation({
    policy: runContext.policy,
    targets,
    outputPath: '/out',
  });

  const workingDirectory = join(tmpdir(), 'attestor', scanRunId);
  await mkdir(workingDirectory, { recursive: true });
  // The tool container runs as uid 65532 and writes its output here through a bind mount. This
  // process is not root and cannot chown to that uid, so the directory has to be group- and
  // world-writable for the tool to produce anything at all. It sits inside a workspace root that is
  // 0700 to the worker, holds one run's scratch, and is removed as soon as the run ends.
  await chmod(workingDirectory, 0o777);

  for (const file of invocation.inputFiles ?? []) {
    await writeFile(join(workingDirectory, file.name), file.contents, 'utf8');
  }

  await context.database
    .update(scanRunTable)
    .set({ status: 'running', startedAt: new Date(), toolVersionDigest: digests[toolId] ?? '' })
    .where(eq(scanRunTable.id, scanRunId));

  try {
    const outcome = await runToolForEngagement(
      {
        engagementId,
        scanRunId,
        toolId,
        targets,
        command: invocation.command,
        environment: invocation.environment,
        outputDirectory: workingDirectory,
        readOnlyMounts: NUCLEI_TEMPLATE_MOUNT[toolId],
        requiresCloudPolicyAcknowledgement: adapter.modules.includes('cloud'),
      },
      {
        scopeContext: runContext.scopeContext,
        policy: runContext.policy,
        auditLog: context.auditLog,
        logger,
        containerRunner: context.containerRunner,
        digests,
        actorId: requestedBy,
        dryRun,
      },
    );

    if (outcome.status === 'refused') {
      await context.database
        .update(scanRunTable)
        .set({
          status: 'refused',
          finishedAt: new Date(),
          abortReason: `${outcome.rule}: ${outcome.detail}`,
        })
        .where(eq(scanRunTable.id, scanRunId));
      logger.warn('run refused by the scope guard', { rule: outcome.rule });
      return;
    }

    if (outcome.status === 'dryRun') {
      await context.database
        .update(scanRunTable)
        .set({
          status: 'completed',
          finishedAt: new Date(),
          stats: {
            dryRun: true,
            approvedTargets: outcome.approvedTargets.map((entry) => entry.hostname),
            command: outcome.command,
          },
        })
        .where(eq(scanRunTable.id, scanRunId));
      logger.info('dry run complete; nothing was sent');
      return;
    }

    // A tool that exited non-zero did not do the job it was asked to do, and its checks must not
    // count as covered. Recording it as completed made a tool that never started — nuclei refusing
    // to run under the read-only root filesystem — indistinguishable from a clean scan, and the
    // coverage matrix then claimed every check that tool contributes to had been tested.
    // `coverageFromRuns` reads `failed` as an aborted run, so the matrix carries the reason instead.
    if (outcome.result.exitCode !== 0) {
      const detail = stripAnsi(outcome.result.stderr).trim().split('\n').slice(-3).join(' ').slice(0, 500);
      await context.database
        .update(scanRunTable)
        .set({
          status: 'failed',
          finishedAt: new Date(),
          exitCode: outcome.result.exitCode,
          abortReason: `the tool exited ${outcome.result.exitCode}${detail === '' ? '' : `: ${detail}`}`,
        })
        .where(eq(scanRunTable.id, scanRunId));
      logger.error('tool exited non-zero; not counting its checks as covered', {
        exitCode: outcome.result.exitCode,
        detail,
      });
      return;
    }

    const rawOutput = await readFile(join(workingDirectory, invocation.outputFile), 'utf8').catch(
      () => '',
    );

    // Raw output is retained for defensibility: if a finding is ever disputed, this is what the
    // tool actually said. It passes through the same masking and redaction as any other evidence.
    const storedRaw = await context.evidence.capture({
      engagementId,
      scanRunId,
      kind: 'terminal',
      text: rawOutput === '' ? outcome.result.stdout : rawOutput,
      filename: invocation.outputFile,
      disabledMaskingRuleIds: runContext.policy.evidence.disabledMaskingRuleIds,
    });

    await context.database.insert(evidenceTable).values({
      engagementId,
      scanRunId,
      kind: 'terminal',
      objectKey: storedRaw.objectKey,
      contentType: storedRaw.contentType,
      byteSize: storedRaw.byteSize,
      sha256: storedRaw.sha256,
      redactionApplied: storedRaw.redactionApplied,
    });

    // Inventory, as distinct from findings. Every adapter may produce it and the recon adapters do;
    // until this call existed it was parsed and discarded, which left the report's ports-and-
    // services appendix claiming no port scanning had been performed on engagements where nmap and
    // naabu had both run.
    const discovered = adapter.parseAssets?.(rawOutput) ?? [];
    if (discovered.length > 0) {
      await context.database
        .insert(discoveredAssetTable)
        .values(
          discovered.map((asset) => ({
            engagementId,
            scanRunId,
            kind: asset.kind,
            value: asset.value,
            host: asset.host,
            port: asset.port ?? null,
            metadata: asset.metadata ?? {},
          })),
        )
        .onConflictDoUpdate({
          target: [
            discoveredAssetTable.engagementId,
            discoveredAssetTable.kind,
            discoveredAssetTable.value,
          ],
          set: { lastSeenAt: new Date(), scanRunId, metadata: sql`excluded.metadata` },
        });
    }

    const parsed = adapter.parse(rawOutput, {
      defaultAsset: targets[0] ?? runContext.reference,
      cvssVersion: runContext.policy.report.cvssVersion,
    });

    const ingested = await ingestFindings(context.database, {
      engagementId,
      clientId: runContext.clientId,
      scanRunId,
      toolName: toolId,
      raw: parsed,
      cvssVersion: runContext.policy.report.cvssVersion,
    });

    // Attach the tool's own record of each new finding, through the same masking the raw output
    // gets. Without this every tool-derived finding reached triage with nothing attached, and the
    // pre-release checklist refused to release a report that was otherwise complete.
    for (const created of ingested.createdFindings) {
      if (created.evidenceText === undefined) continue;
      const stored = await context.evidence.capture({
        engagementId,
        scanRunId,
        kind: 'terminal',
        text: created.evidenceText,
        filename: `${toolId}-${created.id}.json`,
        disabledMaskingRuleIds: runContext.policy.evidence.disabledMaskingRuleIds,
      });
      await context.database.insert(evidenceTable).values({
        engagementId,
        scanRunId,
        findingId: created.id,
        kind: 'terminal',
        objectKey: stored.objectKey,
        contentType: stored.contentType,
        byteSize: stored.byteSize,
        sha256: stored.sha256,
        redactionApplied: stored.redactionApplied,
      });
    }

    await context.database
      .update(scanRunTable)
      .set({
        status: outcome.result.timedOut ? 'aborted' : 'completed',
        finishedAt: new Date(),
        exitCode: outcome.result.exitCode,
        rawOutputKey: storedRaw.objectKey,
        abortReason: outcome.result.timedOut
          ? 'the tool exceeded its wall-clock limit and was stopped'
          : null,
        stats: {
          durationMs: outcome.result.durationMs,
          rawFindings: parsed.length,
          ...ingested,
        },
      })
      .where(eq(scanRunTable.id, scanRunId));

    logger.info('run complete', { ...ingested, rawFindings: parsed.length });
  } catch (error) {
    await context.database
      .update(scanRunTable)
      .set({
        status: 'failed',
        finishedAt: new Date(),
        abortReason: error instanceof Error ? error.message : 'unknown error',
      })
      .where(eq(scanRunTable.id, scanRunId));
    throw error;
  } finally {
    // The working directory holds raw tool output that has already been stored, masked, in object
    // storage. Leaving an unmasked copy on the worker's disk would undo that.
    await rm(workingDirectory, { recursive: true, force: true }).catch(() => undefined);
  }
}
