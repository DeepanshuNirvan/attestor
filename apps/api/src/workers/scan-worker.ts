import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { eq } from 'drizzle-orm';
import type { Job } from 'bullmq';
import { runToolForEngagement } from '@attestor/core';
import { adapterFor } from '@attestor/scanners';
import type { ConsoleContext } from '../context.ts';
import { evidence as evidenceTable, scanRun as scanRunTable } from '../db/schema.ts';
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
