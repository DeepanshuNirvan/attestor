import { chmod, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { eq, sql } from 'drizzle-orm';
import type { Job } from 'bullmq';
import { inProcessToolById, runToolForEngagement } from '@attestor/core';
import { adapterFor } from '@attestor/scanners';
import type { ConsoleContext } from '../context.ts';
import {
  discoveredAsset as discoveredAssetTable,
  evidence as evidenceTable,
  scanRun as scanRunTable,
} from '../db/schema.ts';
import { ingestFindings } from '../services/findings-service.ts';
import { runAccessControlMatrix } from './access-control-job.ts';
import { runRateLimitProbe } from './rate-limit-job.ts';
import { runRequestManipulation } from './request-manipulation-job.ts';
import { openRunCredentials } from '../services/run-credentials.ts';
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
 * Two tools need data they do not ship with, and both would otherwise fetch it mid-engagement.
 *
 * nuclei's image omits its template repository and `-disable-update-check` stops it fetching one at
 * run time, so without the pack it starts, finds nothing to run and exits — which for a long time
 * looked exactly like a clean scan.
 *
 * httpx fetches a 92.6 MB classification model from huggingface at startup whenever it is asked for
 * JSON output, which the adapter always asks for. Sending a client's engagement through a third
 * party's CDN unannounced is the objection; paying for it on every run is the other one, because the
 * container's home is a 64 MB tmpfs and the download cannot be kept. Mounted read-only, the tool
 * finds the model already there and asks nobody for it.
 *
 * Both packs are provisioned once by an init service in the compose file. The paths are under
 * `tmpdir()/attestor` because that directory means the same thing to this process and to the daemon
 * that will resolve the bind — see the workspace note in the compose file.
 */
const DATA_PACK_MOUNTS: Record<string, { hostPath: string; containerPath: string }[]> = {
  nuclei: [
    { hostPath: join(tmpdir(), 'attestor', 'nuclei-templates'), containerPath: '/templates' },
  ],
  // `/home/nonroot` is the HOME the container runner gives a tool that needs a writable temp.
  httpx: [
    { hostPath: join(tmpdir(), 'attestor', 'httpx-dit'), containerPath: '/home/nonroot/.dit' },
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

  // A probe runs in this process rather than in a container, so it has no image, no output file and
  // nothing to parse. It shares the row, the status and the coverage accounting, and it goes through
  // its own choke point which applies the same scope guard and rate limits.
  if (inProcessToolById(toolId)?.implemented === true) {
    await handleProbeRun(context, {
      engagementId,
      scanRunId,
      toolId,
      targets,
      runContext,
      dryRun,
      requestedBy,
      logger,
    });
    return;
  }

  const adapter = adapterFor(toolId);
  const digests = await loadToolDigests();

  // A tool that needs something this engagement has not supplied does not start. Recorded as an
  // aborted run carrying the reason, exactly as a refused run is, so the coverage matrix says "no
  // OpenAPI schema was named" rather than leaving a silent hole where the API testing should be.
  const blocked = adapter.cannotRunBecause?.(runContext.policy);
  if (blocked !== undefined) {
    await context.database
      .update(scanRunTable)
      .set({ status: 'aborted', finishedAt: new Date(), abortReason: blocked })
      .where(eq(scanRunTable.id, scanRunId));
    logger.warn('tool cannot run under this policy', { reason: blocked });
    return;
  }

  // Opened only for a tool that can use one, so a port scan never decrypts a client's password.
  // The values go to the container's environment and nowhere else; the invocation this builds
  // carries `${...}` references, which is what makes the plan file safe to write to disk.
  const runCredentials = adapter.usesCredentials
    ? await openRunCredentials(context.database, context.vault, engagementId, runContext.policy)
    : { credentials: [], secrets: {}, warnings: [] };
  for (const warning of runCredentials.warnings) logger.warn(warning);

  const invocation = adapter.buildInvocation({
    policy: runContext.policy,
    targets,
    outputPath: '/out',
    credentials: runCredentials.credentials,
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
        secrets: runCredentials.secrets,
        outputDirectory: workingDirectory,
        readOnlyMounts: DATA_PACK_MOUNTS[toolId],
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

    // Most tools exit zero whether or not they found anything. A few report findings through the
    // exit code instead — schemathesis exits 1 precisely when its checks fail — and treating that
    // as a failure threw away every run that found something and kept only the quiet ones.
    const succeeded =
      outcome.result.exitCode === 0 ||
      (adapter.successExitCodes ?? []).includes(outcome.result.exitCode);

    // The output file first, stdout when there is no file. The evidence record already fell back
    // this way and the parser did not, so an adapter that forgot to ask its tool for a file produced
    // evidence a human could read and no findings at all — dnsx did exactly that, and its check was
    // reported as covered every time.
    //
    // Read before the exit code is judged, on purpose: what a tool said is most worth keeping in the
    // run where it failed. The three lines of stderr that fit in `abortReason` are rarely the three
    // that explain it, and until this moved, a failed run left nothing behind to diagnose it with.
    const fileOutput = await readFile(join(workingDirectory, invocation.outputFile), 'utf8').catch(
      () => '',
    );
    const rawOutput = fileOutput === '' ? outcome.result.stdout : fileOutput;

    // Raw output is retained for defensibility: if a finding is ever disputed, this is what the
    // tool actually said. It passes through the same masking and redaction as any other evidence.
    const storedRaw = await context.evidence.capture({
      engagementId,
      scanRunId,
      kind: 'terminal',
      text: rawOutput,
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

    // A tool that exited non-zero did not do the job it was asked to do, and its checks must not
    // count as covered. Recording it as completed made a tool that never started — nuclei refusing
    // to run under the read-only root filesystem — indistinguishable from a clean scan, and the
    // coverage matrix then claimed every check that tool contributes to had been tested.
    // `coverageFromRuns` reads `failed` as an aborted run, so the matrix carries the reason instead.
    if (!succeeded) {
      const detail = stripAnsi(outcome.result.stderr).trim().split('\n').slice(-3).join(' ').slice(0, 500);
      await context.database
        .update(scanRunTable)
        .set({
          status: 'failed',
          finishedAt: new Date(),
          exitCode: outcome.result.exitCode,
          rawOutputKey: storedRaw.objectKey,
          abortReason: `the tool exited ${outcome.result.exitCode}${detail === '' ? '' : `: ${detail}`}`,
          stats: { durationMs: outcome.result.durationMs, rawOutputBytes: rawOutput.length },
        })
        .where(eq(scanRunTable.id, scanRunId));
      logger.error('tool exited non-zero; not counting its checks as covered', {
        exitCode: outcome.result.exitCode,
        detail,
      });
      return;
    }

    // Inventory, as distinct from findings. Every adapter may produce it and the recon adapters do;
    // until this call existed it was parsed and discarded, which left the report's ports-and-
    // services appendix claiming no port scanning had been performed on engagements where nmap and
    // naabu had both run.
    const discovered = adapter.parseAssets?.(rawOutput) ?? [];

    // One tool run names the same thing many times over: nuclei matches a dozen templates at `/`,
    // and every one of them is the same URL. Postgres refuses an `ON CONFLICT DO UPDATE` whose own
    // VALUES list reaches the same row twice — "cannot affect row a second time" — so the insert
    // threw, the whole run was recorded as `failed`, and the checks it had genuinely covered were
    // reported to the client as untested. Collapsing here keeps the last of each, which is the row
    // the conflict update would have left behind anyway.
    const uniqueAssets = new Map<string, (typeof discovered)[number]>();
    for (const asset of discovered) uniqueAssets.set(JSON.stringify([asset.kind, asset.value]), asset);

    if (uniqueAssets.size > 0) {
      await context.database
        .insert(discoveredAssetTable)
        .values(
          [...uniqueAssets.values()].map((asset) => ({
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

    if (rawOutput.trim() === '') {
      logger.warn('the tool exited zero and produced no output; treat a clean result with suspicion', {
        outputFile: invocation.outputFile,
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
          // How much the tool actually said. A tool that exits zero having written nothing looks
          // exactly like a clean scan, and one of them was doing precisely that: httpx now fetches
          // a 92 MB model from a third party at startup, and when it cannot store it the process
          // ends successfully having produced no output at all. Recording the size makes an empty
          // run visible in the console instead of indistinguishable from a quiet one.
          rawOutputBytes: rawOutput.length,
          ...ingested,
          // Whether the tool was logged in, recorded beside its results. Without it, "was this an
          // authenticated scan?" — the question that decides what the report is worth — can only be
          // answered by re-reading the policy and guessing.
          ...(adapter.usesCredentials
            ? {
                authenticatedAs: runCredentials.credentials
                  .filter((credential) => !credential.isSecondary)
                  .map((credential) => credential.roleName),
                credentialWarnings: runCredentials.warnings,
              }
            : {}),
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

/**
 * A probe run, recorded exactly as a container run is.
 *
 * The status vocabulary is deliberately the same — `completed`, `refused`, `failed` — because the
 * coverage matrix reads it and does not care how the work was done. The one addition is that a
 * probe with nothing to do finishes `completed` with the reason in its stats: an engagement holding
 * one account has not failed to test access control, it has nothing to test.
 */
async function handleProbeRun(
  context: ConsoleContext,
  input: {
    engagementId: string;
    scanRunId: string;
    toolId: string;
    targets: string[];
    runContext: Awaited<ReturnType<typeof loadRunContext>>;
    dryRun: boolean;
    requestedBy: string;
    logger: ReturnType<ConsoleContext['logger']['child']>;
  },
): Promise<void> {
  const { engagementId, scanRunId, targets, logger } = input;

  await context.database
    .update(scanRunTable)
    .set({ status: 'running', startedAt: new Date() })
    .where(eq(scanRunTable.id, scanRunId));

  try {
    const shared = {
      engagementId,
      scanRunId,
      targets,
      runContext: input.runContext,
      actorId: input.requestedBy,
      dryRun: input.dryRun,
      logger,
    };

    // One line per probe. They return the same shape, so everything below this point is shared —
    // a further probe adds a case here and nothing else.
    const result =
      input.toolId === 'rateLimitProbe'
        ? await runRateLimitProbe(context, shared)
        : input.toolId === 'requestManipulationProbe'
          ? await runRequestManipulation(context, shared)
          : await runAccessControlMatrix(context, { ...shared, panicStopActive: false });

    if (result.refusal) {
      await context.database
        .update(scanRunTable)
        .set({
          status: 'refused',
          finishedAt: new Date(),
          abortReason: `${result.refusal.rule}: ${result.refusal.detail}`,
        })
        .where(eq(scanRunTable.id, scanRunId));
      logger.warn('probe refused by the scope guard', { rule: result.refusal.rule });
      return;
    }

    // A probe that did not do its work must not be counted as having done it. `skipped` is the
    // probe saying so — no endpoint was named, or the policy switched the whole thing off — and
    // recording that as `completed` handed its `coveredCheckIds` to the coverage matrix as tested.
    // `aborted` carries the reason through to the client instead, which is what a refused container
    // run already does.
    if (result.skipped !== undefined) {
      await context.database
        .update(scanRunTable)
        .set({
          status: 'aborted',
          finishedAt: new Date(),
          abortReason: result.skipped,
          stats: result.stats,
        })
        .where(eq(scanRunTable.id, scanRunId));
      logger.warn('probe did no work', { reason: result.skipped });
      return;
    }

    if (result.abortReason !== undefined) {
      await context.database
        .update(scanRunTable)
        .set({ status: 'aborted', finishedAt: new Date(), abortReason: result.abortReason })
        .where(eq(scanRunTable.id, scanRunId));
      logger.error('probe stopped early', { reason: result.abortReason });
      return;
    }

    const ingested =
      result.findings.length > 0
        ? await ingestFindings(context.database, {
            engagementId,
            clientId: input.runContext.clientId,
            scanRunId,
            toolName: input.toolId,
            raw: result.findings,
            cvssVersion: input.runContext.policy.report.cvssVersion,
          })
        : { createdFindings: [], created: 0, updated: 0, duplicates: 0 };

    // The comparison itself is the evidence. A finding that says "these two responses matched"
    // is worth nothing without the two responses beside it.
    for (const created of ingested.createdFindings) {
      if (created.evidenceText === undefined) continue;
      const stored = await context.evidence.capture({
        engagementId,
        scanRunId,
        kind: 'terminal',
        text: created.evidenceText,
        filename: `access-control-${created.id}.json`,
        disabledMaskingRuleIds: input.runContext.policy.evidence.disabledMaskingRuleIds,
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
        status: 'completed',
        finishedAt: new Date(),
        exitCode: 0,
        stats: { ...result.stats, ...ingested },
      })
      .where(eq(scanRunTable.id, scanRunId));

    logger.info('probe complete', { ...ingested });
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
  }
}
