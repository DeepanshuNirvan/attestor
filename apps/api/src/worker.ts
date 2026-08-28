import { buildConsoleContext } from './context.ts';
import { QUEUE_NAMES, buildQueues, buildWorker } from './queue.ts';
import type { RetainerJob, RetentionJob, ScanJob } from './queue.ts';
import { handleScanJob } from './workers/scan-worker.ts';
import { handleRetentionJob } from './workers/retention-worker.ts';
import { handleRetainerJob } from './workers/retainer-worker.ts';

/**
 * The worker process.
 *
 * Separate from the API so a tool run cannot take the console down with it, and so the worker can
 * be given the Docker socket while the API is not.
 *
 * The scan worker runs one job at a time. Tool containers are memory-hungry and the outbound rate
 * limits are global anyway, so parallelism inside one process buys little and makes the memory
 * ceiling harder to reason about. Scale by running more worker processes, sharded by engagement.
 */

const context = buildConsoleContext();
const queues = buildQueues(context.config.REDIS_URL);
const logger = context.logger.child({ process: 'worker' });

// A worker that was killed mid-run leaves its tool container and its per-run network behind, since
// the cleanup lives in a `finally` that never ran. Reclaim those before taking any new work —
// running containers are left alone, because they belong to a worker that is still alive.
const orphans = await context.containerRunner.reclaimOrphans().catch((error: unknown) => {
  logger.warn('could not reclaim orphaned run containers', { error });
  return null;
});
if (orphans && (orphans.containers > 0 || orphans.networks > 0)) {
  logger.info('reclaimed orphaned run resources from a previous worker', orphans);
}

const scanWorker = buildWorker<ScanJob>(
  QUEUE_NAMES.scan,
  (job) => handleScanJob(context, job),
  { redisUrl: context.config.REDIS_URL, concurrency: 1 },
);

const retentionWorker = buildWorker<RetentionJob>(
  QUEUE_NAMES.retention,
  (job) => handleRetentionJob(context, job),
  { redisUrl: context.config.REDIS_URL, concurrency: 1 },
);

const retainerWorker = buildWorker<RetainerJob>(
  QUEUE_NAMES.retainer,
  (job) => handleRetainerJob(context, queues, job),
  { redisUrl: context.config.REDIS_URL, concurrency: 1 },
);

for (const [name, worker] of [
  ['scan', scanWorker],
  ['retention', retentionWorker],
  ['retainer', retainerWorker],
] as const) {
  worker.on('failed', (job, error) => {
    logger.error(`${name} job failed`, { jobId: job?.id, error });
  });
  worker.on('completed', (job) => {
    logger.debug(`${name} job completed`, { jobId: job.id });
  });
}

// The retention sweep runs daily. A repeatable job rather than a cron process, so it survives a
// restart and shows up in the same queue dashboard as everything else.
await queues.retention.upsertJobScheduler(
  'daily-retention-sweep',
  { pattern: '0 3 * * *' },
  { name: 'retention', data: {} },
);

logger.info('worker started', {
  queues: [QUEUE_NAMES.scan, QUEUE_NAMES.retention, QUEUE_NAMES.retainer],
});

async function shutdown(signal: string): Promise<void> {
  logger.info('shutting down', { signal });
  // Close the workers first so no new job is picked up, then the queues.
  await Promise.all([scanWorker.close(), retentionWorker.close(), retainerWorker.close()]);
  await queues.close();
  process.exit(0);
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
