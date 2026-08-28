import { Queue, Worker, type ConnectionOptions, type Job } from 'bullmq';
import { z } from 'zod';

/**
 * The job queue.
 *
 * Everything long-running is a job so that a crashed worker loses at most one tool run rather than
 * an engagement's progress. Jobs are idempotent: each one records its own scan run row before it
 * starts and refuses to start a second time for the same row, so a retry after a crash resumes
 * rather than duplicates.
 */

export const QUEUE_NAMES = {
  scan: 'attestor.scan',
  report: 'attestor.report',
  retention: 'attestor.retention',
  retainer: 'attestor.retainer',
  notification: 'attestor.notification',
} as const;

export const scanJobSchema = z.object({
  engagementId: z.string().uuid(),
  scanRunId: z.string().uuid(),
  module: z.string(),
  toolId: z.string(),
  targets: z.array(z.string()).min(1),
  dryRun: z.boolean().default(false),
  requestedBy: z.string(),
});

export const reportJobSchema = z.object({
  engagementId: z.string().uuid(),
  reportId: z.string().uuid(),
  kind: z.enum(['assessment', 'retest', 'attestation', 'deletionConfirmation', 'executiveOnePager']),
  requestedBy: z.string(),
});

export const retentionJobSchema = z.object({
  /** Absent means "every engagement whose retention has expired". */
  engagementId: z.string().uuid().optional(),
});

export const retainerJobSchema = z.object({
  scheduleId: z.string().uuid(),
});

export const notificationJobSchema = z.object({
  notificationId: z.string().uuid(),
});

export type ScanJob = z.infer<typeof scanJobSchema>;
export type ReportJob = z.infer<typeof reportJobSchema>;
export type RetentionJob = z.infer<typeof retentionJobSchema>;
export type RetainerJob = z.infer<typeof retainerJobSchema>;
export type NotificationJob = z.infer<typeof notificationJobSchema>;

export function connectionFor(redisUrl: string): ConnectionOptions {
  const url = new URL(redisUrl);
  return {
    host: url.hostname,
    port: Number(url.port || 6379),
    password: url.password || undefined,
    // BullMQ requires this to be null for blocking commands.
    maxRetriesPerRequest: null,
  };
}

/**
 * Retries are conservative. A tool run that failed because the target was unhealthy should not be
 * retried three times in quick succession — that is the shape of traffic this platform exists not
 * to produce.
 */
const DEFAULT_JOB_OPTIONS = {
  attempts: 2,
  backoff: { type: 'exponential' as const, delay: 30_000 },
  removeOnComplete: { age: 7 * 24 * 3600, count: 1000 },
  removeOnFail: { age: 30 * 24 * 3600 },
};

export interface Queues {
  scan: Queue<ScanJob>;
  report: Queue<ReportJob>;
  retention: Queue<RetentionJob>;
  retainer: Queue<RetainerJob>;
  notification: Queue<NotificationJob>;
  close: () => Promise<void>;
}

export function buildQueues(redisUrl: string): Queues {
  const connection = connectionFor(redisUrl);
  const options = { connection, defaultJobOptions: DEFAULT_JOB_OPTIONS };

  const scan = new Queue<ScanJob>(QUEUE_NAMES.scan, options);
  const report = new Queue<ReportJob>(QUEUE_NAMES.report, options);
  const retention = new Queue<RetentionJob>(QUEUE_NAMES.retention, options);
  const retainer = new Queue<RetainerJob>(QUEUE_NAMES.retainer, options);
  const notification = new Queue<NotificationJob>(QUEUE_NAMES.notification, options);

  return {
    scan,
    report,
    retention,
    retainer,
    notification,
    close: async () => {
      await Promise.all([
        scan.close(),
        report.close(),
        retention.close(),
        retainer.close(),
        notification.close(),
      ]);
    },
  };
}

export interface WorkerOptions {
  redisUrl: string;
  /**
   * One tool run at a time per worker process by default.
   *
   * ponytail: single-concurrency worker; shard by engagement across processes if throughput
   * matters. Tool containers are memory-hungry and the platform's own rate limits are global, so
   * running several in one process buys little and makes a memory ceiling harder to reason about.
   */
  concurrency?: number;
}

export function buildWorker<T>(
  name: string,
  handler: (job: Job<T>) => Promise<void>,
  options: WorkerOptions,
): Worker<T> {
  return new Worker<T>(name, handler, {
    connection: connectionFor(options.redisUrl),
    concurrency: options.concurrency ?? 1,
    // A tool run can legitimately take two hours; the lock must outlive it or BullMQ will hand the
    // same job to a second worker while the first is still running a container.
    lockDuration: 3 * 60 * 60 * 1000,
    stalledInterval: 60_000,
  });
}
