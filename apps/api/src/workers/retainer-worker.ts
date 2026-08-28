import { and, desc, eq, gte, inArray, lt } from 'drizzle-orm';
import type { Job } from 'bullmq';
import { countBySeverity, diffFindings, type Finding } from '@attestor/findings';
import type { ModuleName } from '@attestor/shared';
import type { ConsoleContext } from '../context.ts';
import {
  engagement as engagementTable,
  finding as findingTable,
  notification as notificationTable,
  retainerSchedule,
  scanRun as scanRunTable,
} from '../db/schema.ts';
import type { Queues, RetainerJob } from '../queue.ts';
import { createRunsForModule, loadRunContext } from '../services/run-service.ts';

/**
 * The retainer engine.
 *
 * Scheduled runs, a diff against the previous run, and a monthly posture summary. The diff is what
 * the client is actually paying for: new findings, resolved findings, and regressions.
 *
 * Regressions are separated out and called out loudly, because a finding that was fixed and has
 * come back is not a security problem, it is a release process problem, and fixing the finding
 * again without fixing the process means seeing it a third time.
 */

const CADENCE_DAYS: Record<string, number> = {
  weekly: 7,
  fortnightly: 14,
  monthly: 30,
  quarterly: 91,
};

export async function handleRetainerJob(
  context: ConsoleContext,
  queues: Queues,
  job: Job<RetainerJob>,
): Promise<void> {
  const logger = context.logger.child({ worker: 'retainer', scheduleId: job.data.scheduleId });

  const schedules = await context.database
    .select()
    .from(retainerSchedule)
    .where(and(eq(retainerSchedule.id, job.data.scheduleId), eq(retainerSchedule.active, true)))
    .limit(1);
  const schedule = schedules[0];
  if (!schedule?.engagementId) {
    logger.warn('retainer schedule is inactive or has no engagement; nothing to do');
    return;
  }

  const panicStopActive = await context.panicStop.isActive(schedule.engagementId);
  if (panicStopActive) {
    logger.warn('a panic stop is in force; the scheduled run is skipped, not queued');
    return;
  }

  const runContext = await loadRunContext(context.database, schedule.engagementId, panicStopActive);

  // Snapshot the findings as they stand before this run, so the diff afterwards is against a known
  // state rather than against whatever the table happens to contain later.
  const before = await loadFindings(context, schedule.engagementId);

  for (const module of schedule.modules as ModuleName[]) {
    const runs = await createRunsForModule(context.database, {
      engagementId: schedule.engagementId,
      module,
      targets: runContext.targets,
      policy: runContext.policy,
      dryRun: false,
    });

    for (const run of runs) {
      await queues.scan.add('scan', {
        engagementId: schedule.engagementId,
        scanRunId: run.scanRunId,
        module: run.module,
        toolId: run.toolId,
        targets: run.targets,
        dryRun: false,
        requestedBy: 'system',
      });
    }
  }

  const nextRunAt = new Date(
    Date.now() + (CADENCE_DAYS[schedule.cadence] ?? 30) * 24 * 60 * 60 * 1000,
  );

  await context.database
    .update(retainerSchedule)
    .set({ lastRunAt: new Date(), nextRunAt })
    .where(eq(retainerSchedule.id, schedule.id));

  logger.info('scheduled runs queued', {
    modules: schedule.modules,
    previousFindings: before.length,
    nextRunAt,
  });
}

async function loadFindings(context: ConsoleContext, engagementId: string): Promise<Finding[]> {
  const rows = await context.database
    .select()
    .from(findingTable)
    .where(
      and(
        eq(findingTable.engagementId, engagementId),
        inArray(findingTable.status, ['open', 'fixed', 'riskAccepted']),
      ),
    );

  return rows.map((row) => ({
    id: row.id,
    engagementId: row.engagementId,
    source: row.source as Finding['source'],
    title: row.title,
    description: row.description,
    severity: row.severity as Finding['severity'],
    affectedAssets: row.affectedAssets as Finding['affectedAssets'],
    businessImpact: row.businessImpact,
    likelihood: row.likelihood,
    attackerPrerequisites: row.attackerPrerequisites,
    reproductionSteps: row.reproductionSteps as string[],
    remediation: row.remediation,
    references: row.references as Finding['references'],
    status: row.status as Finding['status'],
    dedupeKey: row.dedupeKey,
    firstSeenAt: row.firstSeenAt,
    lastSeenAt: row.lastSeenAt,
  }));
}

export interface PostureSummary {
  engagementId: string;
  reference: string;
  counts: ReturnType<typeof countBySeverity>;
  newFindings: number;
  resolved: number;
  regressions: { reference: string | null; title: string }[];
  attackSurfaceChanges: string[];
  slaBreaches: { reference: string | null; title: string; ageDays: number }[];
}

/**
 * The monthly one-page summary. Built here, queued for a human, never auto-sent.
 */
export async function buildMonthlySummary(
  context: ConsoleContext,
  engagementId: string,
  since: Date,
): Promise<PostureSummary> {
  const engagements = await context.database
    .select({ reference: engagementTable.reference })
    .from(engagementTable)
    .where(eq(engagementTable.id, engagementId))
    .limit(1);

  const current = await loadFindings(context, engagementId);

  const previouslySeen = await context.database
    .select()
    .from(findingTable)
    .where(and(eq(findingTable.engagementId, engagementId), lt(findingTable.firstSeenAt, since)));

  const previous: Finding[] = previouslySeen.map((row) => ({
    id: row.id,
    engagementId: row.engagementId,
    source: row.source as Finding['source'],
    title: row.title,
    description: row.description,
    severity: row.severity as Finding['severity'],
    affectedAssets: row.affectedAssets as Finding['affectedAssets'],
    businessImpact: row.businessImpact,
    likelihood: row.likelihood,
    attackerPrerequisites: row.attackerPrerequisites,
    reproductionSteps: row.reproductionSteps as string[],
    remediation: row.remediation,
    references: row.references as Finding['references'],
    status: row.status as Finding['status'],
    dedupeKey: row.dedupeKey,
    firstSeenAt: row.firstSeenAt,
    lastSeenAt: row.lastSeenAt,
  }));

  const diff = diffFindings(previous, current);

  // Attack surface changes come from the recon runs since the cut-off: new hosts, new ports, new
  // certificates. The recon adapter's asset output is what feeds this.
  const recentRuns = await context.database
    .select({ stats: scanRunTable.stats, module: scanRunTable.module })
    .from(scanRunTable)
    .where(
      and(
        eq(scanRunTable.engagementId, engagementId),
        eq(scanRunTable.module, 'recon'),
        gte(scanRunTable.createdAt, since),
      ),
    )
    .orderBy(desc(scanRunTable.createdAt));

  const attackSurfaceChanges = recentRuns
    .map((run) => (run.stats as { newAssets?: string[] }).newAssets ?? [])
    .flat();

  // SLA timers: a critical open longer than 14 days, a high longer than 30, is escalated.
  const now = Date.now();
  const slaBreaches = current
    .filter((finding) => finding.status === 'open')
    .map((finding) => ({
      finding,
      ageDays: Math.floor((now - finding.firstSeenAt.getTime()) / 86_400_000),
    }))
    .filter(
      (entry) =>
        (entry.finding.severity === 'critical' && entry.ageDays > 14) ||
        (entry.finding.severity === 'high' && entry.ageDays > 30),
    )
    .map((entry) => ({
      reference: entry.finding.id,
      title: entry.finding.title,
      ageDays: entry.ageDays,
    }));

  return {
    engagementId,
    reference: engagements[0]?.reference ?? '',
    counts: countBySeverity(current.filter((finding) => finding.status === 'open')),
    newFindings: diff.newFindings.length,
    resolved: diff.resolved.length,
    regressions: diff.regressions.map((finding) => ({
      reference: finding.reference ?? null,
      title: finding.title,
    })),
    attackSurfaceChanges,
    slaBreaches,
  };
}

/**
 * Queue a client-facing message. Nothing here sends: a human reviews and releases it, which is the
 * rule for every client-facing message in v1.
 */
export async function queueClientNotification(
  context: ConsoleContext,
  input: {
    engagementId: string;
    template: string;
    subject: string;
    body: string;
    severityThreshold?: string;
  },
): Promise<void> {
  await context.database.insert(notificationTable).values({
    engagementId: input.engagementId,
    channel: 'email',
    template: input.template,
    subject: input.subject,
    // Findings detail never goes in an email body. The message points at the portal.
    body: input.body,
    severityThreshold: input.severityThreshold ?? null,
  });
}
