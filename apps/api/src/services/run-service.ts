import { and, desc, eq, isNull } from 'drizzle-orm';
import { resolvePolicy, windowsToMinutes, type Policy } from '@attestor/policy';
import type { EngagementScopeContext } from '@attestor/core';
import { adapterFor, adaptersForModule } from '@attestor/scanners';
import type { ModuleName } from '@attestor/shared';
import type { Database } from '../db/client.ts';
import {
  authorisation as authorisationTable,
  client as clientTable,
  engagement as engagementTable,
  scanRun as scanRunTable,
  scopeItem as scopeItemTable,
} from '../db/schema.ts';

/**
 * Everything needed to start a run, assembled from the database.
 *
 * The scope context this builds is what the guard evaluates. It is deliberately assembled in one
 * place: a caller that constructed its own context could omit the authorisation or the panic-stop
 * flag, and the guard would then be checking a fiction.
 */

export interface EngagementRunContext {
  engagementId: string;
  clientId: string;
  reference: string;
  policy: Policy;
  policyWarnings: string[];
  scopeContext: EngagementScopeContext;
  /** Hostnames and addresses the engagement authorises, for building tool target lists. */
  targets: string[];
}

export async function loadRunContext(
  database: Database,
  engagementId: string,
  panicStopActive: boolean,
): Promise<EngagementRunContext> {
  const engagements = await database
    .select()
    .from(engagementTable)
    .where(eq(engagementTable.id, engagementId))
    .limit(1);
  const record = engagements[0];
  if (!record) throw new Error(`engagement ${engagementId} not found`);

  const clients = await database
    .select({ policyYaml: clientTable.policyYaml })
    .from(clientTable)
    .where(eq(clientTable.id, record.clientId))
    .limit(1);

  const scopeItems = await database
    .select()
    .from(scopeItemTable)
    .where(eq(scopeItemTable.engagementId, engagementId));

  const authorisations = await database
    .select()
    .from(authorisationTable)
    .where(
      and(eq(authorisationTable.engagementId, engagementId), isNull(authorisationTable.revokedAt)),
    )
    .orderBy(desc(authorisationTable.createdAt))
    .limit(1);
  const authorisation = authorisations[0];

  const { policy, warnings } = resolvePolicy([
    { name: 'client', yamlSource: clients[0]?.policyYaml ?? '' },
    { name: 'engagement', yamlSource: record.policyYaml },
  ]);

  const scopeContext: EngagementScopeContext = {
    engagementId,
    state: record.state as EngagementScopeContext['state'],
    authorisation: authorisation
      ? {
          id: authorisation.id,
          signedAt: authorisation.signedAt,
          revokedAt: authorisation.revokedAt,
          validFrom: authorisation.validFrom,
          validUntil: authorisation.validUntil,
        }
      : null,
    scopeItems: scopeItems.map((item) => ({
      id: item.id,
      kind: item.kind as EngagementScopeContext['scopeItems'][number]['kind'],
      value: item.value,
      included: item.included,
    })),
    testWindows: windowsToMinutes(policy.windows),
    timezone: record.timezone,
    ownedPrivateRanges: scopeItems
      .filter((item) => item.included && item.kind === 'cidr')
      .map((item) => item.value),
    thirdPartyInfrastructureAcknowledged: record.thirdPartyInfrastructureAcknowledgedAt !== null,
    cloudTestingPolicyAcknowledged: record.cloudTestingPolicyAcknowledgedAt !== null,
    panicStopActive,
  };

  const targets = scopeItems
    .filter((item) => item.included)
    .filter((item) => ['domain', 'wildcard', 'url', 'ip', 'llmEndpoint'].includes(item.kind))
    // A wildcard is not a target in itself; the hosts under it come from recon.
    .filter((item) => item.kind !== 'wildcard')
    .map((item) => item.value);

  return {
    engagementId,
    clientId: record.clientId,
    reference: record.reference,
    policy,
    policyWarnings: warnings,
    scopeContext,
    targets,
  };
}

export interface QueuedRun {
  scanRunId: string;
  toolId: string;
  module: ModuleName;
  targets: string[];
}

/**
 * Create the scan run rows for a module. The rows exist before any job is queued, so a crash
 * between "queued" and "started" leaves a visible row in `queued` rather than a silent gap.
 */
export async function createRunsForModule(
  database: Database,
  input: {
    engagementId: string;
    module: ModuleName;
    targets: string[];
    policy: Policy;
    dryRun: boolean;
  },
): Promise<QueuedRun[]> {
  const adapters = adaptersForModule(input.module);
  const runs: QueuedRun[] = [];

  for (const adapter of adapters) {
    const [row] = await database
      .insert(scanRunTable)
      .values({
        engagementId: input.engagementId,
        module: input.module,
        toolName: adapter.id,
        policySnapshot: input.policy,
        coveredCheckIds: adapter.coversCheckIds,
        targets: input.targets,
        status: 'queued',
        dryRun: input.dryRun,
      })
      .returning({ id: scanRunTable.id });

    if (!row) continue;
    runs.push({
      scanRunId: row.id,
      toolId: adapter.id,
      module: input.module,
      targets: input.targets,
    });
  }

  return runs;
}

/**
 * Which catalogue checks a set of completed runs actually covered. Feeds the coverage matrix, and
 * is the reason `coversCheckIds` is stored on the run rather than looked up at report time: an
 * adapter that gains coverage next month must not retroactively change an issued report.
 */
export async function coverageFromRuns(
  database: Database,
  engagementId: string,
): Promise<{
  completedRuns: { scanRunId: string; checkIds: string[] }[];
  abortedRuns: { scanRunId: string; checkIds: string[]; abortReason: string }[];
}> {
  const runs = await database
    .select()
    .from(scanRunTable)
    .where(eq(scanRunTable.engagementId, engagementId));

  return {
    completedRuns: runs
      .filter((run) => run.status === 'completed' && !run.dryRun)
      .map((run) => ({ scanRunId: run.id, checkIds: run.coveredCheckIds as string[] })),
    abortedRuns: runs
      .filter((run) => run.status === 'aborted' || run.status === 'failed')
      .map((run) => ({
        scanRunId: run.id,
        checkIds: run.coveredCheckIds as string[],
        abortReason: run.abortReason ?? 'the run did not complete',
      })),
  };
}

export function invocationFor(
  toolId: string,
  policy: Policy,
  targets: string[],
): ReturnType<ReturnType<typeof adapterFor>['buildInvocation']> {
  return adapterFor(toolId).buildInvocation({ policy, targets, outputPath: '/out' });
}
