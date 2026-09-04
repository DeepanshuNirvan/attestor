import { and, eq } from 'drizzle-orm';
import type { RawFinding } from '@attestor/findings';
import {
  accessControlMatrixProbe,
  runProbeForEngagement,
  type AccessObservation,
  type ReplayTemplate,
} from '@attestor/core';
import type { Logger } from '@attestor/shared';
import type { ConsoleContext } from '../context.ts';
import { discoveredAsset as discoveredAssetTable } from '../db/schema.ts';
import { accessIdentitiesFrom, openRunCredentials } from '../services/run-credentials.ts';
import { endpointsWithinTargets } from '../services/run-service.ts';
import type { EngagementRunContext } from '../services/run-service.ts';

/**
 * Running the access control matrix as part of an engagement.
 *
 * Kept out of the scan worker because it shares none of that path: no image, no container, no
 * output file to parse. What it does share is everything that matters — the scope guard, the rate
 * limiter, the audit trail — and those come from `runProbeForEngagement` rather than from here.
 */

/** Observation kinds that become candidate findings. The rest are the evidence that they are real. */
const REPORTABLE = new Set<AccessObservation['kind']>([
  'crossUserAccess',
  'crossRoleAccess',
  'unauthenticatedAccess',
]);

interface FindingShape {
  checkId: string;
  title: string;
  severity: RawFinding['severity'];
  cweId: number;
  wstgId: string;
  owaspCategory: RawFinding['owaspCategory'];
  remediation: string;
}

function shapeOf(observation: AccessObservation): FindingShape {
  switch (observation.kind) {
    case 'crossUserAccess':
      return {
        checkId: 'web-horizontal-access-control',
        title: `One account can read another account's data at ${new URL(observation.url).pathname}`,
        severity: 'high',
        cweId: 639,
        wstgId: 'WSTG-ATHZ-04',
        owaspCategory: 'A01:2025',
        remediation:
          'Check ownership on the server for every request that names an object, using the identity in the session rather than an identifier in the URL. An identifier that is hard to guess is not a control; the check has to happen whether or not the caller knew the value.',
      };
    case 'crossRoleAccess':
      return {
        checkId: 'web-vertical-access-control',
        title: `The ${observation.actor} role reaches ${new URL(observation.url).pathname}, which belongs to ${observation.owner}`,
        severity: 'high',
        cweId: 285,
        wstgId: 'WSTG-ATHZ-03',
        owaspCategory: 'A01:2025',
        remediation:
          'Decide authorisation on the server for every endpoint, from the role in the session. Hiding a link from a menu does not stop anyone requesting the URL.',
      };
    default:
      return {
        checkId: 'web-vertical-access-control',
        title: `${new URL(observation.url).pathname} answers an unauthenticated caller with the signed-in response`,
        severity: 'medium',
        cweId: 306,
        wstgId: 'WSTG-ATHZ-02',
        owaspCategory: 'A01:2025',
        remediation:
          'Require an authenticated session on this endpoint, or confirm deliberately that its content is meant to be public.',
      };
  }
}

function toFinding(observation: AccessObservation, cvssVersion: '3.1' | '4.0'): RawFinding {
  const shape = shapeOf(observation);
  const { hostname, pathname } = new URL(observation.url);

  return {
    source: 'tool',
    evidenceText: JSON.stringify(observation, null, 2),
    toolName: 'accessControlMatrix',
    toolFindingRef: `${observation.kind}:${observation.method} ${pathname}`,
    checkId: shape.checkId,
    title: shape.title,
    description: `${observation.detail} Replayed ${observation.method} ${observation.url}: ${observation.owner} received HTTP ${observation.ownerStatus}, ${observation.actor} received HTTP ${observation.actorStatus}, and the two responses were ${Math.round(observation.similarity * 100)}% the same.`,
    severity: shape.severity,
    cvssVersion,
    cweId: shape.cweId,
    owaspCategory: shape.owaspCategory,
    wstgId: shape.wstgId,
    affectedAssets: [{ value: hostname, location: pathname, method: observation.method }],
    businessImpact: '',
    likelihood: '',
    attackerPrerequisites: `An account on the application — the one held by ${observation.actor}.`,
    reproductionSteps: [
      `Sign in as ${observation.owner} and request ${observation.url}. Note the response.`,
      `Sign in as ${observation.actor} and request the same URL unchanged.`,
      'Compare the two responses. They are recorded in the evidence attached to this finding.',
    ],
    remediation: shape.remediation,
    references: [
      {
        title: 'OWASP Cheat Sheet: Authorization',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html',
      },
    ],
    evidence: [],
  };
}

/** Scope items are hostnames as often as URLs; the probe needs something it can request. */
function asAbsoluteUrl(target: string): string {
  return target.includes('://') ? target : `https://${target}`;
}

export interface AccessControlRunResult {
  findings: RawFinding[];
  /** Recorded on the run so a tester can see what was compared, not only what was wrong. */
  stats: Record<string, unknown>;
  /** Set when the probe had nothing to do. Not a failure. */
  skipped?: string;
  refusal?: { rule: string; detail: string };
  abortReason?: string;
}

export async function runAccessControlMatrix(
  context: ConsoleContext,
  input: {
    engagementId: string;
    scanRunId: string;
    targets: string[];
    runContext: EngagementRunContext;
    panicStopActive: boolean;
    actorId: string;
    dryRun: boolean;
    logger: Logger;
  },
): Promise<AccessControlRunResult> {
  const { policy } = input.runContext;

  // The policy switch that turns cross-role replay off was read for its threshold and its budget
  // and never for whether to run at all, so an engagement that had said no to replay testing got it
  // anyway. Two shipped profiles say no — `quick-external`, which is the one described as gentle
  // enough for production without a conversation, and `cloud-review`, which sends no web traffic at
  // all. Refusing here rather than at run creation keeps the reason on the run, where a client can
  // read it, instead of leaving a silent hole in the coverage matrix.
  if (!policy.accessControlMatrix.enabled) {
    return {
      findings: [],
      stats: { enabled: false },
      skipped:
        'Cross-role access control testing is switched off in this engagement policy. Set ' +
        'accessControlMatrix.enabled to run it.',
    };
  }

  const resolved = await openRunCredentials(
    context.database,
    context.vault,
    input.engagementId,
    policy,
  );
  const { identities, withoutSession } = accessIdentitiesFrom(resolved, policy);

  // Endpoints the crawl recorded. `replayable` is set by the crawl adapter and keeps stylesheets and
  // images out; without it the budget goes on static files before the first real endpoint.
  const assets = await context.database
    .select({ value: discoveredAssetTable.value, metadata: discoveredAssetTable.metadata })
    .from(discoveredAssetTable)
    .where(
      and(
        eq(discoveredAssetTable.engagementId, input.engagementId),
        eq(discoveredAssetTable.kind, 'endpoint'),
      ),
    );

  const owner = identities[0];
  const crawled = assets
    .filter((asset) => (asset.metadata as { replayable?: boolean } | null)?.replayable === true)
    .map((asset) => asset.value);

  // Falling back to the targets themselves when no crawl has run yet. It is a thin list, but the
  // probe reads the owner's own responses for object URLs, so a single authenticated page is often
  // enough to find them — and an engagement where recon has not run should still get something
  // rather than a run that completed having sent nothing.
  const inScope = endpointsWithinTargets(crawled, input.targets);
  const urls = inScope.length > 0 ? inScope : input.targets.map(asAbsoluteUrl);
  const templates: ReplayTemplate[] = owner
    ? urls.map((url) => ({ method: 'GET', url, owner: owner.name }))
    : [];

  const outcome = await runProbeForEngagement(
    accessControlMatrixProbe({
      identities,
      templates,
      similarityThreshold: policy.accessControlMatrix.responseSimilarityThreshold,
      maxReplayRequests: policy.accessControlMatrix.maxReplayRequests,
      testUnauthenticated: policy.accessControlMatrix.testUnauthenticated,
      rolePairs: policy.accessControlMatrix.rolePairs,
    }),
    {
      engagementId: input.engagementId,
      scanRunId: input.scanRunId,
      probeId: 'accessControlMatrix',
      targets: input.targets,
      secrets: resolved.secrets,
    },
    {
      scopeContext: input.runContext.scopeContext,
      policy,
      auditLog: context.auditLog,
      logger: input.logger,
      actorId: input.actorId,
      dryRun: input.dryRun,
    },
  );

  const shared = {
    identitiesCompared: identities.map((identity) => identity.name),
    identitiesWithoutSession: withoutSession,
    credentialWarnings: resolved.warnings,
    endpointsAvailable: templates.length,
  };

  if (outcome.status === 'refused') {
    return { findings: [], stats: shared, refusal: { rule: outcome.rule, detail: outcome.detail } };
  }
  if (outcome.status === 'dryRun') {
    return { findings: [], stats: { ...shared, dryRun: true } };
  }
  if (outcome.status === 'aborted') {
    return { findings: [], stats: shared, abortReason: outcome.reason };
  }

  const { observations, skipped, unavailableIdentities } = outcome.result;
  const findings = observations
    .filter((observation) => REPORTABLE.has(observation.kind))
    .map((observation) => toFinding(observation, policy.report.cvssVersion));

  const byKind: Record<string, number> = {};
  for (const observation of observations) byKind[observation.kind] = (byKind[observation.kind] ?? 0) + 1;

  return {
    findings,
    skipped,
    stats: {
      ...shared,
      identitiesWithoutSession: [...withoutSession, ...unavailableIdentities],
      requestsSent: outcome.requestCount,
      comparisons: observations.length,
      byKind,
    },
  };
}
