import type { RawFinding } from '@attestor/findings';
import {
  rateLimitProbe,
  runProbeForEngagement,
  type RateLimitObservation,
  type RateLimitTarget,
} from '@attestor/core';
import type { Logger } from '@attestor/shared';
import type { ConsoleContext } from '../context.ts';
import type { EngagementRunContext } from '../services/run-service.ts';

/**
 * Measuring throttling as part of an engagement.
 *
 * Which endpoints matter is read from the policy rather than discovered: an OTP request costs the
 * client money per message and a password reset emails a real person, so the decision to repeat a
 * request thirty times against one of them belongs to a person, in writing, before the run.
 *
 * The login named by the auth profile is included automatically because it is the one endpoint that
 * matters on every engagement, and it is probed with an address that cannot exist.
 */

/**
 * A local-part nobody owns under a reserved TLD. RFC 2606 keeps `.test` from ever resolving, so a
 * lockout counter that fires belongs to no account and no person is emailed.
 */
const NOBODY = 'nobody.attestor-probe@invalid.test';

export function rateLimitTargetsFrom(runContext: EngagementRunContext): RateLimitTarget[] {
  const { policy } = runContext;
  const targets: RateLimitTarget[] = [];

  for (const profile of policy.authProfiles) {
    const url = profile.apiLogin?.url ?? profile.loginUrl;
    if (profile.apiLogin === undefined || url === undefined) continue;
    targets.push({
      url,
      method: 'POST',
      description: `the sign-in endpoint for the ${profile.roleName} role`,
      body: {
        [profile.apiLogin.usernameField]: NOBODY,
        [profile.apiLogin.passwordField]: 'not-a-real-password',
      },
    });
  }

  for (const endpoint of policy.checks.rateLimitEndpoints) {
    targets.push({
      url: endpoint.url,
      method: endpoint.method,
      description: endpoint.description === '' ? endpoint.url : endpoint.description,
    });
  }

  return targets;
}

function toFinding(
  observation: RateLimitObservation,
  cvssVersion: '3.1' | '4.0',
  burst: number,
): RawFinding {
  const { hostname, pathname } = new URL(observation.url);

  return {
    source: 'tool',
    evidenceText: JSON.stringify(observation, null, 2),
    toolName: 'rateLimitProbe',
    toolFindingRef: `${observation.method} ${pathname}`,
    checkId: 'web-rate-limit-effectiveness',
    title: `No throttling on ${pathname} within ${observation.requestsSent} requests`,
    description: `${observation.requestsSent} requests were sent to ${observation.method} ${observation.url} — ${observation.description} — one after another, and every one was answered normally. Nothing slowed the caller down and nothing refused them. This is a bounded measurement: it shows there is no limit below ${burst} requests, not that there is no limit at all.`,
    severity: 'medium',
    cvssVersion,
    cweId: 307,
    owaspCategory: 'A07:2025',
    wstgId: 'WSTG-BUSL-05',
    affectedAssets: [{ value: hostname, location: pathname, method: observation.method }],
    businessImpact: '',
    likelihood: '',
    attackerPrerequisites: 'Nothing beyond the ability to make requests.',
    reproductionSteps: [
      `Send ${observation.method} ${observation.url} repeatedly.`,
      `Observe that ${observation.requestsSent} consecutive requests were answered without a 429, without a Retry-After, and without any delay.`,
    ],
    remediation:
      'Throttle by source address and by account on the endpoints where repetition is the attack — sign-in, one-time code requests, password reset and anything that costs money per call. Answer with 429 and a Retry-After so a legitimate client can back off, and count failures per account as well as per address so a distributed attempt is caught too.',
    references: [
      {
        title: 'OWASP Cheat Sheet: Denial of Service — application-level controls',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html',
      },
    ],
    evidence: [],
  };
}

export interface RateLimitRunResult {
  findings: RawFinding[];
  stats: Record<string, unknown>;
  skipped?: string;
  refusal?: { rule: string; detail: string };
  abortReason?: string;
}

export async function runRateLimitProbe(
  context: ConsoleContext,
  input: {
    engagementId: string;
    scanRunId: string;
    targets: string[];
    runContext: EngagementRunContext;
    actorId: string;
    dryRun: boolean;
    logger: Logger;
  },
): Promise<RateLimitRunResult> {
  const { policy } = input.runContext;
  const probeTargets = rateLimitTargetsFrom(input.runContext);
  const burst = policy.checks.rateLimitBurst;

  const outcome = await runProbeForEngagement(
    rateLimitProbe({ targets: probeTargets, burst }),
    {
      engagementId: input.engagementId,
      scanRunId: input.scanRunId,
      probeId: 'rateLimitProbe',
      targets: input.targets,
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

  const shared = { endpointsProbed: probeTargets.length, burst };

  if (outcome.status === 'refused') {
    return { findings: [], stats: shared, refusal: { rule: outcome.rule, detail: outcome.detail } };
  }
  if (outcome.status === 'dryRun') return { findings: [], stats: { ...shared, dryRun: true } };
  if (outcome.status === 'aborted') {
    return { findings: [], stats: shared, abortReason: outcome.reason };
  }

  const { observations } = outcome.result;

  // Nothing measured is not a clean result. One endpoint that could not be probed is a note in the
  // stats; every endpoint failing means the run covered nothing, and the worker records that as an
  // aborted run with the reason rather than as a completed one that found no problem.
  const unmeasured = observations.filter((observation) => observation.skipped !== undefined);
  const skipped =
    observations.length > 0 && unmeasured.length === observations.length
      ? `No endpoint could be measured. ${unmeasured[0]?.skipped ?? ''}`.trim()
      : outcome.result.skipped;

  const findings = observations
    .filter((observation) => observation.skipped === undefined && observation.throttledAfter === null)
    .filter((observation) => observation.requestsSent > 0)
    .map((observation) => toFinding(observation, policy.report.cvssVersion, burst));

  return {
    findings,
    skipped,
    stats: {
      ...shared,
      requestsSent: outcome.requestCount,
      // The endpoints that did throttle are recorded too. A control that worked is worth showing a
      // client, and it is the evidence that the ones which did not were measured the same way.
      results: observations.map((observation) => ({
        url: observation.url,
        throttledAfter: observation.throttledAfter,
        throttleStatus: observation.throttleStatus,
        requestsSent: observation.requestsSent,
        ...(observation.skipped ? { skipped: observation.skipped } : {}),
      })),
    },
  };
}
