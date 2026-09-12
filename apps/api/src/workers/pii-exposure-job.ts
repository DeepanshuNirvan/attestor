import { and, eq } from 'drizzle-orm';
import type { RawFinding } from '@attestor/findings';
import {
  piiExposureProbe,
  runProbeForEngagement,
  type PiiExposureObservation,
} from '@attestor/core';
import type { Logger } from '@attestor/shared';
import type { ConsoleContext } from '../context.ts';
import { discoveredAsset as discoveredAssetTable } from '../db/schema.ts';
import { endpointsWithinTargets, type EngagementRunContext } from '../services/run-service.ts';

/**
 * Readable personal data in URLs, as part of an engagement.
 *
 * The endpoints come from what the crawl already discovered, narrowed to the hosts this run may
 * touch. Nothing is requested: the probe reads strings. That makes it the one probe with no rate
 * limit cost and no production risk, and it is why it is safe to leave on for every web engagement.
 */

const RULE_LABELS: Record<string, string> = {
  email: 'an email address',
  indianMobile: 'an Indian mobile number',
  internationalPhone: 'a phone number',
  pan: 'a PAN',
  aadhaar: 'an Aadhaar number',
  paymentCard: 'a payment card number',
  ifsc: 'a bank IFSC code',
};

function describeRules(ruleIds: string[]): string {
  const described = ruleIds.map((id) => RULE_LABELS[id] ?? id);
  if (described.length === 1) return described[0]!;
  return `${described.slice(0, -1).join(', ')} and ${described[described.length - 1]}`;
}

function toFinding(
  observation: PiiExposureObservation,
  cvssVersion: '3.1' | '4.0',
  endpointsExamined: number,
): RawFinding {
  const { hostname, pathname } = new URL(observation.maskedUrl);
  const where =
    observation.location === 'query'
      ? `the query string (${observation.parameterNames.join(', ')})`
      : 'the URL path';

  return {
    source: 'tool',
    // The masked URL, deliberately. Proving that personal data reaches the access log by copying it
    // into evidence storage would put it somewhere else nobody audited.
    evidenceText: JSON.stringify(observation, null, 2),
    toolName: 'piiExposureProbe',
    toolFindingRef: `${observation.location} ${pathname}`,
    checkId: 'web-sensitive-data-in-transit',
    title: `Personal data in the URL of ${pathname}`,
    description: `${pathname} carries ${describeRules(observation.ruleIds)} in ${where}. HTTPS encrypts the body of a request, but not its URL in the places the URL is copied to: the web server's access log, every proxy and load balancer in between, the browser's history, and — unless a referrer policy prevents it — the Referer header of requests the page makes to third parties. The value is therefore readable by anyone with access to any of those, long after the TLS session has ended, and it is outside the retention and access controls applied to the database. The URL above is masked in this report; the live one is not. This finding comes from examining ${endpointsExamined} endpoint${endpointsExamined === 1 ? '' : 's'} recorded during discovery.`,
    severity: 'medium',
    cvssVersion,
    cweId: 598,
    owaspCategory: 'A04:2025',
    wstgId: 'WSTG-CRYP-03',
    affectedAssets: [{ value: hostname, location: pathname, method: 'GET' }],
    businessImpact: '',
    likelihood: '',
    attackerPrerequisites:
      'Access to any log, proxy, analytics tool or browser that recorded the URL. No access to the application itself is required.',
    reproductionSteps: [
      `Request a page that links to ${pathname}.`,
      'Observe the value carried in the URL rather than in the request body.',
      'Check the web server access log for the same request: the value appears there in full.',
    ],
    remediation:
      'Move the value into the request body of a POST, or replace it with an identifier that means nothing outside your database — a UUID or an opaque token. Where the URL must carry it, set Referrer-Policy to same-origin or stricter so the value does not leave in the Referer header, and confirm the value is not written to access logs. Changing the log format is not a fix on its own: the URL still reaches proxies and browser history.',
    references: [
      {
        title: 'OWASP WSTG: Testing for Sensitive Information Sent via Unencrypted Channels',
        url: 'https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels',
      },
      {
        title: 'CWE-598: Use of GET Request Method With Sensitive Query Strings',
        url: 'https://cwe.mitre.org/data/definitions/598.html',
      },
    ],
    evidence: [],
  };
}

export interface PiiExposureRunResult {
  findings: RawFinding[];
  stats: Record<string, unknown>;
  skipped?: string;
  refusal?: { rule: string; detail: string };
  abortReason?: string;
}

export async function runPiiExposureProbe(
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
): Promise<PiiExposureRunResult> {
  const { policy } = input.runContext;

  const assets = await context.database
    .select({ value: discoveredAssetTable.value })
    .from(discoveredAssetTable)
    .where(
      and(
        eq(discoveredAssetTable.engagementId, input.engagementId),
        eq(discoveredAssetTable.kind, 'endpoint'),
      ),
    );

  const endpoints = endpointsWithinTargets(
    assets.map((asset) => asset.value),
    input.targets,
  );

  const outcome = await runProbeForEngagement(
    piiExposureProbe({ endpoints }),
    {
      engagementId: input.engagementId,
      scanRunId: input.scanRunId,
      probeId: 'piiExposureProbe',
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

  const shared = { endpointsExamined: endpoints.length };

  if (outcome.status === 'refused') {
    return { findings: [], stats: shared, refusal: { rule: outcome.rule, detail: outcome.detail } };
  }
  if (outcome.status === 'dryRun') return { findings: [], stats: { ...shared, dryRun: true } };
  if (outcome.status === 'aborted') {
    return { findings: [], stats: shared, abortReason: outcome.reason };
  }

  const { observations, endpointsExamined, skipped } = outcome.result;

  return {
    findings: observations.map((observation) =>
      toFinding(observation, policy.report.cvssVersion, endpointsExamined),
    ),
    skipped,
    stats: {
      ...shared,
      // Masked URLs only, for the same reason the finding carries them masked.
      results: observations.map((observation) => ({
        maskedUrl: observation.maskedUrl,
        location: observation.location,
        ruleIds: observation.ruleIds,
      })),
    },
  };
}
