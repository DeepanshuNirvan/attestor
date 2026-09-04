import { and, eq } from 'drizzle-orm';
import type { RawFinding } from '@attestor/findings';
import {
  requestManipulationProbe,
  runProbeForEngagement,
  type HostHeaderObservation,
  type MethodObservation,
  type ParameterPollutionObservation,
} from '@attestor/core';
import type { Logger } from '@attestor/shared';
import type { ConsoleContext } from '../context.ts';
import { discoveredAsset as discoveredAssetTable } from '../db/schema.ts';
import { endpointsWithinTargets } from '../services/run-service.ts';
import type { EngagementRunContext } from '../services/run-service.ts';

/**
 * Verb tampering, parameter pollution and host header injection, as part of an engagement.
 *
 * The URLs come from what a crawl recorded, the same source the access control matrix reads, so the
 * probe examines the application's real endpoints rather than its front page. Every request is a
 * GET, a HEAD or an OPTIONS, which is why this runs unchanged in read-only mode.
 */

/** How many endpoints to examine. Each costs at most six requests, so this is the whole budget. */
const MAX_URLS = 12;

function asAbsoluteUrl(target: string): string {
  return /^https?:\/\//.test(target) ? target : `http://${target}`;
}

function assetOf(url: string, method?: string): RawFinding['affectedAssets'] {
  const parsed = new URL(url);
  return [{ value: parsed.host, location: parsed.pathname, ...(method ? { method } : {}) }];
}

function verbTamperingFinding(
  observation: MethodObservation,
  cvssVersion: '3.1' | '4.0',
): RawFinding {
  const bypass = observation.verbBypass;
  const detail = bypass ?? { restrictedWith: 'GET', allowedWith: 'HEAD', restrictedStatus: 403 };
  return {
    source: 'tool',
    toolName: 'requestManipulationProbe',
    toolFindingRef: `verb-tampering ${new URL(observation.url).pathname}`,
    checkId: 'web-http-methods',
    title: `Access control depends on the HTTP method at ${new URL(observation.url).pathname}`,
    description: `${detail.restrictedWith} ${observation.url} is refused with ${detail.restrictedStatus}, and ${detail.allowedWith} on the same URL is answered normally. The resource is therefore guarded by which method is used rather than by who is asking, which is the classic result of a server-level rule that names its methods — an Apache \`<Limit>\` block or a servlet \`<http-method>\` constraint. Anything the rule does not name reaches the resource.`,
    severity: 'high',
    cvssVersion,
    cweId: 288,
    owaspCategory: 'A01:2025',
    wstgId: 'WSTG-INPV-03',
    affectedAssets: assetOf(observation.url, detail.allowedWith),
    evidenceText: JSON.stringify(observation, null, 2),
    businessImpact: '',
    likelihood: '',
    attackerPrerequisites: 'Nothing beyond the ability to choose a request method.',
    reproductionSteps: [
      `Send ${detail.restrictedWith} ${observation.url} and observe ${detail.restrictedStatus}.`,
      `Send ${detail.allowedWith} to the same URL and observe that it is answered.`,
    ],
    remediation:
      'Authorise the request, not the verb. Deny by default and allow named methods explicitly, rather than restricting a list and leaving everything outside it open, and apply the check in application code where the identity is known rather than in a server configuration block that enumerates methods.',
    references: [
      {
        title: 'OWASP WSTG: Testing for HTTP Verb Tampering',
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering',
      },
    ],
    evidence: [],
  };
}

function writeMethodFinding(
  observation: MethodObservation,
  cvssVersion: '3.1' | '4.0',
): RawFinding {
  return {
    source: 'tool',
    toolName: 'requestManipulationProbe',
    toolFindingRef: `methods ${new URL(observation.url).pathname}`,
    checkId: 'web-http-methods',
    title: `${observation.notable.join(', ')} advertised at ${new URL(observation.url).pathname}`,
    description: `An OPTIONS request to ${observation.url} advertises ${observation.advertised.join(', ')}. ${observation.notable.join(' and ')} can modify or echo state, and a method that is advertised is usually a method that is routed. The probe did not send any of them — confirming what they do is a decision for a person with the client's agreement in hand, because the request that proves it is the request that changes something.`,
    severity: 'low',
    cvssVersion,
    cweId: 650,
    owaspCategory: 'A05:2025',
    wstgId: 'WSTG-CONF-06',
    affectedAssets: assetOf(observation.url),
    evidenceText: JSON.stringify(observation, null, 2),
    businessImpact: '',
    likelihood: '',
    attackerPrerequisites: 'Nothing. The methods are advertised to anyone who asks.',
    reproductionSteps: [`Send OPTIONS ${observation.url} and read the Allow header.`],
    remediation:
      'Disable the methods the application does not implement at the edge, and make sure the ones it does implement are subject to the same authorisation as GET. TRACE in particular should be off everywhere: it exists to echo the request back, including headers the client cannot otherwise read.',
    references: [
      {
        title: 'OWASP WSTG: Test HTTP Methods',
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
      },
    ],
    evidence: [],
  };
}

function pollutionFinding(
  observation: ParameterPollutionObservation,
  cvssVersion: '3.1' | '4.0',
): RawFinding {
  const { pathname } = new URL(observation.url);
  return {
    source: 'tool',
    toolName: 'requestManipulationProbe',
    toolFindingRef: `hpp ${pathname}?${observation.parameter}`,
    checkId: 'web-parameter-pollution',
    title: `Duplicated \`${observation.parameter}\` resolves to the ${observation.resolvedAs} value at ${pathname}`,
    description: `Sending \`${observation.parameter}\` twice on ${observation.url} produced a response matching the ${observation.resolvedAs === 'neither' ? 'neither of the two single-value requests' : `${observation.resolvedAs} of the two values`}. That matters because the layers in front of an application rarely agree about which copy to read: a WAF, a gateway and a framework can each pick a different one, so a value that passes inspection is not always the value that is used. Where a parameter carries an identifier, a price or a role, that disagreement is the vulnerability.`,
    severity: 'low',
    cvssVersion,
    cweId: 235,
    owaspCategory: 'A03:2025',
    wstgId: 'WSTG-INPV-04',
    affectedAssets: assetOf(observation.url, 'GET'),
    evidenceText: JSON.stringify(observation, null, 2),
    businessImpact: '',
    likelihood: '',
    attackerPrerequisites: 'Nothing beyond the ability to add a query parameter.',
    reproductionSteps: [
      `Request ${observation.url} with \`${observation.parameter}\` set once, then again with a different value.`,
      `Request it with both values present and compare the response against the two above.`,
    ],
    remediation:
      'Reject a request that carries the same parameter twice rather than picking one, and make the choice identical in every layer that inspects the request. Where a framework silently takes the first or the last, say so explicitly in code at the point the value is read.',
    references: [
      {
        title: 'OWASP WSTG: Testing for HTTP Parameter Pollution',
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution',
      },
    ],
    evidence: [],
  };
}

function hostHeaderFinding(
  observation: HostHeaderObservation,
  cvssVersion: '3.1' | '4.0',
): RawFinding {
  const { pathname } = new URL(observation.url);
  const inLocation = observation.reflectedIn === 'location';
  return {
    source: 'tool',
    toolName: 'requestManipulationProbe',
    toolFindingRef: `host-header ${pathname}`,
    checkId: 'web-host-header-handling',
    title: `The application builds ${inLocation ? 'a redirect' : 'page content'} from a client-supplied host header at ${pathname}`,
    description: `A request to ${observation.url} carrying \`X-Forwarded-Host: attestor-probe.invalid\` came back with that name ${inLocation ? 'in the Location header, so the redirect target is chosen by the requester' : 'inside the response body, so a link or an absolute URL on the page is built from it'}. The consequence is worst where the application sends a link to somebody else: a password-reset or invitation mail generated from a request an attacker made points wherever the attacker asked, and the recipient's token arrives at the attacker's server. It also poisons any cache keyed on the path alone.`,
    severity: inLocation ? 'high' : 'medium',
    cvssVersion,
    cweId: 644,
    owaspCategory: 'A05:2025',
    wstgId: 'WSTG-INPV-17',
    affectedAssets: assetOf(observation.url, 'GET'),
    evidenceText: JSON.stringify(observation, null, 2),
    businessImpact: '',
    likelihood: '',
    attackerPrerequisites: 'The ability to send a request with a header of their choosing.',
    reproductionSteps: [
      `Send GET ${observation.url} with the header \`X-Forwarded-Host: attestor-probe.invalid\`.`,
      inLocation
        ? 'Observe that the Location header names that host.'
        : 'Observe that the response body contains that host.',
    ],
    remediation:
      'Build absolute URLs from configuration, never from the request. Where a reverse proxy genuinely terminates the public name, set the forwarded headers at the proxy and have the application ignore any copy that arrived from outside it, then validate the resulting host against an allow-list before it reaches a link, a redirect or a cache key.',
    references: [
      {
        title: 'OWASP WSTG: Testing for Host Header Injection',
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection',
      },
    ],
    evidence: [],
  };
}

export interface RequestManipulationRunResult {
  findings: RawFinding[];
  stats: Record<string, unknown>;
  skipped?: string;
  refusal?: { rule: string; detail: string };
  abortReason?: string;
}

export async function runRequestManipulation(
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
): Promise<RequestManipulationRunResult> {
  const { policy } = input.runContext;

  // The endpoints a crawl recorded, same source and same filter as the access control matrix. The
  // fallback keeps an engagement where recon has not run from producing a run that sent nothing.
  const assets = await context.database
    .select({ value: discoveredAssetTable.value, metadata: discoveredAssetTable.metadata })
    .from(discoveredAssetTable)
    .where(
      and(
        eq(discoveredAssetTable.engagementId, input.engagementId),
        eq(discoveredAssetTable.kind, 'endpoint'),
      ),
    );

  const crawled = assets
    .filter((asset) => (asset.metadata as { replayable?: boolean } | null)?.replayable === true)
    .map((asset) => asset.value);
  const inScope = endpointsWithinTargets(crawled, input.targets);
  const urls = inScope.length > 0 ? inScope : input.targets.map(asAbsoluteUrl);

  const outcome = await runProbeForEngagement(
    requestManipulationProbe({ urls, maxUrls: MAX_URLS }),
    {
      engagementId: input.engagementId,
      scanRunId: input.scanRunId,
      probeId: 'requestManipulationProbe',
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

  const shared = { urlsAvailable: urls.length, urlsExamined: Math.min(urls.length, MAX_URLS) };

  if (outcome.status === 'refused') {
    return { findings: [], stats: shared, refusal: { rule: outcome.rule, detail: outcome.detail } };
  }
  if (outcome.status === 'dryRun') return { findings: [], stats: { ...shared, dryRun: true } };
  if (outcome.status === 'aborted') {
    return { findings: [], stats: shared, abortReason: outcome.reason };
  }

  const { methods, pollution, hostHeader, skipped } = outcome.result;
  const cvssVersion = policy.report.cvssVersion;

  const findings = [
    ...methods.filter((m) => m.verbBypass !== undefined).map((m) => verbTamperingFinding(m, cvssVersion)),
    ...methods.filter((m) => m.notable.length > 0).map((m) => writeMethodFinding(m, cvssVersion)),
    // `last` is what almost every stack does and is not on its own a finding. `first` and `neither`
    // are the shapes where a filter and the application can disagree, which is the vulnerability.
    ...pollution
      .filter((p) => p.resolvedAs !== 'last')
      .map((p) => pollutionFinding(p, cvssVersion)),
    ...hostHeader
      .filter((h) => h.reflectedIn !== undefined)
      .map((h) => hostHeaderFinding(h, cvssVersion)),
  ];

  return {
    findings,
    skipped,
    stats: {
      ...shared,
      requestsSent: outcome.requestCount,
      methodsProbed: methods.length,
      parametersProbed: pollution.length,
      // What was checked and came back clean is worth recording: it is the evidence that the tests
      // which found nothing were actually performed.
      hostHeaderReflections: hostHeader.filter((h) => h.reflectedIn !== undefined).length,
      hostHeaderChecked: hostHeader.length,
    },
  };
}
