import { buildCoverageMatrix, checkCatalogue } from '@attestor/findings';
import type { ReportData, ReportFinding } from '../render.ts';
import {
  sampleAttackNarrative,
  sampleEngagement,
  sampleFindings,
  samplePositiveObservations,
} from './juice-shop-sample.ts';

/**
 * The sample report as `ReportData`.
 *
 * This is the fixture the golden-file test renders and the one the website publishes, so the
 * document a prospect reads and the document the tests assert on are the same document.
 *
 * Every date is a literal. Nothing here reads the clock, or the golden file would change daily.
 */

const dateFormat = new Intl.DateTimeFormat('en-GB', {
  day: 'numeric',
  month: 'long',
  year: 'numeric',
  timeZone: 'UTC',
});

function evidenceFor(reference: string): ReportFinding['evidence'] {
  switch (reference) {
    case 'ATT-2026-000-001':
      return [
        {
          kind: 'request',
          caption: 'Authentication request and response, masked',
          text: `POST /rest/user/login HTTP/1.1
Host: juice.attestor-lab.internal
Content-Type: application/json

{"email":"' OR 1=1--","password":"anything"}

--- response ---
HTTP 200
Content-Type: application/json

{"authentication":{"token":"[REDACTED]","bid":1,"umail":"a*****@j*********.***"}}`,
        },
      ];
    case 'ATT-2026-000-002':
      return [
        {
          kind: 'request',
          caption: 'Basket belonging to a different customer, retrieved with account A\'s session',
          text: `GET /rest/basket/2 HTTP/1.1
Host: juice.attestor-lab.internal
Authorization: [REDACTED]

--- response ---
HTTP 200

{"data":{"id":2,"UserId":2,"Products":[{"name":"Melon Bike","price":2999,"quantity":1}],"coupon":"WELCOME10"}}`,
        },
      ];
    case 'ATT-2026-000-005':
      return [
        {
          kind: 'response',
          caption: 'Application configuration returned by the download endpoint',
          text: `GET /ftp/quarantine/%2e%2e%2f%2e%2e%2fpackage.json HTTP/1.1
Host: juice.attestor-lab.internal

--- response ---
HTTP 200
Content-Type: application/json

{"name":"sample-retail-storefront","version":"14.2.0","dependencies":{ … }}`,
        },
      ];
    case 'ATT-2026-000-006':
      return [
        {
          kind: 'request',
          caption: 'Checkout accepted at a total submitted by the client',
          text: `POST /rest/basket/1/checkout HTTP/1.1
Host: juice.attestor-lab.internal
Content-Type: application/json

{"basketId":1,"totalPrice":1,"couponData":""}

--- response ---
HTTP 200

{"orderConfirmation":{"orderId":"a1b2c3","totalPrice":1,"paymentId":"[REDACTED]"}}`,
        },
      ];
    default:
      return [
        {
          kind: 'terminal',
          caption: 'Tool output, redacted',
          text: `$ attestor run --check ${reference}\nreproduced 1/1 attempts\nevidence captured: 1 object`,
        },
      ];
  }
}

export function buildSampleReportData(): ReportData {
  const findings: ReportFinding[] = sampleFindings.map((finding) => ({
    ...finding,
    evidence: evidenceFor(finding.reference ?? ''),
  }));

  const coveredCheckIds = new Set(
    checkCatalogue
      .filter((check) => check.modules.some((module) => ['recon', 'web', 'api'].includes(module)))
      .filter((check) => check.automation !== 'manual' || check.category === 'businessLogic')
      .map((check) => check.id),
  );

  const findingCountByCheckId = new Map<string, number>();
  for (const finding of findings) {
    if (!finding.checkId) continue;
    findingCountByCheckId.set(
      finding.checkId,
      (findingCountByCheckId.get(finding.checkId) ?? 0) + 1,
    );
  }

  const coverage = buildCoverageMatrix({
    selectedModules: ['recon', 'web', 'api'],
    excludedCheckIds: new Map([
      [
        'web-request-smuggling',
        'No proxy or CDN sits in front of the staging environment, so the class does not apply here.',
      ],
    ]),
    completedRuns: [{ scanRunId: 'sample-run-1', checkIds: [...coveredCheckIds] }],
    abortedRuns: [],
    manuallyCovered: new Map([
      ['web-workflow-bypass', 'Tested by hand across the checkout and returns flows.'],
      ['web-price-and-quantity-manipulation', 'Tested by hand; produced ATT-2026-000-006.'],
      ['web-finding-chaining', 'Tested by hand; produced the attack narrative in section 6.'],
      ['web-authentication-bypass', 'Tested by hand across both login flows.'],
      ['web-vertical-access-control', 'Replay matrix across three roles.'],
      ['web-horizontal-access-control', 'Replay matrix across two customer accounts.'],
    ]),
    findingCountByCheckId,
  });

  return {
    kind: 'assessment',
    templateId: 'attestor-standard-v1',
    branding: {
      wordmark: 'Attestor',
      legalEntityName: 'Attestor Security',
      brandName: 'Attestor Security',
      contactEmail: 'hello@attestorsecurity.com',
      country: 'India',
      jurisdiction: 'the courts at the registered office of Attestor Security',
    },

    clientLegalName: sampleEngagement.clientLegalName,
    clientDisplayName: sampleEngagement.clientDisplayName,
    engagementTitle: sampleEngagement.title,
    reportReference: sampleEngagement.reference,
    reportVersion: sampleEngagement.reportVersion,
    reportDate: dateFormat.format(sampleEngagement.reportDate),
    testStartDate: dateFormat.format(sampleEngagement.startsAt),
    testEndDate: dateFormat.format(sampleEngagement.endsAt),
    statusDate: dateFormat.format(sampleEngagement.reportDate),

    testType: sampleEngagement.testType,
    cvssVersion: sampleEngagement.cvssVersion,
    methodology: [
      'OWASP Web Security Testing Guide 4.2',
      'OWASP Application Security Verification Standard 5.0',
      'OWASP Top 10:2025',
      'OWASP API Security Top 10:2023',
      'NIST SP 800-115',
      'PTES',
    ],
    timezone: sampleEngagement.timezone,

    scopeIncluded: [...sampleEngagement.scopeIncluded],
    scopeExcluded: [...sampleEngagement.scopeExcluded],
    environments: [...sampleEngagement.environments],
    rolesTested: [...sampleEngagement.rolesTested],
    constraints: [...sampleEngagement.constraints],
    toolsUsed: sampleEngagement.toolsUsed.map((tool) => ({ ...tool })),

    documentControl: {
      author: 'Attestor Security',
      reviewer: 'Attestor Security',
      distribution: ['Sample Retail Private Limited — engineering and security'],
      versionHistory: [
        { version: '0.1', date: '18 July 2026', note: 'Internal draft for review' },
        { version: '1.0', date: '20 July 2026', note: 'Issued to the client' },
      ],
    },

    executiveSummary: [
      'Sample Retail asked us to assess the customer web application and the API behind it before the July release. We tested for five working days across three user roles against the staging environment running the release candidate, using the published OWASP methodology and the tools listed in section 4.',
      'The application is not ready to ship. Three findings, taken together, give an unauthenticated attacker the whole customer database in under an hour, and they do it through ordinary application features rather than anything exotic. Section 6 sets that path out step by step. Separately, and independently of that chain, the checkout accepts the order total from the browser, which means an order can be placed for any amount the customer chooses.',
      'Not everything is bad, and the parts that are right are right for structural reasons rather than by accident. Password storage uses a modern hashing function with per-user salts. TLS is correctly configured. Card details never reach the application because the payment integration uses hosted fields — a design decision that removed an entire class of finding from this assessment and is worth carrying into the next feature.',
      'The remediation order in section 9 is not the severity order. Two of the findings that are individually low or medium are steps in the chain, and each of them is a small change.',
    ],
    headlineActions: [
      'Parameterise the login query (ATT-2026-000-001). One change to one handler, and it removes the most direct route to administrator.',
      'Pin the accepted signature algorithm on token verification and rotate the signing key (ATT-2026-000-003). Until this is done, every other authentication control is advisory.',
      'Recompute the order total on the server (ATT-2026-000-006). This one is losing money now rather than hypothetically.',
    ],
    positiveObservations: [...samplePositiveObservations],
    roadmap: [
      {
        horizon: 'First 30 days',
        items: [
          'Parameterise every raw query in the codebase, not only the login handler. Static analysis will find the rest in an afternoon.',
          'Pin token verification to one algorithm, rotate the signing key, and invalidate live sessions.',
          'Recompute order totals server-side and add a reconciliation check against the payment provider.',
          'Remove the client-supplied filename from the download path.',
        ],
      },
      {
        horizon: 'Days 30 to 60',
        items: [
          'Introduce an authorisation layer that resolves the object and checks ownership, and apply it to every handler that takes an identifier. The basket finding is one instance of a pattern.',
          'Move the session token out of browser storage into a Secure, HttpOnly, SameSite cookie.',
          'Deploy the security headers in report-only mode, collect violations for a week, then enforce.',
        ],
      },
      {
        horizon: 'Days 60 to 90',
        items: [
          'Add rate limiting and a breached-password check on the authentication paths.',
          'Put dependency scanning into the pipeline and fail the build on a reachable high-severity match.',
          'Book the retest. One is included within 30 days of this report.',
        ],
      },
    ],

    attackNarrative: {
      title: sampleAttackNarrative.title,
      steps: sampleAttackNarrative.steps.map((step) => ({ ...step })),
      conclusion: sampleAttackNarrative.conclusion,
      diagram: `  anonymous visitor
        |
        |  1. reset endpoint distinguishes registered addresses      (ATT-2026-000-008, low)
        v
  list of real customer addresses
        |
        |  2. download endpoint returns the configuration file       (ATT-2026-000-005, high)
        v
  token signing material
        |
        |  3. verifier trusts the algorithm named in the token       (ATT-2026-000-003, critical)
        v
  valid session for any account, including administrator
        |
        |  4. ordinary administrative screens
        v
  every order, address and payment reference`,
    },

    findings,
    coverage,
    complianceFrameworks: ['iso27001', 'soc2', 'pciDss', 'dpdp'],

    appendices: {
      assetInventory: [
        'juice.attestor-lab.internal — customer web application, staging',
        'juice.attestor-lab.internal/rest/* — REST API consumed by the web application',
        'juice.attestor-lab.internal/api/* — legacy REST surface, still reachable',
        'juice.attestor-lab.internal/#/administration — administration interface',
      ],
      portsAndServices: [
        { host: 'juice.attestor-lab.internal', port: 443, service: 'https', version: 'nginx 1.27' },
        { host: 'juice.attestor-lab.internal', port: 80, service: 'http', version: 'nginx 1.27, redirects to 443' },
      ],
      outOfScopeNotes: [
        'The payment provider was excluded by agreement and was not contacted at any point.',
        'No denial-of-service, load or volumetric testing was performed. The platform used for this assessment contains no such capability.',
      ],
      glossary: [
        {
          term: 'CVSS',
          definition:
            'Common Vulnerability Scoring System. A published method for scoring the severity of a finding. The vector string beside each score records how it was derived.',
        },
        {
          term: 'IDOR',
          definition:
            'Insecure direct object reference. A request that identifies a record by an identifier the server does not check the caller is entitled to.',
        },
        {
          term: 'Attack narrative',
          definition:
            'A written walkthrough of how several findings combine into one outcome. Included because severity per finding does not describe combined risk.',
        },
      ],
    },
  };
}
