import type { RawFinding } from '@attestor/findings';
import {
  normaliseSeverity,
  parseJsonLines,
  parseJsonObject,
  splitTarget,
  type ParseContext,
  type ScannerAdapter,
} from '../adapter.ts';

/**
 * OWASP ZAP and dalfox.
 *
 * ZAP is driven through its automation framework rather than through the classic CLI flags: the
 * plan is a YAML file we generate, which is the only way to express an authenticated context, a
 * scope, an exclusion list and a rate limit in one place that the tool actually honours.
 */

interface ZapAlertInstance {
  uri?: string;
  method?: string;
  param?: string;
  attack?: string;
  evidence?: string;
  otherinfo?: string;
}

interface ZapAlert {
  pluginid?: string;
  alertRef?: string;
  alert?: string;
  name?: string;
  riskcode?: string;
  confidence?: string;
  riskdesc?: string;
  desc?: string;
  instances?: ZapAlertInstance[];
  count?: string;
  solution?: string;
  otherinfo?: string;
  reference?: string;
  cweid?: string;
  wascid?: string;
  sourceid?: string;
}

interface ZapSite {
  '@name'?: string;
  '@host'?: string;
  '@port'?: string;
  alerts?: ZapAlert[];
}

interface ZapReport {
  site?: ZapSite[];
}

/** ZAP writes risk as a numeric code. Anything outside this table is informational. */
const ZAP_RISK: Record<string, string> = { '0': 'info', '1': 'low', '2': 'medium', '3': 'high' };

/** ZAP plugin id to catalogue check, for the ones where the mapping is unambiguous. */
const ZAP_PLUGIN_TO_CHECK: Record<string, string> = {
  '10038': 'web-security-headers', // CSP header not set
  '10020': 'web-clickjacking', // anti-clickjacking header
  '10021': 'web-security-headers', // X-Content-Type-Options
  '10035': 'web-security-headers', // HSTS
  '10098': 'web-cors-configuration',
  '10054': 'web-cookie-attributes', // cookie without SameSite
  '10010': 'web-cookie-attributes', // cookie no HttpOnly
  '10011': 'web-cookie-attributes', // cookie without Secure
  '40012': 'web-reflected-xss',
  '40014': 'web-stored-xss',
  '40016': 'web-dom-xss',
  '40018': 'web-sql-injection',
  '40019': 'web-sql-injection',
  '90019': 'web-command-injection',
  '90020': 'web-command-injection',
  '6': 'web-directory-traversal',
  '10045': 'web-directory-traversal',
  '40003': 'web-header-injection',
  '20019': 'web-open-redirect',
  '10202': 'web-csrf',
  '90022': 'web-error-handling',
  '10096': 'web-error-handling',
  '90034': 'web-ssrf',
  '10063': 'web-security-headers',
};

function zapCweFromString(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
}

export const zapAdapter: ScannerAdapter = {
  id: 'zap',
  displayName: 'OWASP ZAP',
  modules: ['web', 'api'],
  coversCheckIds: [
    'web-security-headers',
    'web-cookie-attributes',
    'web-cors-configuration',
    'web-http-methods',
    'web-cache-configuration',
    'web-user-enumeration',
    'web-session-token-strength',
    'web-session-fixation',
    'web-csrf',
    'web-directory-traversal',
    'web-sql-injection',
    'web-nosql-injection',
    'web-command-injection',
    'web-reflected-xss',
    'web-stored-xss',
    'web-template-injection',
    'web-xxe',
    'web-open-redirect',
    'web-header-injection',
    'web-error-handling',
    'web-clickjacking',
    'web-ssrf',
    'api-error-verbosity',
    'api-cors-and-preflight',
  ],

  /**
   * The automation plan. Everything the engagement's policy decides — scope, exclusions, rate,
   * authentication, read-only behaviour — is expressed here rather than scattered across flags.
   */
  buildInvocation: ({ policy, targets }) => {
    const contextUrls = targets.map((target) =>
      target.includes('://') ? target : `https://${target}`,
    );

    const excludePaths = [...policy.exclusions.paths, ...policy.forbiddenActions].map(
      (pattern) => `    - ".*${pattern.replace(/\*+/g, '.*')}.*"`,
    );

    const plan = `env:
  contexts:
    - name: engagement
      urls:
${contextUrls.map((url) => `        - "${url}"`).join('\n')}
      includePaths:
${contextUrls.map((url) => `        - "${url}.*"`).join('\n')}
      excludePaths:
${excludePaths.length > 0 ? excludePaths.join('\n') : '        - "(?!)"'}
  parameters:
    failOnError: false
    progressToStdout: true

jobs:
  - type: passiveScan-config
    parameters:
      maxAlertsPerRule: 20
      scanOnlyInScope: true

  - type: spider
    parameters:
      context: engagement
      maxDuration: 20
      maxDepth: 8
      maxChildren: 60
      acceptCookies: true

  - type: spiderAjax
    parameters:
      context: engagement
      maxDuration: 20
      maxCrawlDepth: 6
      browserId: firefox-headless
      numberOfBrowsers: ${Math.min(2, policy.rateLimits.concurrency)}

  - type: passiveScan-wait
    parameters:
      maxDuration: 10

${
  policy.readOnlyMode
    ? '  # readOnlyMode: the active scan is omitted entirely, so no state-changing request is sent.'
    : `  - type: activeScan
    parameters:
      context: engagement
      maxRuleDurationInMins: 5
      maxScanDurationInMins: 90
      threadPerHost: ${policy.rateLimits.concurrency}
      delayInMs: ${Math.max(0, Math.round(1000 / policy.rateLimits.perTargetRequestsPerSecond))}
    policyDefinition:
      defaultStrength: ${policy.intensity === 'thorough' ? 'high' : 'medium'}
      defaultThreshold: medium
      rules:
        # Denial-of-service rules are excluded outright and are never enabled by any policy.
        - id: 20000
          strength: off
          threshold: off
        - id: 20001
          strength: off
          threshold: off`
}

  - type: report
    parameters:
      template: traditional-json
      reportDir: /out
      reportFile: zap-report.json
`;

    return {
      command: ['zap.sh', '-cmd', '-autorun', '/out/zap-plan.yaml'],
      outputFile: 'zap-report.json',
      inputFiles: [{ name: 'zap-plan.yaml', contents: plan }],
    };
  },

  parse: (raw, context: ParseContext): RawFinding[] => {
    const report = parseJsonObject<ZapReport>(raw);
    if (!report?.site) return [];

    const findings: RawFinding[] = [];

    for (const site of report.site) {
      for (const alert of site.alerts ?? []) {
        const instances = alert.instances ?? [];
        const pluginId = alert.pluginid ?? '';

        findings.push({
          source: 'tool',
          toolName: 'zap',
          toolFindingRef: pluginId,
          checkId: ZAP_PLUGIN_TO_CHECK[pluginId],
          title: alert.name ?? alert.alert ?? `ZAP alert ${pluginId}`,
          description: [alert.desc, alert.otherinfo].filter(Boolean).join('\n\n'),
          severity: normaliseSeverity(ZAP_RISK[alert.riskcode ?? '0']),
          cvssVersion: context.cvssVersion,
          cweId: zapCweFromString(alert.cweid),
          affectedAssets:
            instances.length > 0
              ? instances.map((instance) => {
                  const { host, location } = splitTarget(instance.uri ?? context.defaultAsset);
                  return {
                    value: host,
                    location,
                    parameter: instance.param || undefined,
                    method: instance.method || undefined,
                  };
                })
              : [{ value: site['@host'] ?? context.defaultAsset }],
          businessImpact: '',
          likelihood: '',
          attackerPrerequisites: '',
          reproductionSteps: instances[0]?.attack
            ? [
                `Send ${instances[0].method ?? 'GET'} ${instances[0].uri ?? ''} with ${instances[0].param ?? 'the parameter'} set to: ${instances[0].attack}`,
                'Compare the response against the evidence recorded below.',
              ]
            : [],
          remediation: alert.solution ?? '',
          references: (alert.reference ?? '')
            .split(/\s+/)
            .filter((url) => /^https?:\/\//.test(url))
            .map((url) => ({ title: 'ZAP reference', url })),
          evidence: [],
        });
      }
    }

    return findings;
  },
};

interface DalfoxResult {
  type?: string;
  inject_type?: string;
  poc_type?: string;
  method?: string;
  data?: string;
  param?: string;
  payload?: string;
  evidence?: string;
  cwe?: string;
  severity?: string;
  message_id?: number;
  message_str?: string;
}

export const dalfoxAdapter: ScannerAdapter = {
  id: 'dalfox',
  displayName: 'dalfox',
  modules: ['web'],
  coversCheckIds: ['web-reflected-xss', 'web-dom-xss', 'web-prototype-pollution'],

  buildInvocation: ({ policy, targets }) => ({
    command: [
      'file',
      '/out/urls.txt',
      '--format',
      'jsonl',
      '--output',
      '/out/dalfox.jsonl',
      '--silence',
      '--no-color',
      '--skip-bav',
      '--worker',
      String(policy.rateLimits.concurrency),
      '--delay',
      String(Math.max(0, Math.round(1000 / policy.rateLimits.perTargetRequestsPerSecond))),
      '--timeout',
      '15',
    ],
    outputFile: 'dalfox.jsonl',
    inputFiles: [{ name: 'urls.txt', contents: `${targets.join('\n')}\n` }],
  }),

  parse: (raw, context: ParseContext): RawFinding[] =>
    parseJsonLines<DalfoxResult>(raw)
      .filter((result) => result.type === 'V' || result.poc_type !== undefined)
      .map((result) => {
        const { host, location } = splitTarget(result.data ?? context.defaultAsset);
        const isDom = (result.inject_type ?? '').toUpperCase().includes('DOM');

        return {
          source: 'tool' as const,
          toolName: 'dalfox',
          toolFindingRef: result.inject_type ?? 'xss',
          checkId: isDom ? 'web-dom-xss' : 'web-reflected-xss',
          title: `Cross-site scripting in the ${result.param ?? 'unnamed'} parameter`,
          description: `dalfox verified script execution by injecting into the ${result.param ?? 'unnamed'} parameter. Injection point: ${result.inject_type ?? 'unknown'}. ${result.message_str ?? ''}`.trim(),
          severity: normaliseSeverity(result.severity ?? 'high'),
          cvssVersion: context.cvssVersion,
          cweId: result.cwe ? Number(result.cwe.replace(/\D/g, '')) || 79 : 79,
          owaspCategory: 'A05:2025',
          wstgId: isDom ? 'WSTG-CLNT-01' : 'WSTG-INPV-01',
          asvsRequirement: isDom ? 'v5.0.0-3.1.1' : 'v5.0.0-1.3.1',
          affectedAssets: [
            {
              value: host,
              location,
              parameter: result.param || undefined,
              method: result.method || undefined,
            },
          ],
          businessImpact: '',
          likelihood: '',
          attackerPrerequisites: '',
          reproductionSteps: result.payload
            ? [
                `Request ${result.data ?? ''} with ${result.param ?? 'the parameter'} set to: ${result.payload}`,
                'Observe that the payload executes in the rendered page.',
              ]
            : [],
          remediation:
            'Encode the value for the context it is written into rather than filtering it on the way in, and serve a Content-Security-Policy that does not permit inline script.',
          references: [
            {
              title: 'OWASP Cheat Sheet: Cross Site Scripting Prevention',
              url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
            },
          ],
          evidence: [],
        } satisfies RawFinding;
      }),
};
