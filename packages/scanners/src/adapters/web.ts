import type { RawFinding } from '@attestor/findings';
import {
  normaliseSeverity,
  parseJsonLines,
  recordAsEvidence,
  parseJsonObject,
  splitTarget,
  type ParseContext,
  type RunCredential,
  type ScannerAdapter,
} from '../adapter.ts';

/**
 * OWASP ZAP and dalfox.
 *
 * ZAP is driven through its automation framework rather than through the classic CLI flags: the
 * plan is a YAML file we generate, which is the only way to express an authenticated context, a
 * scope, an exclusion list and a rate limit in one place that the tool actually honours.
 *
 * The authenticated context is the reason the whole credential path exists. Everything behind a
 * login — the account pages, the ordering flow, the admin screens, every access control question —
 * is invisible to an unauthenticated scan, and an unauthenticated scan of an application that has
 * a login is a scan of its login page.
 */

/** Credential kinds that are a login to perform, rather than a token to present. */
const LOGIN_AUTH_TYPES = new Set(['formLogin', 'scriptedLogin', 'otpAssisted', 'oauth2']);

/** The ZAP user name. One per plan: a context carries a single authentication method. */
const ZAP_USER = 'primary';

interface ZapLogin {
  username: string;
  loginUrl: string;
  credential: RunCredential;
}

/**
 * Choose the credential this plan logs in with.
 *
 * One, not several: a ZAP context has exactly one authentication method, so a second role means a
 * second run rather than a second user. The primary account is preferred over the second account
 * for the same role, because the second exists to be compared against the first.
 *
 * A login needs somewhere to go, and `loginUrl` comes from the policy's auth profile rather than
 * from the client — asking a client for their login page is asking them to answer a question we
 * can see for ourselves, and getting it wrong silently produces an unauthenticated scan that looks
 * like an authenticated one.
 */
function zapLogin(credentials: readonly RunCredential[] = []): ZapLogin | null {
  for (const credential of credentials) {
    if (credential.isSecondary) continue;
    if (!LOGIN_AUTH_TYPES.has(credential.authType)) continue;
    if (credential.secretRefs.password === undefined) continue;

    const username =
      credential.fields.email ?? credential.fields.username ?? credential.fields.mobile;
    if (username === undefined || credential.loginUrl === undefined) continue;

    return { username, loginUrl: credential.loginUrl, credential };
  }
  return null;
}

/**
 * The context's authentication block.
 *
 * `browser` rather than `form`: it drives a real browser at the login page and finds the fields
 * itself, which is what makes this work on a single-page application whose login form does not
 * exist in the served HTML — and those are most of them now. It also means the tester does not have
 * to supply field selectors that break the next time the client ships a redesign.
 *
 * `autodetect` session management for the same reason: the session may be a cookie, a bearer token
 * in a header, or both, and ZAP works it out from what the login actually did.
 *
 * Every secret is a `${...}` reference resolved by ZAP from the container's environment, so this
 * file — which is written to disk and mounted into the container — never holds a client's password.
 * This is verified behaviour, not an assumption: substitution happens for user credentials, and
 * does *not* happen for job parameters, which is why nothing here puts a secret in a job.
 */
function authenticationBlock(login: ZapLogin): string {
  const { credential } = login;
  const totpSecret = credential.secretRefs.totpSecret;
  const loggedOut = credential.sessionIndicator?.loggedOutText;

  return `      authentication:
        method: browser
        parameters:
          loginPageUrl: "${login.loginUrl}"
          browserId: firefox-headless${
            loggedOut === undefined
              ? ''
              : `
        verification:
          method: response
          loggedOutRegex: "${loggedOut.replace(/"/g, '\\"')}"
          pollFrequency: ${credential.sessionCheckEveryRequests}
          pollUnits: requests`
          }
      sessionManagement:
        method: autodetect
      users:
        - name: ${ZAP_USER}
          credentials:
            username: "${login.username}"
            password: "${credential.secretRefs.password}"${
              totpSecret === undefined
                ? ''
                : `
            totp:
              secret: "${totpSecret}"
              period: 30
              digits: 6
              algorithm: SHA1`
            }
`;
}

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

/**
 * Why the active scan policy turns off exactly one rule, by threshold, quoted.
 *
 * 40044 is Exponential Entity Expansion — the billion-laughs XML bomb, and the only rule in ZAP's
 * release set that attacks availability rather than confidentiality or integrity. This platform does
 * not perform denial of service in any form, so it is off in every policy.
 *
 * Those four lines used to be wrong in three independent ways, and any one of them alone was enough
 * to make ZAP finish the plan, write a complete report, and exit 2 with a warning:
 *
 *   - the ids named were 20000 and 20001, the retired alpha denial-of-service rules, which are not
 *     in the release set and have not been for years;
 *   - the values were bare `off`, which YAML 1.1 reads as the boolean false;
 *   - one of them was `strength`, and ZAP's strength enum has no off at all — Low, Medium, High,
 *     Insane and Default is the whole of it. A rule is disabled by its threshold.
 *
 * The worker reads a non-zero exit as a run that did not happen, correctly, so every ZAP active scan
 * in the platform's history was recorded as failed and its findings discarded — by the safety rail
 * itself, which meanwhile excluded nothing. The unit test asserted the plan contained `id: 20000`,
 * so it passed on the strength of the mistake being present.
 */
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
    // Named against a rule in the release set, which is the whole policy this adapter enables:
    // ServerSideInclude, XpathInjection, FormatString and PaddingOracle are active rules; Jso,
    // InfoSessionIdUrl, LinkTarget, UserControlledHTMLAttributes, UserControlledJavascriptEvent and
    // UserControlledCharset are passive ones. Each was already running on every web engagement and
    // the catalogue simply never said so.
    'web-server-side-includes',
    'web-xpath-injection',
    'web-format-string-injection',
    'web-padding-oracle',
    'web-deserialisation',
    'web-exposed-session-variables',
    'web-reverse-tabnabbing',
    'web-html-injection',
    'web-client-side-javascript-execution',
    'web-client-side-resource-manipulation',
    'api-error-verbosity',
    'api-cors-and-preflight',
  ],

  usesCredentials: true,

  /**
   * The automation plan. Everything the engagement's policy decides — scope, exclusions, rate,
   * authentication, read-only behaviour — is expressed here rather than scattered across flags.
   */
  buildInvocation: ({ policy, targets, credentials }) => {
    const contextUrls = targets.map((target) =>
      target.includes('://') ? target : `https://${target}`,
    );

    const login = zapLogin(credentials);
    // Every crawling and scanning job runs as this user when there is one. A job that leaves it out
    // browses as a stranger, which is how an "authenticated" scan quietly covers nothing.
    const asUser =
      login === null
        ? ''
        : `
      user: ${ZAP_USER}`;

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
${login === null ? '' : authenticationBlock(login)}  parameters:
    failOnError: false
    progressToStdout: true

jobs:
  - type: passiveScan-config
    parameters:
      maxAlertsPerRule: 20
      scanOnlyInScope: true

  - type: spider
    parameters:
      context: engagement${asUser}
      maxDuration: 20
      maxDepth: 8
      maxChildren: 60
      acceptCookies: true

  - type: spiderAjax
    parameters:
      context: engagement${asUser}
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
      context: engagement${asUser}
      maxRuleDurationInMins: 5
      maxScanDurationInMins: 90
      threadPerHost: ${policy.rateLimits.concurrency}
      delayInMs: ${Math.max(0, Math.round(1000 / policy.rateLimits.perTargetRequestsPerSecond))}
    policyDefinition:
      defaultStrength: ${policy.intensity === 'thorough' ? 'high' : 'medium'}
      defaultThreshold: medium
      rules:
        # Exponential Entity Expansion. Availability is never a target; see the adapter.
        - id: 40044
          threshold: "off"`
}

  - type: report
    parameters:
      template: traditional-json
      reportDir: /out
      reportFile: zap-report.json
`;

    return {
      // `-dir` is not optional here. The container runs as uid 65532, which has no passwd entry, so
      // the JVM reports `user.home` as "?" and ZAP resolves its home directory to `/zap/?/.ZAP/`
      // against a read-only root filesystem: it prints "Unable to create home directory" and exits
      // before reading the plan. Every ZAP run in this platform failed that way.
      //
      // It points at the tmpfs rather than at `/out`, because ZAP's home holds the session database
      // — which contains the login request, and therefore the client's password in the clear. On
      // the tmpfs that never reaches a disk and dies with the container.
      //
      // ponytail: 512m of tmpfs is the ceiling. A very large site could fill it mid-scan; move the
      // home to `/out` and accept the on-disk session if that ever happens.
      command: ['zap.sh', '-cmd', '-dir', '/tmp/zap-home', '-autorun', '/out/zap-plan.yaml'],
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
          evidenceText: recordAsEvidence(alert),
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
    // The binary, then dalfox's own `file` sub-command. `hahwul/dalfox` declares no ENTRYPOINT —
    // its `CMD` is `./dalfox`, which the runner replaces — so the first element here is what Docker
    // execs. Without the path every dalfox run died at container creation with
    // `exec: "file": executable file not found in $PATH`, and the relative `./dalfox` would not
    // resolve either because the runner sets the working directory to /out.
    command: [
      '/app/dalfox',
      'file',
      '--format',
      'jsonl',
      '--output',
      '/out/dalfox.jsonl',
      '--silence',
      '--no-color',
      // The WAF probe sends unsolicited malformed requests to fingerprint a filter. Not our job,
      // and the noise it makes is the kind a client's monitoring reports as an attack.
      '--skip-waf-probe',
      '--workers',
      String(policy.rateLimits.concurrency),
      // Requests per second across every worker, which is what the policy actually promises the
      // client. dalfox defaults to 50 workers and no cap, so leaving this out is how a scan that
      // was sold as polite arrives as a burst.
      '--rate-limit',
      String(policy.rateLimits.perTargetRequestsPerSecond),
      '--timeout',
      '15',
      '/out/urls.txt',
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
          evidenceText: recordAsEvidence(result),
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
