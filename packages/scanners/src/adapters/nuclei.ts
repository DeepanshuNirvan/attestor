import type { RawFinding } from '@attestor/findings';
import {
  normaliseSeverity,
  parseJsonLines,
  splitTarget,
  type ParseContext,
  type ScannerAdapter,
} from '../adapter.ts';

/**
 * nuclei.
 *
 * Output is JSON Lines, one object per match. The fields that matter are `template-id`,
 * `info.severity`, `matched-at`, and `info.classification`, which carries CVE and CWE ids when the
 * template author supplied them.
 *
 * nuclei is the highest-volume source of candidates in a web run and also the noisiest. Everything
 * here lands as a candidate; nothing from this adapter reaches a report without a human.
 */

interface NucleiClassification {
  'cve-id'?: string[] | string;
  'cwe-id'?: string[] | string;
  'cvss-metrics'?: string;
  'cvss-score'?: number;
}

interface NucleiInfo {
  name?: string;
  severity?: string;
  description?: string;
  remediation?: string;
  reference?: string[] | string;
  tags?: string[] | string;
  classification?: NucleiClassification;
}

interface NucleiResult {
  'template-id'?: string;
  'template-url'?: string;
  info?: NucleiInfo;
  type?: string;
  host?: string;
  'matched-at'?: string;
  'extracted-results'?: string[];
  request?: string;
  response?: string;
  'matcher-name'?: string;
  timestamp?: string;
}

function asArray(value: string[] | string | undefined): string[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

function firstCwe(classification: NucleiClassification | undefined): number | undefined {
  const raw = asArray(classification?.['cwe-id'])[0];
  if (!raw) return undefined;
  const digits = /(\d+)/.exec(raw);
  return digits ? Number(digits[1]) : undefined;
}

/**
 * Template tag to catalogue check. Only the mappings that are unambiguous are listed: a template
 * tagged `misconfig` could satisfy a dozen checks, and guessing would corrupt the coverage matrix.
 */
const TAG_TO_CHECK: Record<string, string> = {
  'ssl': 'recon-tls-configuration',
  'tls': 'recon-tls-configuration',
  'http-headers': 'web-security-headers',
  'headers': 'web-security-headers',
  'cors': 'web-cors-configuration',
  'xss': 'web-reflected-xss',
  'sqli': 'web-sql-injection',
  'lfi': 'web-directory-traversal',
  'traversal': 'web-directory-traversal',
  'ssrf': 'web-ssrf',
  'redirect': 'web-open-redirect',
  'exposure': 'recon-exposed-version-control',
  'takeover': 'recon-subdomain-takeover',
  'default-login': 'web-default-credentials',
  'graphql': 'api-graphql-introspection',
  'jwt': 'web-jwt-handling',
  'clickjacking': 'web-clickjacking',
  'debug': 'web-admin-interface-exposure',
  'panel': 'web-admin-interface-exposure',
};

function checkIdFor(info: NucleiInfo | undefined, templateId: string): string | undefined {
  for (const tag of asArray(info?.tags)) {
    const mapped = TAG_TO_CHECK[tag.toLowerCase()];
    if (mapped) return mapped;
  }
  for (const [tag, check] of Object.entries(TAG_TO_CHECK)) {
    if (templateId.toLowerCase().includes(tag)) return check;
  }
  return undefined;
}

export const nucleiAdapter: ScannerAdapter = {
  id: 'nuclei',
  displayName: 'nuclei',
  modules: ['recon', 'web', 'api', 'network'],
  coversCheckIds: [
    'recon-subdomain-takeover',
    'recon-tls-configuration',
    'recon-exposed-version-control',
    'recon-javascript-endpoint-extraction',
    'recon-cloud-storage-exposure',
    'recon-technology-inventory',
    'web-security-headers',
    'web-cors-configuration',
    'web-admin-interface-exposure',
    'web-file-extension-handling',
    'web-default-credentials',
    'web-error-handling',
    'web-clickjacking',
    'web-open-redirect',
    'web-header-injection',
    'web-browser-storage-of-secrets-in-source-maps',
    'api-graphql-introspection',
    'api-cors-and-preflight',
    'network-cve-correlation',
    'network-information-disclosure',
  ],

  buildInvocation: ({ policy, targets }) => {
    const severities = policy.checks.nucleiSeverities.join(',');
    const command = [
      '-jsonl',
      '-o',
      '/out/nuclei.jsonl',
      '-severity',
      severities,
      // Rate limiting is the platform's, not the tool's default. These come from the resolved
      // policy, which cannot express a value above the ceiling.
      '-rate-limit',
      String(Math.max(1, Math.round(policy.rateLimits.perTargetRequestsPerSecond * 60))),
      '-concurrency',
      String(policy.rateLimits.concurrency),
      '-timeout',
      '15',
      '-retries',
      '1',
      '-disable-update-check',
      // Interactsh is an out-of-band service run by a third party. Blind checks that need it are
      // handled by our own collector, so the tool must not send client data to someone else's.
      '-no-interactsh',
      '-list',
      '/out/targets.txt',
    ];

    if (policy.checks.nucleiTags.length > 0) {
      command.push('-tags', policy.checks.nucleiTags.join(','));
    }
    if (policy.readOnlyMode) {
      // Templates that write or delete are excluded outright in read-only mode.
      command.push('-exclude-tags', 'intrusive,dos,fuzz');
    } else {
      command.push('-exclude-tags', 'dos');
    }

    return {
      command,
      outputFile: 'nuclei.jsonl',
      inputFiles: [{ name: 'targets.txt', contents: `${targets.join('\n')}\n` }],
    };
  },

  parse: (raw, context: ParseContext): RawFinding[] => {
    const results = parseJsonLines<NucleiResult>(raw);

    return results.map((result) => {
      const templateId = result['template-id'] ?? 'unknown-template';
      const matchedAt = result['matched-at'] ?? result.host ?? context.defaultAsset;
      const { host, port, location } = splitTarget(matchedAt);
      const info = result.info;
      const cves = asArray(info?.classification?.['cve-id']);

      const references = [
        ...asArray(info?.reference).map((url) => ({ title: 'Template reference', url })),
        ...cves.map((cve) => ({
          title: cve.toUpperCase(),
          url: `https://nvd.nist.gov/vuln/detail/${cve.toUpperCase()}`,
        })),
      ].filter((reference) => /^https?:\/\//.test(reference.url));

      const extracted = result['extracted-results'] ?? [];

      return {
        source: 'tool' as const,
        toolName: 'nuclei',
        toolFindingRef: templateId,
        checkId: checkIdFor(info, templateId),
        title: info?.name ?? templateId,
        description: [
          info?.description?.trim(),
          result['matcher-name'] ? `Matcher: ${result['matcher-name']}.` : '',
          extracted.length > 0 ? `Extracted: ${extracted.join(', ')}` : '',
        ]
          .filter(Boolean)
          .join('\n\n'),
        severity: normaliseSeverity(info?.severity),
        cvssVersion: info?.classification?.['cvss-metrics'] ? context.cvssVersion : undefined,
        cvssVector: info?.classification?.['cvss-metrics'],
        cvssScore: info?.classification?.['cvss-score'],
        cweId: firstCwe(info?.classification),
        affectedAssets: [{ value: port ? `${host}:${port}` : host, location }],
        businessImpact: '',
        likelihood: '',
        attackerPrerequisites: '',
        reproductionSteps: result.request
          ? ['Send the recorded request below and compare the response against the matcher.']
          : [],
        remediation: info?.remediation ?? '',
        references,
        evidence: [],
      } satisfies RawFinding;
    });
  },

  parseAssets: (raw) =>
    parseJsonLines<NucleiResult>(raw)
      .map((result) => {
        const matchedAt = result['matched-at'] ?? result.host ?? '';
        if (matchedAt === '') return null;
        const { host, port } = splitTarget(matchedAt);
        return { kind: 'url' as const, value: matchedAt, host, ...(port ? { port } : {}) };
      })
      .filter((asset): asset is NonNullable<typeof asset> => asset !== null),
};
