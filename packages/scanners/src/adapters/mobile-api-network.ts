import type { RawFinding } from '@attestor/findings';
import {
  hostList,
  normaliseSeverity,
  recordAsEvidence,
  parseJsonObject,
  splitTarget,
  type DiscoveredAsset,
  type ParseContext,
  type ScannerAdapter,
} from '../adapter.ts';

/**
 * MobSF, Schemathesis and Nmap.
 *
 * Three tools, three very different output shapes, grouped because each is the only tool for its
 * module and splitting them would be three files of imports.
 */

interface MobSfFinding {
  title?: string;
  severity?: string;
  description?: string;
  cvss?: number;
  cwe?: string;
  owasp?: string;
  'owasp-mobile'?: string;
  masvs?: string;
  files?: Record<string, string> | string[];
  path?: string[];
}

interface MobSfReport {
  app_name?: string;
  package_name?: string;
  version_name?: string;
  file_name?: string;
  code_analysis?: { findings?: Record<string, MobSfFinding> };
  manifest_analysis?: { manifest_findings?: MobSfFinding[] };
  network_security?: { network_findings?: MobSfFinding[] };
  certificate_analysis?: { certificate_findings?: [string, string, string][] };
  secrets?: string[];
  permissions?: Record<string, { status?: string; info?: string; description?: string }>;
  trackers?: { detected_trackers?: number; trackers?: { name?: string; categories?: string }[] };
}

/** MobSF prints a MASVS reference in several shapes; normalise to the 2.1 control identifier. */
function masvsControl(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const match = /MASVS-([A-Z]+)-(\d)/i.exec(value);
  return match ? `MASVS-${match[1]!.toUpperCase()}-${match[2]}` : undefined;
}

function cweNumber(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const match = /CWE-(\d+)/i.exec(value);
  return match ? Number(match[1]) : undefined;
}

function filesFor(finding: MobSfFinding): string[] {
  if (Array.isArray(finding.path)) return finding.path;
  if (Array.isArray(finding.files)) return finding.files;
  if (finding.files && typeof finding.files === 'object') return Object.keys(finding.files);
  return [];
}

export const mobsfAdapter: ScannerAdapter = {
  id: 'mobsf',
  displayName: 'MobSF',
  modules: ['mobile'],
  coversCheckIds: [
    'mobile-binary-composition',
    'mobile-hardcoded-secrets',
    'mobile-insecure-local-storage',
    'mobile-logging-leakage',
    'mobile-transport-security',
    'mobile-exported-components',
    'mobile-webview-configuration',
    'mobile-cryptography-use',
    'mobile-permission-review',
    'mobile-update-enforcement',
  ],

  buildInvocation: () => ({
    // MobSF runs as a service; the container entrypoint uploads the package and writes the report.
    command: ['/out/mobsf-run.sh'],
    outputFile: 'mobsf.json',
    inputFiles: [
      {
        name: 'mobsf-run.sh',
        contents: `#!/bin/sh
set -eu
# Upload the package, run static analysis, write the JSON report. The API key is supplied by the
# runner as an environment variable and never written to disk.
HASH=$(curl -sS -F "file=@/in/app.bin" -H "Authorization: $MOBSF_API_KEY" \\
  http://127.0.0.1:8000/api/v1/upload | sed -n 's/.*"hash":"\\([^"]*\\)".*/\\1/p')
curl -sS -X POST --data "hash=$HASH" -H "Authorization: $MOBSF_API_KEY" \\
  http://127.0.0.1:8000/api/v1/scan > /dev/null
curl -sS -X POST --data "hash=$HASH" -H "Authorization: $MOBSF_API_KEY" \\
  http://127.0.0.1:8000/api/v1/report_json > /out/mobsf.json
`,
      },
    ],
  }),

  parse: (raw, context: ParseContext): RawFinding[] => {
    const report = parseJsonObject<MobSfReport>(raw);
    if (!report) return [];

    const packageName = report.package_name ?? report.app_name ?? context.defaultAsset;
    const findings: RawFinding[] = [];

    const push = (finding: MobSfFinding, checkId: string, fallbackTitle: string): void => {
      const files = filesFor(finding);
      findings.push({
        source: 'tool',
        toolName: 'mobsf',
        toolFindingRef: finding.title ?? fallbackTitle,
        checkId,
        title: finding.title ?? fallbackTitle,
        description: finding.description ?? '',
        severity: normaliseSeverity(finding.severity),
        cvssVersion: context.cvssVersion,
        cvssScore: finding.cvss,
        cweId: cweNumber(finding.cwe),
        masvsControl: masvsControl(finding.masvs),
        affectedAssets:
          files.length > 0
            ? files.slice(0, 25).map((file) => ({ value: packageName, location: file }))
            : [{ value: packageName }],
        businessImpact: '',
        likelihood: '',
        attackerPrerequisites: '',
        reproductionSteps: files[0]
          ? [`Decompile the package and open ${files[0]}.`]
          : ['Decompile the package and inspect the reported component.'],
        remediation: '',
        references: [
          { title: 'OWASP MASVS', url: 'https://mas.owasp.org/MASVS/' },
        ],
        evidence: [],
      });
    };

    for (const finding of Object.values(report.code_analysis?.findings ?? {})) {
      push(finding, 'mobile-insecure-local-storage', 'Code analysis finding');
    }
    for (const finding of report.manifest_analysis?.manifest_findings ?? []) {
      push(finding, 'mobile-exported-components', 'Manifest finding');
    }
    for (const finding of report.network_security?.network_findings ?? []) {
      push(finding, 'mobile-transport-security', 'Network security configuration finding');
    }

    if ((report.secrets ?? []).length > 0) {
      findings.push({
        source: 'tool',
        toolName: 'mobsf',
        toolFindingRef: 'hardcoded-secrets',
        checkId: 'mobile-hardcoded-secrets',
        title: `${report.secrets?.length ?? 0} possible hardcoded secrets in the shipped package`,
        description:
          'Values matching credential patterns are present in the application package. Anything shipped in a binary is readable by anyone who downloads it; a key in an app is a public key in every sense that matters.',
        severity: 'high',
        cvssVersion: context.cvssVersion,
        cweId: 798,
        masvsControl: 'MASVS-STORAGE-1',
        affectedAssets: [{ value: packageName }],
        businessImpact: '',
        likelihood: '',
        attackerPrerequisites: '',
        reproductionSteps: [
          'Decompile the package and search the string and resource tables for credential patterns.',
        ],
        remediation:
          'Move the credential server-side and have the application request a short-lived token instead. Rotate anything that has shipped, because it is already public.',
        references: [{ title: 'OWASP MASVS', url: 'https://mas.owasp.org/MASVS/' }],
        evidence: [],
      });
    }

    const trackerCount = report.trackers?.detected_trackers ?? 0;
    if (trackerCount > 0) {
      findings.push({
        source: 'tool',
        toolName: 'mobsf',
        toolFindingRef: 'trackers',
        checkId: 'mobile-data-safety-consistency',
        title: `${trackerCount} third-party trackers detected in the package`,
        description: `The package contains ${trackerCount} known tracking SDK(s): ${(report.trackers?.trackers ?? [])
          .map((tracker) => tracker.name ?? 'unnamed')
          .slice(0, 10)
          .join(', ')}. Each collects data on the application's behalf and each must appear in the store data-safety declaration.`,
        severity: 'medium',
        cvssVersion: context.cvssVersion,
        masvsControl: 'MASVS-PRIVACY-3',
        affectedAssets: [{ value: packageName }],
        businessImpact: '',
        likelihood: '',
        attackerPrerequisites: '',
        reproductionSteps: [
          'Compare the detected SDK list against the data-safety declaration on the store listing.',
        ],
        remediation:
          'Reconcile the declaration with what the binary actually does, and remove SDKs whose collection the product does not need.',
        references: [{ title: 'OWASP MASVS', url: 'https://mas.owasp.org/MASVS/' }],
        evidence: [],
      });
    }

    return findings;
  },
};

interface SchemathesisCheck {
  name?: string;
  value?: string;
  message?: string;
  example?: { path?: string; method?: string; query?: Record<string, unknown>; body?: unknown };
}

interface SchemathesisResult {
  method?: string;
  path?: string;
  verbose_name?: string;
  has_failures?: boolean;
  checks?: SchemathesisCheck[];
  errors?: { exception?: string; example?: { path?: string; method?: string } }[];
}

interface SchemathesisOutput {
  results?: SchemathesisResult[];
  generic_errors?: { exception?: string }[];
}

/** Schemathesis check names map cleanly onto the API Top 10 and the catalogue. */
const SCHEMATHESIS_CHECK_MAP: Record<string, { checkId: string; apiCategory: string; cwe?: number }> =
  {
    not_a_server_error: { checkId: 'api-error-verbosity', apiCategory: 'API8:2023', cwe: 209 },
    status_code_conformance: {
      checkId: 'api-injection-through-schema',
      apiCategory: 'API8:2023',
      cwe: 20,
    },
    content_type_conformance: {
      checkId: 'api-content-type-handling',
      apiCategory: 'API8:2023',
      cwe: 436,
    },
    response_schema_conformance: {
      checkId: 'api-excessive-data-exposure',
      apiCategory: 'API3:2023',
      cwe: 213,
    },
    negative_data_rejection: {
      checkId: 'api-injection-through-schema',
      apiCategory: 'API8:2023',
      cwe: 20,
    },
    ignored_auth: { checkId: 'api-authentication-mechanisms', apiCategory: 'API2:2023', cwe: 306 },
  };

export const schemathesisAdapter: ScannerAdapter = {
  id: 'schemathesis',
  displayName: 'Schemathesis',
  modules: ['api'],
  coversCheckIds: [
    'api-specification-import',
    'api-injection-through-schema',
    'api-content-type-handling',
    'api-error-verbosity',
    'api-excessive-data-exposure',
    'api-authentication-mechanisms',
    'api-resource-consumption',
  ],

  buildInvocation: ({ policy, targets }) => ({
    command: [
      'run',
      '/out/openapi.json',
      '--url',
      targets[0] ?? '',
      '--checks',
      'all',
      '--report',
      'json',
      '--report-json-path',
      '/out/schemathesis.json',
      '--max-examples',
      policy.intensity === 'thorough' ? '100' : '30',
      '--workers',
      String(policy.rateLimits.concurrency),
      '--request-timeout',
      '20',
      // Deterministic runs, so a finding reported today can be reproduced tomorrow.
      '--seed',
      '1',
      ...(policy.readOnlyMode ? ['--include-method', 'GET', '--include-method', 'HEAD'] : []),
    ],
    outputFile: 'schemathesis.json',
  }),

  parse: (raw, context: ParseContext): RawFinding[] => {
    const output = parseJsonObject<SchemathesisOutput>(raw);
    if (!output?.results) return [];

    const findings: RawFinding[] = [];

    for (const result of output.results) {
      if (!result.has_failures) continue;
      const { host } = splitTarget(context.defaultAsset);

      for (const check of result.checks ?? []) {
        if ((check.value ?? '').toLowerCase() !== 'failure') continue;
        const mapped = SCHEMATHESIS_CHECK_MAP[check.name ?? ''] ?? {
          checkId: 'api-injection-through-schema',
          apiCategory: 'API8:2023',
        };

        findings.push({
          source: 'tool',
          evidenceText: recordAsEvidence(check),
          toolName: 'schemathesis',
          toolFindingRef: check.name ?? 'schemathesis-check',
          checkId: mapped.checkId,
          apiCategory: mapped.apiCategory,
          title: `${result.method ?? 'GET'} ${result.path ?? '/'}: ${check.name ?? 'check'} failed`,
          description: check.message ?? '',
          severity: check.name === 'not_a_server_error' ? 'medium' : 'low',
          cvssVersion: context.cvssVersion,
          cweId: mapped.cwe,
          affectedAssets: [
            { value: host, location: result.path, method: result.method },
          ],
          businessImpact: '',
          likelihood: '',
          attackerPrerequisites: '',
          reproductionSteps: check.example
            ? [
                `Send ${check.example.method ?? result.method ?? 'GET'} ${check.example.path ?? result.path ?? '/'} with the generated case recorded in the evidence.`,
              ]
            : [],
          remediation: '',
          references: [
            {
              title: 'OWASP API Security Top 10',
              url: 'https://owasp.org/API-Security/editions/2023/en/0x11-t10/',
            },
          ],
          evidence: [],
        });
      }
    }

    return findings;
  },
};

interface NmapPort {
  port: number;
  protocol: string;
  state: string;
  service: string;
  product: string;
  version: string;
  scripts: { id: string; output: string }[];
}

/**
 * Nmap emits XML. Parsing it with a regular expression would be wrong for a general XML document
 * and is acceptable here for exactly one reason: the shape is fixed, machine-generated by a tool
 * whose output format we pin, and never contains nested user content. A DOM parser would be a
 * dependency for a document with four element types.
 */
export function parseNmapXml(xml: string): { host: string; ports: NmapPort[] }[] {
  const hosts: { host: string; ports: NmapPort[] }[] = [];
  const hostBlocks = xml.split(/<host\b/).slice(1);

  for (const block of hostBlocks) {
    const address = /<address addr="([^"]+)"/.exec(block)?.[1];
    const hostname = /<hostname name="([^"]+)"/.exec(block)?.[1];
    const host = hostname ?? address;
    if (!host) continue;

    const ports: NmapPort[] = [];
    for (const portBlock of block.split(/<port\b/).slice(1)) {
      const portId = /portid="(\d+)"/.exec(portBlock)?.[1];
      const protocol = /protocol="([^"]+)"/.exec(portBlock)?.[1] ?? 'tcp';
      const state = /<state state="([^"]+)"/.exec(portBlock)?.[1] ?? 'unknown';
      if (!portId || state !== 'open') continue;

      const scripts: { id: string; output: string }[] = [];
      for (const scriptBlock of portBlock.split(/<script\b/).slice(1)) {
        const id = /id="([^"]+)"/.exec(scriptBlock)?.[1];
        const outputRaw = /output="([^"]*)"/.exec(scriptBlock)?.[1];
        if (id) {
          scripts.push({
            id,
            output: (outputRaw ?? '')
              .replace(/&quot;/g, '"')
              .replace(/&#10;/g, '\n')
              .replace(/&amp;/g, '&'),
          });
        }
      }

      ports.push({
        port: Number(portId),
        protocol,
        state,
        service: /<service name="([^"]+)"/.exec(portBlock)?.[1] ?? 'unknown',
        product: /product="([^"]+)"/.exec(portBlock)?.[1] ?? '',
        version: /version="([^"]+)"/.exec(portBlock)?.[1] ?? '',
        scripts,
      });
    }

    hosts.push({ host, ports });
  }

  return hosts;
}

export const nmapAdapter: ScannerAdapter = {
  id: 'nmap',
  displayName: 'Nmap',
  modules: ['network', 'recon'],
  coversCheckIds: [
    'network-host-discovery',
    'network-service-identification',
    'network-transport-encryption',
    'network-information-disclosure',
    'recon-port-service-enumeration',
  ],

  buildInvocation: ({ targets }) => ({
    command: [
      '-sV',
      '--version-intensity',
      '5',
      // The `safe` category only, which is the claim the tool inventory and the report both make.
      // No exploit, no brute, no dos — those are not available through this platform and never will
      // be. `discovery` used to be here and does not belong: it is not a safe category, and several
      // of its scripts (whois-ip, whois-domain, targets-*) send the client's hostnames to third
      // parties that never authorised anything. `default` is dropped for the same reason — it is a
      // convenience selection, not a safety one, and it overlaps `safe` for everything wanted here.
      '--script',
      'safe',
      '--script-timeout',
      '60s',
      '-Pn',
      '-oX',
      '/out/nmap.xml',
      '-iL',
      '/out/hosts.txt',
      // Politeness template. T1 and T2 exist and are slower; T3 is the default and is already
      // gentler than anything a client would notice.
      '-T3',
      '--max-retries',
      '2',
    ],
    outputFile: 'nmap.xml',
    inputFiles: [{ name: 'hosts.txt', contents: hostList(targets) }],
  }),

  parse: (raw, context: ParseContext): RawFinding[] => {
    const findings: RawFinding[] = [];

    for (const { host, ports } of parseNmapXml(raw)) {
      for (const port of ports) {
        const cleartextServices = ['telnet', 'ftp', 'http', 'smtp', 'pop3', 'imap', 'ldap'];
        if (cleartextServices.includes(port.service) && port.service !== 'http') {
          findings.push({
            source: 'tool',
            evidenceText: recordAsEvidence(port),
            toolName: 'nmap',
            toolFindingRef: `cleartext-${port.service}`,
            checkId: 'network-transport-encryption',
            title: `${port.service.toUpperCase()} offered without transport encryption on ${host}:${port.port}`,
            description: `${host}:${port.port} runs ${port.service}${port.product ? ` (${port.product} ${port.version})` : ''} without transport encryption. Credentials and data on this service travel in the clear.`,
            severity: port.service === 'telnet' ? 'high' : 'medium',
            cvssVersion: context.cvssVersion,
            cweId: 319,
            owaspCategory: 'A04:2025',
            affectedAssets: [{ value: `${host}:${port.port}` }],
            businessImpact: '',
            likelihood: '',
            attackerPrerequisites: '',
            reproductionSteps: [`Connect to ${host} on port ${port.port} and observe the banner.`],
            remediation: `Disable ${port.service} and use the encrypted equivalent, or restrict the port to a private network if the service cannot be replaced.`,
            references: [],
            evidence: [],
          });
        }

        const versionScript = port.scripts.find((script) => script.id === 'vulners');
        if (versionScript && versionScript.output.trim() !== '') {
          findings.push({
            source: 'tool',
            evidenceText: recordAsEvidence(port),
            toolName: 'nmap',
            toolFindingRef: 'known-vulnerabilities',
            checkId: 'network-cve-correlation',
            title: `Known vulnerabilities reported for ${port.product || port.service} on ${host}:${port.port}`,
            description: `Version detection identified ${port.product} ${port.version}. Published advisories exist for this version:\n\n${versionScript.output.trim()}`,
            severity: 'medium',
            cvssVersion: context.cvssVersion,
            cweId: 1104,
            owaspCategory: 'A03:2025',
            affectedAssets: [{ value: `${host}:${port.port}` }],
            businessImpact: '',
            likelihood: '',
            attackerPrerequisites: '',
            reproductionSteps: [
              `Confirm the running version on ${host}:${port.port} against the service banner, then check each advisory applies to that exact build.`,
            ],
            remediation:
              'Confirm the deployed build against each advisory before acting: banner-derived matches include versions that are patched by a distribution backport. Upgrade the ones that genuinely apply.',
            references: [],
            evidence: [],
          });
        }
      }
    }

    return findings;
  },

  parseAssets: (raw): DiscoveredAsset[] =>
    parseNmapXml(raw).flatMap(({ host, ports }) =>
      ports.map((port) => ({
        kind: 'port' as const,
        value: `${host}:${port.port}`,
        host,
        port: port.port,
        metadata: {
          protocol: port.protocol,
          service: port.service,
          product: port.product,
          version: port.version,
        },
      })),
    ),
};
