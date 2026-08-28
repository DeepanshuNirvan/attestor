import type { RawFinding } from '@attestor/findings';
import {
  normaliseSeverity,
  parseJsonLines,
  parseJsonObject,
  type ParseContext,
  type ScannerAdapter,
} from '../adapter.ts';

/**
 * Code and supply chain: semgrep, gitleaks, trufflehog, trivy.
 *
 * These run against a repository or an image mounted read-only into the container. Nothing here
 * touches a network target, so these adapters are the only ones whose findings do not carry a host.
 * The affected asset is a file and a line, which is what a developer needs.
 */

interface SemgrepResult {
  check_id?: string;
  path?: string;
  start?: { line?: number; col?: number };
  end?: { line?: number };
  extra?: {
    message?: string;
    severity?: string;
    lines?: string;
    fix?: string;
    metadata?: {
      cwe?: string[] | string;
      owasp?: string[] | string;
      references?: string[];
      category?: string;
      confidence?: string;
      technology?: string[];
    };
  };
}

interface SemgrepOutput {
  results?: SemgrepResult[];
  errors?: { message?: string }[];
}

function asArray(value: string[] | string | undefined): string[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

function cweNumber(values: string[]): number | undefined {
  const first = values[0];
  if (!first) return undefined;
  const digits = /CWE-(\d+)/i.exec(first);
  return digits ? Number(digits[1]) : undefined;
}

/** Semgrep's OWASP metadata uses the 2021 names. Map them to the 2025 categories we report. */
const OWASP_2021_TO_2025: Record<string, string> = {
  'A01:2021': 'A01:2025',
  'A02:2021': 'A04:2025',
  'A03:2021': 'A05:2025',
  'A04:2021': 'A06:2025',
  'A05:2021': 'A02:2025',
  'A06:2021': 'A03:2025',
  'A07:2021': 'A07:2025',
  'A08:2021': 'A08:2025',
  'A09:2021': 'A09:2025',
  // SSRF was folded into Broken Access Control in the 2025 edition.
  'A10:2021': 'A01:2025',
};

function mapOwasp(values: string[]): string | undefined {
  for (const value of values) {
    const key = /A\d{2}:2021/.exec(value)?.[0];
    if (key && OWASP_2021_TO_2025[key]) return OWASP_2021_TO_2025[key];
    const current = /A\d{2}:2025/.exec(value)?.[0];
    if (current) return current;
  }
  return undefined;
}

export const semgrepAdapter: ScannerAdapter = {
  id: 'semgrep',
  displayName: 'Semgrep',
  modules: ['code'],
  coversCheckIds: [
    'code-static-analysis',
    'code-authorisation-logic-review',
    'code-cryptography-review',
    'code-input-validation-review',
    'code-logging-review',
    'code-ci-cd-configuration',
    'web-weak-cryptographic-storage',
    'web-randomness',
  ],

  buildInvocation: ({ policy }) => ({
    command: [
      'semgrep',
      'scan',
      '--config',
      'p/security-audit',
      '--config',
      'p/secrets',
      '--config',
      'p/owasp-top-ten',
      '--config',
      'p/ci',
      '--json',
      '--output',
      '/out/semgrep.json',
      '--metrics',
      'off',
      '--quiet',
      '--timeout',
      policy.intensity === 'thorough' ? '120' : '45',
      '/src',
    ],
    // Semgrep phones home unless told not to; a security firm sending a client's rule matches to a
    // vendor by default is not acceptable.
    environment: { SEMGREP_SEND_METRICS: 'off' },
    outputFile: 'semgrep.json',
  }),

  parse: (raw, context: ParseContext): RawFinding[] => {
    const output = parseJsonObject<SemgrepOutput>(raw);
    if (!output?.results) return [];

    return output.results.map((result) => {
      const metadata = result.extra?.metadata;
      const line = result.start?.line ?? 0;
      const path = result.path ?? 'unknown';

      return {
        source: 'tool' as const,
        toolName: 'semgrep',
        toolFindingRef: result.check_id ?? 'semgrep-rule',
        checkId: 'code-static-analysis',
        title: `${result.extra?.message?.split('.')[0] ?? result.check_id ?? 'Static analysis match'}`,
        description: [
          result.extra?.message,
          result.extra?.lines ? `Matched source:\n${result.extra.lines.trim()}` : '',
        ]
          .filter(Boolean)
          .join('\n\n'),
        severity: normaliseSeverity(result.extra?.severity),
        cvssVersion: context.cvssVersion,
        cweId: cweNumber(asArray(metadata?.cwe)),
        owaspCategory: mapOwasp(asArray(metadata?.owasp)),
        affectedAssets: [{ value: path, location: `:${line}` }],
        businessImpact: '',
        likelihood: '',
        attackerPrerequisites: '',
        reproductionSteps: [`Open ${path} at line ${line} and read the matched expression.`],
        remediation: result.extra?.fix ?? '',
        references: (metadata?.references ?? [])
          .filter((url) => /^https?:\/\//.test(url))
          .map((url) => ({ title: 'Rule reference', url })),
        evidence: [],
      } satisfies RawFinding;
    });
  },
};

interface GitleaksResult {
  RuleID?: string;
  Description?: string;
  File?: string;
  StartLine?: number;
  Commit?: string;
  Author?: string;
  Date?: string;
  Entropy?: number;
  Match?: string;
}

export const gitleaksAdapter: ScannerAdapter = {
  id: 'gitleaks',
  displayName: 'gitleaks',
  modules: ['code'],
  coversCheckIds: ['code-secret-scanning-history', 'recon-public-credential-exposure'],

  buildInvocation: () => ({
    command: [
      'detect',
      '--source',
      '/src',
      '--report-format',
      'json',
      '--report-path',
      '/out/gitleaks.json',
      '--redact',
      '--no-banner',
      '--exit-code',
      '0',
    ],
    outputFile: 'gitleaks.json',
  }),

  parse: (raw, context: ParseContext): RawFinding[] => {
    // gitleaks writes `[]` for a clean scan and a bare object on some error paths; anything that is
    // not an array is not results.
    const parsed = parseJsonObject<GitleaksResult[]>(raw);
    const results = Array.isArray(parsed) ? parsed : [];

    return results.map((result) => ({
      source: 'tool' as const,
      toolName: 'gitleaks',
      toolFindingRef: result.RuleID ?? 'secret',
      checkId: 'code-secret-scanning-history',
      title: `Secret in version control: ${result.Description ?? result.RuleID ?? 'unknown type'}`,
      description: `A credential matching the ${result.RuleID ?? 'unknown'} pattern is present in the repository${result.Commit ? ` at commit ${result.Commit.slice(0, 12)}` : ''}. Removing it from the current tree does not help: it stays in history and stays valid until it is rotated.`,
      severity: 'high' as const,
      cvssVersion: context.cvssVersion,
      cweId: 798,
      owaspCategory: 'A02:2025',
      affectedAssets: [{ value: result.File ?? 'unknown', location: `:${result.StartLine ?? 0}` }],
      businessImpact: '',
      likelihood: '',
      attackerPrerequisites: '',
      reproductionSteps: [
        `Open ${result.File ?? 'the file'} at line ${result.StartLine ?? 0}${result.Commit ? ` in commit ${result.Commit}` : ''}.`,
      ],
      remediation:
        'Rotate the credential first — that is the fix. Then remove it from the working tree, move it into the secrets service, and add a pre-commit hook so the next one is caught before it is committed. Rewriting history is optional and does not substitute for rotation.',
      references: [
        {
          title: 'OWASP Cheat Sheet: Secrets Management',
          url: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
        },
      ],
      evidence: [],
    }));
  },
};

interface TruffleHogResult {
  DetectorName?: string;
  DetectorType?: number;
  Verified?: boolean;
  Raw?: string;
  SourceMetadata?: {
    Data?: {
      Git?: { commit?: string; file?: string; line?: number; repository?: string };
      Filesystem?: { file?: string; line?: number };
    };
  };
}

export const truffleHogAdapter: ScannerAdapter = {
  id: 'trufflehog',
  displayName: 'TruffleHog',
  modules: ['code', 'recon'],
  coversCheckIds: ['code-secret-scanning-history', 'recon-public-credential-exposure'],

  buildInvocation: () => ({
    command: ['filesystem', '/src', '--json', '--no-update', '--results=verified,unknown'],
    outputFile: 'trufflehog.jsonl',
  }),

  parse: (raw, context: ParseContext): RawFinding[] =>
    parseJsonLines<TruffleHogResult>(raw).map((result) => {
      const git = result.SourceMetadata?.Data?.Git;
      const file = git?.file ?? result.SourceMetadata?.Data?.Filesystem?.file ?? 'unknown';
      const line = git?.line ?? result.SourceMetadata?.Data?.Filesystem?.line ?? 0;

      return {
        source: 'tool' as const,
        toolName: 'trufflehog',
        toolFindingRef: result.DetectorName ?? 'secret',
        checkId: 'code-secret-scanning-history',
        title: result.Verified
          ? `Live credential found: ${result.DetectorName ?? 'unknown provider'}`
          : `Possible credential found: ${result.DetectorName ?? 'unknown provider'}`,
        description: result.Verified
          ? `TruffleHog verified this credential against the provider: it is currently valid. This is not a pattern match, it is a working key.`
          : `A value matching the ${result.DetectorName ?? 'unknown'} credential pattern. Verification against the provider was not possible, so it may be inactive.`,
        // A verified live credential is a different finding from a pattern match, and scoring them
        // the same is how a real key ends up in a backlog.
        severity: result.Verified ? ('critical' as const) : ('medium' as const),
        cvssVersion: context.cvssVersion,
        cweId: 798,
        owaspCategory: 'A02:2025',
        affectedAssets: [{ value: file, location: `:${line}` }],
        businessImpact: '',
        likelihood: '',
        attackerPrerequisites: '',
        reproductionSteps: [`Open ${file} at line ${line}.`],
        remediation:
          'Rotate immediately, then remove from the source and move to the secrets service. For a verified credential, treat the window between commit and rotation as a period of possible unauthorised access and review the provider\'s access logs for it.',
        references: [],
        evidence: [],
      } satisfies RawFinding;
    }),
};

interface TrivyVulnerability {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  Title?: string;
  Description?: string;
  PrimaryURL?: string;
  References?: string[];
  CweIDs?: string[];
  CVSS?: Record<string, { V3Vector?: string; V3Score?: number; V40Vector?: string; V40Score?: number }>;
}

interface TrivyMisconfiguration {
  ID?: string;
  Title?: string;
  Description?: string;
  Message?: string;
  Severity?: string;
  Resolution?: string;
  PrimaryURL?: string;
  CauseMetadata?: { StartLine?: number };
}

interface TrivyResultBlock {
  Target?: string;
  Class?: string;
  Type?: string;
  Vulnerabilities?: TrivyVulnerability[];
  Misconfigurations?: TrivyMisconfiguration[];
  Secrets?: { RuleID?: string; Title?: string; Severity?: string; StartLine?: number }[];
}

interface TrivyOutput {
  ArtifactName?: string;
  Results?: TrivyResultBlock[];
}

export const trivyAdapter: ScannerAdapter = {
  id: 'trivy',
  displayName: 'Trivy',
  modules: ['code', 'cloud'],
  coversCheckIds: [
    'code-dependency-vulnerabilities',
    'code-sbom-generation',
    'code-container-image-review',
    'code-iac-misconfiguration',
    'code-licence-review',
    'code-dependency-provenance',
    'cloud-container-registry',
  ],

  buildInvocation: () => ({
    command: [
      'filesystem',
      '--scanners',
      'vuln,misconfig,secret,license',
      '--format',
      'json',
      '--output',
      '/out/trivy.json',
      '--quiet',
      // Reachability is judged by a human; the tool's job is to be complete, not to guess.
      '--severity',
      'CRITICAL,HIGH,MEDIUM,LOW',
      '/src',
    ],
    outputFile: 'trivy.json',
  }),

  parse: (raw, context: ParseContext): RawFinding[] => {
    const output = parseJsonObject<TrivyOutput>(raw);
    if (!output?.Results) return [];

    const findings: RawFinding[] = [];

    for (const block of output.Results) {
      const target = block.Target ?? output.ArtifactName ?? 'unknown';

      for (const vulnerability of block.Vulnerabilities ?? []) {
        const cvss = vulnerability.CVSS?.nvd ?? Object.values(vulnerability.CVSS ?? {})[0];
        const useV4 = context.cvssVersion === '4.0' && cvss?.V40Vector;

        findings.push({
          source: 'tool',
          toolName: 'trivy',
          toolFindingRef: vulnerability.VulnerabilityID ?? 'unknown',
          checkId: 'code-dependency-vulnerabilities',
          title: `${vulnerability.PkgName ?? 'component'} ${vulnerability.InstalledVersion ?? ''}: ${vulnerability.Title ?? vulnerability.VulnerabilityID ?? 'known vulnerability'}`,
          description: [
            vulnerability.Description,
            vulnerability.FixedVersion
              ? `Fixed in ${vulnerability.FixedVersion}.`
              : 'No fixed version is published yet.',
          ]
            .filter(Boolean)
            .join('\n\n'),
          severity: normaliseSeverity(vulnerability.Severity),
          cvssVersion: cvss ? context.cvssVersion : undefined,
          cvssVector: useV4 ? cvss?.V40Vector : cvss?.V3Vector,
          cvssScore: useV4 ? cvss?.V40Score : cvss?.V3Score,
          cweId: cweNumber(vulnerability.CweIDs ?? []),
          owaspCategory: 'A03:2025',
          affectedAssets: [{ value: target, parameter: vulnerability.PkgName }],
          businessImpact: '',
          likelihood: '',
          attackerPrerequisites: '',
          reproductionSteps: [
            `Resolve the dependency tree for ${target} and confirm ${vulnerability.PkgName ?? 'the component'} is at ${vulnerability.InstalledVersion ?? 'the reported version'}.`,
          ],
          remediation: vulnerability.FixedVersion
            ? `Upgrade ${vulnerability.PkgName ?? 'the component'} to ${vulnerability.FixedVersion} or later, and pin the lockfile so the fixed version is what deploys.`
            : 'No fixed version is available. Assess reachability from the request path and mitigate at the boundary until one is published.',
          references: [vulnerability.PrimaryURL, ...(vulnerability.References ?? [])]
            .filter((url): url is string => typeof url === 'string' && /^https?:\/\//.test(url))
            .slice(0, 5)
            .map((url) => ({ title: 'Advisory', url })),
          evidence: [],
        });
      }

      for (const misconfiguration of block.Misconfigurations ?? []) {
        findings.push({
          source: 'tool',
          toolName: 'trivy',
          toolFindingRef: misconfiguration.ID ?? 'misconfig',
          checkId: 'code-iac-misconfiguration',
          title: misconfiguration.Title ?? misconfiguration.ID ?? 'Infrastructure misconfiguration',
          description: [misconfiguration.Description, misconfiguration.Message]
            .filter(Boolean)
            .join('\n\n'),
          severity: normaliseSeverity(misconfiguration.Severity),
          cvssVersion: context.cvssVersion,
          cweId: 1032,
          owaspCategory: 'A02:2025',
          affectedAssets: [
            { value: target, location: `:${misconfiguration.CauseMetadata?.StartLine ?? 0}` },
          ],
          businessImpact: '',
          likelihood: '',
          attackerPrerequisites: '',
          reproductionSteps: [`Open ${target} and read the resource definition.`],
          remediation: misconfiguration.Resolution ?? '',
          references: misconfiguration.PrimaryURL
            ? [{ title: 'Check reference', url: misconfiguration.PrimaryURL }]
            : [],
          evidence: [],
        });
      }
    }

    return findings;
  },
};
