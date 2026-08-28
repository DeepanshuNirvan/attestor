import type { RawFinding } from '@attestor/findings';
import {
  normaliseSeverity,
  parseJsonLines,
  parseJsonObject,
  type ParseContext,
  type ScannerAdapter,
} from '../adapter.ts';

/**
 * Cloud posture: prowler and kubescape.
 *
 * Both run with read-only credentials. The prowler invocation below is explicitly the read-only
 * profile, and the role the client grants has no write permission — so a mistake in this file
 * cannot change a client's environment, which is the property that gets a cloud review approved.
 *
 * Prowler emits OCSF JSON. The fields that matter are the check id, the resource, the status and
 * the remediation block, which prowler populates with the actual CLI command for the fix.
 */

interface ProwlerRemediation {
  desc?: string;
  references?: string[];
  kb_article_list?: { title?: string; url?: string }[];
}

interface ProwlerFinding {
  message?: string;
  severity?: string;
  status_code?: string;
  status_detail?: string;
  finding_info?: {
    uid?: string;
    title?: string;
    desc?: string;
    types?: string[];
  };
  resources?: {
    uid?: string;
    name?: string;
    type?: string;
    region?: string;
    group?: { name?: string };
    cloud_partition?: string;
  }[];
  remediation?: ProwlerRemediation;
  unmapped?: {
    check_id?: string;
    compliance?: Record<string, string[]>;
    risk?: string;
    related_url?: string;
    categories?: string[];
  };
  cloud?: { account?: { uid?: string; name?: string }; provider?: string; region?: string };
  metadata?: { event_code?: string };
}

/** Prowler check id prefix to catalogue check. Coarse on purpose; a wrong mapping is worse. */
const PROWLER_PREFIX_TO_CHECK: { prefix: string; checkId: string }[] = [
  { prefix: 'iam_', checkId: 'cloud-iam-privilege-analysis' },
  { prefix: 'accessanalyzer_', checkId: 'cloud-cross-account-trust' },
  { prefix: 's3_', checkId: 'cloud-storage-exposure' },
  { prefix: 'ec2_ebs_snapshot', checkId: 'cloud-snapshot-and-image-exposure' },
  { prefix: 'ec2_ami', checkId: 'cloud-snapshot-and-image-exposure' },
  { prefix: 'ec2_instance_imdsv2', checkId: 'cloud-workload-identity' },
  { prefix: 'ec2_securitygroup', checkId: 'cloud-network-exposure' },
  { prefix: 'ec2_networkacl', checkId: 'cloud-network-exposure' },
  { prefix: 'vpc_', checkId: 'cloud-network-exposure' },
  { prefix: 'rds_', checkId: 'cloud-database-exposure' },
  { prefix: 'elasticache_', checkId: 'cloud-database-exposure' },
  { prefix: 'dynamodb_', checkId: 'cloud-database-exposure' },
  { prefix: 'kms_', checkId: 'cloud-encryption-at-rest' },
  { prefix: 'efs_', checkId: 'cloud-encryption-at-rest' },
  { prefix: 'cloudtrail_', checkId: 'cloud-logging-coverage' },
  { prefix: 'cloudwatch_', checkId: 'cloud-monitoring-and-alerting' },
  { prefix: 'guardduty_', checkId: 'cloud-monitoring-and-alerting' },
  { prefix: 'securityhub_', checkId: 'cloud-monitoring-and-alerting' },
  { prefix: 'secretsmanager_', checkId: 'cloud-secrets-management' },
  { prefix: 'ssm_', checkId: 'cloud-secrets-management' },
  { prefix: 'awslambda_', checkId: 'cloud-serverless-configuration' },
  { prefix: 'ecr_', checkId: 'cloud-container-registry' },
  { prefix: 'eks_', checkId: 'cloud-kubernetes-benchmark' },
  { prefix: 'backup_', checkId: 'cloud-backup-and-recovery' },
  { prefix: 'elb_', checkId: 'cloud-tls-and-edge' },
  { prefix: 'cloudfront_', checkId: 'cloud-tls-and-edge' },
  { prefix: 'organizations_', checkId: 'cloud-account-inventory' },
];

function checkIdFor(checkId: string | undefined): string | undefined {
  if (!checkId) return undefined;
  const match = PROWLER_PREFIX_TO_CHECK.find((entry) => checkId.startsWith(entry.prefix));
  return match?.checkId;
}

/** Prowler's key-rotation and MFA checks map to specific catalogue entries rather than IAM broadly. */
const EXACT_CHECK_MAP: Record<string, string> = {
  iam_rotate_access_key_90_days: 'cloud-key-rotation',
  iam_user_accesskey_unused: 'cloud-key-rotation',
  iam_root_hardware_mfa_enabled: 'cloud-root-and-break-glass',
  iam_root_mfa_enabled: 'cloud-root-and-break-glass',
  iam_no_root_access_key: 'cloud-root-and-break-glass',
  iam_user_mfa_enabled_console_access: 'cloud-mfa-enforcement',
};

export const prowlerAdapter: ScannerAdapter = {
  id: 'prowler',
  displayName: 'Prowler',
  modules: ['cloud'],
  coversCheckIds: [
    'cloud-account-inventory',
    'cloud-iam-privilege-analysis',
    'cloud-root-and-break-glass',
    'cloud-mfa-enforcement',
    'cloud-key-rotation',
    'cloud-storage-exposure',
    'cloud-snapshot-and-image-exposure',
    'cloud-database-exposure',
    'cloud-network-exposure',
    'cloud-encryption-at-rest',
    'cloud-logging-coverage',
    'cloud-monitoring-and-alerting',
    'cloud-secrets-management',
    'cloud-serverless-configuration',
    'cloud-container-registry',
    'cloud-workload-identity',
    'cloud-cross-account-trust',
    'cloud-backup-and-recovery',
    'cloud-tls-and-edge',
    'cloud-compliance-framework-mapping',
  ],

  buildInvocation: () => ({
    command: [
      'aws',
      '--output-formats',
      'json-ocsf',
      '--output-directory',
      '/out',
      '--output-filename',
      'prowler',
      '--status',
      'FAIL',
      // Read-only by construction: the assumed role carries no write permission, and this flag
      // stops prowler from attempting the mutating checks it would otherwise offer.
      '--no-banner',
      '--ignore-exit-code-3',
    ],
    outputFile: 'prowler.ocsf.json',
  }),

  parse: (raw, context: ParseContext): RawFinding[] => {
    // Prowler has emitted both a JSON array and JSON Lines across versions; accept either.
    const asArray = parseJsonObject<ProwlerFinding[]>(raw);
    const results = Array.isArray(asArray) ? asArray : parseJsonLines<ProwlerFinding>(raw);

    return results
      .filter((result) => (result.status_code ?? 'FAIL').toUpperCase() === 'FAIL')
      .map((result) => {
        const checkId = result.unmapped?.check_id ?? result.metadata?.event_code;
        const resources = result.resources ?? [];
        const account = result.cloud?.account?.uid ?? context.defaultAsset;

        const compliance = Object.entries(result.unmapped?.compliance ?? {})
          .map(([framework, controls]) => `${framework}: ${controls.join(', ')}`)
          .join('\n');

        return {
          source: 'tool' as const,
          toolName: 'prowler',
          toolFindingRef: checkId ?? 'prowler-check',
          checkId: (checkId && EXACT_CHECK_MAP[checkId]) ?? checkIdFor(checkId),
          title: result.finding_info?.title ?? result.message ?? checkId ?? 'Cloud configuration finding',
          description: [
            result.finding_info?.desc,
            result.status_detail,
            result.unmapped?.risk ? `Risk: ${result.unmapped.risk}` : '',
            compliance ? `Framework mappings:\n${compliance}` : '',
          ]
            .filter(Boolean)
            .join('\n\n'),
          severity: normaliseSeverity(result.severity),
          cvssVersion: context.cvssVersion,
          owaspCategory: 'A02:2025',
          affectedAssets:
            resources.length > 0
              ? resources.map((resource) => ({
                  value: resource.uid ?? resource.name ?? account,
                  location: resource.region ? `region:${resource.region}` : undefined,
                  parameter: resource.type,
                }))
              : [{ value: account }],
          businessImpact: '',
          likelihood: '',
          attackerPrerequisites: '',
          reproductionSteps: [
            `Inspect ${resources[0]?.uid ?? 'the resource'} in account ${account}${resources[0]?.region ? ` (${resources[0].region})` : ''} and confirm the configuration described above.`,
          ],
          remediation: result.remediation?.desc ?? '',
          references: [
            ...(result.remediation?.references ?? []),
            ...(result.remediation?.kb_article_list ?? []).map((article) => article.url ?? ''),
            result.unmapped?.related_url ?? '',
          ]
            .filter((url) => /^https?:\/\//.test(url))
            .slice(0, 5)
            .map((url) => ({ title: 'Provider documentation', url })),
          evidence: [],
        } satisfies RawFinding;
      });
  },
};

interface KubescapeControlReport {
  controlID?: string;
  name?: string;
  status?: { status?: string };
  scoreFactor?: number;
  resourceIDs?: { failedResources?: string[] };
}

interface KubescapeOutput {
  summaryDetails?: {
    controls?: Record<string, KubescapeControlReport>;
  };
}

/** Kubescape scores a control 1–10; map that onto the severity bands the report uses. */
function severityFromScoreFactor(score: number | undefined): string {
  if (score === undefined) return 'info';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

export const kubescapeAdapter: ScannerAdapter = {
  id: 'kubescape',
  displayName: 'Kubescape',
  modules: ['cloud'],
  coversCheckIds: ['cloud-kubernetes-benchmark', 'cloud-kubernetes-rbac'],

  buildInvocation: () => ({
    command: [
      'scan',
      'framework',
      'nsa,mitre',
      '--format',
      'json',
      '--output',
      '/out/kubescape.json',
      '--enable-host-scan=false',
      '--submit=false',
      '--verbose=false',
    ],
    // Kubescape uploads results to a hosted backend unless told not to.
    environment: { KS_SKIP_UPDATE_CHECK: 'true' },
    outputFile: 'kubescape.json',
  }),

  parse: (raw, context: ParseContext): RawFinding[] => {
    const output = parseJsonObject<KubescapeOutput>(raw);
    const controls = output?.summaryDetails?.controls ?? {};

    return Object.values(controls)
      .filter((control) => (control.status?.status ?? '').toLowerCase() === 'failed')
      .map((control) => {
        const failed = control.resourceIDs?.failedResources ?? [];
        return {
          source: 'tool' as const,
          toolName: 'kubescape',
          toolFindingRef: control.controlID ?? 'kubescape-control',
          checkId: (control.name ?? '').toLowerCase().includes('rbac')
            ? 'cloud-kubernetes-rbac'
            : 'cloud-kubernetes-benchmark',
          title: control.name ?? control.controlID ?? 'Kubernetes control failed',
          description: `Control ${control.controlID ?? 'unknown'} failed against ${failed.length} resource(s).`,
          severity: normaliseSeverity(severityFromScoreFactor(control.scoreFactor)),
          cvssVersion: context.cvssVersion,
          owaspCategory: 'A02:2025',
          affectedAssets:
            failed.length > 0
              ? failed.slice(0, 50).map((resource) => ({ value: resource }))
              : [{ value: context.defaultAsset }],
          businessImpact: '',
          likelihood: '',
          attackerPrerequisites: '',
          reproductionSteps: [
            `Run kubescape against the cluster and inspect control ${control.controlID ?? ''}.`,
          ],
          remediation: '',
          references: control.controlID
            ? [
                {
                  title: 'Kubescape control documentation',
                  url: `https://hub.armosec.io/docs/${control.controlID.toLowerCase()}`,
                },
              ]
            : [],
          evidence: [],
        } satisfies RawFinding;
      });
  },
};
