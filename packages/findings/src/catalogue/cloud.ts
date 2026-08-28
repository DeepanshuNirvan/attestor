import type { Check } from './types.ts';

/**
 * Cloud checks are read-only by construction. The role Attestor assumes has no write permission,
 * so a misconfigured check cannot change a client's environment.
 */
export const cloudChecks: Check[] = [
  {
    id: 'cloud-account-inventory',
    title: 'Account, subscription and project inventory',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Enumerate every account, subscription, project, region and enabled service, so the review covers what exists rather than what the client remembered.',
    example:
      'A forgotten region carrying a public instance from a proof of concept two years ago.',
    automation: 'automated',
    tools: ['prowler'],
    standards: { owaspTop10: ['A02:2025'], cwe: [1059] },
  },
  {
    id: 'cloud-iam-privilege-analysis',
    title: 'IAM privilege and escalation path analysis',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Analyse identities, roles and policies for excessive privilege, wildcard actions and resources, and known privilege-escalation paths reachable from a low-privileged identity.',
    example:
      'A build role able to pass any role to a compute service, which is a complete path to administrator.',
    automation: 'automated',
    tools: ['prowler', 'cloudsplaining'],
    standards: { owaspTop10: ['A01:2025'], cwe: [269, 732] },
  },
  {
    id: 'cloud-root-and-break-glass',
    title: 'Root and break-glass account controls',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Check whether the root or global administrator account has multi-factor authentication, active access keys, and monitored use.',
    example:
      'A root account with an access key created during setup and never rotated or removed.',
    automation: 'automated',
    tools: ['prowler'],
    standards: { owaspTop10: ['A07:2025'], cwe: [1392, 269] },
  },
  {
    id: 'cloud-mfa-enforcement',
    title: 'Multi-factor enforcement across identities',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Check that every human identity requires multi-factor authentication and that conditional access or equivalent policy actually applies to all of them.',
    example:
      'A conditional access policy in report-only mode, enforcing nothing.',
    automation: 'automated',
    tools: ['prowler'],
    standards: { owaspTop10: ['A07:2025'], cwe: [308] },
  },
  {
    id: 'cloud-key-rotation',
    title: 'Access key age and rotation',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Report long-lived access keys, unused credentials and identities with more than one active key.',
    example:
      'A programmatic key three years old, last used eleven months ago, still active.',
    automation: 'automated',
    tools: ['prowler'],
    standards: { owaspTop10: ['A07:2025'], cwe: [798, 324] },
  },
  {
    id: 'cloud-storage-exposure',
    title: 'Public storage exposure',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Check object storage, file shares and static hosting for public access, permissive policies and public access-block settings that are off.',
    example:
      'A bucket allowing anonymous listing that contains customer document uploads.',
    automation: 'automated',
    tools: ['prowler'],
    standards: { owaspTop10: ['A01:2025', 'A02:2025'], cwe: [732, 200] },
  },
  {
    id: 'cloud-snapshot-and-image-exposure',
    title: 'Snapshot, image and backup exposure',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Check disk snapshots, machine images and database snapshots for public or cross-account sharing.',
    example:
      'A database snapshot shared publicly during a support case and never unshared.',
    automation: 'automated',
    tools: ['prowler'],
    standards: { owaspTop10: ['A01:2025'], cwe: [732, 200] },
  },
  {
    id: 'cloud-database-exposure',
    title: 'Managed database exposure and configuration',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Check public accessibility, network placement, encryption at rest and in transit, backup retention, deletion protection and audit logging on managed databases and caches.',
    example:
      'A managed cache reachable from the internet without authentication, holding session data.',
    automation: 'automated',
    tools: ['prowler'],
    standards: { owaspTop10: ['A02:2025', 'A04:2025'], cwe: [1327, 311] },
  },
  {
    id: 'cloud-network-exposure',
    title: 'Network exposure and segmentation',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Review security groups, network security groups, firewall rules, route tables and peering for rules that open management or database ports to the internet.',
    example:
      'A security group permitting remote administration from any address, attached to nine instances.',
    automation: 'automated',
    tools: ['prowler'],
    standards: { owaspTop10: ['A02:2025'], cwe: [1327, 668] },
  },
  {
    id: 'cloud-encryption-at-rest',
    title: 'Encryption at rest and key management',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Check that storage, databases, queues and logs are encrypted, whether customer-managed keys are used where required, and whether key policies permit broad use.',
    example:
      'A key policy allowing every principal in the account to decrypt, which makes the key boundary meaningless.',
    automation: 'automated',
    tools: ['prowler'],
    standards: { owaspTop10: ['A04:2025'], cwe: [311, 732] },
  },
  {
    id: 'cloud-logging-coverage',
    title: 'Audit logging coverage and integrity',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Check that management-plane logging is enabled in every region, delivered to a protected destination, retained long enough to investigate, and protected against deletion.',
    example:
      'Management logging enabled in one region only, so activity elsewhere leaves no record.',
    automation: 'automated',
    tools: ['prowler'],
    standards: { owaspTop10: ['A09:2025'], cwe: [778] },
  },
  {
    id: 'cloud-monitoring-and-alerting',
    title: 'Monitoring and alerting on security events',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Check for alarms on root use, policy changes, network changes, failed authentication and disabled logging, and whether the alerts reach a person.',
    example:
      'Alerts configured but delivered to a distribution list nobody has read since the person who created it left.',
    automation: 'automated',
    tools: ['prowler'],
    standards: { owaspTop10: ['A09:2025'], cwe: [778] },
  },
  {
    id: 'cloud-secrets-management',
    title: 'Secrets management',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Check for secrets in environment variables, launch templates, task definitions, function configuration and infrastructure code, and whether the secrets service is used where one exists.',
    example:
      'A database password in a container task definition, visible to anyone with read access to the service.',
    automation: 'automated',
    tools: ['prowler', 'trufflehog'],
    standards: { owaspTop10: ['A02:2025'], cwe: [798, 522] },
  },
  {
    id: 'cloud-serverless-configuration',
    title: 'Serverless function configuration',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Review function execution roles, environment variables, public URLs, timeout and memory settings, and whether functions can reach more than their purpose requires.',
    example:
      'An image-resize function with a role granting full storage access across the account.',
    automation: 'automated',
    tools: ['prowler'],
    standards: { owaspTop10: ['A01:2025'], cwe: [269, 732] },
  },
  {
    id: 'cloud-container-registry',
    title: 'Container registry and image controls',
    category: 'cloudSpecific',
    modules: ['cloud', 'code'],
    description:
      'Check registry access policy, image scanning, immutable tags and whether production pulls from a registry the organisation controls.',
    example:
      'A production deployment pulling `:latest` from a public registry, so the running image is whatever was pushed last.',
    automation: 'automated',
    tools: ['prowler', 'trivy'],
    standards: { owaspTop10: ['A03:2025', 'A08:2025'], cwe: [494, 1104] },
  },
  {
    id: 'cloud-kubernetes-benchmark',
    title: 'Kubernetes cluster benchmark',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Run benchmark checks against control plane and node configuration, and review admission control, network policy and pod security standards.',
    example:
      'No network policy anywhere in the cluster, so every pod can reach every other pod and the metadata endpoint.',
    automation: 'automated',
    tools: ['kube-bench', 'kubescape'],
    standards: { owaspTop10: ['A02:2025'], cwe: [1327, 668] },
  },
  {
    id: 'cloud-kubernetes-rbac',
    title: 'Kubernetes RBAC review',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Review roles and bindings for wildcard verbs, cluster-admin grants, service accounts with excessive rights, and paths from a pod to cluster administrator.',
    example:
      'A default service account bound to cluster-admin, so any pod compromise is a cluster compromise.',
    automation: 'automated',
    tools: ['kubescape'],
    standards: { owaspTop10: ['A01:2025'], cwe: [269] },
  },
  {
    id: 'cloud-workload-identity',
    title: 'Workload identity and metadata protection',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Check that the instance metadata service requires session tokens, that hop limits are set, and that workloads use short-lived identities rather than embedded keys.',
    example:
      'Metadata service version 1 still enabled, turning any server-side request forgery into cloud credentials.',
    automation: 'automated',
    tools: ['prowler'],
    standards: { owaspTop10: ['A01:2025'], cwe: [918, 522] },
  },
  {
    id: 'cloud-cross-account-trust',
    title: 'Cross-account and external trust relationships',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Review trust policies for external principals, missing external identifiers on third-party roles, and federated trust that is broader than intended.',
    example:
      'A vendor role trusting the vendor\'s whole account with no external identifier, so any of that vendor\'s customers could assume it.',
    automation: 'automated',
    tools: ['prowler', 'cloudsplaining'],
    standards: { owaspTop10: ['A01:2025'], cwe: [1032, 269] },
  },
  {
    id: 'cloud-backup-and-recovery',
    title: 'Backup coverage and recovery configuration',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Check backup coverage, retention, cross-region or cross-account copies, and whether backups are protected from deletion by the same identity that can delete the data.',
    example:
      'Backups in the same account with the same permissions as production, so one compromised identity removes both.',
    automation: 'automated',
    tools: ['prowler'],
    standards: { owaspTop10: ['A02:2025'], cwe: [1188] },
  },
  {
    id: 'cloud-tls-and-edge',
    title: 'Edge, load balancer and TLS configuration',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Check listener protocols and policies, redirect behaviour, access logging, origin protection and whether the origin is reachable directly, bypassing the edge.',
    example:
      'An origin load balancer reachable by address, so the WAF at the edge can be walked around.',
    automation: 'automated',
    tools: ['prowler', 'tlsx'],
    standards: { owaspTop10: ['A02:2025', 'A04:2025'], cwe: [693, 326] },
  },
  {
    id: 'cloud-cost-anomaly-surface',
    title: 'Cost exposure from public resources',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Identify resources whose exposure creates a financial risk rather than only a data risk, and report the exposure alongside the security finding.',
    example:
      'An unauthenticated function URL invoking a paid model API, billable to the client by anyone who finds it.',
    automation: 'assisted',
    tools: ['prowler'],
    standards: { owaspTop10: ['A02:2025'], cwe: [770] },
  },
  {
    id: 'cloud-compliance-framework-mapping',
    title: 'Benchmark and framework mapping',
    category: 'cloudSpecific',
    modules: ['cloud'],
    description:
      'Map findings to the frameworks the client is being audited against, so the output can be handed to the auditor without translation.',
    example:
      'A logging gap reported against both the benchmark control and the SOC 2 criterion the auditor will ask about.',
    automation: 'automated',
    tools: ['prowler'],
    standards: {},
  },
];
