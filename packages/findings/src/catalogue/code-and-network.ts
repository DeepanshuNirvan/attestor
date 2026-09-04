import type { Check } from './types.ts';

export const codeChecks: Check[] = [
  {
    id: 'code-static-analysis',
    title: 'Static analysis with curated rule packs',
    category: 'supplyChain',
    modules: ['code'],
    description:
      'Run static analysis with rule packs selected for the languages and frameworks in use, tuned to the classes that produce real findings rather than the full default set.',
    example:
      'A raw query built by string concatenation in a reporting module that the dynamic testing could not reach.',
    automation: 'automated',
    tools: ['semgrep'],
    standards: { owaspTop10: ['A05:2025'], asvs: ['v5.0.0-15.1.1'], cwe: [89, 79, 78] },
  },
  {
    id: 'code-secret-scanning-history',
    title: 'Secret scanning across repository history',
    category: 'supplyChain',
    modules: ['code'],
    description:
      'Scan the full commit history, not only the current tree, since a removed secret is still present in history and still valid unless it was rotated.',
    example:
      'A production database password removed from the code in 2024 and never rotated, still in the history and still working.',
    automation: 'automated',
    tools: ['gitleaks', 'trufflehog'],
    standards: { owaspTop10: ['A02:2025'], cwe: [798, 540] },
  },
  {
    id: 'code-dependency-vulnerabilities',
    title: 'Dependency vulnerability analysis',
    category: 'supplyChain',
    modules: ['code'],
    description:
      'Resolve the full dependency tree, match against vulnerability data, and distinguish dependencies that are actually reachable from those that are merely present.',
    example:
      'A deserialisation issue in a transitive dependency that is on the request path, not just in the build.',
    automation: 'automated',
    tools: ['trivy', 'grype', 'syft'],
    standards: { owaspTop10: ['A03:2025'], cwe: [1104, 1395] },
  },
  {
    id: 'code-sbom-generation',
    title: 'Software bill of materials',
    category: 'supplyChain',
    modules: ['code'],
    description:
      'Produce an SBOM for the application and its container images, which is increasingly what enterprise buyers ask for alongside the report.',
    example:
      'An SBOM that reveals two versions of the same cryptography library linked into one image.',
    automation: 'automated',
    tools: ['syft', 'trivy'],
    standards: { owaspTop10: ['A03:2025'], cwe: [1104] },
  },
  {
    id: 'code-dependency-provenance',
    title: 'Dependency provenance and typosquatting',
    category: 'supplyChain',
    modules: ['code'],
    description:
      'Check for packages resolved from unexpected registries, names close to popular packages, packages with a single recent maintainer change, and lockfile drift.',
    example:
      'An internal package name resolvable from the public registry, which is the dependency confusion path.',
    automation: 'assisted',
    tools: ['trivy', 'semgrep'],
    standards: { owaspTop10: ['A03:2025'], cwe: [427, 494] },
  },
  {
    id: 'code-container-image-review',
    title: 'Container image review',
    category: 'supplyChain',
    modules: ['code'],
    description:
      'Check base image age, running user, exposed ports, embedded secrets, package vulnerabilities and whether the image includes build tooling it does not need at runtime.',
    example:
      'A production image running as root with a compiler and a package manager still installed.',
    automation: 'automated',
    tools: ['trivy', 'grype'],
    standards: { owaspTop10: ['A02:2025', 'A03:2025'], cwe: [250, 1104] },
  },
  {
    id: 'code-iac-misconfiguration',
    title: 'Infrastructure-as-code misconfiguration',
    category: 'supplyChain',
    modules: ['code', 'cloud'],
    description:
      'Scan infrastructure definitions for misconfiguration before it is deployed, and compare the definitions against what is actually running.',
    example:
      'A storage bucket defined as private in code while the deployed bucket is public, because someone changed it in the console.',
    automation: 'automated',
    tools: ['checkov', 'trivy'],
    standards: { owaspTop10: ['A02:2025'], cwe: [1032] },
  },
  {
    id: 'code-ci-cd-configuration',
    title: 'CI/CD pipeline configuration review',
    category: 'supplyChain',
    modules: ['code'],
    description:
      'Review pipeline triggers, secret exposure to forks and pull requests, third-party action pinning, artefact signing and who can approve a deployment.',
    example:
      'A workflow triggered by pull requests from forks with access to deployment secrets.',
    automation: 'assisted',
    tools: ['semgrep', 'checkov'],
    standards: { owaspTop10: ['A03:2025', 'A08:2025'], cwe: [284, 494] },
  },
  {
    id: 'code-authorisation-logic-review',
    title: 'Authorisation logic review in source',
    category: 'accessControl',
    modules: ['code'],
    description:
      'Read the authorisation implementation directly: where checks are applied, whether they are applied at the boundary or inside handlers, and which routes bypass the middleware.',
    example:
      'Three routes registered outside the authorisation middleware because they were added to a different router.',
    automation: 'manual',
    tools: ['semgrep'],
    standards: { owaspTop10: ['A01:2025'], asvs: ['v5.0.0-8.1.1'], cwe: [285, 862] },
  },
  {
    id: 'code-cryptography-review',
    title: 'Cryptographic implementation review in source',
    category: 'cryptography',
    modules: ['code'],
    description:
      'Review algorithm choice, mode, key derivation, initialisation vector generation, comparison of secrets and key storage in the source rather than inferring it from behaviour.',
    example:
      'A token comparison using string equality, which leaks the correct value through timing.',
    automation: 'assisted',
    tools: ['semgrep'],
    standards: { owaspTop10: ['A04:2025'], asvs: ['v5.0.0-11.1.1'], cwe: [327, 208] },
  },
  {
    id: 'code-input-validation-review',
    title: 'Input validation and output encoding review',
    category: 'inputValidation',
    modules: ['code'],
    description:
      'Check where validation happens, whether it is allowlist-based, and whether output encoding is contextual rather than a single global escape.',
    example:
      'HTML escaping applied globally, which does nothing for a value interpolated into a JavaScript string.',
    automation: 'assisted',
    tools: ['semgrep'],
    standards: { owaspTop10: ['A05:2025'], asvs: ['v5.0.0-1.1.1'], cwe: [20, 116] },
  },
  {
    id: 'code-logging-review',
    title: 'Logging and error handling review in source',
    category: 'errorHandling',
    modules: ['code'],
    description:
      'Check what is logged, whether secrets or personal data reach the logs, whether errors are swallowed, and whether security-relevant events are recorded at all.',
    example:
      'A catch block that logs the whole request object, including the Authorization header.',
    automation: 'assisted',
    tools: ['semgrep'],
    standards: { owaspTop10: ['A09:2025', 'A10:2025'], cwe: [532, 390] },
  },
  {
    id: 'code-licence-review',
    title: 'Dependency licence review',
    category: 'supplyChain',
    modules: ['code'],
    description:
      'Report dependency licences that conflict with the client\'s distribution model, which is a commercial risk their buyers increasingly ask about.',
    example:
      'A copyleft library linked into a distributed desktop client.',
    automation: 'automated',
    tools: ['syft', 'trivy'],
    standards: {},
  },
];

export const networkChecks: Check[] = [
  {
    id: 'network-host-discovery',
    title: 'Host discovery within the authorised range',
    category: 'infrastructure',
    modules: ['network'],
    description:
      'Identify live hosts across the authorised address space and produce an inventory the client can reconcile against their own records.',
    example:
      'Eleven live hosts in a range the client believed had been decommissioned.',
    automation: 'automated',
    tools: ['naabu', 'nmap'],
    standards: { owaspTop10: ['A02:2025'], cwe: [1059] },
  },
  {
    id: 'network-service-identification',
    title: 'Service and version identification',
    category: 'infrastructure',
    modules: ['network'],
    description:
      'Identify the service and version behind each open port using safe detection scripts only, with no exploitation and no brute forcing.',
    example:
      'An unauthenticated message broker on an internal-only port that is reachable from the office network.',
    automation: 'automated',
    tools: ['nmap'],
    // WSTG-CONF-01 asks what is running across the network and how it is configured, and names nmap
    // as the tool for it. This check is that test, performed with that tool.
    standards: { wstg: ['WSTG-CONF-01'], owaspTop10: ['A02:2025'], cwe: [200] },
  },
  {
    id: 'network-cve-correlation',
    title: 'Known vulnerability correlation',
    category: 'infrastructure',
    modules: ['network'],
    description:
      'Correlate identified service versions against vulnerability data and separate what is confirmed present from what is inferred from a banner.',
    example:
      'A remote service two patch levels behind, with a published pre-authentication issue for that version.',
    automation: 'automated',
    tools: ['nuclei', 'nmap'],
    standards: { owaspTop10: ['A03:2025'], cwe: [1104] },
  },
  {
    id: 'network-default-credentials',
    title: 'Default credentials on network services',
    category: 'authentication',
    modules: ['network'],
    description:
      'Test a small, documented set of vendor defaults against management services. Bounded attempts, disposable accounts only, and never against a directory that would lock real users out.',
    example:
      'A network device management interface still on the vendor default password.',
    automation: 'assisted',
    tools: ['nuclei'],
    standards: { owaspTop10: ['A07:2025'], cwe: [1392] },
  },
  {
    id: 'network-transport-encryption',
    title: 'Transport encryption on network services',
    category: 'cryptography',
    modules: ['network'],
    description:
      'Check whether administrative and data services are exposed without encryption, and whether encrypted alternatives are available but unused.',
    example:
      'A database accepting unencrypted connections from the application subnet.',
    automation: 'automated',
    tools: ['tlsx', 'testssl', 'nmap'],
    standards: { owaspTop10: ['A04:2025'], cwe: [319] },
  },
  {
    id: 'network-segmentation-review',
    title: 'Segmentation and reachability review',
    category: 'infrastructure',
    modules: ['network'],
    description:
      'From an authorised position in the network, establish what is actually reachable and compare it against the segmentation the client believes exists.',
    example:
      'The guest wireless network able to reach the production database subnet.',
    automation: 'assisted',
    tools: ['nmap', 'naabu'],
    standards: { owaspTop10: ['A02:2025'], cwe: [668, 923] },
  },
  {
    id: 'network-exposed-management-interfaces',
    title: 'Exposed management and remote access interfaces',
    category: 'infrastructure',
    modules: ['network'],
    description:
      'Identify remote administration, out-of-band management, backup and monitoring interfaces reachable from a network they should not be reachable from.',
    example:
      'An out-of-band server management interface reachable from the internet.',
    automation: 'automated',
    tools: ['naabu', 'nmap', 'httpx'],
    standards: { owaspTop10: ['A02:2025'], cwe: [1327] },
  },
  {
    id: 'network-information-disclosure',
    title: 'Information disclosure from network services',
    category: 'informationGathering',
    modules: ['network'],
    description:
      'Check for services disclosing internal hostnames, usernames, version detail, share listings or configuration to unauthenticated clients.',
    example:
      'A directory service permitting anonymous binding and enumeration of every user account.',
    automation: 'automated',
    tools: ['nmap', 'nuclei'],
    standards: { owaspTop10: ['A02:2025'], cwe: [200] },
  },
];
