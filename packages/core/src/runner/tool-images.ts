/**
 * The tool catalogue.
 *
 * Every third-party security tool runs as a container, pinned by digest. Pinning by tag would mean
 * a client's engagement silently changing tool version between the assessment and the retest, which
 * makes a "verified fixed" claim unprovable.
 *
 * `digest` is empty here because a digest is environment-specific and is filled in by
 * `scripts/pin-tool-images.mjs`, which resolves each tag once and writes the result to
 * `infra/tool-images.lock.json`. The runner refuses to start a tool with no pinned digest.
 */

import type { ModuleName } from '@attestor/shared';

export interface ToolImage {
  /** Stable id used by adapters, policies and the coverage matrix. */
  id: string;
  displayName: string;
  image: string;
  tag: string;
  modules: ModuleName[];
  /** What the tool does, for the report's tool inventory. */
  purpose: string;
  /** Tools that only read remote data and never send an unsafe request. */
  readOnly: boolean;
  /** Seconds before the run is killed. A tool that has not finished by then has hung. */
  timeoutSeconds: number;
  /** Memory ceiling in megabytes. */
  memoryMb: number;
  /** Some tools genuinely need to write; they get a tmpfs, never a writable root filesystem. */
  needsWritableTmp: boolean;
}

export const TOOL_IMAGES: ToolImage[] = [
  // Recon and attack surface
  { id: 'subfinder', displayName: 'subfinder', image: 'projectdiscovery/subfinder', tag: 'latest', modules: ['recon'], purpose: 'Passive subdomain enumeration', readOnly: true, timeoutSeconds: 900, memoryMb: 512, needsWritableTmp: true },
  { id: 'amass', displayName: 'OWASP Amass', image: 'caffix/amass', tag: 'latest', modules: ['recon'], purpose: 'Attack surface mapping', readOnly: true, timeoutSeconds: 1800, memoryMb: 1024, needsWritableTmp: true },
  { id: 'dnsx', displayName: 'dnsx', image: 'projectdiscovery/dnsx', tag: 'latest', modules: ['recon'], purpose: 'DNS resolution and record enumeration', readOnly: true, timeoutSeconds: 600, memoryMb: 256, needsWritableTmp: true },
  { id: 'httpx', displayName: 'httpx', image: 'projectdiscovery/httpx', tag: 'latest', modules: ['recon', 'web'], purpose: 'HTTP probing and fingerprinting', readOnly: false, timeoutSeconds: 900, memoryMb: 512, needsWritableTmp: true },
  { id: 'naabu', displayName: 'naabu', image: 'projectdiscovery/naabu', tag: 'latest', modules: ['recon', 'network'], purpose: 'Port enumeration', readOnly: false, timeoutSeconds: 1800, memoryMb: 512, needsWritableTmp: true },
  { id: 'tlsx', displayName: 'tlsx', image: 'projectdiscovery/tlsx', tag: 'latest', modules: ['recon', 'web', 'network'], purpose: 'TLS configuration and certificate inspection', readOnly: true, timeoutSeconds: 600, memoryMb: 256, needsWritableTmp: true },
  { id: 'katana', displayName: 'katana', image: 'projectdiscovery/katana', tag: 'latest', modules: ['recon', 'web'], purpose: 'Browser-based crawling and endpoint extraction', readOnly: false, timeoutSeconds: 1800, memoryMb: 2048, needsWritableTmp: true },
  { id: 'gau', displayName: 'gau', image: 'lc/gau', tag: 'latest', modules: ['recon'], purpose: 'Historical URL collection', readOnly: true, timeoutSeconds: 600, memoryMb: 256, needsWritableTmp: true },
  { id: 'whatweb', displayName: 'WhatWeb', image: 'guisecurity/whatweb', tag: 'latest', modules: ['recon', 'web'], purpose: 'Technology fingerprinting', readOnly: false, timeoutSeconds: 900, memoryMb: 512, needsWritableTmp: true },

  // Web
  { id: 'zap', displayName: 'OWASP ZAP', image: 'zaproxy/zap-stable', tag: 'latest', modules: ['web', 'api'], purpose: 'Authenticated crawling and active scanning', readOnly: false, timeoutSeconds: 7200, memoryMb: 4096, needsWritableTmp: true },
  { id: 'nuclei', displayName: 'nuclei', image: 'projectdiscovery/nuclei', tag: 'latest', modules: ['recon', 'web', 'api', 'network'], purpose: 'Templated checks for known issues and exposures', readOnly: false, timeoutSeconds: 3600, memoryMb: 2048, needsWritableTmp: true },
  { id: 'nikto', displayName: 'Nikto', image: 'sullo/nikto', tag: 'latest', modules: ['web'], purpose: 'Web server configuration checks', readOnly: false, timeoutSeconds: 1800, memoryMb: 512, needsWritableTmp: true },
  { id: 'testssl', displayName: 'testssl.sh', image: 'drwetter/testssl.sh', tag: '3.2', modules: ['web', 'network'], purpose: 'Detailed TLS configuration review', readOnly: true, timeoutSeconds: 1200, memoryMb: 512, needsWritableTmp: true },
  { id: 'ffuf', displayName: 'ffuf', image: 'secsi/ffuf', tag: 'latest', modules: ['recon', 'web'], purpose: 'Content and parameter discovery within the agreed rate limit', readOnly: false, timeoutSeconds: 1800, memoryMb: 512, needsWritableTmp: true },
  { id: 'dalfox', displayName: 'dalfox', image: 'hahwul/dalfox', tag: 'latest', modules: ['web'], purpose: 'Cross-site scripting analysis', readOnly: false, timeoutSeconds: 1800, memoryMb: 1024, needsWritableTmp: true },
  { id: 'arjun', displayName: 'Arjun', image: 'secsi/arjun', tag: 'latest', modules: ['web', 'api'], purpose: 'Hidden parameter discovery', readOnly: false, timeoutSeconds: 1200, memoryMb: 512, needsWritableTmp: true },
  { id: 'sqlmap', displayName: 'sqlmap', image: 'secsi/sqlmap', tag: 'latest', modules: ['web', 'api'], purpose: 'Injection confirmation, read-only settings only', readOnly: false, timeoutSeconds: 3600, memoryMb: 1024, needsWritableTmp: true },
  { id: 'commix', displayName: 'commix', image: 'secsi/commix', tag: 'latest', modules: ['web'], purpose: 'Command injection confirmation, guarded', readOnly: false, timeoutSeconds: 1800, memoryMb: 512, needsWritableTmp: true },

  // API
  { id: 'schemathesis', displayName: 'Schemathesis', image: 'schemathesis/schemathesis', tag: 'stable', modules: ['api'], purpose: 'Specification-driven API testing', readOnly: false, timeoutSeconds: 3600, memoryMb: 2048, needsWritableTmp: true },
  { id: 'kiterunner', displayName: 'kiterunner', image: 'secsi/kiterunner', tag: 'latest', modules: ['api'], purpose: 'API endpoint discovery', readOnly: false, timeoutSeconds: 1800, memoryMb: 1024, needsWritableTmp: true },
  { id: 'mitmproxy', displayName: 'mitmproxy', image: 'mitmproxy/mitmproxy', tag: 'latest', modules: ['api', 'mobile'], purpose: 'Traffic capture for specification building', readOnly: false, timeoutSeconds: 7200, memoryMb: 1024, needsWritableTmp: true },

  // Code and supply chain
  { id: 'semgrep', displayName: 'Semgrep', image: 'semgrep/semgrep', tag: 'latest', modules: ['code'], purpose: 'Static analysis with curated rule packs', readOnly: true, timeoutSeconds: 3600, memoryMb: 4096, needsWritableTmp: true },
  { id: 'gitleaks', displayName: 'gitleaks', image: 'zricethezav/gitleaks', tag: 'latest', modules: ['code'], purpose: 'Secret scanning across history', readOnly: true, timeoutSeconds: 1800, memoryMb: 1024, needsWritableTmp: true },
  { id: 'trufflehog', displayName: 'TruffleHog', image: 'trufflesecurity/trufflehog', tag: 'latest', modules: ['code', 'recon'], purpose: 'Verified secret detection', readOnly: true, timeoutSeconds: 1800, memoryMb: 1024, needsWritableTmp: true },
  { id: 'trivy', displayName: 'Trivy', image: 'aquasec/trivy', tag: 'latest', modules: ['code', 'cloud'], purpose: 'Dependency, container, IaC and SBOM analysis', readOnly: true, timeoutSeconds: 3600, memoryMb: 4096, needsWritableTmp: true },
  { id: 'syft', displayName: 'Syft', image: 'anchore/syft', tag: 'latest', modules: ['code'], purpose: 'Software bill of materials generation', readOnly: true, timeoutSeconds: 1800, memoryMb: 2048, needsWritableTmp: true },
  { id: 'grype', displayName: 'Grype', image: 'anchore/grype', tag: 'latest', modules: ['code'], purpose: 'Vulnerability matching against the SBOM', readOnly: true, timeoutSeconds: 1800, memoryMb: 2048, needsWritableTmp: true },
  { id: 'checkov', displayName: 'Checkov', image: 'bridgecrew/checkov', tag: 'latest', modules: ['code', 'cloud'], purpose: 'Infrastructure-as-code misconfiguration scanning', readOnly: true, timeoutSeconds: 1800, memoryMb: 2048, needsWritableTmp: true },

  // Cloud
  { id: 'prowler', displayName: 'Prowler', image: 'toniblyx/prowler', tag: 'latest', modules: ['cloud'], purpose: 'Cloud posture checks with framework mappings', readOnly: true, timeoutSeconds: 7200, memoryMb: 4096, needsWritableTmp: true },
  { id: 'cloudsplaining', displayName: 'Cloudsplaining', image: 'salesforce/cloudsplaining', tag: 'latest', modules: ['cloud'], purpose: 'IAM policy privilege analysis', readOnly: true, timeoutSeconds: 1800, memoryMb: 2048, needsWritableTmp: true },
  { id: 'kube-bench', displayName: 'kube-bench', image: 'aquasec/kube-bench', tag: 'latest', modules: ['cloud'], purpose: 'Kubernetes benchmark checks', readOnly: true, timeoutSeconds: 1800, memoryMb: 1024, needsWritableTmp: true },
  { id: 'kubescape', displayName: 'Kubescape', image: 'quay.io/kubescape/kubescape', tag: 'latest', modules: ['cloud'], purpose: 'Kubernetes posture and RBAC analysis', readOnly: true, timeoutSeconds: 1800, memoryMb: 2048, needsWritableTmp: true },

  // Network
  { id: 'nmap', displayName: 'Nmap', image: 'instrumentisto/nmap', tag: 'latest', modules: ['network', 'recon'], purpose: 'Service identification using safe script categories only', readOnly: false, timeoutSeconds: 3600, memoryMb: 1024, needsWritableTmp: true },

  // Mobile
  { id: 'mobsf', displayName: 'MobSF', image: 'opensecurity/mobile-security-framework-mobsf', tag: 'latest', modules: ['mobile'], purpose: 'Mobile static and dynamic analysis', readOnly: false, timeoutSeconds: 7200, memoryMb: 6144, needsWritableTmp: true },
  { id: 'apktool', displayName: 'apktool', image: 'mobilesf/apktool', tag: 'latest', modules: ['mobile'], purpose: 'Android package decoding', readOnly: true, timeoutSeconds: 1800, memoryMb: 2048, needsWritableTmp: true },
  { id: 'jadx', displayName: 'jadx', image: 'mobilesf/jadx', tag: 'latest', modules: ['mobile'], purpose: 'Android decompilation', readOnly: true, timeoutSeconds: 3600, memoryMb: 4096, needsWritableTmp: true },

  // LLM and AI
  { id: 'garak', displayName: 'garak', image: 'leondz/garak', tag: 'latest', modules: ['llm'], purpose: 'Broad LLM probe sweep', readOnly: false, timeoutSeconds: 7200, memoryMb: 4096, needsWritableTmp: true },
  { id: 'promptfoo', displayName: 'promptfoo', image: 'promptfoo/promptfoo', tag: 'latest', modules: ['llm'], purpose: 'YAML-defined adversarial suites with graded assertions', readOnly: false, timeoutSeconds: 7200, memoryMb: 2048, needsWritableTmp: true },
  { id: 'pyrit', displayName: 'PyRIT', image: 'attestor/pyrit', tag: 'local', modules: ['llm'], purpose: 'Multi-turn adaptive campaigns', readOnly: false, timeoutSeconds: 7200, memoryMb: 4096, needsWritableTmp: true },
  { id: 'deepteam', displayName: 'DeepTeam', image: 'attestor/deepteam', tag: 'local', modules: ['llm'], purpose: 'OWASP LLM Top 10 mapped vulnerability coverage', readOnly: false, timeoutSeconds: 7200, memoryMb: 4096, needsWritableTmp: true },

  // Agentic, shipped disabled
  { id: 'strix', displayName: 'Strix', image: 'usestrix/strix', tag: 'latest', modules: ['agentic'], purpose: 'Autonomous breadth pass, candidates only, off by default', readOnly: false, timeoutSeconds: 7200, memoryMb: 4096, needsWritableTmp: true },
];

const byId = new Map(TOOL_IMAGES.map((tool) => [tool.id, tool]));

export function toolImageById(id: string): ToolImage {
  const found = byId.get(id);
  if (!found) throw new Error(`unknown tool "${id}"`);
  return found;
}

export function toolsForModule(module: ModuleName): ToolImage[] {
  return TOOL_IMAGES.filter((tool) => tool.modules.includes(module));
}

/**
 * Tools that run inside the platform rather than in a container: the browser driver, the
 * access-control replay matrix, the rate-limit probe and the custom LLM probe corpus. They appear
 * in the catalogue for the coverage matrix and the report's tool inventory.
 */
export const IN_PROCESS_TOOLS = [
  { id: 'playwright', displayName: 'Playwright', purpose: 'Authenticated browsing, session capture and evidence' },
  { id: 'accessControlMatrix', displayName: 'Access control matrix', purpose: 'Cross-role request replay and comparison' },
  { id: 'rateLimitProbe', displayName: 'Rate limit probe', purpose: 'Bounded throttling measurement on sensitive endpoints' },
  { id: 'attestorProbes', displayName: 'Attestor LLM probe corpus', purpose: 'Versioned in-house adversarial prompts' },
] as const;
