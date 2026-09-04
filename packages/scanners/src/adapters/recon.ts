import type { RawFinding } from '@attestor/findings';
import {
  hostList,
  parseJsonLines,
  recordAsEvidence,
  splitTarget,
  type DiscoveredAsset,
  type ParseContext,
  type ScannerAdapter,
} from '../adapter.ts';

/**
 * The ProjectDiscovery recon tools: subfinder, dnsx, httpx, naabu, tlsx.
 *
 * These are mostly inventory rather than findings. What they contribute to the report is the asset
 * list everything else works from, plus a small number of genuine findings — an expiring
 * certificate, a management port open to the internet, a stale subdomain.
 *
 * They share an output shape closely enough to live in one file, and separating them would be four
 * files of near-identical boilerplate.
 */

interface SubfinderResult {
  host?: string;
  input?: string;
  source?: string;
}

interface HttpxResult {
  url?: string;
  host?: string;
  input?: string;
  port?: string;
  scheme?: string;
  status_code?: number;
  title?: string;
  webserver?: string;
  tech?: string[];
  content_length?: number;
  location?: string;
  failed?: boolean;
  cdn_name?: string;
  a?: string[];
  /** Present when `-path` was used. `/` is the ordinary root probe. */
  path?: string;
  /** Present when `-include-response` was used. */
  body?: string;
}

/**
 * Files a site publishes about itself, probed alongside the root in the same run.
 *
 * Four extra requests per host, which is nothing, and they answer WSTG-INFO-03 directly: what a
 * site says about itself in the files it serves to anybody. A host with none of them returns 404
 * four times and produces no findings, which is the normal case and must stay silent.
 */
const METAFILE_PATHS = ['/robots.txt', '/sitemap.xml', '/security.txt', '/.well-known/security.txt'];

interface NaabuResult {
  host?: string;
  ip?: string;
  port?: number;
  protocol?: string;
}

interface TlsxResult {
  host?: string;
  port?: string;
  not_after?: string;
  not_before?: string;
  expired?: boolean;
  self_signed?: boolean;
  mismatched?: boolean;
  revoked?: boolean;
  untrusted?: boolean;
  tls_version?: string;
  cipher?: string;
  subject_cn?: string;
  subject_an?: string[];
  issuer_cn?: string;
}

const CERTIFICATE_WARNING_DAYS = 30;

export const subfinderAdapter: ScannerAdapter = {
  id: 'subfinder',
  displayName: 'subfinder',
  modules: ['recon'],
  coversCheckIds: ['recon-subdomain-enumeration', 'recon-attack-surface-change'],

  buildInvocation: ({ targets }) => ({
    command: ['-silent', '-json', '-o', '/out/subfinder.jsonl', '-dL', '/out/domains.txt'],
    outputFile: 'subfinder.jsonl',
    inputFiles: [{ name: 'domains.txt', contents: `${targets.join('\n')}\n` }],
  }),

  // Subdomain enumeration produces inventory, not findings. Anything interesting about a discovered
  // host comes from probing it, which is httpx's job.
  parse: () => [],

  parseAssets: (raw): DiscoveredAsset[] =>
    parseJsonLines<SubfinderResult>(raw)
      .map((result) => result.host)
      .filter((host): host is string => typeof host === 'string' && host !== '')
      .map((host) => ({ kind: 'host', value: host, host })),
};

/**
 * A published metafile, and what it gives away.
 *
 * Reported at `info`, because publishing a robots.txt is not a vulnerability. What makes it worth a
 * row in the report is the paths it names: `Disallow: /admin-v2/` is an administrative interface
 * advertised to everyone who asks, and a client reading their own report is often seeing that line
 * for the first time in years.
 */
function metafileFinding(
  result: HttpxResult,
  host: string,
  path: string,
  context: ParseContext,
): RawFinding {
  const body = result.body ?? '';
  const named = [...body.matchAll(/^\s*(?:Disallow|Allow|Sitemap)\s*:\s*(\S+)/gim)]
    .map((match) => match[1])
    .filter((value): value is string => value !== undefined && value !== '/')
    .slice(0, 25);

  const isRobots = path.endsWith('robots.txt');
  const description = isRobots
    ? `The site publishes ${path}. It asks crawlers not to visit certain paths, which makes it a public list of the paths the operator considers sensitive.${named.length > 0 ? ` It names: ${named.join(', ')}.` : ''}`
    : `The site publishes ${path}, which describes its structure or its security contacts to anyone who asks.${named.length > 0 ? ` It names: ${named.join(', ')}.` : ''}`;

  return {
    source: 'tool',
    evidenceText: recordAsEvidence({ ...result, body: body.slice(0, 4000) }),
    toolName: 'httpx',
    toolFindingRef: path,
    checkId: 'recon-webserver-metafiles',
    title: `${path} is published and names ${named.length} path${named.length === 1 ? '' : 's'}`,
    description,
    severity: 'info',
    cvssVersion: context.cvssVersion,
    cweId: 200,
    wstgId: 'WSTG-INFO-03',
    affectedAssets: [{ value: host, location: path }],
    businessImpact: '',
    likelihood: '',
    attackerPrerequisites: '',
    reproductionSteps: [`Request ${path} on ${host} and read the paths it names.`],
    remediation: isRobots
      ? 'Do not use robots.txt to hide anything. A path that must not be reached needs authorisation on the server; naming it here only tells an attacker where to look. Remove entries pointing at administrative or internal paths and protect those paths properly.'
      : 'Review what this file discloses and confirm every detail in it is intended to be public.',
    references: [
      {
        title: 'OWASP WSTG: Review Webserver Metafiles for Information Leakage',
        url: 'https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage',
      },
    ],
    evidence: [],
  };
}

export const httpxAdapter: ScannerAdapter = {
  id: 'httpx',
  displayName: 'httpx',
  modules: ['recon', 'web'],
  coversCheckIds: [
    'recon-http-probing',
    'recon-technology-inventory',
    'recon-virtual-host-discovery',
    'recon-webserver-metafiles',
    'web-credentials-over-encrypted-channel',
  ],

  buildInvocation: ({ policy, targets }) => ({
    command: [
      '-json',
      '-o',
      '/out/httpx.jsonl',
      '-list',
      '/out/hosts.txt',
      '-status-code',
      '-title',
      '-tech-detect',
      '-web-server',
      '-content-length',
      '-location',
      '-ip',
      '-follow-redirects',
      '-max-redirects',
      '3',
      // The root plus the files a site publishes about itself, in one run. `/` has to be listed
      // explicitly: passing `-path` replaces the root probe rather than adding to it, and without
      // it every service would lose its status, title and technology inventory.
      '-path',
      ['/', ...METAFILE_PATHS].join(','),
      // Needed to read what a metafile actually says. A robots.txt is only interesting for the
      // paths it names, and reporting that it exists without them tells a client nothing.
      '-include-response',
      '-rate-limit',
      String(Math.max(1, Math.round(policy.rateLimits.globalRequestsPerSecond))),
      '-threads',
      String(policy.rateLimits.concurrency),
      '-timeout',
      '10',
      '-silent',
      // Two calls to somebody who is not the client, refused. The version check is one; the other
      // is the 92.6 MB classification model httpx fetches from huggingface whenever `-json` is
      // asked for, which the worker heads off by mounting a provisioned copy at the tool's home.
      '-disable-update-check',
    ],
    outputFile: 'httpx.jsonl',
    inputFiles: [{ name: 'hosts.txt', contents: `${targets.join('\n')}\n` }],
  }),

  parse: (raw, context: ParseContext): RawFinding[] => {
    const findings: RawFinding[] = [];

    for (const result of parseJsonLines<HttpxResult>(raw)) {
      const url = result.url ?? result.input ?? '';
      if (url === '' || result.failed) continue;
      const { host } = splitTarget(url);
      const path = result.path ?? '/';
      const status = result.status_code ?? 0;

      if (path !== '/') {
        // A metafile probe. Only a 2xx is a file; the 404s are the ordinary answer for a host that
        // publishes none of them, and they must produce nothing at all.
        if (status < 200 || status >= 300) continue;
        findings.push(metafileFinding(result, host, path, context));
        continue;
      }

      // An application that answers on plain HTTP without redirecting is a real finding, not
      // inventory: credentials submitted to it travel in the clear.
      if (result.scheme === 'http' && !result.location?.startsWith('https://')) {
        findings.push({
          source: 'tool',
          evidenceText: recordAsEvidence(result),
          toolName: 'httpx',
          toolFindingRef: 'plaintext-http',
          checkId: 'web-credentials-over-encrypted-channel',
          title: 'Service answers over plain HTTP without redirecting to HTTPS',
          description: `${url} returned HTTP ${result.status_code ?? 0} over an unencrypted connection and did not redirect to HTTPS. Anything submitted to it, including credentials and session cookies, travels in the clear.`,
          severity: 'medium',
          cvssVersion: context.cvssVersion,
          cweId: 319,
          owaspCategory: 'A04:2025',
          wstgId: 'WSTG-ATHN-01',
          affectedAssets: [{ value: host, location: '/' }],
          businessImpact: '',
          likelihood: '',
          attackerPrerequisites: '',
          reproductionSteps: [`Request ${url} and observe that the response is served over HTTP.`],
          remediation:
            'Redirect every plain HTTP request to HTTPS with a 301, and serve Strict-Transport-Security on the HTTPS response so the browser never tries HTTP again.',
          references: [
            {
              title: 'OWASP Cheat Sheet: Transport Layer Security',
              url: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html',
            },
          ],
          evidence: [],
        });
      }
    }

    return findings;
  },

  parseAssets: (raw): DiscoveredAsset[] => {
    const assets: DiscoveredAsset[] = [];
    for (const result of parseJsonLines<HttpxResult>(raw)) {
      const url = result.url ?? result.input;
      if (!url || result.failed) continue;
      // Inventory is per service, not per probed path. Without this the metafile probes would add
      // four more "url" assets and repeat the technology list for every host.
      if ((result.path ?? '/') !== '/') continue;
      const { host, port } = splitTarget(url);
      assets.push({
        kind: 'url',
        value: url,
        host,
        ...(port ? { port } : {}),
        metadata: {
          status: result.status_code ?? 0,
          title: result.title ?? '',
          server: result.webserver ?? '',
          cdn: result.cdn_name ?? '',
        },
      });
      for (const technology of result.tech ?? []) {
        assets.push({ kind: 'technology', value: technology, host });
      }
    }
    return assets;
  },
};

export const naabuAdapter: ScannerAdapter = {
  id: 'naabu',
  displayName: 'naabu',
  modules: ['recon', 'network'],
  coversCheckIds: [
    'recon-port-service-enumeration',
    'network-host-discovery',
    'network-exposed-management-interfaces',
  ],

  buildInvocation: ({ policy, targets }) => ({
    command: [
      '-json',
      '-o',
      '/out/naabu.jsonl',
      '-list',
      '/out/hosts.txt',
      '-top-ports',
      policy.intensity === 'thorough' ? '1000' : '100',
      '-rate',
      // naabu's rate is packets per second; keep it well below anything that resembles a flood.
      String(Math.max(10, Math.round(policy.rateLimits.globalRequestsPerSecond * 10))),
      '-silent',
      // Connect scan only. SYN scanning needs raw sockets, which the container does not have,
      // and a half-open scan is harder to explain to a client's network team.
      '-scan-type',
      'c',
    ],
    outputFile: 'naabu.jsonl',
    inputFiles: [{ name: 'hosts.txt', contents: hostList(targets) }],
  }),

  parse: (raw, context: ParseContext): RawFinding[] => {
    /** Ports whose exposure to the internet is a finding rather than an observation. */
    const sensitivePorts: Record<number, string> = {
      22: 'SSH',
      23: 'Telnet',
      445: 'SMB',
      1433: 'Microsoft SQL Server',
      1521: 'Oracle database',
      3306: 'MySQL',
      3389: 'Remote Desktop',
      5432: 'PostgreSQL',
      5900: 'VNC',
      6379: 'Redis',
      9200: 'Elasticsearch',
      11211: 'memcached',
      27017: 'MongoDB',
    };

    const grouped = new Map<string, number[]>();
    for (const result of parseJsonLines<NaabuResult>(raw)) {
      const host = result.host ?? result.ip;
      const port = result.port;
      if (!host || !port || !(port in sensitivePorts)) continue;
      const list = grouped.get(host);
      if (list) list.push(port);
      else grouped.set(host, [port]);
    }

    return [...grouped.entries()].map(([host, ports]) => ({
      source: 'tool' as const,
      // One finding covers several of naabu's result lines, so the evidence is the set of ports it
      // grouped rather than a single record.
      evidenceText: recordAsEvidence(
        [...ports]
          .sort((a, b) => a - b)
          .map((port) => ({ host, port, service: sensitivePorts[port] ?? 'unknown' })),
      ),
      toolName: 'naabu',
      toolFindingRef: 'sensitive-port-exposed',
      checkId: 'network-exposed-management-interfaces',
      title: `Management or database ports reachable on ${host}`,
      description: `Ports ${ports
        .sort((a, b) => a - b)
        .map((port) => `${port} (${sensitivePorts[port] ?? 'unknown'})`)
        .join(', ')} accepted a TCP connection from our source address. Services of this kind are normally reachable only from an internal network or a bastion.`,
      severity: 'medium' as const,
      cvssVersion: context.cvssVersion,
      cweId: 1327,
      owaspCategory: 'A02:2025',
      affectedAssets: ports.map((port) => ({ value: `${host}:${port}` })),
      businessImpact: '',
      likelihood: '',
      attackerPrerequisites: '',
      reproductionSteps: [`Open a TCP connection to ${host} on each listed port.`],
      remediation:
        'Restrict these ports at the firewall or security group to the addresses that genuinely need them, and reach them through a bastion or a private network rather than from the internet.',
      references: [],
      evidence: [],
    }));
  },

  parseAssets: (raw): DiscoveredAsset[] =>
    parseJsonLines<NaabuResult>(raw)
      .map((result) => {
        const host = result.host ?? result.ip;
        if (!host || !result.port) return null;
        return {
          kind: 'port' as const,
          value: `${host}:${result.port}`,
          host,
          port: result.port,
          metadata: { protocol: result.protocol ?? 'tcp' },
        };
      })
      .filter((asset): asset is NonNullable<typeof asset> => asset !== null),
};

export const tlsxAdapter: ScannerAdapter = {
  id: 'tlsx',
  displayName: 'tlsx',
  modules: ['recon', 'web', 'network'],
  coversCheckIds: ['recon-tls-configuration', 'network-transport-encryption'],

  buildInvocation: ({ targets }) => ({
    command: [
      '-json',
      '-o',
      '/out/tlsx.jsonl',
      '-list',
      '/out/hosts.txt',
      '-expired',
      '-self-signed',
      '-mismatched',
      '-revoked',
      '-untrusted',
      '-tls-version',
      '-cipher',
      // No -san here. It is a display probe in tlsx, not an extra field: combining it with the
      // certificate probes above makes the tool refuse to start with "san or cn flag cannot be
      // used with other probes". `-json` already emits subject_an, and the parser does not read it.
      '-silent',
    ],
    outputFile: 'tlsx.jsonl',
    inputFiles: [{ name: 'hosts.txt', contents: hostList(targets) }],
  }),

  parse: (raw, context: ParseContext): RawFinding[] => {
    const findings: RawFinding[] = [];
    const weakVersions = new Set(['tls10', 'tls11', 'ssl30', 'TLS1.0', 'TLS1.1']);

    for (const result of parseJsonLines<TlsxResult>(raw)) {
      const host = result.host;
      if (!host) continue;
      const asset = result.port ? `${host}:${result.port}` : host;

      if (result.expired || result.self_signed || result.mismatched || result.untrusted || result.revoked) {
        const problems = [
          result.expired ? 'expired' : '',
          result.self_signed ? 'self-signed' : '',
          result.mismatched ? 'does not match the hostname' : '',
          result.untrusted ? 'not trusted by the default store' : '',
          result.revoked ? 'revoked' : '',
        ].filter(Boolean);

        findings.push({
          source: 'tool',
          evidenceText: recordAsEvidence(result),
          toolName: 'tlsx',
          toolFindingRef: 'certificate-problem',
          checkId: 'recon-tls-configuration',
          title: `TLS certificate problem on ${asset}`,
          description: `The certificate presented by ${asset} is ${problems.join(', ')}. Issuer: ${result.issuer_cn ?? 'unknown'}. Subject: ${result.subject_cn ?? 'unknown'}.`,
          severity: result.expired || result.revoked ? 'high' : 'medium',
          cvssVersion: context.cvssVersion,
          cweId: 295,
          owaspCategory: 'A04:2025',
          wstgId: 'WSTG-CRYP-01',
          affectedAssets: [{ value: asset }],
          businessImpact: '',
          likelihood: '',
          attackerPrerequisites: '',
          reproductionSteps: [`Open a TLS connection to ${asset} and inspect the presented certificate.`],
          remediation:
            'Issue a certificate from a publicly trusted authority covering every name the service is reached by, and automate renewal so it cannot lapse again.',
          references: [],
          evidence: [],
        });
      }

      if (result.not_after) {
        const expiry = new Date(result.not_after);
        const daysLeft = Math.floor((expiry.getTime() - Date.now()) / 86_400_000);
        if (daysLeft >= 0 && daysLeft <= CERTIFICATE_WARNING_DAYS) {
          findings.push({
            source: 'tool',
            evidenceText: recordAsEvidence(result),
            toolName: 'tlsx',
            toolFindingRef: 'certificate-expiring',
            checkId: 'recon-tls-configuration',
            title: `TLS certificate on ${asset} expires in ${daysLeft} days`,
            description: `The certificate presented by ${asset} expires on ${result.not_after}. An expired certificate takes the service offline for every browser and every API client at once.`,
            severity: daysLeft <= 7 ? 'medium' : 'low',
            cvssVersion: context.cvssVersion,
            affectedAssets: [{ value: asset }],
            businessImpact: '',
            likelihood: '',
            attackerPrerequisites: '',
            reproductionSteps: [`Inspect the certificate validity dates on ${asset}.`],
            remediation:
              'Renew the certificate and put renewal on an automated schedule with alerting well before expiry.',
            references: [],
            evidence: [],
          });
        }
      }

      if (result.tls_version && weakVersions.has(result.tls_version)) {
        findings.push({
          source: 'tool',
          evidenceText: recordAsEvidence(result),
          toolName: 'tlsx',
          toolFindingRef: 'weak-tls-version',
          checkId: 'recon-tls-configuration',
          title: `Deprecated TLS version accepted on ${asset}`,
          description: `${asset} negotiated ${result.tls_version}. Versions below TLS 1.2 are deprecated and carry known weaknesses.`,
          severity: 'medium',
          cvssVersion: context.cvssVersion,
          cweId: 326,
          owaspCategory: 'A04:2025',
          wstgId: 'WSTG-CRYP-01',
          asvsRequirement: 'v5.0.0-12.1.2',
          affectedAssets: [{ value: asset }],
          businessImpact: '',
          likelihood: '',
          attackerPrerequisites: '',
          reproductionSteps: [`Negotiate ${result.tls_version} against ${asset} and observe that it is accepted.`],
          remediation:
            'Disable TLS 1.0 and 1.1 on the listener and offer TLS 1.2 and 1.3 only, with a modern cipher suite list.',
          references: [],
          evidence: [],
        });
      }
    }

    return findings;
  },

  parseAssets: (raw): DiscoveredAsset[] =>
    parseJsonLines<TlsxResult>(raw)
      .map((result) => {
        if (!result.host) return null;
        return {
          kind: 'certificate' as const,
          value: result.subject_cn ?? result.host,
          host: result.host,
          ...(result.port ? { port: Number(result.port) } : {}),
          metadata: {
            notAfter: result.not_after ?? '',
            issuer: result.issuer_cn ?? '',
            tlsVersion: result.tls_version ?? '',
            names: (result.subject_an ?? []).join(','),
          },
        };
      })
      .filter((asset): asset is NonNullable<typeof asset> => asset !== null),
};
