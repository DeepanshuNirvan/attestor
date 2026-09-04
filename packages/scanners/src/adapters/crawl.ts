import type { RawFinding } from '@attestor/findings';
import {
  parseJsonLines,
  recordAsEvidence,
  splitTarget,
  type DiscoveredAsset,
  type ParseContext,
  type ScannerAdapter,
} from '../adapter.ts';

/**
 * katana — the crawl that everything downstream depends on.
 *
 * Its value is the endpoint list, not findings. An access control test needs requests to replay, a
 * parameter test needs parameters to tamper with, and a coverage claim of "we tested your API" needs
 * to name what "your API" turned out to be. Without a crawl, every one of those is guesswork about a
 * site nobody mapped.
 *
 * Deliberately produces almost no findings of its own. A crawler that reported "found a URL" as a
 * vulnerability would inflate a report with a hundred rows that mean nothing, which is the opposite
 * of what a client is paying for. The one thing it does report is a metafile that names paths the
 * application did not otherwise link — `robots.txt` listing `/admin` is a real, ordinary finding and
 * has been for twenty years.
 */

interface KatanaRecord {
  timestamp?: string;
  request?: {
    method?: string;
    endpoint?: string;
    /** The HTML element the URL came from: `script`, `a`, `form`, `link`. */
    tag?: string;
    attribute?: string;
    source?: string;
    body?: string;
  };
  response?: {
    status_code?: number;
    headers?: Record<string, string>;
    content_length?: number;
    technologies?: string[];
  };
}

/** Paths a crawl reaches by asking for them rather than by following a link. */
const KNOWN_FILES = /\/(robots\.txt|sitemap[^/]*\.xml|security\.txt|\.well-known\/[^/]+)$/i;

/**
 * Static assets. Kept out of the endpoint inventory because replaying a stylesheet as three
 * different users answers nothing, and a thousand of them would exhaust the replay budget before
 * the first real endpoint was reached.
 */
const STATIC_ASSET = /\.(js|mjs|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map|pdf|zip)(\?|$)/i;

/**
 * katana finds nothing at all for a single-label hostname unless the port is written out.
 *
 * Observed against a real server: `http://intranet` crawls zero endpoints and exits 0, while
 * `http://intranet:80` crawls the site normally. A dotted name works either way. Left alone, an
 * internal engagement — where single-label hostnames are the norm — would produce an empty crawl
 * that reads exactly like a one-page application, and every test downstream of the crawl would
 * have nothing to work on while the run recorded itself as completed.
 *
 * The port is only added where it is missing and the host has no dot, so ordinary external targets
 * keep the URLs the client recognises.
 */
export function withExplicitPortForSingleLabelHost(target: string): string {
  const withScheme = target.includes('://') ? target : `https://${target}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return target;
  }

  if (url.port !== '' || url.hostname.includes('.')) return target;
  // Built by hand rather than through `URL`, which drops a port that is the default for the
  // scheme — setting `url.port = '80'` on an http URL and reading it back gives the string we
  // started with, and the whole point here is to write the port out.
  const port = url.protocol === 'https:' ? '443' : '80';
  const path = url.pathname === '/' ? '' : url.pathname;
  return target.includes('://')
    ? `${url.protocol}//${url.hostname}:${port}${path}`
    : `${url.hostname}:${port}`;
}

export function isReplayableEndpoint(url: string): boolean {
  if (STATIC_ASSET.test(url)) return false;
  if (KNOWN_FILES.test(url)) return false;
  return true;
}

export const katanaAdapter: ScannerAdapter = {
  id: 'katana',
  displayName: 'katana',
  modules: ['recon', 'web'],
  coversCheckIds: ['recon-entry-point-mapping'],

  buildInvocation: ({ policy, targets }) => ({
    command: [
      '-list',
      '/out/urls.txt',
      '-jsonl',
      '-output',
      '/out/katana.jsonl',
      '-depth',
      String(policy.intensity === 'thorough' ? 4 : 3),
      // Asked for, but not relied on. Verified against a real server: this katana build emits no
      // record for robots.txt or sitemap.xml even at the depth it demands for the option. The
      // metafile check is covered by httpx probing those paths directly, and this stays only
      // because a future build fixing it would then feed the crawl for free.
      '-known-files',
      'all',
      '-js-crawl',
      // The raw request and the response body would otherwise be written into the output file for
      // every URL, which on a large site is hundreds of megabytes of a client's content on our disk
      // for no benefit — the parser needs the endpoint, the method and the status.
      '-omit-raw',
      '-omit-body',
      '-rate-limit',
      String(Math.max(1, Math.round(policy.rateLimits.globalRequestsPerSecond))),
      '-concurrency',
      String(policy.rateLimits.concurrency),
      // Same host only. A crawler that follows an outbound link is a crawler that tests somebody
      // who never authorised anything; the scope guard would refuse it, and this stops it arising.
      '-field-scope',
      'fqdn',
      '-timeout',
      '10',
      '-silent',
      '-no-color',
      '-disable-update-check',
    ],
    outputFile: 'katana.jsonl',
    inputFiles: [
      {
        name: 'urls.txt',
        contents: `${targets.map(withExplicitPortForSingleLabelHost).join('\n')}\n`,
      },
    ],
  }),

  parse: (raw, context: ParseContext): RawFinding[] => {
    const findings: RawFinding[] = [];

    for (const record of parseJsonLines<KatanaRecord>(raw)) {
      const endpoint = record.request?.endpoint;
      const status = record.response?.status_code ?? 0;
      if (!endpoint || !KNOWN_FILES.test(endpoint) || status < 200 || status >= 300) continue;

      const { host, location } = splitTarget(endpoint);
      const isRobots = /robots\.txt$/i.test(endpoint);

      findings.push({
        source: 'tool',
        evidenceText: recordAsEvidence(record),
        toolName: 'katana',
        toolFindingRef: location ?? endpoint,
        checkId: 'recon-webserver-metafiles',
        title: `${isRobots ? 'robots.txt' : 'A metadata file'} is published at ${location ?? endpoint}`,
        description: isRobots
          ? 'The site publishes a robots.txt. Its purpose is to ask crawlers not to index certain paths, which means it is also a list of paths the operator considers sensitive, readable by anyone. It is not a vulnerability in itself; it is worth reading to see what it names.'
          : 'The site publishes a metadata file that describes its structure or contacts. Worth reading for paths and details that were not meant to be advertised.',
        severity: 'info',
        cvssVersion: context.cvssVersion,
        cweId: 200,
        wstgId: 'WSTG-INFO-03',
        affectedAssets: [{ value: host, location }],
        businessImpact: '',
        likelihood: '',
        attackerPrerequisites: '',
        reproductionSteps: [`Request ${endpoint} and read the paths it names.`],
        remediation:
          'Do not use robots.txt to hide anything. A path that must not be reached needs authorisation on the server; naming it here only tells an attacker where to look. Remove entries that point at administrative or internal paths and protect those paths properly.',
        references: [
          {
            title: 'OWASP WSTG: Review Webserver Metafiles for Information Leakage',
            url: 'https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage',
          },
        ],
        evidence: [],
      });
    }

    return findings;
  },

  /**
   * The endpoint inventory. This is what katana is for, and what the access control matrix replays.
   */
  parseAssets: (raw): DiscoveredAsset[] => {
    const assets: DiscoveredAsset[] = [];
    const seen = new Set<string>();

    for (const record of parseJsonLines<KatanaRecord>(raw)) {
      const endpoint = record.request?.endpoint;
      if (!endpoint) continue;

      const method = (record.request?.method ?? 'GET').toUpperCase();
      const key = `${method} ${endpoint}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const { host, port } = splitTarget(endpoint);
      if (host === '') continue;

      assets.push({
        kind: 'endpoint',
        value: endpoint,
        host,
        port,
        metadata: {
          method,
          status: record.response?.status_code ?? 0,
          contentLength: record.response?.content_length ?? 0,
          // Read by the access control matrix to decide what is worth replaying. A stylesheet is an
          // endpoint too, and replaying one as three identities proves nothing.
          replayable: isReplayableEndpoint(endpoint) && method === 'GET',
          ...(record.request?.tag ? { foundIn: record.request.tag } : {}),
        },
      });
    }

    return assets;
  },
};
