import type { RawFinding } from '@attestor/findings';
import {
  normaliseSeverity,
  parseJsonObject,
  recordAsEvidence,
  splitTarget,
  type DiscoveredAsset,
  type ParseContext,
  type ScannerAdapter,
} from '../adapter.ts';

/**
 * ffuf, for the paths nothing links to.
 *
 * A crawler finds what the application admits exists. This finds what it does not: the admin panel
 * with no link to it, the `.env` somebody deployed, last year's `/api/v1` still answering after
 * everyone moved to v2, the `backup.zip` from the migration.
 *
 * **The wordlist is deliberately short.** The obvious approach is a hundred thousand entries from a
 * public list, and it is the wrong one here: this platform holds itself to a rate the client agreed
 * to, and a hundred thousand requests at a polite rate is a scan that runs for days and finishes
 * after the engagement ends. A few hundred paths chosen for what they actually turn up finds the
 * same things in ten minutes. It ships in this file rather than as a provisioned pack for the same
 * reason nuclei's templates are pinned — a list that updates itself changes what a report means
 * between two runs of the same tool.
 */

/**
 * Ordered roughly by what is worth finding rather than alphabetically, because a run cut short by
 * the wall clock should have asked the important questions first.
 */
const WORDLIST = [
  // Secrets and configuration left in the web root. The highest-value miss in this whole list.
  '.env',
  '.env.local',
  '.env.production',
  '.git/config',
  '.git/HEAD',
  '.svn/entries',
  '.DS_Store',
  'config.json',
  'config.php',
  'configuration.php',
  'settings.py',
  'web.config',
  'appsettings.json',
  'application.properties',
  'docker-compose.yml',
  'Dockerfile',
  'package.json',
  'composer.json',
  'composer.lock',
  'yarn.lock',
  'Gemfile',
  'wp-config.php.bak',
  'credentials',
  'secrets.json',
  'id_rsa',
  '.htpasswd',
  '.npmrc',
  '.aws/credentials',

  // Backups and copies, which is how a source file becomes a download.
  'backup',
  'backup.zip',
  'backup.tar.gz',
  'backup.sql',
  'db.sql',
  'dump.sql',
  'database.sql',
  'site.zip',
  'www.zip',
  'archive.zip',
  'old',
  'old.zip',
  'index.php.bak',
  'index.html.bak',
  'index.php~',
  'app.js.map',

  // Administrative interfaces.
  'admin',
  'administrator',
  'admin.php',
  'admin/login',
  'wp-admin',
  'wp-login.php',
  'phpmyadmin',
  'adminer.php',
  'manager/html',
  'cpanel',
  'console',
  'dashboard',
  'portal',
  'backend',
  'management',

  // Framework and platform consoles that ship enabled more often than anyone expects.
  'actuator',
  'actuator/env',
  'actuator/health',
  'actuator/heapdump',
  '_profiler',
  'debug',
  'debug/pprof',
  'telescope',
  'horizon',
  'graphiql',
  'playground',
  'swagger',
  'swagger-ui.html',
  'swagger/index.html',
  'api-docs',
  'v2/api-docs',
  'v3/api-docs',
  'openapi.json',
  'openapi.yaml',
  'graphql',
  'graphql/console',
  'altair',

  // API versions, where an older one usually enforces less.
  'api',
  'api/v1',
  'api/v2',
  'api/v3',
  'api/internal',
  'api/admin',
  'api/private',
  'rest',
  'v1',
  'v2',
  'internal',
  'private',

  // Status, monitoring and anything that answers with the environment.
  'server-status',
  'server-info',
  'status',
  'health',
  'healthz',
  'metrics',
  'info',
  'version',
  'phpinfo.php',
  'test.php',
  'info.php',
  'elmah.axd',
  'trace.axd',

  // Storage, uploads and logs.
  'uploads',
  'files',
  'downloads',
  'storage',
  'tmp',
  'temp',
  'logs',
  'log',
  'error.log',
  'access.log',
  'debug.log',

  // Ordinary directories worth knowing about.
  'assets',
  'static',
  'includes',
  'vendor',
  'node_modules',
  'cgi-bin',
  'scripts',
  'test',
  'tests',
  'dev',
  'staging',
  'demo',
  'docs',
];

interface FfufResult {
  input?: Record<string, string>;
  url?: string;
  status?: number;
  length?: number;
  words?: number;
  lines?: number;
  content_type?: string;
  redirectlocation?: string;
}

interface FfufOutput {
  results?: FfufResult[];
}

/**
 * Paths whose mere existence is a finding rather than inventory.
 *
 * Everything else ffuf turns up is recorded as a discovered endpoint and left for the crawl and the
 * scanners to work on. Reporting "the /assets directory exists" as a vulnerability is how a report
 * gets long and stops being read.
 */
const REPORTABLE = [
  { pattern: /^\.env|\/\.env/i, title: 'Environment file', severity: 'high', cwe: 538 },
  { pattern: /\/\.git\/|^\.git\//i, title: 'Version control directory', severity: 'high', cwe: 527 },
  { pattern: /\/\.svn\//i, title: 'Version control directory', severity: 'high', cwe: 527 },
  { pattern: /backup|dump\.sql|\.sql$|\.zip$|\.tar\.gz$|~$|\.bak$/i, title: 'Backup or archive', severity: 'high', cwe: 530 },
  { pattern: /id_rsa|\.htpasswd|credentials|secrets\.json|\.npmrc/i, title: 'Credential file', severity: 'critical', cwe: 522 },
  { pattern: /actuator|heapdump|debug\/pprof|phpinfo|_profiler|elmah\.axd|trace\.axd/i, title: 'Debug or diagnostic endpoint', severity: 'high', cwe: 489 },
  { pattern: /server-status|server-info/i, title: 'Server status page', severity: 'medium', cwe: 200 },
  { pattern: /\.map$/i, title: 'Source map', severity: 'low', cwe: 540 },
] as const;

function reportableFor(url: string): (typeof REPORTABLE)[number] | undefined {
  const { location } = splitTarget(url);
  const path = location ?? url;
  return REPORTABLE.find((entry) => entry.pattern.test(path));
}

export const ffufAdapter: ScannerAdapter = {
  id: 'ffuf',
  displayName: 'ffuf',
  modules: ['recon', 'web'],
  coversCheckIds: ['recon-content-discovery', 'web-forced-browsing', 'api-inventory-and-versioning'],

  buildInvocation: ({ policy, targets }) => {
    const bases = targets.map((target) => {
      const withScheme = target.includes('://') ? target : `https://${target}`;
      return withScheme.endsWith('/') ? withScheme : `${withScheme}/`;
    });

    return {
      command: [
        // Two wordlists in clusterbomb mode, so one run covers every target rather than needing one
        // run per host. `-u TARGETFUZZ` substitutes both keywords.
        '-w',
        '/out/paths.txt:FUZZ',
        '-w',
        '/out/targets.txt:TARGET',
        '-mode',
        'clusterbomb',
        '-u',
        'TARGETFUZZ',
        '-mc',
        '200,201,204,301,302,307,401,403',
        // A wildcard host answers 200 to everything. Filtering on the size of that answer is what
        // stops the report claiming the entire wordlist exists.
        '-ac',
        '-of',
        'json',
        '-o',
        '/out/ffuf.json',
        '-rate',
        String(Math.max(1, Math.round(policy.rateLimits.globalRequestsPerSecond))),
        '-t',
        String(policy.rateLimits.concurrency),
        '-timeout',
        '10',
        '-s',
      ],
      outputFile: 'ffuf.json',
      inputFiles: [
        { name: 'paths.txt', contents: `${WORDLIST.join('\n')}\n` },
        { name: 'targets.txt', contents: `${bases.join('\n')}\n` },
      ],
    };
  },

  parse: (raw, context: ParseContext): RawFinding[] => {
    const output = parseJsonObject<FfufOutput>(raw);
    const findings: RawFinding[] = [];

    for (const result of output?.results ?? []) {
      const url = result.url;
      const status = result.status ?? 0;
      if (url === undefined) continue;
      // 401 and 403 are matched so the inventory records that something is there, but a path that
      // refuses us is a path with a control on it, not a finding.
      if (status === 401 || status === 403) continue;

      const reportable = reportableFor(url);
      if (!reportable) continue;

      const { host, location } = splitTarget(url);
      findings.push({
        source: 'tool',
        evidenceText: recordAsEvidence(result),
        toolName: 'ffuf',
        toolFindingRef: location ?? url,
        checkId: 'recon-content-discovery',
        title: `${reportable.title} reachable at ${location ?? url}`,
        description: `${url} answered HTTP ${status} with ${result.length ?? 0} bytes. Nothing in the application links to it; it was found by asking for it directly, which means anybody can.`,
        severity: normaliseSeverity(reportable.severity),
        cvssVersion: context.cvssVersion,
        cweId: reportable.cwe,
        owaspCategory: 'A02:2025',
        wstgId: 'WSTG-CONF-04',
        affectedAssets: [{ value: host, location }],
        businessImpact: '',
        likelihood: '',
        attackerPrerequisites: 'Nothing. The path was reached without authentication.',
        reproductionSteps: [`Request ${url} and observe HTTP ${status}.`],
        remediation:
          'Remove the file from anything the web server publishes, and check how it got there — a deployment that copies a working directory into the web root will put it back. Where the path has to exist, put authorisation in front of it rather than relying on nothing linking to it.',
        references: [
          {
            title: 'OWASP WSTG: Review Old Backup and Unreferenced Files for Sensitive Information',
            url: 'https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information',
          },
        ],
        evidence: [],
      });
    }

    return findings;
  },

  /** Everything found, reportable or not. The crawl and the scanners work from this. */
  parseAssets: (raw): DiscoveredAsset[] => {
    const output = parseJsonObject<FfufOutput>(raw);
    const assets: DiscoveredAsset[] = [];

    for (const result of output?.results ?? []) {
      const url = result.url;
      if (url === undefined) continue;
      const { host, port } = splitTarget(url);
      if (host === '') continue;

      assets.push({
        kind: 'endpoint',
        value: url,
        host,
        port,
        metadata: {
          method: 'GET',
          status: result.status ?? 0,
          contentLength: result.length ?? 0,
          // A path that refuses us is still worth replaying as another identity: that is exactly
          // the question the access control matrix exists to ask.
          replayable: true,
          foundBy: 'content-discovery',
        },
      });
    }

    return assets;
  },
};
