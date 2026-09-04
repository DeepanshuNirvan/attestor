import type { Check } from './types.ts';

export const reconChecks: Check[] = [
  {
    id: 'recon-entry-point-mapping',
    title: 'Application entry point and execution path mapping',
    category: 'informationGathering',
    modules: ['recon', 'web'],
    description:
      'Crawl the application and record what is actually reachable: every URL, the methods it answers to, the forms and parameters that reach it, and where each was linked from. This is the map every later test is aimed at — an injection test can only reach parameters somebody found, and an access control test can only replay requests somebody recorded.',
    example:
      'A checkout step reachable directly by URL without passing through the two screens before it, found because the crawl recorded the path and nothing linked to it from the basket.',
    automation: 'automated',
    tools: ['katana', 'zap'],
    standards: {
      wstg: ['WSTG-INFO-06', 'WSTG-INFO-07'],
      asvs: ['v5.0.0-1.1.2'],
      cwe: [1059],
    },
  },
  {
    id: 'recon-webserver-metafiles',
    title: 'Webserver metafile review',
    category: 'informationGathering',
    modules: ['recon', 'web'],
    description:
      'Read the files a site publishes about itself — robots.txt, sitemap.xml, security.txt and the .well-known directory — for paths, contacts and infrastructure detail that were not meant to be advertised. Distinct from path discovery, which guesses at paths nobody published: this reads the ones the operator published on purpose and may not have reread since.',
    example:
      'A robots.txt with `Disallow: /admin-v2/` — an administrative interface nothing links to, named in a file served to anyone who asks for it.',
    automation: 'automated',
    tools: ['httpx'],
    standards: {
      wstg: ['WSTG-INFO-03'],
      owaspTop10: ['A02:2025'],
      cwe: [200],
    },
  },
  {
    id: 'recon-subdomain-enumeration',
    title: 'Subdomain and hostname enumeration',
    category: 'informationGathering',
    modules: ['recon'],
    description:
      'Build the list of hostnames that belong to the organisation, from certificate transparency logs, public DNS datasets, search engine indexes and, where the scope allows it, resolution of a wordlist.',
    example:
      'A forgotten `staging-admin.example.com` running last year\'s build with debug mode on and no WAF in front of it.',
    automation: 'automated',
    tools: ['subfinder', 'amass', 'dnsx'],
    standards: { wstg: ['WSTG-INFO-04'], owaspTop10: ['A02:2025'], cwe: [200] },
  },
  {
    id: 'recon-dns-records',
    title: 'DNS record review',
    category: 'informationGathering',
    modules: ['recon'],
    description:
      'Enumerate A, AAAA, CNAME, MX, NS, TXT and SRV records and check for records pointing at infrastructure the organisation no longer controls.',
    example:
      'A CNAME pointing at a deprovisioned cloud bucket, which anyone can claim and serve content from under the client\'s domain.',
    automation: 'automated',
    tools: ['dnsx', 'subfinder'],
    standards: { wstg: ['WSTG-INFO-04'], owaspTop10: ['A02:2025'], cwe: [350] },
  },
  {
    id: 'recon-subdomain-takeover',
    title: 'Subdomain takeover',
    category: 'informationGathering',
    modules: ['recon'],
    description:
      'Test every dangling DNS record against the fingerprints of providers that allow an unclaimed name to be registered by a third party.',
    example:
      'A dangling record on a retired documentation host that an attacker can claim and use to serve phishing pages from a domain the client\'s customers trust.',
    automation: 'automated',
    tools: ['nuclei', 'httpx'],
    standards: { wstg: ['WSTG-CONF-10'], owaspTop10: ['A02:2025'], cwe: [350] },
  },
  {
    id: 'recon-http-probing',
    title: 'HTTP service discovery and fingerprinting',
    category: 'informationGathering',
    modules: ['recon', 'web'],
    description:
      'Probe every discovered host over HTTP and HTTPS, record status, title, redirect chain, server and framework fingerprints, and identify which hosts are actually live.',
    example:
      'An internal admin panel published on a non-standard port with no authentication, discovered because it answered on 8443.',
    automation: 'automated',
    tools: ['httpx', 'whatweb'],
    standards: { wstg: ['WSTG-INFO-02', 'WSTG-INFO-08'], cwe: [200] },
  },
  {
    id: 'recon-port-service-enumeration',
    title: 'Port and service enumeration',
    category: 'infrastructure',
    modules: ['recon', 'network'],
    description:
      'Identify open TCP and UDP ports and the services behind them across the in-scope address space, using service-version detection and safe scripts only.',
    example:
      'A database port open to the internet because a security group was widened for a migration and never narrowed again.',
    automation: 'automated',
    tools: ['naabu', 'nmap'],
    standards: { wstg: ['WSTG-INFO-02'], owaspTop10: ['A02:2025'], cwe: [1327] },
  },
  {
    id: 'recon-tls-configuration',
    title: 'TLS configuration and certificate review',
    category: 'cryptography',
    modules: ['recon', 'web', 'network'],
    description:
      'Check protocol versions, cipher suites, key exchange, certificate chain, expiry, hostname coverage, OCSP stapling and support for renegotiation and compression.',
    example:
      'A wildcard certificate expiring in eleven days on the payment host, and TLS 1.0 still enabled on the same listener.',
    automation: 'automated',
    tools: ['tlsx', 'testssl'],
    standards: {
      wstg: ['WSTG-CRYP-01'],
      asvs: ['v5.0.0-12.1.1', 'v5.0.0-12.1.2'],
      owaspTop10: ['A04:2025'],
      cwe: [326, 327],
    },
  },
  {
    id: 'recon-mail-authentication',
    title: 'SPF, DKIM and DMARC review',
    category: 'configuration',
    modules: ['recon'],
    description:
      'Check that the domain publishes SPF, DKIM and DMARC records, that DMARC is at an enforcing policy, and that subdomain policy is set.',
    example:
      'DMARC published at `p=none`, so anyone can send mail as the finance team and nothing rejects it.',
    automation: 'automated',
    tools: ['dnsx'],
    standards: { owaspTop10: ['A02:2025'], cwe: [290] },
  },
  {
    id: 'recon-content-discovery',
    title: 'Content and path discovery',
    category: 'informationGathering',
    modules: ['recon', 'web'],
    description:
      'Discover paths that are not linked from the application, using historical URL datasets, archived crawls, sitemap and robots hints, and a controlled wordlist within the agreed rate limits.',
    example:
      'A `/backup/` directory containing a database dump, reachable because directory listing was left on.',
    automation: 'automated',
    tools: ['ffuf', 'katana', 'httpx'],
    standards: { wstg: ['WSTG-CONF-04', 'WSTG-INFO-05'], owaspTop10: ['A02:2025'], cwe: [548] },
  },
  {
    id: 'recon-javascript-endpoint-extraction',
    title: 'JavaScript endpoint and secret extraction',
    category: 'informationGathering',
    modules: ['recon', 'web'],
    description:
      'Parse every JavaScript bundle the application serves for API endpoints, internal hostnames, feature flags and credentials committed into the front end.',
    example:
      'A third-party analytics write key and an internal admin API base path, both readable in the production bundle.',
    automation: 'automated',
    tools: ['katana', 'nuclei', 'trufflehog'],
    standards: { wstg: ['WSTG-INFO-05'], owaspTop10: ['A02:2025'], cwe: [200, 615] },
  },
  {
    id: 'recon-cloud-storage-exposure',
    title: 'Exposed cloud storage discovery',
    category: 'cloudSpecific',
    modules: ['recon', 'cloud'],
    description:
      'Look for storage buckets and containers belonging to the organisation that permit anonymous listing or reading.',
    example:
      'A bucket holding customer-uploaded identity documents with public read enabled for a support tool that was retired.',
    automation: 'automated',
    tools: ['nuclei', 'cloudsplaining'],
    // WSTG-CONF-11 is the cloud storage test. This is it.
    standards: {
      wstg: ['WSTG-CONF-11'],
      owaspTop10: ['A01:2025', 'A02:2025'],
      cwe: [732, 200],
    },
  },
  {
    id: 'recon-virtual-host-discovery',
    title: 'Virtual host discovery',
    category: 'informationGathering',
    modules: ['recon'],
    description:
      'Test whether a single IP serves additional sites under different Host headers, which frequently exposes staging copies of production applications.',
    example:
      'The production IP also serving `uat.example.com`, which has the same data and no rate limiting.',
    automation: 'automated',
    tools: ['ffuf', 'httpx'],
    standards: { wstg: ['WSTG-CONF-04'], cwe: [200] },
  },
  {
    id: 'recon-technology-inventory',
    title: 'Technology and version inventory',
    category: 'informationGathering',
    modules: ['recon', 'web'],
    description:
      'Record the frameworks, servers, CDNs, WAFs and third-party components in use, with versions where they are disclosed, and correlate against known vulnerabilities.',
    example:
      'A reverse proxy two majors behind, with a published authentication bypass affecting the deployed version.',
    automation: 'automated',
    tools: ['whatweb', 'httpx', 'nuclei'],
    standards: {
      wstg: ['WSTG-INFO-08', 'WSTG-INFO-09'],
      owaspTop10: ['A03:2025'],
      cwe: [1104, 1035],
    },
  },
  {
    id: 'recon-exposed-version-control',
    title: 'Exposed version control and build artefacts',
    category: 'configuration',
    modules: ['recon', 'web'],
    description:
      'Check for `.git`, `.svn`, `.env`, source maps, CI configuration and build metadata served from the web root.',
    example:
      'A readable `.git` directory that allows the whole application source, including historical secrets, to be reconstructed.',
    automation: 'automated',
    tools: ['nuclei', 'ffuf'],
    standards: { wstg: ['WSTG-CONF-04'], owaspTop10: ['A02:2025'], cwe: [527, 540] },
  },
  {
    id: 'recon-public-credential-exposure',
    title: 'Credentials exposed in public sources',
    category: 'supplyChain',
    modules: ['recon', 'code'],
    description:
      'Search public code hosting, paste sites and package registries for credentials and internal material published under the organisation\'s name or domain.',
    example:
      'A cloud access key committed to a personal repository by a contractor, still active six months later.',
    automation: 'automated',
    tools: ['trufflehog', 'gitleaks'],
    standards: { owaspTop10: ['A03:2025', 'A07:2025'], cwe: [798, 200] },
  },
  {
    id: 'recon-attack-surface-change',
    title: 'Attack surface change detection',
    category: 'informationGathering',
    modules: ['recon'],
    description:
      'For retainer clients, diff each run against the last: new hostnames, new open ports, new services, certificates approaching expiry, and DNS changes.',
    example:
      'A new subdomain appearing on a Friday evening deploy, serving an unauthenticated internal tool.',
    automation: 'automated',
    tools: ['subfinder', 'httpx', 'naabu', 'tlsx'],
    standards: { owaspTop10: ['A02:2025'], cwe: [1059] },
  },

  /* Guide tests the platform holds as work a person does ------------------------------------- *
   *                                                                                             *
   * Nothing automates these, and pretending otherwise is the failure this catalogue exists to    *
   * avoid. They are here so the tester works through them and the coverage matrix records them   *
   * as manually tested, rather than leaving them absent from the report altogether.              */
  {
    id: 'recon-search-engine-discovery',
    title: 'Search engine and public source discovery',
    category: 'informationGathering',
    modules: ['recon'],
    description:
      'Search the indexed and archived web for material about the client that was never meant to be public: cached pages taken down since, documents indexed from a directory nobody protected, error pages with internal paths, and posts by staff naming systems or versions. Done by a person, from a machine that is not the client, because the queries themselves reveal what is being looked at.',
    example:
      'A cached copy of a staging login page, taken down a year ago and still indexed, naming an internal hostname that resolves.',
    automation: 'manual',
    tools: [],
    standards: { wstg: ['WSTG-INFO-01'], owaspTop10: ['A02:2025'], cwe: [200] },
  },
  {
    id: 'recon-application-architecture-mapping',
    title: 'Application architecture mapping',
    category: 'informationGathering',
    modules: ['recon', 'web'],
    description:
      'Draw what sits between the client and the application: reverse proxies, load balancers, a web application firewall, caches, an API gateway, and the trust boundary each one is meant to enforce. The map is what makes several later tests interpretable, because a header rewritten at the edge and a header honoured by the application are different facts.',
    example:
      'A cache in front of the application keyed on the path alone, which turns any header-controlled response variation into a poisoning primitive.',
    automation: 'manual',
    tools: [],
    standards: { wstg: ['WSTG-INFO-10'], owaspTop10: ['A04:2025'], cwe: [1008] },
  },
];
