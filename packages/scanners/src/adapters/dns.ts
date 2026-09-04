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
 * dnsx, for the part of a domain's DNS an attacker uses directly: whether anybody can send mail as
 * the client.
 *
 * A domain with no SPF and no DMARC can be spoofed with a mail client, and the phishing that follows
 * arrives from the client's own domain, at their own staff, passing every filter that trusts it. It
 * is a finding they can fix in an afternoon, and no web scanner will ever raise it, because it is
 * not on the web.
 *
 * `_dmarc.<domain>` is queried alongside the domain itself. The policy does not live on the apex,
 * and a check that read only the apex would report every domain on the internet as having no DMARC.
 */

interface DnsxResult {
  host?: string;
  a?: string[];
  aaaa?: string[];
  cname?: string[];
  mx?: string[];
  ns?: string[];
  txt?: string[];
  status_code?: string;
}

const SPF = /^v=spf1\b/i;
const DMARC = /^v=DMARC1\b/i;

const MAIL_REFERENCE = {
  title: 'M3AAWG: Email Authentication Best Practices',
  url: 'https://www.m3aawg.org/EmailAuthentication',
};

/** Everything these findings share, so the differences between them are the only thing written out. */
function mailFinding(
  result: DnsxResult,
  domain: string,
  context: ParseContext,
  parts: {
    ref: string;
    title: string;
    description: string;
    severity: RawFinding['severity'];
    step: string;
    remediation: string;
  },
): RawFinding {
  return {
    source: 'tool',
    evidenceText: recordAsEvidence(result),
    toolName: 'dnsx',
    toolFindingRef: parts.ref,
    checkId: 'recon-mail-authentication',
    title: parts.title,
    description: parts.description,
    severity: parts.severity,
    cvssVersion: context.cvssVersion,
    cweId: 290,
    owaspCategory: 'A07:2025',
    affectedAssets: [{ value: domain }],
    businessImpact: '',
    likelihood: '',
    attackerPrerequisites: 'A mail client.',
    reproductionSteps: [parts.step],
    remediation: parts.remediation,
    references: [MAIL_REFERENCE],
    evidence: [],
  };
}

function mailFindings(result: DnsxResult, context: ParseContext): RawFinding[] {
  const host = result.host ?? '';
  const txt = result.txt ?? [];
  if (host === '') return [];

  if (host.startsWith('_dmarc.')) {
    const domain = host.slice('_dmarc.'.length);
    const dmarc = txt.find((entry) => DMARC.test(entry));

    if (dmarc === undefined) {
      return [
        mailFinding(result, domain, context, {
          ref: `dmarc-missing:${domain}`,
          title: `${domain} publishes no DMARC policy`,
          description: `There is no DMARC record at ${host}. Without one, a receiving mail server has no instruction about what to do with a message that claims to be from ${domain} and fails authentication, and most will deliver it.`,
          severity: 'medium',
          step: `Query the TXT records of ${host} and observe that no DMARC record is returned.`,
          remediation:
            'Publish a DMARC record at _dmarc.<domain>. Start at p=none with a reporting address so you can see who is sending as you, then move to p=quarantine and p=reject once every legitimate sender passes.',
        }),
      ];
    }

    if (/\bp=none\b/i.test(dmarc)) {
      return [
        mailFinding(result, domain, context, {
          ref: `dmarc-none:${domain}`,
          title: `${domain} publishes DMARC but asks for no enforcement`,
          description: `The DMARC record at ${host} is set to p=none, which tells receiving servers to deliver a failing message anyway. That is the right place to start while you find your legitimate senders, and it stops nothing for as long as it stays there. Record: ${dmarc}`,
          severity: 'low',
          step: `Query the TXT records of ${host} and read the p= value: ${dmarc}`,
          remediation:
            'Work through the DMARC reports until every legitimate sender aligns, then move the policy to quarantine and finally to reject.',
        }),
      ];
    }

    return [];
  }

  const spf = txt.find((entry) => SPF.test(entry));

  if (spf === undefined) {
    return [
      mailFinding(result, host, context, {
        ref: `spf-missing:${host}`,
        title: `${host} publishes no SPF record`,
        description: `There is no SPF record on ${host}. Nothing states which servers may send mail as this domain, so a receiving server has no basis on which to reject a message claiming to come from it.`,
        severity: 'medium',
        step: `Query the TXT records of ${host} and observe that none begins v=spf1.`,
        remediation:
          'Publish an SPF record listing every server that sends mail as this domain, ending in -all. A domain that sends no mail should publish "v=spf1 -all", which says exactly that.',
      }),
    ];
  }

  if (/[?+]all\s*$/i.test(spf)) {
    const permissive = /\+all\s*$/i.test(spf);
    return [
      mailFinding(result, host, context, {
        ref: `spf-weak:${host}`,
        title: `The SPF record on ${host} refuses nothing`,
        description: permissive
          ? `The SPF record ends in +all, which authorises every server on the internet to send mail as this domain — the same position as having no record, stated deliberately. Record: ${spf}`
          : `The SPF record ends in ?all, which tells receiving servers to make no judgement about a message that fails. Record: ${spf}`,
        severity: 'medium',
        step: `Query the TXT records of ${host} and read the SPF record: ${spf}`,
        remediation: 'End the SPF record in -all once the list of legitimate senders is complete.',
      }),
    ];
  }

  return [];
}

export const dnsxAdapter: ScannerAdapter = {
  id: 'dnsx',
  displayName: 'dnsx',
  modules: ['recon'],
  coversCheckIds: ['recon-dns-records', 'recon-mail-authentication'],

  buildInvocation: ({ policy, targets }) => {
    // A resolver takes a name, not a URL, and two URLs on one host are one domain to ask about.
    const hosts = new Set<string>();
    for (const target of targets) {
      const { host } = splitTarget(target);
      if (host === '') continue;
      hosts.add(host);
      hosts.add(`_dmarc.${host}`);
    }

    return {
      command: [
        '-list',
        '/out/hosts.txt',
        // Without this dnsx writes only to stdout, the output file the worker reads never exists,
        // and the parser is handed an empty string — a tool that ran, answered, and told nobody.
        '-o',
        '/out/dnsx.jsonl',
        '-a',
        '-aaaa',
        '-cname',
        '-mx',
        '-ns',
        '-txt',
        '-json',
        '-resp',
        '-silent',
        // Nothing reaches a third party from inside a tool container during an engagement, version
        // checks included.
        '-disable-update-check',
        '-retry',
        '2',
        '-rate-limit',
        String(Math.max(1, Math.round(policy.rateLimits.globalRequestsPerSecond))),
      ],
      outputFile: 'dnsx.jsonl',
      inputFiles: [{ name: 'hosts.txt', contents: `${[...hosts].join('\n')}\n` }],
    };
  },

  parse: (raw, context: ParseContext): RawFinding[] =>
    parseJsonLines<DnsxResult>(raw).flatMap((result) => mailFindings(result, context)),

  parseAssets: (raw): DiscoveredAsset[] => {
    const assets: DiscoveredAsset[] = [];
    for (const result of parseJsonLines<DnsxResult>(raw)) {
      const host = result.host;
      // The DMARC name is a policy record, not a host anybody connects to.
      if (host === undefined || host === '' || host.startsWith('_dmarc.')) continue;

      for (const address of [...(result.a ?? []), ...(result.aaaa ?? [])]) {
        assets.push({ kind: 'host', value: address, host });
      }
      for (const name of result.cname ?? []) {
        if (name !== '') assets.push({ kind: 'host', value: name, host });
      }
    }
    return assets;
  },
};
