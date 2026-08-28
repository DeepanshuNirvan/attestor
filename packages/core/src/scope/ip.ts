import { isIP } from 'node:net';

/**
 * IP address handling for the scope guard.
 *
 * Everything here is written to fail closed: an address that cannot be parsed is not "probably
 * fine", it is out of scope. The ranges below are the ones that turn an authorised engagement into
 * an unauthorised one — loopback, link-local, cloud metadata, and anything on the operator's own
 * network that the client does not own.
 */

export type IpVersion = 4 | 6;

export interface ParsedIp {
  version: IpVersion;
  /** Numeric value, as a bigint for both families so one comparison path covers both. */
  value: bigint;
}

const IPV4_BITS = 32n;
const IPV6_BITS = 128n;

export function parseIp(input: string): ParsedIp | null {
  const trimmed = input.trim();
  const family = isIP(trimmed);
  if (family === 4) return { version: 4, value: ipv4ToBigInt(trimmed) };
  if (family === 6) return { version: 6, value: ipv6ToBigInt(trimmed) };
  return null;
}

function ipv4ToBigInt(address: string): bigint {
  const octets = address.split('.');
  let value = 0n;
  for (const octet of octets) {
    value = (value << 8n) | BigInt(Number(octet));
  }
  return value;
}

function ipv6ToBigInt(address: string): bigint {
  // An IPv4-mapped tail (::ffff:203.0.113.1) is legal and common in dual-stack logs.
  let working = address;
  const lastColon = working.lastIndexOf(':');
  const tail = working.slice(lastColon + 1);
  if (tail.includes('.')) {
    const mapped = ipv4ToBigInt(tail);
    const high = Number((mapped >> 16n) & 0xffffn).toString(16);
    const low = Number(mapped & 0xffffn).toString(16);
    working = `${working.slice(0, lastColon + 1)}${high}:${low}`;
  }

  const [head = '', rest] = working.split('::');
  const headGroups = head === '' ? [] : head.split(':');
  const tailGroups = rest === undefined || rest === '' ? [] : rest.split(':');
  const missing = 8 - headGroups.length - tailGroups.length;
  const groups = [
    ...headGroups,
    ...Array.from({ length: rest === undefined ? 0 : missing }, () => '0'),
    ...tailGroups,
  ];

  let value = 0n;
  for (const group of groups) {
    value = (value << 16n) | BigInt(parseInt(group === '' ? '0' : group, 16));
  }
  return value;
}

export interface Cidr {
  version: IpVersion;
  network: bigint;
  prefix: number;
  mask: bigint;
  source: string;
}

export function parseCidr(input: string): Cidr | null {
  const trimmed = input.trim();
  const slash = trimmed.lastIndexOf('/');
  if (slash === -1) {
    const single = parseIp(trimmed);
    if (!single) return null;
    const bits = single.version === 4 ? IPV4_BITS : IPV6_BITS;
    return {
      version: single.version,
      network: single.value,
      prefix: Number(bits),
      mask: (1n << bits) - 1n,
      source: trimmed,
    };
  }

  const address = trimmed.slice(0, slash);
  const prefixText = trimmed.slice(slash + 1);
  const parsed = parseIp(address);
  if (!parsed) return null;
  if (!/^\d{1,3}$/.test(prefixText)) return null;

  const prefix = Number(prefixText);
  const bits = parsed.version === 4 ? IPV4_BITS : IPV6_BITS;
  if (prefix < 0 || BigInt(prefix) > bits) return null;

  const mask = prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << (bits - BigInt(prefix));
  return {
    version: parsed.version,
    network: parsed.value & mask,
    prefix,
    mask,
    source: trimmed,
  };
}

export function cidrContains(cidr: Cidr, ip: ParsedIp): boolean {
  if (cidr.version !== ip.version) return false;
  return (ip.value & cidr.mask) === cidr.network;
}

/**
 * Ranges the platform refuses to target regardless of what a scope item says. These are not
 * "unusual", they are the ranges where a mistake means testing infrastructure nobody authorised:
 * the operator's own network, the container host, the cloud metadata service.
 */
const ALWAYS_FORBIDDEN_CIDRS = [
  // IPv4
  '0.0.0.0/8', // "this network"
  '10.0.0.0/8', // RFC1918
  '100.64.0.0/10', // carrier-grade NAT, which is somebody else's customers
  '127.0.0.0/8', // loopback
  '169.254.0.0/16', // link-local, and the cloud metadata service lives here
  '172.16.0.0/12', // RFC1918
  '192.0.0.0/24', // IETF protocol assignments
  '192.0.2.0/24', // TEST-NET-1
  '192.168.0.0/16', // RFC1918
  '198.18.0.0/15', // benchmarking
  '198.51.100.0/24', // TEST-NET-2
  '203.0.113.0/24', // TEST-NET-3
  '224.0.0.0/4', // multicast
  '240.0.0.0/4', // reserved, includes broadcast
  // IPv6
  '::/128', // unspecified
  '::1/128', // loopback
  '64:ff9b::/96', // NAT64
  '100::/64', // discard-only
  '2001:db8::/32', // documentation
  'fc00::/7', // unique local
  'fe80::/10', // link-local
  'ff00::/8', // multicast
].map((entry) => {
  const parsed = parseCidr(entry);
  if (!parsed) throw new Error(`bad built-in CIDR: ${entry}`);
  return parsed;
});

/**
 * Cloud instance metadata endpoints. They are inside link-local already, but they are listed
 * separately so a refusal names the actual reason rather than "link-local range".
 */
export const METADATA_ENDPOINTS = new Set([
  '169.254.169.254', // AWS, Azure, GCP, DigitalOcean, Oracle
  '169.254.170.2', // AWS ECS task metadata
  '169.254.169.253', // AWS DNS
  '100.100.100.200', // Alibaba Cloud
  'fd00:ec2::254', // AWS IMDS over IPv6
]);

export interface ForbiddenIpReason {
  reason: string;
  detail: string;
}

/**
 * Returns why an address is forbidden, or null when it is not. `ownedPrivateRanges` lets a client
 * authorise their own internal ranges for an internal engagement — that is a deliberate, signed
 * decision recorded on the authorisation, not a default.
 */
export function forbiddenIpReason(
  address: string,
  ownedPrivateRanges: readonly Cidr[] = [],
): ForbiddenIpReason | null {
  const parsed = parseIp(address);
  if (!parsed) {
    return { reason: 'unparseableAddress', detail: `"${address}" is not a valid IP address` };
  }

  const normalised = address.trim().toLowerCase();
  if (METADATA_ENDPOINTS.has(normalised)) {
    return {
      reason: 'cloudMetadataEndpoint',
      detail: `${address} is a cloud instance metadata endpoint and is never a valid target`,
    };
  }

  // An IPv4-mapped IPv6 address must be judged on the IPv4 it carries, or ::ffff:127.0.0.1 walks
  // straight past every IPv4 rule above.
  if (parsed.version === 6) {
    const mappedPrefix = parseCidr('::ffff:0:0/96');
    if (mappedPrefix && cidrContains(mappedPrefix, parsed)) {
      const embedded = parsed.value & 0xffffffffn;
      const dotted = [24n, 16n, 8n, 0n].map((shift) => Number((embedded >> shift) & 0xffn)).join('.');
      const nested = forbiddenIpReason(dotted, ownedPrivateRanges);
      if (nested) {
        return {
          reason: nested.reason,
          detail: `${address} maps to ${dotted}: ${nested.detail}`,
        };
      }
    }
  }

  for (const range of ownedPrivateRanges) {
    if (cidrContains(range, parsed)) return null;
  }

  for (const range of ALWAYS_FORBIDDEN_CIDRS) {
    if (cidrContains(range, parsed)) {
      return {
        reason: 'reservedOrPrivateRange',
        detail: `${address} is inside ${range.source}, which is not authorised for this engagement`,
      };
    }
  }

  return null;
}

export function isIpAddress(value: string): boolean {
  return isIP(value.trim()) !== 0;
}
