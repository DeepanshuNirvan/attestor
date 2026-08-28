import type { EngagementState, ScopeItemKind } from '@attestor/shared';
import { hostnameMatches, isValidHostnamePattern, normaliseHostname, parseTargetUrl } from './hostname.ts';
import { cidrContains, forbiddenIpReason, isIpAddress, parseCidr, parseIp, type Cidr } from './ip.ts';
import { NEVER_TOUCH_CIDRS, NEVER_TOUCH_HOSTS } from './never-touch-list.ts';

/**
 * The scope guard.
 *
 * Every tool run passes through here first. It answers one question — may this exact target be
 * touched right now, under this engagement — and it answers it with a typed decision rather than a
 * boolean, so a caller cannot accidentally treat a refusal as a warning.
 *
 * The order of the checks is deliberate. Cheap structural checks come first so a malformed target
 * never reaches DNS resolution, and the never-touch list is evaluated before the client's own scope
 * so no authorisation can override it.
 */

export const REFUSAL_RULES = [
  'panicStopActive',
  'unparseableTarget',
  'neverTouchHost',
  'neverTouchAddress',
  'forbiddenAddress',
  'noAuthorisation',
  'authorisationUnsigned',
  'authorisationRevoked',
  'authorisationNotYetValid',
  'authorisationExpired',
  'engagementStateForbidsExecution',
  'outsideTestWindow',
  'targetExplicitlyExcluded',
  'targetNotInScope',
  'resolvedAddressNotInScope',
  'dnsResolutionFailed',
  'thirdPartyInfrastructureUnacknowledged',
  'cloudTestingPolicyUnacknowledged',
] as const;

export type RefusalRule = (typeof REFUSAL_RULES)[number];

export interface ScopeAllowed {
  allowed: true;
  /** The normalised host the run will actually contact. */
  hostname: string;
  port: number | null;
  /** Addresses the hostname resolved to, each of which was checked. Empty for a literal address. */
  resolvedAddresses: string[];
  /** Which scope item authorised it, for the audit log. */
  matchedScopeItemId: string;
}

export interface ScopeRefused {
  allowed: false;
  rule: RefusalRule;
  /** Written for a human reading an audit log entry a year later. */
  detail: string;
  hostname: string | null;
}

export type ScopeDecision = ScopeAllowed | ScopeRefused;

export interface ScopeItem {
  id: string;
  kind: ScopeItemKind;
  value: string;
  included: boolean;
}

export interface Authorisation {
  id: string;
  signedAt: Date | null;
  revokedAt: Date | null;
  validFrom: Date;
  validUntil: Date;
}

export interface TestWindow {
  /** 0 = Sunday, matching Date#getUTCDay. */
  daysOfWeek: number[];
  /** Minutes from midnight in the engagement timezone. */
  startMinute: number;
  endMinute: number;
}

export interface EngagementScopeContext {
  engagementId: string;
  state: EngagementState;
  authorisation: Authorisation | null;
  scopeItems: ScopeItem[];
  /** Windows from the resolved policy. An empty list means no window restriction. */
  testWindows: TestWindow[];
  /** IANA timezone the windows are expressed in. */
  timezone: string;
  /** Private ranges the client owns and has authorised, for an internal engagement. */
  ownedPrivateRanges: string[];
  /** Set when the tester acknowledged that a scope item sits on shared or third-party hosting. */
  thirdPartyInfrastructureAcknowledged: boolean;
  /** Set when the tester acknowledged the provider's testing policy, required before cloud runs. */
  cloudTestingPolicyAcknowledged: boolean;
  /** True while a panic stop is in force for this engagement or platform-wide. */
  panicStopActive: boolean;
}

/** States in which a tool may execute. Everything else refuses. */
const EXECUTABLE_STATES = new Set<EngagementState>([
  'running',
  'triage',
  'manualTesting',
  'retestPending',
]);

export interface ScopeCheckOptions {
  /** Injected so tests are deterministic and so the check uses one instant throughout. */
  now?: Date;
  /** Injected so tests never touch a resolver. Returns the addresses a hostname resolves to. */
  resolve?: (hostname: string) => Promise<string[]>;
  /**
   * Set when the target is a cloud provider run. Cloud runs additionally require the provider's
   * testing policy to have been acknowledged.
   */
  requiresCloudPolicyAcknowledgement?: boolean;
}

function refuse(rule: RefusalRule, detail: string, hostname: string | null = null): ScopeRefused {
  return { allowed: false, rule, detail, hostname };
}

function parseOwnedRanges(values: readonly string[]): Cidr[] {
  const ranges: Cidr[] = [];
  for (const value of values) {
    const parsed = parseCidr(value);
    if (parsed) ranges.push(parsed);
  }
  return ranges;
}

/** Minutes since midnight in the given IANA timezone, plus the weekday there. */
export function localTimeParts(instant: Date, timezone: string): { minute: number; weekday: number } {
  const formatter = new Intl.DateTimeFormat('en-GB', {
    timeZone: timezone,
    hour: '2-digit',
    minute: '2-digit',
    weekday: 'short',
    hour12: false,
  });
  const parts = formatter.formatToParts(instant);
  const hour = Number(parts.find((part) => part.type === 'hour')?.value ?? '0');
  const minute = Number(parts.find((part) => part.type === 'minute')?.value ?? '0');
  const weekdayName = parts.find((part) => part.type === 'weekday')?.value ?? 'Sun';
  const weekdays = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  return { minute: hour * 60 + minute, weekday: Math.max(0, weekdays.indexOf(weekdayName)) };
}

export function isInsideTestWindow(
  windows: readonly TestWindow[],
  instant: Date,
  timezone: string,
): boolean {
  if (windows.length === 0) return true;
  const { minute, weekday } = localTimeParts(instant, timezone);
  return windows.some(
    (window) =>
      window.daysOfWeek.includes(weekday) &&
      minute >= window.startMinute &&
      minute < window.endMinute,
  );
}

function neverTouchHostReason(hostname: string): string | null {
  for (const entry of NEVER_TOUCH_HOSTS) {
    if (hostnameMatches(entry.pattern, hostname)) return `${entry.pattern}: ${entry.reason}`;
  }
  return null;
}

function neverTouchAddressReason(address: string): string | null {
  const parsed = parseIp(address);
  if (!parsed) return null;
  for (const entry of NEVER_TOUCH_CIDRS) {
    const cidr = parseCidr(entry.pattern);
    if (cidr && cidrContains(cidr, parsed)) return `${entry.pattern}: ${entry.reason}`;
  }
  return null;
}

/** Does a scope item cover this host or address? */
function scopeItemCovers(item: ScopeItem, hostname: string): boolean {
  switch (item.kind) {
    case 'domain':
      return hostnameMatches(item.value, hostname);
    case 'wildcard':
      return hostnameMatches(
        item.value.startsWith('*.') ? item.value : `*.${item.value}`,
        hostname,
      );
    case 'url': {
      const parsed = parseTargetUrl(item.value);
      return parsed !== null && parsed.hostname === hostname;
    }
    case 'ip': {
      if (!isIpAddress(hostname)) return false;
      const target = parseIp(hostname);
      const authorised = parseIp(item.value);
      return (
        target !== null &&
        authorised !== null &&
        target.version === authorised.version &&
        target.value === authorised.value
      );
    }
    case 'cidr': {
      const target = parseIp(hostname);
      const cidr = parseCidr(item.value);
      return target !== null && cidr !== null && cidrContains(cidr, target);
    }
    case 'llmEndpoint': {
      const parsed = parseTargetUrl(item.value);
      return parsed !== null && parsed.hostname === hostname;
    }
    default:
      // repo, cloudAccount and mobilePackage are not network targets and never authorise a host.
      return false;
  }
}

function addressCoveredByScope(items: readonly ScopeItem[], address: string): boolean {
  const parsed = parseIp(address);
  if (!parsed) return false;
  return items.some((item) => {
    if (!item.included) return false;
    if (item.kind === 'ip') {
      const value = parseIp(item.value);
      return value !== null && value.version === parsed.version && value.value === parsed.value;
    }
    if (item.kind === 'cidr') {
      const cidr = parseCidr(item.value);
      return cidr !== null && cidrContains(cidr, parsed);
    }
    return false;
  });
}

async function defaultResolve(hostname: string): Promise<string[]> {
  const { lookup } = await import('node:dns/promises');
  const records = await lookup(hostname, { all: true, verbatim: true });
  return records.map((record) => record.address);
}

/**
 * The single decision function. Every caller that is about to touch a target calls this and acts on
 * the result; there is no variant that skips a check.
 */
export async function checkScope(
  context: EngagementScopeContext,
  target: string,
  options: ScopeCheckOptions = {},
): Promise<ScopeDecision> {
  const now = options.now ?? new Date();
  const resolve = options.resolve ?? defaultResolve;

  if (context.panicStopActive) {
    return refuse('panicStopActive', 'A panic stop is in force. No target may be contacted.');
  }

  const parsed = parseTargetUrl(target);
  if (!parsed) {
    return refuse(
      'unparseableTarget',
      `"${target}" is not a target this platform will contact. Only http, https, ws and wss hosts without embedded credentials are accepted.`,
    );
  }
  const { hostname } = parsed;

  const neverTouch = neverTouchHostReason(hostname);
  if (neverTouch) {
    return refuse(
      'neverTouchHost',
      `${hostname} is on the global never-touch list. ${neverTouch} No client authorisation can override this.`,
      hostname,
    );
  }

  const ownedRanges = parseOwnedRanges(context.ownedPrivateRanges);

  // A literal address target is checked directly; a hostname is checked after resolution.
  if (isIpAddress(hostname)) {
    const blockedRange = neverTouchAddressReason(hostname);
    if (blockedRange) {
      return refuse('neverTouchAddress', `${hostname} is on the never-touch list. ${blockedRange}`, hostname);
    }
    const forbidden = forbiddenIpReason(hostname, ownedRanges);
    if (forbidden) {
      return refuse('forbiddenAddress', forbidden.detail, hostname);
    }
  }

  const { authorisation } = context;
  if (!authorisation) {
    return refuse(
      'noAuthorisation',
      `Engagement ${context.engagementId} has no authorisation record. Testing without signed, scoped authorisation is a criminal offence.`,
      hostname,
    );
  }
  if (!authorisation.signedAt) {
    return refuse('authorisationUnsigned', `Authorisation ${authorisation.id} has not been signed.`, hostname);
  }
  if (authorisation.revokedAt && authorisation.revokedAt <= now) {
    return refuse(
      'authorisationRevoked',
      `Authorisation ${authorisation.id} was revoked at ${authorisation.revokedAt.toISOString()}.`,
      hostname,
    );
  }
  if (now < authorisation.validFrom) {
    return refuse(
      'authorisationNotYetValid',
      `Authorisation ${authorisation.id} is valid from ${authorisation.validFrom.toISOString()}; it is now ${now.toISOString()}.`,
      hostname,
    );
  }
  if (now >= authorisation.validUntil) {
    return refuse(
      'authorisationExpired',
      `Authorisation ${authorisation.id} expired at ${authorisation.validUntil.toISOString()}.`,
      hostname,
    );
  }

  if (!EXECUTABLE_STATES.has(context.state)) {
    return refuse(
      'engagementStateForbidsExecution',
      `Engagement is in state "${context.state}". Execution is only permitted in: ${[...EXECUTABLE_STATES].join(', ')}.`,
      hostname,
    );
  }

  if (!isInsideTestWindow(context.testWindows, now, context.timezone)) {
    return refuse(
      'outsideTestWindow',
      `It is outside the agreed test window for this engagement (${context.timezone}).`,
      hostname,
    );
  }

  const excluded = context.scopeItems.find((item) => !item.included && scopeItemCovers(item, hostname));
  if (excluded) {
    return refuse(
      'targetExplicitlyExcluded',
      `${hostname} matches the exclusion "${excluded.value}" (scope item ${excluded.id}).`,
      hostname,
    );
  }

  const included = context.scopeItems.find((item) => item.included && scopeItemCovers(item, hostname));
  if (!included) {
    return refuse(
      'targetNotInScope',
      `${hostname} does not match any included scope item for engagement ${context.engagementId}.`,
      hostname,
    );
  }

  if (options.requiresCloudPolicyAcknowledgement && !context.cloudTestingPolicyAcknowledged) {
    return refuse(
      'cloudTestingPolicyUnacknowledged',
      'The cloud provider testing policy has not been acknowledged for this engagement.',
      hostname,
    );
  }

  // A hostname in scope can still resolve to infrastructure nobody authorised. This is the check
  // that separates a lawful engagement from an unlawful one, and it is why resolution happens here
  // rather than inside the tool.
  if (isIpAddress(hostname)) {
    return {
      allowed: true,
      hostname,
      port: parsed.port,
      resolvedAddresses: [],
      matchedScopeItemId: included.id,
    };
  }

  let addresses: string[];
  try {
    addresses = await resolve(hostname);
  } catch (error) {
    return refuse(
      'dnsResolutionFailed',
      `${hostname} could not be resolved: ${error instanceof Error ? error.message : 'unknown error'}.`,
      hostname,
    );
  }

  if (addresses.length === 0) {
    return refuse('dnsResolutionFailed', `${hostname} resolved to no addresses.`, hostname);
  }

  for (const address of addresses) {
    const blockedRange = neverTouchAddressReason(address);
    if (blockedRange) {
      return refuse(
        'neverTouchAddress',
        `${hostname} resolves to ${address}, which is on the never-touch list. ${blockedRange}`,
        hostname,
      );
    }

    const forbidden = forbiddenIpReason(address, ownedRanges);
    if (forbidden) {
      return refuse(
        'forbiddenAddress',
        `${hostname} resolves to ${address}: ${forbidden.detail}.`,
        hostname,
      );
    }

    // When the engagement lists addresses or ranges explicitly, every resolved address must be
    // inside them. Where scope is expressed only by hostname there is nothing to compare against,
    // and the third-party acknowledgement below is what covers shared hosting.
    const hasAddressScope = context.scopeItems.some(
      (item) => item.included && (item.kind === 'ip' || item.kind === 'cidr'),
    );
    if (hasAddressScope && !addressCoveredByScope(context.scopeItems, address)) {
      return refuse(
        'resolvedAddressNotInScope',
        `${hostname} resolves to ${address}, which is not covered by any authorised address or range. The name may point at infrastructure the client does not own.`,
        hostname,
      );
    }
  }

  if (addresses.length > 1 && !context.thirdPartyInfrastructureAcknowledged) {
    // More than one address usually means a CDN or shared hosting. That is not a refusal on its
    // own, but it must be acknowledged once by a human, because the client's authorisation may not
    // cover the provider.
    return refuse(
      'thirdPartyInfrastructureUnacknowledged',
      `${hostname} resolves to ${addresses.length} addresses (${addresses.join(', ')}), which suggests shared or third-party infrastructure. A tester must acknowledge that the client's authorisation covers it before this target can be contacted.`,
      hostname,
    );
  }

  return {
    allowed: true,
    hostname,
    port: parsed.port,
    resolvedAddresses: addresses,
    matchedScopeItemId: included.id,
  };
}

/**
 * Validate scope items when they are entered, so a typo is a form error rather than a refusal on
 * the morning of the test.
 */
export function validateScopeItem(item: Pick<ScopeItem, 'kind' | 'value'>): string | null {
  const value = item.value.trim();
  if (value === '') return 'value is empty';

  switch (item.kind) {
    case 'domain':
      return normaliseHostname(value) ? null : `"${value}" is not a valid hostname`;
    case 'wildcard':
      return isValidHostnamePattern(value.startsWith('*.') ? value : `*.${value}`)
        ? null
        : `"${value}" is not a valid wildcard pattern`;
    case 'ip':
      return isIpAddress(value) ? null : `"${value}" is not a valid IP address`;
    case 'cidr':
      return parseCidr(value) ? null : `"${value}" is not a valid CIDR range`;
    case 'url':
    case 'llmEndpoint':
      return parseTargetUrl(value) ? null : `"${value}" is not a valid http(s) URL`;
    case 'repo':
      return /^[\w.@:/-]+$/.test(value) ? null : `"${value}" is not a valid repository reference`;
    case 'cloudAccount':
      return /^[\w-]{4,64}$/.test(value) ? null : `"${value}" is not a valid cloud account identifier`;
    case 'mobilePackage':
      return /^[A-Za-z][\w]*(\.[A-Za-z][\w]*)+$/.test(value)
        ? null
        : `"${value}" is not a valid application identifier`;
    default:
      return `unknown scope item kind`;
  }
}
