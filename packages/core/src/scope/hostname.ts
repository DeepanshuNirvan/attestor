import { domainToASCII } from 'node:url';

/**
 * Hostname normalisation and wildcard matching.
 *
 * This is the function that decides whether `*.example.com` covers the thing about to be scanned.
 * Every failure here is a criminal exposure, so matching is label-wise and never a string suffix
 * comparison: `notexample.com` ends with `example.com` as a string and must not match, and
 * `example.com.attacker.net` starts with it and must not match either.
 */

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * What a hostname may contain, checked before IDN conversion: unicode letters and digits, plus
 * hyphen and full stop. Everything else is rejected, because domainToASCII silently drops some
 * characters and would turn "exam ple.com" into "example.com".
 */
const ALLOWED_HOST_CHARACTERS = /^[\p{L}\p{N}.-]+$/u;

/**
 * Normalise to lowercase punycode with no trailing dot. Returns null for anything that is not a
 * hostname, including inputs with control characters, spaces, credentials or empty labels — all of
 * which have been used to slip past naive matchers.
 */
export function normaliseHostname(input: string): string | null {
  if (typeof input !== 'string') return null;
  const trimmed = input.trim();
  if (trimmed === '' || trimmed.length > 253) return null;
  if (!ALLOWED_HOST_CHARACTERS.test(trimmed)) return null;

  const withoutTrailingDot = trimmed.endsWith('.') ? trimmed.slice(0, -1) : trimmed;
  if (withoutTrailingDot === '') return null;

  const ascii = domainToASCII(withoutTrailingDot).toLowerCase();
  if (ascii === '') return null;

  const labels = ascii.split('.');
  for (const label of labels) {
    if (!LABEL.test(label)) return null;
  }

  return ascii;
}

export function hostLabels(hostname: string): string[] {
  return hostname.split('.');
}

/**
 * Does `candidate` fall under `pattern`?
 *
 *   `example.com`    — exactly that host, nothing else
 *   `*.example.com`  — any subdomain at any depth, but NOT the apex
 *
 * A leading `*.` is the only wildcard form accepted. `*example.com`, `ex*.com` and a bare `*` are
 * rejected, because each has a plausible-looking reading that is wrong.
 */
export function hostnameMatches(pattern: string, candidate: string): boolean {
  const normalisedCandidate = normaliseHostname(candidate);
  if (!normalisedCandidate) return false;

  const trimmedPattern = pattern.trim().toLowerCase();

  if (!trimmedPattern.startsWith('*')) {
    const exact = normaliseHostname(trimmedPattern);
    return exact !== null && exact === normalisedCandidate;
  }

  if (!trimmedPattern.startsWith('*.')) return false;

  const base = normaliseHostname(trimmedPattern.slice(2));
  if (!base) return false;

  const candidateLabels = hostLabels(normalisedCandidate);
  const baseLabels = hostLabels(base);

  // Must be strictly deeper than the base: an apex is not covered by its own wildcard.
  if (candidateLabels.length <= baseLabels.length) return false;

  const offset = candidateLabels.length - baseLabels.length;
  for (let index = 0; index < baseLabels.length; index += 1) {
    if (candidateLabels[offset + index] !== baseLabels[index]) return false;
  }
  return true;
}

/** Validates a scope pattern at entry time, so a typo is caught before an engagement runs. */
export function isValidHostnamePattern(pattern: string): boolean {
  const trimmed = pattern.trim().toLowerCase();
  if (trimmed.startsWith('*.')) return normaliseHostname(trimmed.slice(2)) !== null;
  if (trimmed.includes('*')) return false;
  return normaliseHostname(trimmed) !== null;
}

/**
 * Schemes the platform will speak. A `file:` or `gopher:` target in a scope item is a mistake or an
 * attack, not a website.
 */
const ALLOWED_SCHEMES = new Set(['http:', 'https:', 'ws:', 'wss:']);

export interface ParsedTarget {
  hostname: string;
  port: number | null;
  scheme: string;
  url: URL;
}

/**
 * Extract the host from a target string for scope checking. Returns null rather than throwing.
 * Credentials embedded in the URL are rejected outright: they are how a target gets pointed
 * somewhere other than where it appears to point.
 */
export function parseTargetUrl(input: string): ParsedTarget | null {
  let url: URL;
  try {
    url = new URL(input.includes('://') ? input : `https://${input}`);
  } catch {
    return null;
  }
  if (!ALLOWED_SCHEMES.has(url.protocol)) return null;
  if (url.username !== '' || url.password !== '') return null;

  // A bracketed IPv6 literal arrives with brackets attached; strip them for comparison.
  const raw = url.hostname.startsWith('[') ? url.hostname.slice(1, -1) : url.hostname;
  const hostname = normaliseHostname(raw) ?? raw.toLowerCase();
  if (hostname === '') return null;

  return {
    hostname,
    port: url.port === '' ? null : Number(url.port),
    scheme: url.protocol,
    url,
  };
}
