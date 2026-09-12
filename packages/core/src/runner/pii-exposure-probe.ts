import { maskText, type MaskingRule } from '@attestor/shared';
import type { Probe } from './run-probe-for-engagement.ts';

/**
 * Personal data travelling somewhere TLS does not protect it.
 *
 * The question behind WSTG-CRYP-03, and the one clients usually ask backwards: "is the personal
 * data in our requests encrypted?" On an HTTPS site the body already is, by TLS, and encrypting it
 * again at the application layer is not something this firm reports as a finding. Asking for it
 * would mean raising a finding against almost every correctly built application.
 *
 * What TLS does not protect is the URL. A URL is written to the server's access log, to every
 * forward and reverse proxy in between, to the browser's history, and — unless a referrer policy
 * stops it — into the `Referer` header of every request the page then makes to a third party. An
 * email address in a query string is therefore in several places nobody audited, and it stays
 * there after the TLS session is long gone. That is the real exposure, and it is invisible to a
 * scanner looking for weak ciphers.
 *
 * Three things keep this probe honest:
 *
 *   1. **It sends nothing.** It reads the endpoints the crawl already discovered and examines the
 *      strings. There is no request to rate limit, nothing to abort, and it is safe in read-only
 *      mode and against production.
 *   2. **It never stores what it found.** The evidence carries the *masked* URL. Writing a client's
 *      customer's email address into evidence storage to prove their email addresses are exposed
 *      would be the same mistake the finding is about.
 *   3. **It does not guess at ciphertext.** A value that is a UUID, a hex digest or a base64 blob
 *      is not readable personal data whatever produced it, so it is skipped rather than reported.
 *      Which algorithm made it is neither knowable nor interesting: what matters is that a person
 *      reading the log learns nothing from it.
 *
 * Detection reuses `maskText`, so the patterns are the ones already used to mask evidence — email,
 * Indian mobile, international phone, PAN, Aadhaar behind a Verhoeff check, payment card behind a
 * Luhn check, IFSC. One list, so a pattern added for masking is a pattern found here too.
 */

export interface PiiExposureOptions {
  /** Endpoints the crawl discovered, already narrowed to this run's targets by the caller. */
  endpoints: string[];
  /** Extra patterns from the engagement policy, in the shape `maskText` already takes. */
  extraRules?: MaskingRule[];
}

export interface PiiExposureObservation {
  /** Masked. The raw URL is never carried out of this function. */
  maskedUrl: string;
  /** Where in the URL it appeared. Both are logged; a path segment is no safer than a query. */
  location: 'query' | 'path';
  /** Query parameter names that carried it. Empty for a path match. */
  parameterNames: string[];
  /** Masking rule ids that fired, so a tester can see what was matched and judge it. */
  ruleIds: string[];
}

export interface PiiExposureResult {
  observations: PiiExposureObservation[];
  endpointsExamined: number;
  /** Set when the probe could not do its work. The worker records the run as aborted, not done. */
  skipped?: string;
}

/**
 * Is this value opaque to somebody reading a log?
 *
 * A UUID, a hex digest and a base64 blob all fail to tell a reader anything about a person. This is
 * deliberately not an attempt to identify an encryption scheme — that is not decidable from a
 * string, and it does not matter. The question is only whether a human reading the access log
 * learns a fact about a customer.
 */
export function looksOpaque(value: string): boolean {
  if (value.length < 8) return false;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return true;
  if (/^[0-9a-f]{32,}$/i.test(value)) return true;
  // Base64 or base64url of at least 16 bytes, which is long enough not to be a readable word.
  if (/^[A-Za-z0-9+/_-]{24,}={0,2}$/.test(value) && !/^[A-Za-z]+$/.test(value)) return true;
  return false;
}

function rulesFiredOn(value: string, extraRules?: MaskingRule[]): string[] {
  if (looksOpaque(value)) return [];
  return maskText(value, extraRules ? { extraRules } : {}).applied;
}

function maskUrl(url: string, extraRules?: MaskingRule[]): string {
  return maskText(url, extraRules ? { extraRules } : {}).text;
}

export function piiExposureProbe(options: PiiExposureOptions): Probe<PiiExposureResult> {
  return {
    id: 'piiExposureProbe',
    run: () => {
      if (options.endpoints.length === 0) {
        return Promise.resolve({
          observations: [],
          endpointsExamined: 0,
          skipped:
            'No endpoint was available to examine. This probe reads what the crawl discovered, so ' +
            'it has nothing to look at until a recon or web run has completed for these targets.',
        });
      }

      const observations: PiiExposureObservation[] = [];

      for (const endpoint of options.endpoints) {
        let parsed: URL;
        try {
          parsed = new URL(endpoint);
        } catch {
          // Not a URL. The crawl writes these rows, so a malformed one is its problem, not a
          // finding about the client.
          continue;
        }

        const queryRules = new Set<string>();
        const parameterNames: string[] = [];
        for (const [name, value] of parsed.searchParams) {
          const fired = rulesFiredOn(value, options.extraRules);
          if (fired.length === 0) continue;
          parameterNames.push(name);
          for (const rule of fired) queryRules.add(rule);
        }

        if (queryRules.size > 0) {
          observations.push({
            maskedUrl: maskUrl(endpoint, options.extraRules),
            location: 'query',
            parameterNames,
            ruleIds: [...queryRules].sort(),
          });
        }

        // A path segment is examined separately: `/users/alice@example.com/orders` exposes exactly
        // as much as `?email=` does, and reporting them as one finding would hide which it was.
        const pathRules = new Set<string>();
        for (const segment of parsed.pathname.split('/')) {
          if (segment === '') continue;
          for (const rule of rulesFiredOn(decodeURIComponent(segment), options.extraRules)) {
            pathRules.add(rule);
          }
        }

        if (pathRules.size > 0) {
          observations.push({
            maskedUrl: maskUrl(endpoint, options.extraRules),
            location: 'path',
            parameterNames: [],
            ruleIds: [...pathRules].sort(),
          });
        }
      }

      return Promise.resolve({
        observations,
        endpointsExamined: options.endpoints.length,
      });
    },
  };
}
