import type { Probe, ProbeContext } from './run-probe-for-engagement.ts';

/**
 * Does anything actually stop a caller repeating a request?
 *
 * The question behind WSTG-ATHN-03, WSTG-BUSL-05 and API4: a login nobody throttles is a password
 * guessed overnight, and a one-time-code endpoint nobody throttles is a bill the client pays per
 * message. No scanner answers it, because answering it means deliberately repeating a request and
 * watching for the answer to change — which a scanner will not do on its own and should not.
 *
 * Two rules keep this from being the denial-of-service test the platform refuses to perform:
 *
 *   1. **A small, fixed burst.** Thirty requests by default and never more than the policy allows.
 *      Enough to see a limit that exists; nothing like enough to be a load test. The platform's own
 *      outbound rate limiter still applies, so the burst is paced.
 *   2. **Never a real account.** A login is probed with an address that cannot exist, so a lockout
 *      counter that does fire belongs to nobody. Testing a client's brute-force protection by
 *      locking out a real user is how a test becomes an incident.
 *
 * A limit that appears is reported as the control working. A limit that does not appear within the
 * burst is reported as exactly that — "no throttling within 30 requests" — and never as "no rate
 * limiting", which is a claim thirty requests cannot support.
 */

export interface RateLimitTarget {
  url: string;
  method: 'GET' | 'POST';
  /** What the endpoint does, in the words the finding will use. */
  description: string;
  /** Sent as a JSON body on a POST. Must not name a real account. */
  body?: Record<string, string>;
}

export interface RateLimitOptions {
  targets: RateLimitTarget[];
  burst: number;
}

export interface RateLimitObservation {
  url: string;
  method: string;
  description: string;
  requestsSent: number;
  /** Request number at which the answer changed to a throttling one. Null if it never did. */
  throttledAfter: number | null;
  /** The status that signalled throttling, for the evidence. */
  throttleStatus: number | null;
  /** Set when the endpoint could not be probed at all, with why. */
  skipped?: string;
}

export interface RateLimitResult {
  observations: RateLimitObservation[];
  requestsSent: number;
  skipped?: string;
}

/** Answers that mean "you are going too fast". 503 is included because some gateways shed that way. */
const THROTTLE_STATUSES = new Set([429, 503]);

export function isThrottleResponse(status: number, headers: Record<string, string>): boolean {
  if (THROTTLE_STATUSES.has(status)) return true;
  // A `Retry-After` on any status is the server saying the same thing in words.
  return headers['retry-after'] !== undefined;
}

export function rateLimitProbe(options: RateLimitOptions): Probe<RateLimitResult> {
  return {
    id: 'rateLimitProbe',
    run: async (context: ProbeContext): Promise<RateLimitResult> => {
      if (options.targets.length === 0) {
        return {
          observations: [],
          requestsSent: 0,
          skipped:
            'No endpoint was named to measure throttling on. Which endpoint matters is a judgement ' +
            'about the business rather than something to discover, so it is named in the policy — ' +
            'set checks.rateLimitEndpoints, or give the auth profile an apiLogin block.',
        };
      }

      const observations: RateLimitObservation[] = [];
      let requestsSent = 0;

      for (const target of options.targets) {
        if (context.readOnly && target.method !== 'GET') {
          observations.push({
            url: target.url,
            method: target.method,
            description: target.description,
            requestsSent: 0,
            throttledAfter: null,
            throttleStatus: null,
            skipped:
              'This endpoint needs a state-changing request to probe, and the engagement is ' +
              'read-only. Re-run without read-only mode, on an environment where that is agreed.',
          });
          continue;
        }

        let throttledAfter: number | null = null;
        let throttleStatus: number | null = null;
        let sentHere = 0;
        let transportFailed = false;

        for (let attempt = 1; attempt <= options.burst; attempt += 1) {
          const response = await context.request({
            method: target.method,
            url: target.url,
            headers: target.body ? { 'content-type': 'application/json' } : undefined,
            body: target.body ? JSON.stringify(target.body) : undefined,
            identity: 'rate-limit-probe',
          });
          requestsSent += 1;
          sentHere += 1;

          // A transport failure is not a rate limit. It might be the target falling over, which is
          // the platform's own adaptive brake's business, not a finding about throttling.
          if (response.failed) {
            transportFailed = true;
            break;
          }

          if (isThrottleResponse(response.status, response.headers)) {
            throttledAfter = attempt;
            throttleStatus = response.status;
            break;
          }
        }

        observations.push({
          url: target.url,
          method: target.method,
          description: target.description,
          requestsSent: sentHere,
          throttledAfter,
          throttleStatus,
          // A burst that ended because the endpoint stopped answering measured nothing. Reported as
          // an unfinished measurement rather than as an absence of throttling: the first version
          // wrote "no throttling within 1 requests" against a connection that had been refused,
          // which is a finding about a request nobody answered.
          ...(transportFailed && throttledAfter === null
            ? {
                skipped:
                  `The endpoint stopped answering after ${sentHere} request(s), so throttling was ` +
                  'not measured. Nothing can be concluded either way until it is reachable for the ' +
                  'whole burst.',
              }
            : {}),
        });
      }

      return { observations, requestsSent };
    },
  };
}
