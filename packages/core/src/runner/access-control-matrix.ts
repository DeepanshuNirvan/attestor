import type { Probe, ProbeContext, ProbeResponse } from './run-probe-for-engagement.ts';

/**
 * Access control testing, by replay and comparison.
 *
 * This is the check no scanner performs, because no scanner can: deciding whether one user may see
 * another user's data needs two accounts and a definition of "another user's data". A tool given one
 * session can only ever tell you a page loaded.
 *
 * The method is the one a tester uses by hand, done exhaustively. Take a request that belonged to
 * one identity, send it again as every other identity we hold, and compare the answers. If the
 * second identity gets the first identity's data back, that is broken object level authorisation —
 * WSTG-ATHZ-02, ATHZ-03, ATHZ-04 and OWASP API1. If an unauthenticated caller gets it, worse.
 *
 * Three things keep this from producing rubbish, which matters more here than anywhere else in the
 * platform, because a false "your users can read each other's records" costs a client a weekend:
 *
 *   1. **A baseline that succeeded.** A request the owner could not perform tells us nothing about
 *      anybody else, so it is skipped and recorded as inconclusive rather than compared.
 *   2. **A public resource is not a finding.** If the anonymous identity gets the same bytes, the
 *      resource is served to the world and the comparison between two users says nothing about
 *      access control. Those are reported separately, and only as an observation.
 *   3. **Substance.** Two empty objects are identical and mean nothing. A baseline has to carry
 *      enough content to be worth comparing before any conclusion is drawn from matching it.
 *
 * Everything it emits is a candidate for triage with both responses attached, never a confirmed
 * finding. A person reads the comparison and decides.
 */

/** Calling the application to obtain a session, for a credential that is a login rather than a token. */
export interface AccessLogin {
  url: string;
  usernameField: string;
  passwordField: string;
  username: string;
  password: string;
  /** Dotted path to a token in the JSON response. Omit when the answer is a session cookie. */
  tokenPath?: string;
  tokenHeader: string;
  /** `{token}` is replaced. */
  tokenTemplate: string;
}

export interface AccessIdentity {
  /** Stable name used in evidence: `user (primary)`, `admin`, `anonymous`. */
  name: string;
  roleName: string;
  isSecondary: boolean;
  /**
   * Headers that authenticate a request as this identity — a cookie, a bearer token, an API key.
   * Deliberately opaque: this probe does not care which scheme the application uses, which is what
   * lets it work against a JWT API and a session-cookie application without knowing the difference.
   * Empty means the anonymous identity.
   */
  headers: Record<string, string>;
  /**
   * Performed once before any replay, when the credential is a username and password rather than a
   * token. An identity whose login fails or is not configured is left out of the comparison and
   * said so — never guessed at, because a wrong guess at a login form locks a client's account.
   */
  login?: AccessLogin;
}

export interface ReplayTemplate {
  method: string;
  url: string;
  /** The identity whose session this request was observed under. */
  owner: string;
  headers?: Record<string, string>;
  body?: string;
  /**
   * True when the URL came out of the owner's own responses rather than the signed-out crawl.
   *
   * It decides whether an unauthenticated caller getting the same answer is worth reporting. A page
   * the crawl found while signed out is public by definition, and reporting "anyone can read your
   * home page" for every URL on the site would bury the one row that matters.
   */
  ownerDiscovered?: boolean;
}

export interface AccessControlOptions {
  identities: AccessIdentity[];
  templates: ReplayTemplate[];
  /** From the policy. Above this, two responses are "substantially the same". */
  similarityThreshold: number;
  maxReplayRequests: number;
  testUnauthenticated: boolean;
  /** Empty means every ordered pair. Entries are `[fromRole, toRole]`. */
  rolePairs: [string, string][];
  /**
   * Replay methods other than GET and HEAD. Off by default: sending another identity's POST is how
   * a test creates an order in a client's production system.
   */
  replayStateChanging?: boolean;
}

export type AccessObservationKind =
  | 'crossUserAccess'
  | 'crossRoleAccess'
  | 'unauthenticatedAccess'
  | 'correctlyDenied'
  | 'publicResource'
  | 'inconclusive';

export interface AccessObservation {
  kind: AccessObservationKind;
  method: string;
  url: string;
  owner: string;
  actor: string;
  ownerStatus: number;
  actorStatus: number;
  similarity: number;
  /** Why this was classified as it was, in the words the report will use. */
  detail: string;
}

export interface AccessControlResult {
  observations: AccessObservation[];
  requestsSent: number;
  /** Identities that could not be established, and why. Reported, never silently dropped. */
  unavailableIdentities: { name: string; reason: string }[];
  /**
   * Set when the probe could not do its job at all. Not an error: an application with one account,
   * or no discovered requests, is a normal thing to meet, and the coverage matrix records it as
   * having nothing to test rather than as a failure.
   */
  skipped?: string;
}

/**
 * Similarity of two response bodies, between 0 and 1.
 *
 * Token overlap rather than an edit distance: two JSON documents describing different users share
 * almost every character but few of the distinctive tokens, and an edit distance calls them the
 * same. Length is folded in so a short response cannot score highly against a long one just by
 * having a common vocabulary.
 *
 * Deterministic and dependency-free on purpose — this number appears in a report, and a tester has
 * to be able to explain how it was reached.
 */
export function responseSimilarity(left: string, right: string): number {
  if (left === right) return 1;
  const tokensOf = (value: string): Set<string> =>
    new Set(
      value
        .toLowerCase()
        .split(/[^a-z0-9@._-]+/)
        .filter((token) => token.length > 1),
    );

  const a = tokensOf(left);
  const b = tokensOf(right);
  if (a.size === 0 && b.size === 0) return 1;
  if (a.size === 0 || b.size === 0) return 0;

  let shared = 0;
  for (const token of a) if (b.has(token)) shared += 1;
  const jaccard = shared / (a.size + b.size - shared);

  const longer = Math.max(left.length, right.length);
  const lengthRatio = longer === 0 ? 1 : Math.min(left.length, right.length) / longer;

  // Both must agree. A response that shares every token but is a tenth of the length is a summary
  // of the other, not a copy of it.
  return jaccard * lengthRatio;
}

/**
 * Whether a body carries enough to draw a conclusion from.
 *
 * `{}`, `[]`, `OK` and an empty 204 are identical between any two users and always will be. Treating
 * a match on one of those as evidence of anything is how an access control report fills with noise.
 */
export function bodyIsSubstantive(body: string): boolean {
  const stripped = body.replace(/\s+/g, '');
  return stripped.length >= 48;
}

function pairAllowed(pairs: [string, string][], from: string, to: string): boolean {
  if (pairs.length === 0) return true;
  return pairs.some(([a, b]) => a === from && b === to);
}

/** Reads `authentication.token` out of a parsed JSON body. Returns undefined for any miss. */
export function valueAtPath(body: unknown, path: string): string | undefined {
  let current: unknown = body;
  for (const key of path.split('.')) {
    if (typeof current !== 'object' || current === null) return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return typeof current === 'string' && current !== '' ? current : undefined;
}

/**
 * Turn a login response into the headers that carry the session.
 *
 * Two shapes, which between them cover most applications: a token somewhere in a JSON body, and a
 * `Set-Cookie`. Both are taken when both are present, because an application that issues a cookie
 * *and* expects a bearer header will refuse anything less.
 */
export function sessionHeadersFrom(
  response: { status: number; headers: Record<string, string>; body: string },
  login: AccessLogin,
): Record<string, string> | { error: string } {
  if (response.status < 200 || response.status >= 300) {
    return { error: `the login endpoint answered ${response.status || 'nothing'}` };
  }

  const headers: Record<string, string> = {};

  const setCookie = response.headers['set-cookie'];
  if (setCookie !== undefined && setCookie !== '') {
    // Name=value pairs only. Attributes such as Path and HttpOnly are instructions to a browser and
    // are not sent back on a request.
    const cookies = setCookie
      .split(/,(?=[^;=]+=)/)
      .map((entry) => entry.split(';')[0]?.trim())
      .filter((entry): entry is string => entry !== undefined && entry.includes('='));
    if (cookies.length > 0) headers.cookie = cookies.join('; ');
  }

  if (login.tokenPath !== undefined) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(response.body);
    } catch {
      return { error: 'the login response was not JSON, so the token could not be read from it' };
    }
    const token = valueAtPath(parsed, login.tokenPath);
    if (token === undefined) {
      return { error: `the login response carried nothing at "${login.tokenPath}"` };
    }
    headers[login.tokenHeader.toLowerCase()] = login.tokenTemplate.replace('{token}', token);
  }

  // Last resort: some APIs hand the token back in a response header rather than in the body or a
  // cookie. Tried only when neither of the usual two produced anything, so it can add a session
  // where there would otherwise be none and can never override a configured one.
  if (Object.keys(headers).length === 0) {
    for (const name of ['authorization', 'x-auth-token', 'x-access-token', 'x-session-token']) {
      const value = response.headers[name];
      if (value === undefined || value === '') continue;
      headers[name] = value;
      break;
    }
  }

  if (Object.keys(headers).length === 0) {
    return {
      error:
        'the login succeeded but returned no session to present — no cookie, nothing at the configured token path, and no token header',
    };
  }
  return headers;
}

/**
 * URLs belonging to the identity that fetched them.
 *
 * The crawl runs signed out, so it finds the pages anyone can see and never `/basket/6`. Object
 * URLs like that live in what the application says to the account that owns them — its own basket
 * id, its own order numbers — so one pass of reading the owner's responses is what turns a public
 * site map into something worth replaying. One level deep and hard-bounded: this is a targeted read,
 * not a second crawler.
 */
export function sameHostUrlsIn(body: string, base: string, limit = 25): string[] {
  let origin: string;
  try {
    origin = new URL(base).origin;
  } catch {
    return [];
  }

  const found = new Set<string>();
  const candidates = [
    ...[...body.matchAll(/"((?:https?:)?\/[^"\s]{1,300})"/g)].map((match) => match[1]),
    ...[...body.matchAll(/href="([^"]{1,300})"/g)].map((match) => match[1]),
  ];

  for (const candidate of candidates) {
    if (candidate === undefined) continue;
    let resolved: URL;
    try {
      resolved = new URL(candidate, origin);
    } catch {
      continue;
    }
    if (resolved.origin !== origin) continue;
    // A URL with no digit in it is a page, not an object. Object references are what this pass is
    // for, and taking everything else would fill the replay budget with the same site map the crawl
    // already produced.
    if (!/[0-9]/.test(resolved.pathname + resolved.search)) continue;
    found.add(resolved.toString());
    if (found.size >= limit) break;
  }

  return [...found];
}

const REPLAYABLE_BY_DEFAULT = new Set(['GET', 'HEAD']);

/**
 * How many crawled pages are read back as the owner to find its object URLs. Small on purpose:
 * every seed costs a request, and the pages that name a user's own records are the first few — the
 * account page, the dashboard, the basket. Twenty is enough to find them and cheap enough that a
 * client never notices.
 */
const DISCOVERY_SEEDS = 20;

export function accessControlMatrixProbe(options: AccessControlOptions): Probe<AccessControlResult> {
  return {
    id: 'accessControlMatrix',
    run: async (context: ProbeContext): Promise<AccessControlResult> => {
      const anonymous: AccessIdentity = {
        name: 'anonymous',
        roleName: 'anonymous',
        isSecondary: false,
        headers: {},
      };

      const observations: AccessObservation[] = [];
      const unavailableIdentities: { name: string; reason: string }[] = [];
      let requestsSent = 0;

      // Sign in anything that needs to. An identity that cannot be established is set aside with a
      // reason rather than dropped, so a run that compared fewer accounts than the tester expected
      // says which ones were missing and why.
      const identities: AccessIdentity[] = [];
      for (const identity of options.identities) {
        if (identity.login === undefined) {
          identities.push(identity);
          continue;
        }

        requestsSent += 1;
        const response = await context.request({
          method: 'POST',
          url: identity.login.url,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            [identity.login.usernameField]: identity.login.username,
            [identity.login.passwordField]: identity.login.password,
          }),
          identity: identity.name,
          purpose: 'authenticate',
        });

        const resolved = sessionHeadersFrom(response, identity.login);
        if ('error' in resolved) {
          unavailableIdentities.push({ name: identity.name, reason: resolved.error });
          continue;
        }
        identities.push({ ...identity, headers: { ...identity.headers, ...resolved } });
      }

      if (options.testUnauthenticated && !identities.some((entry) => entry.name === 'anonymous')) {
        identities.push(anonymous);
      }

      // Two ways to have nothing to do, both of them ordinary. Neither is an error, and neither
      // produces a finding: an application with one test account cannot be tested for whether one
      // user can reach another's data, and saying so is the honest outcome.
      const authenticated = identities.filter((identity) => Object.keys(identity.headers).length > 0);
      if (authenticated.length < 2) {
        return {
          observations: [],
          requestsSent,
          unavailableIdentities,
          skipped:
            'Access control comparison needs at least two accounts with a working session. This run ' +
            `established ${authenticated.length}. Ask the client for a second account for each role ` +
            'you intend to test, and check that each role has a way to sign in.',
        };
      }

      const owner = authenticated[0]!;
      const crawled = options.templates.filter(
        (template) =>
          REPLAYABLE_BY_DEFAULT.has(template.method.toUpperCase()) ||
          (options.replayStateChanging === true && !context.readOnly),
      );

      // The crawl ran signed out, so it found pages and not objects. One pass over what the owner
      // itself is told — its own basket, its own orders — is what produces the per-account URLs that
      // make the comparison mean anything.
      const discovered: ReplayTemplate[] = [];
      const seen = new Set(crawled.map((template) => template.url));
      for (const template of crawled.slice(0, DISCOVERY_SEEDS)) {
        if (requestsSent >= options.maxReplayRequests) break;
        requestsSent += 1;
        const response = await context.request({
          method: 'GET',
          url: template.url,
          headers: owner.headers,
          identity: owner.name,
        });
        if (response.failed || response.status < 200 || response.status >= 300) continue;

        for (const url of sameHostUrlsIn(response.body, template.url)) {
          if (seen.has(url)) continue;
          seen.add(url);
          discovered.push({ method: 'GET', url, owner: owner.name, ownerDiscovered: true });
        }
      }

      const replayable = [...crawled, ...discovered];
      if (replayable.length === 0) {
        return {
          observations: [],
          requestsSent,
          unavailableIdentities,
          skipped:
            'No replayable requests were discovered for this target. Access control testing replays ' +
            'requests seen during the crawl; a target where the crawl found none has nothing to replay.',
        };
      }

      const send = async (
        template: ReplayTemplate,
        identity: AccessIdentity,
      ): Promise<ProbeResponse> => {
        requestsSent += 1;
        return context.request({
          method: template.method,
          url: template.url,
          headers: { ...template.headers, ...identity.headers },
          body: template.body,
          identity: identity.name,
        });
      };

      for (const template of replayable) {
        if (requestsSent >= options.maxReplayRequests) {
          context.logger.warn('replay budget reached; stopping', {
            maxReplayRequests: options.maxReplayRequests,
          });
          break;
        }

        const owner = identities.find((identity) => identity.name === template.owner);
        if (!owner) continue;

        const baseline = await send(template, owner);

        // A request its own owner could not perform proves nothing about anybody else.
        if (baseline.failed || baseline.status < 200 || baseline.status >= 300) {
          observations.push({
            kind: 'inconclusive',
            method: template.method,
            url: template.url,
            owner: owner.name,
            actor: owner.name,
            ownerStatus: baseline.status,
            actorStatus: baseline.status,
            similarity: 1,
            detail: `The owning account itself received ${baseline.status || 'no response'} for this request, so there was no successful response to compare against.`,
          });
          continue;
        }

        const substantive = bodyIsSubstantive(baseline.body);

        // The public check first, and once per template. If the world can read this, a match between
        // two named users says nothing about access control between them, and reporting it as though
        // it did would be the single easiest way to put a false finding in front of a client.
        let publicResource = false;
        if (options.testUnauthenticated) {
          const anonymousResponse = await send(template, anonymous);
          const anonymousSimilarity = responseSimilarity(baseline.body, anonymousResponse.body);
          const anonymousMatched =
            !anonymousResponse.failed &&
            anonymousResponse.status >= 200 &&
            anonymousResponse.status < 300 &&
            anonymousSimilarity >= options.similarityThreshold;

          if (anonymousMatched && substantive) {
            publicResource = true;
            observations.push({
              // The owner sent credentials and the anonymous caller got the same answer back. That
              // is only news for a URL found in the owner's own responses: the crawl found the rest
              // while signed out, so anonymous access to those is what public means, and reporting
              // it for every page on the site would bury the one row that matters.
              kind: template.ownerDiscovered === true ? 'unauthenticatedAccess' : 'publicResource',
              method: template.method,
              url: template.url,
              owner: owner.name,
              actor: 'anonymous',
              ownerStatus: baseline.status,
              actorStatus: anonymousResponse.status,
              similarity: anonymousSimilarity,
              detail:
                'An unauthenticated request returned substantially the same response as the signed-in account. Either this resource is intended to be public, or it is served without checking who is asking.',
            });
          } else if (anonymousMatched) {
            // Matched, but on a body with nothing in it. The control was not shown to work and was
            // not shown to fail — recording this as "correctly denied" would put a green tick
            // against an endpoint nobody actually tested.
            observations.push({
              kind: 'inconclusive',
              method: template.method,
              url: template.url,
              owner: owner.name,
              actor: 'anonymous',
              ownerStatus: baseline.status,
              actorStatus: anonymousResponse.status,
              similarity: anonymousSimilarity,
              detail:
                'The signed-in and unauthenticated responses were the same, but carried too little content to tell whether anything protected was returned. Worth a look by hand.',
            });
          } else {
            observations.push({
              kind: 'correctlyDenied',
              method: template.method,
              url: template.url,
              owner: owner.name,
              actor: 'anonymous',
              ownerStatus: baseline.status,
              actorStatus: anonymousResponse.status,
              similarity: anonymousSimilarity,
              detail: `An unauthenticated request received ${anonymousResponse.status || 'no response'} rather than the owner's content.`,
            });
          }
        }

        for (const actor of identities) {
          if (actor.name === owner.name || actor.name === 'anonymous') continue;
          if (!pairAllowed(options.rolePairs, owner.roleName, actor.roleName)) continue;
          if (requestsSent >= options.maxReplayRequests) break;

          const response = await send(template, actor);
          const similarity = responseSimilarity(baseline.body, response.body);
          const succeeded = !response.failed && response.status >= 200 && response.status < 300;
          const matched = succeeded && similarity >= options.similarityThreshold;

          if (!succeeded) {
            observations.push({
              kind: 'correctlyDenied',
              method: template.method,
              url: template.url,
              owner: owner.name,
              actor: actor.name,
              ownerStatus: baseline.status,
              actorStatus: response.status,
              similarity,
              detail: `${actor.name} received ${response.status || 'no response'} where ${owner.name} received ${baseline.status}.`,
            });
            continue;
          }

          if (!matched || !substantive || publicResource) {
            observations.push({
              // A match on a body with no substance is not the control working. It is nobody having
              // learned anything, and it says so rather than claiming a pass.
              kind: publicResource ? 'publicResource' : !substantive ? 'inconclusive' : 'correctlyDenied',
              method: template.method,
              url: template.url,
              owner: owner.name,
              actor: actor.name,
              ownerStatus: baseline.status,
              actorStatus: response.status,
              similarity,
              detail: publicResource
                ? 'This resource is served to unauthenticated callers as well, so a match between two accounts is not evidence about access control.'
                : !substantive
                  ? 'The response carries too little content for a match to mean anything — an empty or near-empty body is identical for every caller.'
                  : `${actor.name} received a different response (${Math.round(similarity * 100)}% similar), which is what a per-account resource looks like.`,
            });
            continue;
          }

          const sameRole = owner.roleName === actor.roleName;
          observations.push({
            kind: sameRole ? 'crossUserAccess' : 'crossRoleAccess',
            method: template.method,
            url: template.url,
            owner: owner.name,
            actor: actor.name,
            ownerStatus: baseline.status,
            actorStatus: response.status,
            similarity,
            detail: sameRole
              ? `${actor.name} received substantially the same response as ${owner.name} (${Math.round(similarity * 100)}% similar) for a resource that is not public. One account is reading another account's data.`
              : `${actor.name} holds the ${actor.roleName} role and received substantially the same response as ${owner.name}, who holds ${owner.roleName} (${Math.round(similarity * 100)}% similar). The endpoint does not appear to check the caller's role.`,
          });
        }
      }

      return { observations, requestsSent, unavailableIdentities };
    },
  };
}
