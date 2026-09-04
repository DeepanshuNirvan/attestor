import type { Probe, ProbeContext, ProbeRequest } from './run-probe-for-engagement.ts';

/**
 * Three questions a scanner does not answer, because answering them means sending a request that is
 * deliberately wrong and comparing what comes back.
 *
 *   - **Which methods does this endpoint accept, and does the answer depend on the method?**
 *     WSTG-CONF-06 and WSTG-INPV-03. A resource guarded by `<Limit GET POST>` answers 403 to GET and
 *     200 to HEAD, and the guard is decoration. ZAP's release rules do not test this.
 *   - **What does the application do with a parameter sent twice?** WSTG-INPV-04. The rule that
 *     matters is which of the two values the application acts on, because a filter in front of it
 *     usually reads the other one. ZAP ships this only in its beta rules, which we do not run.
 *   - **Does the application build links out of a header the client controls?** WSTG-INPV-17. A
 *     password-reset mail whose link points wherever the requester asked is a full account takeover,
 *     and there is no ZAP rule for it at all.
 *
 * Everything here is a GET, a HEAD or an OPTIONS. Nothing is sent that could change the client's
 * data, so the whole probe runs unchanged in read-only mode — which is the configuration recommended
 * against production, and the one where an authorisation bypass matters most.
 *
 * The host-header test uses a name under `.invalid`, which RFC 2606 reserves and no resolver will
 * ever answer. If the application does build a link from it and mails that link to somebody, the
 * link goes nowhere: the finding is proved without creating a destination anyone could receive.
 */

/** Reserved by RFC 2606. Never resolves, so a reflected value cannot become a live destination. */
const MARKER_HOST = 'attestor-probe.invalid';

/** Methods worth reporting as accepted. Sending them is another matter; see `advertisedMethods`. */
const NOTABLE_METHODS = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT'];

export interface RequestManipulationOptions {
  /** Absolute URLs to examine. Bounded by the caller; the probe bounds it again. */
  urls: string[];
  /** Most URLs to examine. Each costs at most five requests. */
  maxUrls: number;
}

export interface MethodObservation {
  url: string;
  /** What OPTIONS said the endpoint allows, verbatim. Empty when it said nothing. */
  advertised: string[];
  /** Of `advertised`, the ones that write or echo. These are reported, never sent. */
  notable: string[];
  /** Status for GET, HEAD and OPTIONS. The comparison is the point, not the individual values. */
  statuses: Record<string, number>;
  /** Set when a method reached a resource that GET was refused. */
  verbBypass?: { restrictedWith: string; allowedWith: string; restrictedStatus: number };
}

export interface ParameterPollutionObservation {
  url: string;
  parameter: string;
  /** Which single-value response the duplicated request resembled: 'first', 'last' or 'neither'. */
  resolvedAs: 'first' | 'last' | 'neither';
  status: number;
}

export interface HostHeaderObservation {
  url: string;
  /** The header whose value came back. Absent when nothing did. */
  reflectedVia?: string;
  /** Where it came back: a redirect target is worse than a mention in the body. */
  reflectedIn?: 'location' | 'body';
}

export interface RequestManipulationResult {
  methods: MethodObservation[];
  pollution: ParameterPollutionObservation[];
  hostHeader: HostHeaderObservation[];
  skipped?: string;
}

/** The methods an `Allow` or `Access-Control-Allow-Methods` header named, normalised. */
export function advertisedMethods(headers: Record<string, string>): string[] {
  const raw = headers['allow'] ?? headers['access-control-allow-methods'] ?? '';
  return raw
    .split(',')
    .map((method) => method.trim().toUpperCase())
    .filter((method) => method !== '');
}

/**
 * Whether two responses are the same answer to different questions.
 *
 * Length alone is too crude — a page that echoes the parameter differs by the length of the value —
 * and a full diff is more than the decision needs. Status plus a normalised prefix is what separates
 * "the application used this value" from "the application used the other one".
 */
export function sameAnswer(
  a: { status: number; body: string },
  b: { status: number; body: string },
): boolean {
  if (a.status !== b.status) return false;
  return a.body.slice(0, 2048) === b.body.slice(0, 2048);
}

function withParameter(url: URL, name: string, values: string[]): string {
  const next = new URL(url.toString());
  next.searchParams.delete(name);
  for (const value of values) next.searchParams.append(name, value);
  return next.toString();
}

export function requestManipulationProbe(
  options: RequestManipulationOptions,
): Probe<RequestManipulationResult> {
  return {
    id: 'requestManipulationProbe',
    run: async (context: ProbeContext): Promise<RequestManipulationResult> => {
      const urls = options.urls.slice(0, Math.max(0, options.maxUrls));

      if (urls.length === 0) {
        return {
          methods: [],
          pollution: [],
          hostHeader: [],
          skipped:
            'No URL was available to examine. This probe reads the endpoints a crawl recorded, so ' +
            'run the recon or web module first, or name a target explicitly.',
        };
      }

      const methods: MethodObservation[] = [];
      const pollution: ParameterPollutionObservation[] = [];
      const hostHeader: HostHeaderObservation[] = [];

      const send = (request: Omit<ProbeRequest, 'identity'>): ReturnType<ProbeContext['request']> =>
        context.request({ ...request, identity: 'request-manipulation-probe' });

      for (const raw of urls) {
        let url: URL;
        try {
          url = new URL(raw);
        } catch {
          continue;
        }

        // 1. Which methods, and does the answer depend on which one is used.
        const get = await send({ method: 'GET', url: url.toString() });
        const head = await send({ method: 'HEAD', url: url.toString() });
        const optionsResponse = await send({ method: 'OPTIONS', url: url.toString() });

        if (!get.failed) {
          const advertised = advertisedMethods(optionsResponse.headers);
          const observation: MethodObservation = {
            url: url.toString(),
            advertised,
            notable: advertised.filter((method) => NOTABLE_METHODS.includes(method)),
            statuses: { GET: get.status, HEAD: head.status, OPTIONS: optionsResponse.status },
          };

          // A resource that refuses GET and serves HEAD is guarded by method rather than by
          // identity. The reverse is ordinary — plenty of endpoints simply do not implement HEAD.
          const refused = get.status === 401 || get.status === 403;
          if (refused && !head.failed && head.status >= 200 && head.status < 300) {
            observation.verbBypass = {
              restrictedWith: 'GET',
              allowedWith: 'HEAD',
              restrictedStatus: get.status,
            };
          }

          methods.push(observation);
        }

        // 2. What the application does with a parameter it was given twice.
        const [firstParameter] = [...url.searchParams.keys()];
        if (firstParameter !== undefined && !get.failed) {
          const a = 'attestor1';
          const b = 'attestor2';
          const responseA = await send({ method: 'GET', url: withParameter(url, firstParameter, [a]) });
          const responseB = await send({ method: 'GET', url: withParameter(url, firstParameter, [b]) });
          const both = await send({
            method: 'GET',
            url: withParameter(url, firstParameter, [a, b]),
          });

          if (!responseA.failed && !responseB.failed && !both.failed) {
            const resolvedAs = sameAnswer(both, responseA)
              ? 'first'
              : sameAnswer(both, responseB)
                ? 'last'
                : 'neither';
            pollution.push({
              url: url.toString(),
              parameter: firstParameter,
              resolvedAs,
              status: both.status,
            });
          }
        }

        // 3. Whether a client-controlled host header ends up in what the application builds.
        //
        // `X-Forwarded-Host` rather than `Host`: the runtime forbids setting `Host` on a fetch, and
        // a reverse proxy in front of most applications rewrites it anyway. The forwarded header is
        // the one that actually reaches application code and the one frameworks read.
        const forwarded = await send({
          method: 'GET',
          url: url.toString(),
          headers: { 'x-forwarded-host': MARKER_HOST },
        });

        if (!forwarded.failed) {
          const location = forwarded.headers['location'] ?? '';
          if (location.includes(MARKER_HOST)) {
            hostHeader.push({
              url: url.toString(),
              reflectedVia: 'x-forwarded-host',
              reflectedIn: 'location',
            });
          } else if (forwarded.body.includes(MARKER_HOST)) {
            hostHeader.push({
              url: url.toString(),
              reflectedVia: 'x-forwarded-host',
              reflectedIn: 'body',
            });
          } else {
            hostHeader.push({ url: url.toString() });
          }
        }
      }

      return { methods, pollution, hostHeader };
    },
  };
}
