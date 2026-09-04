import { secretRegistry, redactText, type Logger } from '@attestor/shared';
import type { Policy } from '@attestor/policy';
import { checkScope, type EngagementScopeContext, type ScopeDecision } from '../scope/scope-guard.ts';
import type { AuditLog } from '../audit/audit-log.ts';
import { OutboundRateLimiter, RunAborted } from './rate-limiter.ts';

/**
 * The choke point for probes that run inside this process rather than in a container.
 *
 * Some tests cannot be a container. Replaying one identity's requests as another and comparing the
 * answers needs the credentials, the session handling and the comparison logic in one place, and
 * shipping that as an image would mean handing a container the client's passwords. So it runs here.
 *
 * "Here" must not mean "outside the rules". Everything `runToolForEngagement` enforces is enforced
 * again in this function, for the same reasons and in the same order: every target scope-checked
 * before a packet moves, the whole probe refused if any target fails, the launch and the exit in the
 * audit log, secrets registered with the redaction filter for the life of the probe, and every
 * request through the outbound rate limiter that the policy configures. A second path to the network
 * that skipped any of that would make the first path decorative.
 *
 * The probe itself receives a `request` function and cannot reach the network any other way.
 */

export interface ProbeRequest {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  /** Identity this request is made as, for the audit trail and the probe's own comparisons. */
  identity: string;
  /**
   * Marks the one request that is not a test: signing in.
   *
   * Read-only mode exists to stop testing from changing a client's data, and a login is not that —
   * it is how the session that does the read-only testing is obtained. Without this carve-out an
   * engagement in read-only mode, which is the recommended setting against production, could never
   * perform an authenticated test at all: the login POST was refused and the probe aborted before
   * sending a single test request.
   *
   * Deliberately narrow. It exempts the verb check and nothing else — scope, rate limits and the
   * host allow-list all still apply, and every other request a probe makes is judged as before.
   */
  purpose?: 'authenticate';
}

export interface ProbeResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  latencyMs: number;
  /** A transport failure rather than an HTTP status. The probe decides what that means. */
  failed: boolean;
}

/** What a probe is given. It has no other way to make a request. */
export interface ProbeContext {
  policy: Policy;
  targets: string[];
  logger: Logger;
  request: (request: ProbeRequest) => Promise<ProbeResponse>;
  /** True when the engagement is read-only. A probe must not send a state-changing request then. */
  readOnly: boolean;
}

export interface Probe<T> {
  /** Matches an entry in `IN_PROCESS_TOOLS`. */
  id: string;
  run: (context: ProbeContext) => Promise<T>;
}

export interface ProbeRunRequest {
  engagementId: string;
  scanRunId: string;
  probeId: string;
  targets: string[];
  /** Secrets the probe needs. Registered with the redaction filter for the life of the run. */
  secrets?: Record<string, string>;
}

export interface ProbeRunDependencies {
  scopeContext: EngagementScopeContext;
  policy: Policy;
  auditLog: AuditLog;
  logger: Logger;
  actorId: string;
  now?: Date;
  resolve?: (hostname: string) => Promise<string[]>;
  dryRun?: boolean;
  /** Injected in tests. Defaults to `fetch`. */
  fetchImpl?: typeof fetch;
}

export type ProbeOutcome<T> =
  | { status: 'refused'; rule: string; detail: string; target: string }
  | { status: 'dryRun'; approvedTargets: string[] }
  | { status: 'aborted'; reason: string; requestCount: number }
  | { status: 'completed'; result: T; requestCount: number };

/** Verbs a probe may send when the engagement is read-only. */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * A response body large enough to compare is large enough to be worth truncating. Comparison works
 * on shape and prefix, and a multi-megabyte download from a probe that only wanted a status code is
 * a way to hurt a client's bandwidth bill for nothing.
 */
const MAX_BODY_BYTES = 512 * 1024;

export async function runProbeForEngagement<T>(
  probe: Probe<T>,
  request: ProbeRunRequest,
  dependencies: ProbeRunDependencies,
): Promise<ProbeOutcome<T>> {
  const logger = dependencies.logger.child({
    engagementId: request.engagementId,
    scanRunId: request.scanRunId,
    probe: probe.id,
  });

  if (request.targets.length === 0) {
    return { status: 'refused', rule: 'noTargets', detail: 'a probe must name at least one target', target: '' };
  }

  const approved: string[] = [];
  for (const target of request.targets) {
    const decision: ScopeDecision = await checkScope(dependencies.scopeContext, target, {
      now: dependencies.now,
      resolve: dependencies.resolve,
    });

    if (!decision.allowed) {
      await dependencies.auditLog.record({
        actorId: dependencies.actorId,
        actorKind: 'system',
        action: 'scanRun.refused',
        subjectType: 'scanRun',
        subjectId: request.scanRunId,
        metadata: {
          engagementId: request.engagementId,
          probe: probe.id,
          target,
          rule: decision.rule,
          detail: decision.detail,
        },
      });
      logger.warn('scope guard refused a target; the whole probe is refused', {
        target,
        rule: decision.rule,
      });
      return { status: 'refused', rule: decision.rule, detail: decision.detail, target };
    }

    approved.push(decision.hostname);
  }

  if (dependencies.dryRun) {
    logger.info('dry run: every check passed and nothing was sent', { targetCount: approved.length });
    return { status: 'dryRun', approvedTargets: approved };
  }

  for (const value of Object.values(request.secrets ?? {})) secretRegistry.add(value);

  await dependencies.auditLog.record({
    actorId: dependencies.actorId,
    actorKind: 'system',
    action: 'tool.launched',
    subjectType: 'scanRun',
    subjectId: request.scanRunId,
    metadata: {
      engagementId: request.engagementId,
      tool: probe.id,
      inProcess: true,
      targets: approved,
      readOnlyMode: dependencies.policy.readOnlyMode,
    },
  });

  const startedAt = Date.now();
  const fetchImpl = dependencies.fetchImpl ?? fetch;
  const allowedHosts = new Set(approved);
  let requestCount = 0;

  const limiter = new OutboundRateLimiter({ limits: dependencies.policy.rateLimits });

  const send = async (probeRequest: ProbeRequest): Promise<ProbeResponse> => {
    const method = probeRequest.method.toUpperCase();

    if (
      dependencies.policy.readOnlyMode &&
      !SAFE_METHODS.has(method) &&
      probeRequest.purpose !== 'authenticate'
    ) {
      throw new Error(
        `probe ${probe.id} tried to send ${method} while the engagement is read-only; only ${[...SAFE_METHODS].join(', ')} are permitted, plus the request that signs in`,
      );
    }

    // Re-checked per request rather than once at the start. A probe builds URLs from what the target
    // said back to it — a redirect, a link, an id in a response body — and a target that returns a
    // URL on somebody else's host would otherwise walk the probe straight out of scope.
    let hostname: string;
    try {
      hostname = new URL(probeRequest.url).hostname;
    } catch {
      throw new Error(`probe ${probe.id} produced a malformed URL`);
    }
    if (!allowedHosts.has(hostname)) {
      throw new Error(
        `probe ${probe.id} tried to reach ${hostname}, which is not one of the approved targets`,
      );
    }

    await limiter.acquire(hostname);
    const began = Date.now();
    requestCount += 1;

    try {
      const response = await fetchImpl(probeRequest.url, {
        method,
        headers: probeRequest.headers,
        body: probeRequest.body,
        redirect: 'manual',
      });

      const raw = await response.text();
      const body = raw.length > MAX_BODY_BYTES ? raw.slice(0, MAX_BODY_BYTES) : raw;
      const latencyMs = Date.now() - began;
      limiter.release({ latencyMs, status: response.status });

      const headers: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });

      return { status: response.status, headers, body, latencyMs, failed: false };
    } catch (error) {
      const latencyMs = Date.now() - began;
      if (error instanceof RunAborted) throw error;
      limiter.release({ latencyMs, status: 0, failed: true });
      logger.debug('probe request failed at the transport level', {
        url: redactText(probeRequest.url),
      });
      return { status: 0, headers: {}, body: '', latencyMs, failed: true };
    }
  };

  try {
    const result = await probe.run({
      policy: dependencies.policy,
      targets: request.targets,
      logger,
      request: send,
      readOnly: dependencies.policy.readOnlyMode,
    });

    await dependencies.auditLog.record({
      actorId: dependencies.actorId,
      actorKind: 'system',
      action: 'tool.exited',
      subjectType: 'scanRun',
      subjectId: request.scanRunId,
      metadata: {
        tool: probe.id,
        exitCode: 0,
        durationMs: Date.now() - startedAt,
        requestCount,
      },
    });

    return { status: 'completed', result, requestCount };
  } catch (error) {
    const reason = error instanceof Error ? error.message : 'unknown error';

    await dependencies.auditLog.record({
      actorId: dependencies.actorId,
      actorKind: 'system',
      action: 'tool.exited',
      subjectType: 'scanRun',
      subjectId: request.scanRunId,
      metadata: {
        tool: probe.id,
        exitCode: 1,
        durationMs: Date.now() - startedAt,
        requestCount,
        abortReason: redactText(reason),
      },
    });

    // A probe that stopped early is an aborted run, never a clean one. The coverage matrix reads
    // that as partially tested with the reason attached, which is the difference between "we looked
    // and found nothing" and "we stopped looking".
    return { status: 'aborted', reason: redactText(reason), requestCount };
  } finally {
    secretRegistry.clear();
  }
}
