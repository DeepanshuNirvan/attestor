import { secretRegistry, redactText, type Logger } from '@attestor/shared';
import type { Policy } from '@attestor/policy';
import { checkScope, type EngagementScopeContext, type ScopeDecision } from '../scope/scope-guard.ts';
import type { AuditLog } from '../audit/audit-log.ts';
import { toolImageById, type ToolImage } from './tool-images.ts';
import type { ContainerRunner, ContainerRunResult } from './container-runner.ts';

/**
 * The choke point.
 *
 * Nothing in this platform starts a tool except through this function. It checks scope for every
 * target the tool will be given, records the decision, and only then hands over to the container
 * runner. There is no second path, no bypass flag, and no "internal" variant.
 *
 * Two properties are worth stating plainly, because they are what the whole design rests on:
 *
 *   1. If any target fails the scope check, the whole run is refused. Not filtered — refused. A
 *      partially-scoped run is how a target ends up tested by accident.
 *   2. A dry run performs every check and sends no packet. It exists so a tester can see exactly
 *      what would happen before it happens, and it is the recommended first action on any new
 *      engagement.
 */

export interface ToolRunRequest {
  engagementId: string;
  scanRunId: string;
  toolId: string;
  /** Targets the tool will contact. Every one is checked. */
  targets: string[];
  /** Arguments after the target substitution the adapter performs. */
  command: string[];
  /** Secrets the tool needs. Registered with the redaction filter for the life of the run. */
  secrets?: Record<string, string>;
  environment?: Record<string, string>;
  outputDirectory: string;
  readOnlyMounts?: { hostPath: string; containerPath: string }[];
  /** Cloud and network runs require the provider testing policy to have been acknowledged. */
  requiresCloudPolicyAcknowledgement?: boolean;
}

export interface ToolRunDependencies {
  scopeContext: EngagementScopeContext;
  policy: Policy;
  auditLog: AuditLog;
  logger: Logger;
  containerRunner: ContainerRunner;
  /** Digest per tool id, loaded from infra/tool-images.lock.json. */
  digests: Record<string, string>;
  actorId: string;
  now?: Date;
  resolve?: (hostname: string) => Promise<string[]>;
  /** When true, every check runs and nothing is executed. */
  dryRun?: boolean;
  /**
   * Extra Docker networks for the tool container. This exists for the integration harness, which
   * runs tools against local vulnerable targets on their own internal network. It changes what is
   * reachable, never what is authorised: scope is decided above, before anything starts.
   */
  additionalNetworks?: string[];
}

export interface ToolRunRefused {
  status: 'refused';
  rule: string;
  detail: string;
  target: string;
}

export interface ToolRunDryRun {
  status: 'dryRun';
  tool: ToolImage;
  command: string[];
  approvedTargets: { target: string; hostname: string; resolvedAddresses: string[] }[];
}

export interface ToolRunCompleted {
  status: 'completed';
  tool: ToolImage;
  result: ContainerRunResult;
  approvedTargets: { target: string; hostname: string; resolvedAddresses: string[] }[];
}

export type ToolRunOutcome = ToolRunRefused | ToolRunDryRun | ToolRunCompleted;

function networkNameFor(scanRunId: string): string {
  return `attestor-run-${scanRunId.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 40)}`;
}

export async function runToolForEngagement(
  request: ToolRunRequest,
  dependencies: ToolRunDependencies,
): Promise<ToolRunOutcome> {
  const tool = toolImageById(request.toolId);
  const logger = dependencies.logger.child({
    engagementId: request.engagementId,
    scanRunId: request.scanRunId,
    tool: tool.id,
  });

  if (request.targets.length === 0) {
    return {
      status: 'refused',
      rule: 'noTargets',
      detail: 'a tool run must name at least one target',
      target: '',
    };
  }

  const approved: ToolRunDryRun['approvedTargets'] = [];

  for (const target of request.targets) {
    const decision: ScopeDecision = await checkScope(dependencies.scopeContext, target, {
      now: dependencies.now,
      resolve: dependencies.resolve,
      requiresCloudPolicyAcknowledgement: request.requiresCloudPolicyAcknowledgement,
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
          tool: tool.id,
          target,
          rule: decision.rule,
          detail: decision.detail,
        },
      });
      logger.warn('scope guard refused a target; the whole run is refused', {
        target,
        rule: decision.rule,
        detail: decision.detail,
      });
      return { status: 'refused', rule: decision.rule, detail: decision.detail, target };
    }

    approved.push({
      target,
      hostname: decision.hostname,
      resolvedAddresses: decision.resolvedAddresses,
    });
  }

  if (dependencies.dryRun) {
    logger.info('dry run: every check passed and nothing was sent', {
      targetCount: approved.length,
    });
    return { status: 'dryRun', tool, command: request.command, approvedTargets: approved };
  }

  for (const value of Object.values(request.secrets ?? {})) secretRegistry.add(value);

  const networkName = networkNameFor(request.scanRunId);

  await dependencies.auditLog.record({
    actorId: dependencies.actorId,
    actorKind: 'system',
    action: 'tool.launched',
    subjectType: 'scanRun',
    subjectId: request.scanRunId,
    metadata: {
      engagementId: request.engagementId,
      tool: tool.id,
      image: tool.image,
      digest: dependencies.digests[tool.id],
      targets: approved.map((entry) => entry.hostname),
      resolvedAddresses: approved.flatMap((entry) => entry.resolvedAddresses),
      command: request.command,
      readOnlyMode: dependencies.policy.readOnlyMode,
    },
  });

  try {
    await dependencies.containerRunner.createRunNetwork(networkName).catch(() => undefined);

    const result = await dependencies.containerRunner.run({
      tool,
      digest: dependencies.digests[tool.id] ?? '',
      command: request.command,
      environment: { ...request.environment, ...request.secrets },
      networkName,
      outputDirectory: request.outputDirectory,
      readOnlyMounts: request.readOnlyMounts,
      labels: { engagementId: request.engagementId, scanRunId: request.scanRunId },
      additionalNetworks: dependencies.additionalNetworks,
    });

    await dependencies.auditLog.record({
      actorId: dependencies.actorId,
      actorKind: 'system',
      action: 'tool.exited',
      subjectType: 'scanRun',
      subjectId: request.scanRunId,
      metadata: {
        tool: tool.id,
        exitCode: result.exitCode,
        durationMs: result.durationMs,
        timedOut: result.timedOut,
      },
    });

    // Tool output is persisted, so it goes through the redaction filter before anyone sees it.
    return {
      status: 'completed',
      tool,
      approvedTargets: approved,
      result: {
        ...result,
        stdout: redactText(result.stdout),
        stderr: redactText(result.stderr),
      },
    };
  } finally {
    secretRegistry.clear();
    await dependencies.containerRunner.removeRunNetwork(networkName).catch(() => undefined);
  }
}
