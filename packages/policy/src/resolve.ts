import { parse as parseYaml } from 'yaml';
import { policySchema, RATE_CEILINGS, type Policy } from './schema.ts';

/**
 * Policy resolution.
 *
 * Layers, lowest priority first: global defaults, client override, engagement override, single-run
 * override from the console. Each layer is a partial policy and merges into the one below it.
 *
 * Merge semantics are deliberately boring: objects merge key by key, arrays replace rather than
 * concatenate. Concatenating arrays would make it impossible for an engagement to narrow a client's
 * module list, which is the thing an override is usually for.
 */

export type PolicyLayerName = 'global' | 'client' | 'engagement' | 'run';

export interface PolicyLayer {
  name: PolicyLayerName;
  /** The YAML as written, kept so the console can show a diff and the report can cite a snapshot. */
  yamlSource: string;
}

export class PolicyError extends Error {
  readonly layer: PolicyLayerName;

  constructor(message: string, layer: PolicyLayerName) {
    super(message);
    this.name = 'PolicyError';
    this.layer = layer;
  }
}

type PlainObject = Record<string, unknown>;

function isPlainObject(value: unknown): value is PlainObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function mergePolicyFragments(base: PlainObject, override: PlainObject): PlainObject {
  const out: PlainObject = { ...base };
  for (const [key, value] of Object.entries(override)) {
    if (value === undefined) continue;
    const existing = out[key];
    out[key] = isPlainObject(existing) && isPlainObject(value)
      ? mergePolicyFragments(existing, value)
      : value;
  }
  return out;
}

function parseLayer(layer: PolicyLayer): PlainObject {
  if (layer.yamlSource.trim() === '') return {};
  let parsed: unknown;
  try {
    parsed = parseYaml(layer.yamlSource);
  } catch (error) {
    throw new PolicyError(
      `${layer.name} policy is not valid YAML: ${error instanceof Error ? error.message : 'unknown error'}`,
      layer.name,
    );
  }
  if (parsed === null || parsed === undefined) return {};
  if (!isPlainObject(parsed)) {
    throw new PolicyError(`${layer.name} policy must be a mapping at the top level`, layer.name);
  }
  return parsed;
}

export interface ResolvedPolicy {
  policy: Policy;
  /** The merged YAML-equivalent object, stored on the scan run for defensibility. */
  snapshot: PlainObject;
  /** Warnings that do not stop the run but that a tester should see. */
  warnings: string[];
}

export function resolvePolicy(layers: PolicyLayer[]): ResolvedPolicy {
  let merged: PlainObject = {};
  for (const layer of layers) {
    merged = mergePolicyFragments(merged, parseLayer(layer));
  }

  const parsed = policySchema.safeParse(merged);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('; ');
    const lastLayer = layers[layers.length - 1]?.name ?? 'global';
    throw new PolicyError(`policy failed validation: ${issues}`, lastLayer);
  }

  const policy = applyCeilings(parsed.data);
  return { policy, snapshot: merged, warnings: warningsFor(policy) };
}

/**
 * The ceilings are applied after validation as well as during it. The schema rejects a value above
 * the ceiling outright; this clamp exists so `politeMode` and any future derived value can never
 * push an effective rate above it either.
 */
export function applyCeilings(policy: Policy): Policy {
  const factor = policy.rateLimits.politeMode ? 0.5 : 1;
  return {
    ...policy,
    rateLimits: {
      ...policy.rateLimits,
      globalRequestsPerSecond: Math.min(
        RATE_CEILINGS.globalRequestsPerSecond,
        policy.rateLimits.globalRequestsPerSecond * factor,
      ),
      perTargetRequestsPerSecond: Math.min(
        RATE_CEILINGS.perTargetRequestsPerSecond,
        policy.rateLimits.perTargetRequestsPerSecond * factor,
      ),
      concurrency: Math.max(
        1,
        Math.min(RATE_CEILINGS.concurrency, Math.floor(policy.rateLimits.concurrency * factor)),
      ),
    },
  };
}

function warningsFor(policy: Policy): string[] {
  const warnings: string[] = [];

  if (policy.modules.includes('llm')) {
    const { budget } = policy.llm;
    if (budget.maxSpendUsd === 0 && budget.maxTokens === 0) {
      warnings.push(
        'The LLM module is enabled with no spend or token ceiling. Cost-abuse checks will be skipped until one is set.',
      );
    }
    if (budget.maxSpendUsd > 0 && !budget.clientAcknowledgedCostTesting) {
      warnings.push(
        'A spend ceiling is set but the client has not acknowledged cost-abuse testing. Those checks will be skipped.',
      );
    }
  }

  if (policy.phases.postLogin && policy.authProfiles.length === 0) {
    warnings.push(
      'Post-login testing is enabled but no authentication profiles are configured. Only unauthenticated checks will run.',
    );
  }

  for (const profile of policy.authProfiles) {
    if (profile.type !== 'none' && !profile.sessionIndicator) {
      warnings.push(
        `Authentication profile "${profile.id}" has no session indicator. Session death mid-scan will not be detected, which is the most common cause of a worthless authenticated scan.`,
      );
    }
    if (policy.accessControlMatrix.enabled && !profile.secondaryCredentialSetId) {
      warnings.push(
        `Role "${profile.roleName}" has only one account. Horizontal access control cannot be tested for it; ask the client for a second account.`,
      );
    }
  }

  if (policy.ai.agenticEnabled && policy.ai.spendCeilingUsd === 0) {
    warnings.push('Agentic testing is enabled with no spend ceiling. It will not start.');
  }

  if (!policy.readOnlyMode && policy.intensity === 'thorough') {
    warnings.push(
      'Thorough intensity without read-only mode will send state-changing requests. Confirm this is not production, or enable readOnlyMode for the first pass.',
    );
  }

  return warnings;
}

/** Convert the policy's `HH:MM` window strings into minutes for the scope guard. */
export function windowsToMinutes(
  windows: Policy['windows'],
): { daysOfWeek: number[]; startMinute: number; endMinute: number }[] {
  return windows.map((window) => ({
    daysOfWeek: window.daysOfWeek,
    startMinute: toMinutes(window.start),
    endMinute: toMinutes(window.end),
  }));
}

function toMinutes(value: string): number {
  const [hours = '0', minutes = '0'] = value.split(':');
  return Number(hours) * 60 + Number(minutes);
}
