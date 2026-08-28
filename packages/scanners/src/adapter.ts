import type { ModuleName, Severity } from '@attestor/shared';
import type { RawFinding } from '@attestor/findings';
import type { Policy } from '@attestor/policy';

/**
 * The adapter contract.
 *
 * Adding a tool means writing one file that satisfies this interface and registering it. Nothing
 * else in the platform changes: the runner, the scope guard, the findings pipeline, the coverage
 * matrix and the report all work off this shape.
 *
 * `parse` is a pure function over a string. That is the whole reason adapters are testable without
 * Docker, a network or a target: the fixtures in `src/fixtures` are real tool output, and the tests
 * assert on what comes out.
 */

export interface AdapterContext {
  policy: Policy;
  /** Hostnames or addresses the run was authorised against, already scope-checked. */
  targets: string[];
  /** Where the tool wrote its output inside the container. */
  outputPath: string;
}

export interface ToolInvocation {
  /** Arguments after the image entrypoint. */
  command: string[];
  /** Non-secret environment for the tool. */
  environment?: Record<string, string>;
  /** Files the runner must write into the output directory before starting the container. */
  inputFiles?: { name: string; contents: string }[];
  /** Where the tool will write the output `parse` expects, relative to /out. */
  outputFile: string;
}

export interface ScannerAdapter {
  /** Matches a tool id in `packages/core/src/runner/tool-images.ts`. */
  id: string;
  displayName: string;
  modules: ModuleName[];
  /** Catalogue check ids this tool contributes to, which drives the coverage matrix. */
  coversCheckIds: string[];
  /** Build the command line for a run. */
  buildInvocation: (context: AdapterContext) => ToolInvocation;
  /** Convert raw output into normalised findings. Pure; never touches the network or the clock. */
  parse: (raw: string, context: ParseContext) => RawFinding[];
  /**
   * Output this tool produces that is inventory rather than findings — hosts, ports, endpoints.
   * The recon module feeds this into the asset inventory that later modules consume.
   */
  parseAssets?: (raw: string) => DiscoveredAsset[];
}

export interface ParseContext {
  /** Used to attribute a finding when the tool's output omits the host. */
  defaultAsset: string;
  cvssVersion: '3.1' | '4.0';
}

export interface DiscoveredAsset {
  kind: 'host' | 'url' | 'port' | 'endpoint' | 'certificate' | 'technology';
  value: string;
  host: string;
  port?: number;
  metadata?: Record<string, string | number | boolean>;
}

/** Tool severities are not standardised. This is the one place the mapping lives. */
export function normaliseSeverity(value: string | undefined): Severity {
  const text = (value ?? '').trim().toLowerCase();
  if (['critical', 'crit', 'blocker', 'urgent', 'severe'].includes(text)) return 'critical';
  if (['high', 'error', 'major'].includes(text)) return 'high';
  if (['medium', 'moderate', 'warning', 'warn'].includes(text)) return 'medium';
  if (['low', 'minor', 'note'].includes(text)) return 'low';
  return 'info';
}

/** Most modern tools emit JSON Lines. Malformed lines are skipped, not fatal. */
export function parseJsonLines<T>(raw: string): T[] {
  const out: T[] = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '' || !trimmed.startsWith('{')) continue;
    try {
      out.push(JSON.parse(trimmed) as T);
    } catch {
      // A truncated final line is normal when a tool is killed by the wall-clock timeout.
      continue;
    }
  }
  return out;
}

export function parseJsonObject<T>(raw: string): T | null {
  const trimmed = raw.trim();
  if (trimmed === '') return null;
  try {
    return JSON.parse(trimmed) as T;
  } catch {
    return null;
  }
}

/** Split a `host:port` or URL into the parts a finding's affected asset needs. */
export function splitTarget(value: string): { host: string; port?: number; location?: string } {
  try {
    const url = new URL(value.includes('://') ? value : `https://${value}`);
    return {
      host: url.hostname,
      port: url.port === '' ? undefined : Number(url.port),
      location: url.pathname === '/' && !url.search ? undefined : `${url.pathname}${url.search}`,
    };
  } catch {
    const [host = value, port] = value.split(':');
    return { host, port: port ? Number(port) : undefined };
  }
}
