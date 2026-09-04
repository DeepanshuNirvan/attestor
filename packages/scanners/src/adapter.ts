import type { ModuleName, Severity } from '@attestor/shared';
import type { RawFinding } from '@attestor/findings';
import type { AuthProfile, Policy } from '@attestor/policy';

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

/**
 * A credential this run may use, joined to the policy auth profile it satisfies.
 *
 * **No secret value is ever on this object.** A secret field arrives as `${ENV_NAME}` — a reference
 * to a variable the runner puts in the tool container's environment and registers with the
 * redaction filter. That is what lets `buildInvocation` stay a pure function that can be tested,
 * printed and stored: everything it produces, including the files it writes into the run directory,
 * is safe to keep.
 *
 * A tool that cannot resolve an environment variable itself must not be given a credential this
 * way. Putting the value into `command` instead would write a client's password into the audit
 * log, which records the command line of every launch.
 */
export interface RunCredential {
  credentialSetId: string;
  /** The policy auth profile this satisfies. */
  profileId: string;
  roleName: string;
  authType: AuthProfile['type'];
  /** The second account for the role. Access control testing compares one against the other. */
  isSecondary: boolean;
  loginUrl?: string;
  sessionIndicator?: AuthProfile['sessionIndicator'];
  /** How often to re-confirm the session is alive, in requests. */
  sessionCheckEveryRequests: number;
  /** Fields that are not secret, in the clear: a username, a header name, a cookie name. */
  fields: Record<string, string>;
  /** Secret fields, each value a `${ENV_NAME}` reference rather than the secret itself. */
  secretRefs: Record<string, string>;
}

export interface AdapterContext {
  policy: Policy;
  /** Hostnames or addresses the run was authorised against, already scope-checked. */
  targets: string[];
  /** Where the tool wrote its output inside the container. */
  outputPath: string;
  /**
   * Credentials available to this run. Empty when the engagement has none, when the policy has no
   * auth profiles, or on a dry run — so every adapter must still produce a working unauthenticated
   * invocation.
   */
  credentials?: RunCredential[];
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
  /**
   * Whether this tool does anything with a credential. False for most: a port scanner and a TLS
   * checker have no notion of a logged-in user. The worker reads it before opening the vault, so a
   * run that cannot use a client's password never decrypts one.
   */
  usesCredentials?: boolean;
  /** Build the command line for a run. */
  /**
   * Exit codes that mean the tool did its job, beyond the usual zero.
   *
   * Most tools exit zero whether or not they found anything, and for those a non-zero exit means
   * the run did not happen and its checks must not count as covered. A few report findings through
   * the exit code instead: schemathesis exits 1 precisely when its checks fail, which is the case
   * we most want to keep. Without this, the runs that found something were the runs thrown away.
   */
  successExitCodes?: number[];

  /**
   * Why this tool cannot run under this policy, if it cannot.
   *
   * Some tools need something the engagement has not supplied — an API schema, a mobile binary, a
   * cloud credential — and starting them anyway produces a failed run whose reason is a stack trace.
   * Returning a sentence here makes the run an aborted one carrying that sentence, which is what a
   * client reads in the coverage matrix instead of a silent gap. Omit it when a tool always applies.
   */
  cannotRunBecause?: (policy: Policy) => string | undefined;

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

/**
 * A target list for a tool that scans hosts rather than URLs.
 *
 * Scope items are frequently URLs, and the run request passes whatever it was given straight
 * through to every adapter. naabu and nmap take a host or an address and refuse a URL outright —
 * "no valid ipv4 or ipv6 targets were found" — so the tools that enumerate ports have to reduce
 * their targets to bare hosts. Duplicates are collapsed, because two URLs on one host are one host.
 */
export function hostList(targets: readonly string[]): string {
  const hosts = new Set(
    targets.map((target) => splitTarget(target).host).filter((host) => host !== ''),
  );
  return [...hosts, ''].join('\n');
}

/**
 * The record a finding was parsed from, as evidence text.
 *
 * This is what the tool actually said about this result. It goes through the masking and redaction
 * layer in the worker like any other evidence, and it exists so a candidate arrives in triage with
 * its provenance attached rather than with nothing.
 */
export function recordAsEvidence(record: unknown): string {
  return JSON.stringify(record, null, 2);
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
