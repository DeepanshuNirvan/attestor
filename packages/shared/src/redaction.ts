/**
 * Redaction of secrets. Everything that is persisted — logs, tool stdout, raw scanner output,
 * evidence bodies, error traces — passes through here first.
 *
 * This is a one-way filter. It is deliberately over-eager: a redacted value that turned out to be
 * harmless costs a tester thirty seconds, a leaked client credential costs the firm the client.
 */

const REDACTED = '[REDACTED]';

/** Header names whose entire value is a secret. Compared case-insensitively. */
const SECRET_HEADERS = [
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
  'x-amz-security-token',
  'x-csrf-token',
  'x-xsrf-token',
  'api-key',
  'apikey',
  'authentication',
];

/** Object keys and query/form parameter names whose value is a secret. */
const SECRET_KEYS = [
  'password',
  'passwd',
  'pwd',
  'secret',
  'clientsecret',
  'client_secret',
  'token',
  'accesstoken',
  'access_token',
  'refreshtoken',
  'refresh_token',
  'idtoken',
  'id_token',
  'apikey',
  'api_key',
  'apisecret',
  'api_secret',
  'authorization',
  'auth',
  'cookie',
  'sessionid',
  'session_id',
  'sessiontoken',
  'jsessionid',
  'privatekey',
  'private_key',
  'secretkey',
  'secret_key',
  'credentials',
  'passphrase',
  'otp',
  'totp',
  'mfa',
  'pin',
  'signature',
  'sig',
  'x-api-key',
];

const headerLine = new RegExp(`^(\\s*(?:${SECRET_HEADERS.join('|')})\\s*:\\s*).+$`, 'gim');

const jsonPair = new RegExp(
  `("(?:${SECRET_KEYS.join('|')})"\\s*:\\s*)"(?:\\\\.|[^"\\\\])*"`,
  'gi',
);

const queryPair = new RegExp(`([?&;](?:${SECRET_KEYS.join('|')})=)[^&;\\s"']+`, 'gi');

const formPair = new RegExp(`(^|&)((?:${SECRET_KEYS.join('|')})=)[^&\\s]+`, 'gi');

/**
 * Shaped secrets that carry no key name. Each pattern must anchor on structure the value cannot
 * lose, because a token appearing bare in a log has nothing else identifying it.
 */
const SHAPED_SECRETS: { name: string; pattern: RegExp }[] = [
  { name: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { name: 'bearer', pattern: /\b[Bb]earer\s+[A-Za-z0-9._~+/-]{16,}={0,2}/g },
  { name: 'basic', pattern: /\b[Bb]asic\s+[A-Za-z0-9+/]{12,}={0,2}/g },
  { name: 'awsAccessKeyId', pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g },
  { name: 'githubToken', pattern: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g },
  { name: 'slackToken', pattern: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g },
  { name: 'googleApiKey', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: 'stripeKey', pattern: /\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b/g },
  { name: 'openAiKey', pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { name: 'anthropicKey', pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  {
    name: 'privateKeyBlock',
    pattern: /-----BEGIN[ A-Z]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z]*PRIVATE KEY-----/g,
  },
];

function escapeForRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Values known to be secret for this run — decrypted credential values, session cookies captured
 * during login. Registered by the worker before a tool runs and cleared when it finishes.
 */
export class SecretRegistry {
  private readonly values = new Set<string>();

  add(value: string | null | undefined): void {
    // Very short values would redact ordinary words out of every log line.
    if (typeof value === 'string' && value.trim().length >= 6) this.values.add(value.trim());
  }

  clear(): void {
    this.values.clear();
  }

  get size(): number {
    return this.values.size;
  }

  apply(text: string): string {
    let out = text;
    for (const value of this.values) {
      out = out.replace(new RegExp(escapeForRegex(value), 'g'), REDACTED);
      // Tools frequently print a credential URL-encoded or base64'd; catch the cheap variants.
      const encoded = encodeURIComponent(value);
      if (encoded !== value) out = out.replace(new RegExp(escapeForRegex(encoded), 'g'), REDACTED);
      const base64 = Buffer.from(value, 'utf8').toString('base64');
      if (base64.length >= 8) out = out.replace(new RegExp(escapeForRegex(base64), 'g'), REDACTED);
    }
    return out;
  }
}

export const secretRegistry = new SecretRegistry();

/** Redact a block of text: headers, JSON, query strings, form bodies and shaped secrets. */
export function redactText(input: string, registry: SecretRegistry = secretRegistry): string {
  if (!input) return input;
  let out = registry.apply(input);
  out = out.replace(headerLine, `$1${REDACTED}`);
  out = out.replace(jsonPair, `$1"${REDACTED}"`);
  out = out.replace(queryPair, `$1${REDACTED}`);
  out = out.replace(formPair, `$1$2${REDACTED}`);
  for (const { pattern } of SHAPED_SECRETS) {
    out = out.replace(pattern, REDACTED);
  }
  return out;
}

const MAX_REDACTION_DEPTH = 12;

/**
 * Redact a structure. Keys are matched by name, string values are run through the text filter, and
 * everything else is passed through. Cycles and runaway depth are cut rather than thrown on,
 * because this sits on the logging path and must never be the thing that crashes a worker.
 */
export function redactValue(input: unknown, depth = 0): unknown {
  if (depth > MAX_REDACTION_DEPTH) return '[TRUNCATED]';
  if (typeof input === 'string') return redactText(input);
  if (input === null || typeof input !== 'object') return input;
  if (Array.isArray(input)) return input.map((item) => redactValue(item, depth + 1));
  if (input instanceof Error) {
    return { name: input.name, message: redactText(input.message), stack: redactText(input.stack ?? '') };
  }

  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    out[key] = isSecretKey(key) ? REDACTED : redactValue(value, depth + 1);
  }
  return out;
}

export function isSecretKey(key: string): boolean {
  const normalised = key.toLowerCase().replace(/[-\s]/g, '_');
  return (
    SECRET_KEYS.includes(normalised) ||
    SECRET_KEYS.includes(normalised.replace(/_/g, '')) ||
    SECRET_HEADERS.includes(key.toLowerCase())
  );
}

export const REDACTION_PLACEHOLDER = REDACTED;
