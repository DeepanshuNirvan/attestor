import { z } from 'zod';

/**
 * Configuration comes from the environment only. There is no config file with secrets in it and
 * no default that would work in production by accident: every secret is required and unset means
 * the process refuses to start.
 */

const nonEmpty = z.string().min(1);

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),

  DATABASE_URL: nonEmpty,
  /** Least-privilege role used by the client portal. Cannot read the credential vault. */
  PORTAL_DATABASE_URL: nonEmpty.optional(),
  REDIS_URL: nonEmpty,

  S3_ENDPOINT: nonEmpty,
  S3_REGION: z.string().default('us-east-1'),
  S3_ACCESS_KEY_ID: nonEmpty,
  S3_SECRET_ACCESS_KEY: nonEmpty,
  S3_BUCKET_EVIDENCE: z.string().default('attestor-evidence'),
  S3_BUCKET_REPORTS: z.string().default('attestor-reports'),

  /**
   * 32-byte base64 master key. Per-engagement subkeys are derived from it, so destroying an
   * engagement's salt shreds that engagement's credentials without affecting any other.
   */
  VAULT_MASTER_KEY: z.string().min(44),

  /**
   * A separate 32-byte base64 key for client authenticator secrets.
   *
   * Separate from the vault key on purpose: the portal needs to verify a TOTP code on every sign-in
   * and therefore has to be able to decrypt these, while it must never be able to decrypt a client
   * credential. Two keys is what makes that a fact rather than an intention.
   */
  PORTAL_TOTP_KEY: z.string().min(44),

  SESSION_SECRET: z.string().min(32),

  CONSOLE_ORIGIN: z.string().url().default('http://localhost:3000'),
  PORTAL_ORIGIN: z.string().url().default('http://localhost:3100'),
  API_BIND_ADDRESS: z.string().default('127.0.0.1'),
  API_PORT: z.coerce.number().int().positive().default(8080),
  PORTAL_API_PORT: z.coerce.number().int().positive().default(8081),

  SMTP_URL: z.string().optional(),
  MAIL_FROM: z.string().default('Attestor Security <no-reply@attestorsecurity.com>'),

  /** The whole AI layer is off unless this is explicitly true. */
  AI_ENABLED: z
    .string()
    .default('false')
    .transform((value) => value === 'true'),
  AI_PROVIDER: z.enum(['anthropic', 'openai', 'none']).default('none'),
  AI_API_KEY: z.string().optional(),
  AI_MODEL_DRAFTING: z.string().default('claude-sonnet-5'),
  AI_MODEL_TRIAGE: z.string().default('claude-haiku-4-5-20251001'),
  AI_MONTHLY_BUDGET_USD: z.coerce.number().nonnegative().default(0),
  // Published list prices, used only for the estimate written to the usage log. They drift; the
  // number in the log is an estimate and the provider's invoice is the truth.
  AI_INPUT_COST_PER_MILLION_USD: z.coerce.number().nonnegative().default(3),
  AI_OUTPUT_COST_PER_MILLION_USD: z.coerce.number().nonnegative().default(15),

  /** Fixed source address the client allowlists. Recorded on every authorisation. */
  EGRESS_IP: z.string().optional(),

  DOCKER_SOCKET: z.string().default('/var/run/docker.sock'),
});

export type AppConfig = z.infer<typeof schema>;

function parseOrThrow<T extends z.ZodType>(shape: T, source: NodeJS.ProcessEnv): z.infer<T> {
  const parsed = shape.safeParse(source);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
      .join('; ');
    throw new Error(`invalid configuration: ${issues}`);
  }
  return parsed.data;
}

/**
 * Configuration for the database tools.
 *
 * `migrate` and `seed` open Postgres and nothing else. Parsing the whole schema made them demand
 * Redis and S3 credentials they never touch, which is why the one-shot `migrate` service — the
 * only one in the compose file without those variables — could not start, and why the restore
 * drill in the runbook could not apply a migration without inventing an object store first.
 *
 * The subsets stay here rather than in the scripts so that "unset means the process refuses to
 * start" is still decided in one file.
 */
const migrationSchema = schema.pick({ NODE_ENV: true, LOG_LEVEL: true, DATABASE_URL: true });
const seedSchema = migrationSchema.extend({ VAULT_MASTER_KEY: schema.shape.VAULT_MASTER_KEY });

export type MigrationConfig = z.infer<typeof migrationSchema>;
export type SeedConfig = z.infer<typeof seedSchema>;

export function loadMigrationConfig(source: NodeJS.ProcessEnv = process.env): MigrationConfig {
  return parseOrThrow(migrationSchema, source);
}

export function loadSeedConfig(source: NodeJS.ProcessEnv = process.env): SeedConfig {
  return parseOrThrow(seedSchema, source);
}

let cached: AppConfig | null = null;

export function loadConfig(source: NodeJS.ProcessEnv = process.env): AppConfig {
  if (cached) return cached;
  const config = parseOrThrow(schema, source);
  if (config.AI_ENABLED && !config.AI_API_KEY) {
    throw new Error('AI_ENABLED is true but AI_API_KEY is not set');
  }
  cached = config;
  return cached;
}

/** Tests build a fresh config per case. */
export function resetConfigCache(): void {
  cached = null;
}
