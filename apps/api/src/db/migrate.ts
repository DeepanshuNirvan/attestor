import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { loadConfig, createLogger } from '@attestor/shared';

/**
 * Migrations.
 *
 * Plain SQL files applied in filename order, each inside its own transaction, recorded in
 * `schema_migrations`. Drizzle-kit generates the schema files; the hand-written ones carry the
 * triggers, check constraints and role grants that an ORM cannot express. One runner covers both,
 * so there is no question about which tool owns which file.
 */

const migrationsDirectory = fileURLToPath(new URL('../../../../infra/migrations/', import.meta.url));

export async function runMigrations(databaseUrl: string): Promise<string[]> {
  const client = new pg.Client({ connectionString: databaseUrl });
  await client.connect();
  const applied: string[] = [];

  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        name text PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT now(),
        checksum text NOT NULL
      )
    `);

    const files = (await readdir(migrationsDirectory))
      .filter((entry) => entry.endsWith('.sql'))
      .sort();

    const { rows } = await client.query<{ name: string; checksum: string }>(
      'SELECT name, checksum FROM schema_migrations',
    );
    const known = new Map(rows.map((row) => [row.name, row.checksum]));

    for (const file of files) {
      const sql = await readFile(join(migrationsDirectory, file), 'utf8');
      const checksum = await sha256Hex(sql);
      const previous = known.get(file);

      if (previous !== undefined) {
        if (previous !== checksum) {
          throw new Error(
            `migration ${file} has changed since it was applied. Migrations are immutable; add a new file instead.`,
          );
        }
        continue;
      }

      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)', [
          file,
          checksum,
        ]);
        await client.query('COMMIT');
        applied.push(file);
      } catch (error) {
        await client.query('ROLLBACK');
        throw new Error(
          `migration ${file} failed: ${error instanceof Error ? error.message : 'unknown error'}`,
        );
      }
    }

    await grantPortalRoleLogin(client);
  } finally {
    await client.end();
  }

  return applied;
}

/**
 * Give the portal role its password.
 *
 * Migration 0001 creates `attestor_portal` NOLOGIN, because a migration file cannot carry a secret.
 * Something still has to turn it into a role the portal API can authenticate as, and this is the
 * one step every deployment path already runs as the owner. Without it the portal API cannot
 * connect at all and crash-loops on `password authentication failed`.
 *
 * Idempotent, and a no-op when the password is unset — a deployment that does not run the portal
 * should not be forced to invent a secret for it.
 */
async function grantPortalRoleLogin(client: pg.Client): Promise<void> {
  const password = process.env.PORTAL_DB_PASSWORD;
  if (password === undefined || password === '') return;

  // ALTER ROLE takes no bind parameters, so the password has to be quoted as a literal.
  await client.query(
    `ALTER ROLE attestor_portal WITH LOGIN PASSWORD ${client.escapeLiteral(password)}`,
  );
}

async function sha256Hex(input: string): Promise<string> {
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(input).digest('hex');
}

const isEntryPoint = process.argv[1]?.endsWith('migrate.ts') === true;
if (isEntryPoint) {
  const config = loadConfig();
  const logger = createLogger({ service: 'migrate', level: config.LOG_LEVEL });
  runMigrations(config.DATABASE_URL)
    .then((applied) => {
      logger.info(
        applied.length === 0 ? 'database is up to date' : `applied ${applied.length} migration(s)`,
        { applied },
      );
    })
    .catch((error: unknown) => {
      logger.error('migration failed', { error });
      process.exitCode = 1;
    });
}
