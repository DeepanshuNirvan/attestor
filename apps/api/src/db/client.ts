import pg from 'pg';
import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from './schema.ts';

/**
 * Two connection pools, deliberately.
 *
 * The console API connects as the owner role. The client portal connects as `attestor_portal`,
 * which the migration grants a minimal, mostly-read set of privileges and which cannot read the
 * credential vault at all. Sharing one pool would make that separation decorative.
 */

export type Database = NodePgDatabase<typeof schema>;

let consolePool: pg.Pool | null = null;
let portalPool: pg.Pool | null = null;

function makePool(connectionString: string, applicationName: string): pg.Pool {
  return new pg.Pool({
    connectionString,
    application_name: applicationName,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
  });
}

export function consoleDatabase(connectionString: string): Database {
  consolePool ??= makePool(connectionString, 'attestor-console');
  return drizzle(consolePool, { schema });
}

export function portalDatabase(connectionString: string): Database {
  portalPool ??= makePool(connectionString, 'attestor-portal');
  return drizzle(portalPool, { schema });
}

export async function closeDatabases(): Promise<void> {
  await consolePool?.end();
  await portalPool?.end();
  consolePool = null;
  portalPool = null;
}

export { schema };
