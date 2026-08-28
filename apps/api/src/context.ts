import { createLogger, loadConfig, type AppConfig, type Logger } from '@attestor/shared';
import { ContainerRunner, InMemoryPanicStopStore, type PanicStopStore } from '@attestor/core';
import { consoleDatabase, portalDatabase, type Database } from './db/client.ts';
import { DatabaseAuditLog } from './services/audit.ts';
import { CredentialVault } from './services/credential-vault.ts';
import { EvidenceStore } from './services/evidence-store.ts';
import { RedisPanicStopStore } from './services/panic-stop-store.ts';

/**
 * The application context.
 *
 * Built once per process and passed explicitly. There is no global registry and no service
 * locator: a route that needs the credential vault has to be given it, which makes it obvious in
 * review that the portal's context does not include one.
 */

export interface ConsoleContext {
  kind: 'console';
  config: AppConfig;
  logger: Logger;
  database: Database;
  auditLog: DatabaseAuditLog;
  vault: CredentialVault;
  evidence: EvidenceStore;
  reports: EvidenceStore;
  containerRunner: ContainerRunner;
  panicStop: PanicStopStore;
}

/**
 * The portal's context deliberately omits the credential vault and the container runner. It is the
 * only public surface; giving it the ability to decrypt a client credential or start a container
 * would make every other control in the portal decorative.
 */
export interface PortalContext {
  kind: 'portal';
  config: AppConfig;
  logger: Logger;
  database: Database;
  auditLog: DatabaseAuditLog;
  reports: EvidenceStore;
  evidence: EvidenceStore;
  /**
   * Client authenticator secrets, under their own key. The portal must decrypt these to check a
   * code at sign-in; it must never be able to decrypt a client credential. Different key, different
   * table, no grant — three reasons rather than one.
   */
  totpVault: CredentialVault;
}

function evidenceStoreFor(config: AppConfig, bucket: string): EvidenceStore {
  return new EvidenceStore({
    endpoint: config.S3_ENDPOINT,
    region: config.S3_REGION,
    accessKeyId: config.S3_ACCESS_KEY_ID,
    secretAccessKey: config.S3_SECRET_ACCESS_KEY,
    bucket,
    forcePathStyle: true,
  });
}

export function buildConsoleContext(config = loadConfig()): ConsoleContext {
  const logger = createLogger({ service: 'console-api', level: config.LOG_LEVEL });
  const database = consoleDatabase(config.DATABASE_URL);

  return {
    kind: 'console',
    config,
    logger,
    database,
    auditLog: new DatabaseAuditLog(database),
    vault: new CredentialVault(config.VAULT_MASTER_KEY),
    evidence: evidenceStoreFor(config, config.S3_BUCKET_EVIDENCE),
    reports: evidenceStoreFor(config, config.S3_BUCKET_REPORTS),
    containerRunner: new ContainerRunner({ socketPath: config.DOCKER_SOCKET }),
    panicStop: config.REDIS_URL
      ? new RedisPanicStopStore(config.REDIS_URL)
      : new InMemoryPanicStopStore(),
  };
}

export function buildPortalContext(config = loadConfig()): PortalContext {
  const logger = createLogger({ service: 'portal-api', level: config.LOG_LEVEL });
  // The portal role is granted a minimal, mostly-read privilege set by the migration. Falling back
  // to the console URL would silently undo that, so an unset value is a startup failure.
  if (!config.PORTAL_DATABASE_URL) {
    throw new Error(
      'PORTAL_DATABASE_URL is not set. The portal must connect as the least-privilege role, never as the console role.',
    );
  }
  const database = portalDatabase(config.PORTAL_DATABASE_URL);

  return {
    kind: 'portal',
    config,
    logger,
    database,
    auditLog: new DatabaseAuditLog(database),
    reports: evidenceStoreFor(config, config.S3_BUCKET_REPORTS),
    evidence: evidenceStoreFor(config, config.S3_BUCKET_EVIDENCE),
    totpVault: new CredentialVault(config.PORTAL_TOTP_KEY),
  };
}
