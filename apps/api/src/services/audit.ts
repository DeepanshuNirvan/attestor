import { redactValue } from '@attestor/shared';
import type { AuditEntry, AuditLog } from '@attestor/core';
import type { Database } from '../db/client.ts';
import { auditLog as auditLogTable } from '../db/schema.ts';

/**
 * The database-backed audit log.
 *
 * Metadata is routed through the redaction filter on the way in, because the audit log is the one
 * table that is never deleted and therefore the worst place for a credential to land.
 */
export class DatabaseAuditLog implements AuditLog {
  private readonly database: Database;

  constructor(database: Database) {
    this.database = database;
  }

  async record(entry: AuditEntry): Promise<void> {
    await this.database.insert(auditLogTable).values({
      actorId: entry.actorId,
      actorKind: entry.actorKind,
      action: entry.action,
      subjectType: entry.subjectType,
      subjectId: entry.subjectId,
      ipAddress: entry.ipAddress ?? null,
      userAgent: entry.userAgent ?? null,
      metadata: redactValue(entry.metadata ?? {}) ?? {},
    });
  }
}
