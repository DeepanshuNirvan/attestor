/**
 * The audit log.
 *
 * Append-only, and enforced as such in the database rather than by application discipline: the
 * `audit_log` table carries a trigger that raises on UPDATE and DELETE. This is the firm's legal
 * defence — who ran what, against what, when, under which authorisation — and a record that can be
 * edited is not a defence.
 */

export const AUDIT_ACTIONS = [
  'engagement.created',
  'engagement.updated',
  'engagement.stateChanged',
  'engagement.panicStopped',
  'engagement.panicStopCleared',
  'engagement.preFlightChecklistUpdated',
  'engagement.paymentRecorded',
  'authorisation.uploaded',
  'authorisation.revoked',
  'authorisation.assetListDiffed',
  'scopeItem.added',
  'scopeItem.removed',
  'credentialSet.linkIssued',
  'credentialSet.submitted',
  'credentialSet.verified',
  'credentialSet.revoked',
  'credentialSet.shredded',
  'policy.changed',
  'scanRun.requested',
  'scanRun.started',
  'scanRun.finished',
  'scanRun.aborted',
  'scanRun.refused',
  'tool.launched',
  'tool.exited',
  'finding.created',
  'finding.confirmed',
  'finding.statusChanged',
  'finding.severityOverridden',
  'finding.markedFalsePositive',
  'evidence.captured',
  'evidence.accessed',
  'evidence.purged',
  'report.generated',
  'report.released',
  'report.downloaded',
  'client.created',
  'client.updated',
  'client.dpaRecorded',
  'client.userInvited',
  'client.invitationIssued',
  'client.invitationRevoked',
  'client.userActivated',
  'client.userDeactivated',
  'client.loggedIn',
  'client.retestRequested',
  'client.riskAccepted',
  'staff.loggedIn',
  'staff.mfaEnrolled',
  'ai.requestSent',
  'agentic.actionTaken',
  'acknowledgement.recorded',
  'retainer.created',
  'retainer.paused',
  'retainer.resumed',
  'queue.jobRetried',
  'notification.approved',
  'notification.sent',
  'notification.discarded',
] as const;

export type AuditAction = (typeof AUDIT_ACTIONS)[number];

export interface AuditEntry {
  actorId: string;
  /** `system` for scheduled work, so a machine action is never attributed to a person. */
  actorKind: 'staff' | 'client' | 'system';
  action: AuditAction;
  subjectType: string;
  subjectId: string;
  ipAddress?: string;
  userAgent?: string;
  /** Routed through the redaction filter before it is written. */
  metadata?: Record<string, unknown>;
}

export interface AuditLog {
  record(entry: AuditEntry): Promise<void>;
}

/** Used in tests and in the dry-run path, where nothing should be persisted. */
export class InMemoryAuditLog implements AuditLog {
  readonly entries: (AuditEntry & { at: Date })[] = [];

  record(entry: AuditEntry): Promise<void> {
    this.entries.push({ ...entry, at: new Date() });
    return Promise.resolve();
  }

  find(action: AuditAction): (AuditEntry & { at: Date })[] {
    return this.entries.filter((entry) => entry.action === action);
  }
}
