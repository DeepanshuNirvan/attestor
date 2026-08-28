import { randomBytes, randomUUID, createHash } from 'node:crypto';

/**
 * Identifiers. Two kinds are needed and they are not interchangeable:
 *
 *  - internal ids, which are UUIDs and never appear in a document;
 *  - document references, which a client quotes in an email to their auditor two years later and
 *    therefore must be short, unambiguous, and stable for the life of the engagement.
 */

export function newId(): string {
  return randomUUID();
}

/** Sortable id for rows where creation order matters and a UUID would scatter the index. */
export function newSortableId(): string {
  const time = Date.now().toString(36).padStart(9, '0');
  return `${time}${randomBytes(8).toString('hex')}`;
}

export interface EngagementReferenceParts {
  year: number;
  /** Sequence within the year, assigned by the database. */
  sequence: number;
}

/** `ATT-2026-014` — the engagement. Printed on the report cover and the attestation letter. */
export function engagementReference({ year, sequence }: EngagementReferenceParts): string {
  return `ATT-${year}-${String(sequence).padStart(3, '0')}`;
}

/** `ATT-2026-014-003` — a finding inside that engagement. Quotable and stable across versions. */
export function findingReference(engagementRef: string, sequence: number): string {
  return `${engagementRef}-${String(sequence).padStart(3, '0')}`;
}

const ENGAGEMENT_REFERENCE = /^ATT-\d{4}-\d{3}$/;
const FINDING_REFERENCE = /^ATT-\d{4}-\d{3}-\d{3}$/;

export function isEngagementReference(value: string): boolean {
  return ENGAGEMENT_REFERENCE.test(value);
}

export function isFindingReference(value: string): boolean {
  return FINDING_REFERENCE.test(value);
}

export function sha256(input: Buffer | string): string {
  return createHash('sha256').update(input).digest('hex');
}
