import { describe, expect, it } from 'vitest';
import { autodraftSkipReason } from './ai-routes.ts';

/**
 * `POST /engagements/:id/report/autodraft` writes a first draft of every prose section in one call,
 * so that a report starts from the findings rather than from a blank page.
 *
 * The rule that makes it safe is this one: it never overwrites what a person approved. Approval is
 * the moment somebody put their name to the words, and the release checklist is built on it. An
 * autodraft that could quietly replace approved text would make that gate decorative.
 */

describe('autodraftSkipReason', () => {
  it('drafts a section that does not exist yet', () => {
    expect(autodraftSkipReason(undefined, false)).toBeNull();
  });

  it('drafts a section that exists but is empty', () => {
    expect(autodraftSkipReason({ markdown: '   \n ', approvedAt: null }, false)).toBeNull();
  });

  it('leaves written text alone unless asked to replace it', () => {
    const written = { markdown: 'A paragraph somebody typed.', approvedAt: null };
    expect(autodraftSkipReason(written, false)).toContain('force: true');
    expect(autodraftSkipReason(written, true)).toBeNull();
  });

  it('never overwrites an approved section, even with force', () => {
    const approved = { markdown: 'Approved wording.', approvedAt: new Date('2026-09-01T00:00:00Z') };

    expect(autodraftSkipReason(approved, false)).toContain('approved');
    expect(
      autodraftSkipReason(approved, true),
      'force must not reach approved text: the release gate depends on approval meaning something',
    ).toContain('approved');
  });
});
