import { describe, expect, it } from 'vitest';
import { retestOutcomeFor } from './report-service.ts';

/**
 * The renderer prints a "Retest result" line for every finding that carries `retestOutcome`, with
 * five distinct sentences behind it. Nothing ever set the field, so every retest report went out
 * without a single retest result on it — the one thing the document exists to say.
 *
 * These assert the derivation, and that an assessment report stays silent about a retest that has
 * not happened.
 */

const BEFORE = new Date('2026-09-01T00:00:00Z');
const AFTER = new Date('2026-10-01T00:00:00Z');

function finding(over: Partial<Parameters<typeof retestOutcomeFor>[0]> = {}) {
  return { status: 'open', fixedAt: null, retestedAt: null, riskAcceptedAt: null, ...over };
}

describe('retestOutcomeFor', () => {
  it('says nothing on an assessment report', () => {
    expect(retestOutcomeFor(finding({ retestedAt: AFTER }), 'assessment')).toBeUndefined();
  });

  it('reports a finding that was not retested', () => {
    expect(retestOutcomeFor(finding(), 'retest')).toBe('notRetested');
  });

  it('reports a finding confirmed fixed at retest', () => {
    expect(retestOutcomeFor(finding({ status: 'fixed', retestedAt: AFTER }), 'retest')).toBe(
      'verifiedFixed',
    );
  });

  it('reports a finding that was reproduced again', () => {
    expect(retestOutcomeFor(finding({ retestedAt: AFTER }), 'retest')).toBe('stillOpen');
  });

  /**
   * The distinction worth drawing. A finding that was fixed and came back points at the release
   * process, not at the original defect, and telling a client "still open" would hide that.
   */
  it('separates a regression from something never fixed', () => {
    expect(retestOutcomeFor(finding({ fixedAt: BEFORE, retestedAt: AFTER }), 'retest')).toBe(
      'regressed',
    );
    expect(retestOutcomeFor(finding({ retestedAt: AFTER }), 'retest')).toBe('stillOpen');
  });

  it('reports an accepted risk as accepted rather than as a failure', () => {
    expect(
      retestOutcomeFor(finding({ riskAcceptedAt: AFTER, retestedAt: AFTER }), 'retest'),
    ).toBe('riskAccepted');
  });
});
