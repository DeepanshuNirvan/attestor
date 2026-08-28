import { describe, expect, it } from 'vitest';
import { canTransition, nextStates, type TransitionContext } from './state-machine.ts';

function context(overrides: Partial<TransitionContext> = {}): TransitionContext {
  return {
    scopeItemCount: 3,
    hasSignedAuthorisation: true,
    authorisationValidUntil: new Date('2026-09-01T00:00:00Z'),
    advancePaymentReceived: true,
    advanceGateOverride: null,
    credentialsVerified: true,
    preFlightChecklistComplete: true,
    reviewChecklistComplete: true,
    finalPaymentReceived: true,
    evidencePurged: true,
    now: new Date('2026-08-19T00:00:00Z'),
    ...overrides,
  };
}

describe('canTransition — the authorisation gate', () => {
  it('refuses to authorise without a signed document', () => {
    const outcome = canTransition('scoped', 'authorised', context({ hasSignedAuthorisation: false }));
    expect(outcome.allowed).toBe(false);
    expect(!outcome.allowed && outcome.reason).toContain('signed authorisation');
  });

  it('refuses an authorisation whose window has already closed', () => {
    const outcome = canTransition(
      'scoped',
      'authorised',
      context({ authorisationValidUntil: new Date('2026-08-01T00:00:00Z') }),
    );
    expect(!outcome.allowed && outcome.reason).toContain('already closed');
  });

  it('cannot be reached by skipping straight from draft', () => {
    const outcome = canTransition('draft', 'running', context());
    expect(outcome.allowed).toBe(false);
  });

  it('cannot be reached by skipping from scoped to readyToRun', () => {
    expect(canTransition('scoped', 'readyToRun', context()).allowed).toBe(false);
  });
});

describe('canTransition — the payment gate', () => {
  it('blocks without the advance', () => {
    const outcome = canTransition(
      'authorised',
      'advancePaid',
      context({ advancePaymentReceived: false }),
    );
    expect(!outcome.allowed && outcome.reason).toContain('advance payment');
  });

  it('allows an explicit override, because it is a business rule and not a legal one', () => {
    const outcome = canTransition(
      'authorised',
      'advancePaid',
      context({
        advancePaymentReceived: false,
        advanceGateOverride: { by: 'owner', reason: 'invoice on 30-day terms, agreed in the MSA' },
      }),
    );
    expect(outcome.allowed).toBe(true);
  });

  it('blocks release until the final payment and the review checklist are both done', () => {
    expect(
      canTransition('reportReview', 'released', context({ finalPaymentReceived: false })).allowed,
    ).toBe(false);
    expect(
      canTransition('reportReview', 'released', context({ reviewChecklistComplete: false })).allowed,
    ).toBe(false);
    expect(canTransition('reportReview', 'released', context()).allowed).toBe(true);
  });
});

describe('canTransition — pre-flight', () => {
  it('blocks the run until credentials are verified and the checklist is complete', () => {
    expect(
      canTransition('advancePaid', 'readyToRun', context({ credentialsVerified: false })).allowed,
    ).toBe(false);
    expect(
      canTransition('advancePaid', 'readyToRun', context({ preFlightChecklistComplete: false }))
        .allowed,
    ).toBe(false);
  });
});

describe('canTransition — closure', () => {
  it('will not close until evidence is purged', () => {
    const outcome = canTransition('retestComplete', 'closed', context({ evidencePurged: false }));
    expect(!outcome.allowed && outcome.reason).toContain('evidence');
  });

  it('cannot be reached from the middle of an engagement', () => {
    expect(canTransition('running', 'closed', context()).allowed).toBe(false);
    expect(canTransition('draft', 'closed', context()).allowed).toBe(false);
  });
});

describe('canTransition — backwards moves', () => {
  it('requires a written reason', () => {
    const withoutReason = canTransition('reportReview', 'manualTesting', context());
    expect(withoutReason.allowed).toBe(false);
    expect(!withoutReason.allowed && withoutReason.requiresBackwardsReason).toBe(true);

    const tooShort = canTransition('reportReview', 'manualTesting', context(), 'oops');
    expect(tooShort.allowed).toBe(false);

    const withReason = canTransition(
      'reportReview',
      'manualTesting',
      context(),
      'reviewer asked for the tenant isolation finding to be re-verified',
    );
    expect(withReason.allowed).toBe(true);
  });

  it('does not let a backwards reason unlock a forward skip', () => {
    const outcome = canTransition(
      'draft',
      'running',
      context(),
      'the client is in a hurry and has verbally agreed',
    );
    expect(outcome.allowed).toBe(false);
  });
});

describe('canTransition — miscellaneous', () => {
  it('refuses a transition to the same state', () => {
    expect(canTransition('running', 'running', context()).allowed).toBe(false);
  });

  it('allows running another module after triage has started', () => {
    expect(canTransition('triage', 'running', context()).allowed).toBe(true);
    expect(canTransition('manualTesting', 'running', context()).allowed).toBe(true);
  });

  it('lists the states reachable from each point', () => {
    expect(nextStates('draft')).toEqual(['scoped']);
    expect(nextStates('released')).toContain('retestPending');
    expect(nextStates('closed')).toEqual([]);
  });
});
