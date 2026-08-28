import type { EngagementState } from '@attestor/shared';

/**
 * The engagement lifecycle.
 *
 * Two of these transitions are gates rather than steps: nothing may run before `authorised`, and
 * nothing may run before the advance is recorded. The second is a business rule and can be
 * overridden with a written reason; the first cannot be overridden at all, because testing without
 * signed, scoped, in-window authorisation is a criminal offence in India under the IT Act s.66 and
 * has equivalents elsewhere.
 */

export interface TransitionRule {
  from: EngagementState;
  to: EngagementState;
  /** Conditions that must hold. Each returns null when satisfied, or the reason it is not. */
  requires: (context: TransitionContext) => string | null;
}

export interface TransitionContext {
  scopeItemCount: number;
  hasSignedAuthorisation: boolean;
  authorisationValidUntil: Date | null;
  advancePaymentReceived: boolean;
  advanceGateOverride: { by: string; reason: string } | null;
  credentialsVerified: boolean;
  preFlightChecklistComplete: boolean;
  reviewChecklistComplete: boolean;
  finalPaymentReceived: boolean;
  evidencePurged: boolean;
  now: Date;
}

const satisfied = (): string | null => null;

const FORWARD_RULES: TransitionRule[] = [
  {
    from: 'draft',
    to: 'scoped',
    requires: (context) =>
      context.scopeItemCount > 0 ? null : 'at least one scope item is required',
  },
  {
    from: 'scoped',
    to: 'authorised',
    requires: (context) => {
      if (!context.hasSignedAuthorisation) return 'a signed authorisation document is required';
      if (!context.authorisationValidUntil) return 'the authorisation has no validity window';
      if (context.authorisationValidUntil <= context.now) {
        return 'the authorisation window has already closed';
      }
      return null;
    },
  },
  {
    from: 'authorised',
    to: 'advancePaid',
    requires: (context) =>
      context.advancePaymentReceived || context.advanceGateOverride
        ? null
        : 'the advance payment has not been recorded; override with a written reason to proceed',
  },
  {
    from: 'advancePaid',
    to: 'readyToRun',
    requires: (context) => {
      if (!context.credentialsVerified) return 'credentials have not been verified';
      if (!context.preFlightChecklistComplete) return 'the pre-flight checklist is not complete';
      return null;
    },
  },
  { from: 'readyToRun', to: 'running', requires: satisfied },
  { from: 'running', to: 'triage', requires: satisfied },
  { from: 'triage', to: 'manualTesting', requires: satisfied },
  { from: 'manualTesting', to: 'reportDraft', requires: satisfied },
  { from: 'reportDraft', to: 'reportReview', requires: satisfied },
  {
    from: 'reportReview',
    to: 'released',
    requires: (context) => {
      if (!context.reviewChecklistComplete) return 'the pre-release review checklist is not complete';
      if (!context.finalPaymentReceived) return 'the final payment has not been recorded';
      return null;
    },
  },
  { from: 'released', to: 'retestPending', requires: satisfied },
  { from: 'retestPending', to: 'retestComplete', requires: satisfied },
  {
    from: 'retestComplete',
    to: 'closed',
    requires: (context) =>
      context.evidencePurged ? null : 'evidence has not been purged; closure requires it',
  },
  // A retainer or an engagement with no retest goes straight to closure.
  {
    from: 'released',
    to: 'closed',
    requires: (context) =>
      context.evidencePurged ? null : 'evidence has not been purged; closure requires it',
  },
  // Running an additional module after triage has begun is normal, not an exception.
  { from: 'triage', to: 'running', requires: satisfied },
  { from: 'manualTesting', to: 'running', requires: satisfied },
  { from: 'retestPending', to: 'running', requires: satisfied },
];

export type TransitionOutcome =
  | { allowed: true }
  | { allowed: false; reason: string; requiresBackwardsReason?: boolean };

/**
 * Backwards moves are allowed — a report goes back for edits, an engagement is re-scoped — but they
 * must carry a written reason, which lands in the audit log.
 */
export function canTransition(
  from: EngagementState,
  to: EngagementState,
  context: TransitionContext,
  backwardsReason?: string,
): TransitionOutcome {
  if (from === to) return { allowed: false, reason: 'the engagement is already in that state' };

  if (to === 'closed' && from !== 'released' && from !== 'retestComplete') {
    return {
      allowed: false,
      reason: 'an engagement can only be closed from released or retestComplete',
    };
  }

  const forward = FORWARD_RULES.find((rule) => rule.from === from && rule.to === to);
  if (forward) {
    const problem = forward.requires(context);
    return problem ? { allowed: false, reason: problem } : { allowed: true };
  }

  const order = STATE_ORDER.indexOf(to) - STATE_ORDER.indexOf(from);
  if (order < 0) {
    if (!backwardsReason || backwardsReason.trim().length < 10) {
      return {
        allowed: false,
        reason: 'moving an engagement backwards requires a written reason of at least 10 characters',
        requiresBackwardsReason: true,
      };
    }
    return { allowed: true };
  }

  return { allowed: false, reason: `there is no transition from "${from}" to "${to}"` };
}

export const STATE_ORDER: EngagementState[] = [
  'draft',
  'scoped',
  'authorised',
  'advancePaid',
  'readyToRun',
  'running',
  'triage',
  'manualTesting',
  'reportDraft',
  'reportReview',
  'released',
  'retestPending',
  'retestComplete',
  'closed',
];

/** What the client portal shows. Internal state names never reach a client. */
export const CLIENT_FACING_STATUS: Record<EngagementState, string> = {
  draft: 'Being scoped',
  scoped: 'Being scoped',
  authorised: 'Awaiting start',
  advancePaid: 'Awaiting start',
  readyToRun: 'Starting shortly',
  running: 'Testing in progress',
  triage: 'Testing in progress',
  manualTesting: 'Testing in progress',
  reportDraft: 'Report in preparation',
  reportReview: 'Report in preparation',
  released: 'Report released',
  retestPending: 'Awaiting your retest request',
  retestComplete: 'Retest complete',
  closed: 'Closed',
};

export function nextStates(from: EngagementState): EngagementState[] {
  return FORWARD_RULES.filter((rule) => rule.from === from).map((rule) => rule.to);
}
