/**
 * The pre-flight checklist.
 *
 * `docs/CHECKLISTS.md` §3 in code, because `advancePaid → readyToRun` gates on it and there is no
 * override for that gate — unlike the advance payment, which is a business rule.
 *
 * The list lives here rather than in the console because the server decides the gate. Checking only
 * that "some entries exist and all are true" would let a caller satisfy a safety gate with one
 * invented key, which is the same mistake as trusting the console's own checklist panel instead of
 * re-running the release checklist server-side.
 */

export interface PreFlightItem {
  id: string;
  label: string;
  /** Why it is on the list, shown beside the box so it is not ticked out of habit. */
  note: string;
}

export const PRE_FLIGHT_CHECKLIST: readonly PreFlightItem[] = [
  {
    id: 'inside-test-window',
    label: 'Inside the agreed test window',
    note: 'The guard refuses outside it. Confirming here means the window on file is the one the client agreed to.',
  },
  {
    id: 'authorisation-valid-today',
    label: 'The authorisation is valid today, not only when the engagement started',
    note: 'Windows expire mid-engagement more often than anyone expects.',
  },
  {
    id: 'dry-run-reviewed',
    label: 'A dry run has been performed and the target list read',
    note: 'Every check runs and no packet is sent. If the targets are not exactly what you expected, fix the scope.',
  },
  {
    id: 'rate-limit-suits-target',
    label: 'The rate limit suits this target, not just the policy ceiling',
    note: 'A staging box on shared hosting is not a production cluster.',
  },
  {
    id: 'client-told-if-louder',
    label: 'The client has been told if this run is materially louder than the last',
    note: 'They are paying partly for the absence of surprises in their monitoring.',
  },
  {
    id: 'someone-can-stop-it',
    label: 'Somebody is available to press the panic stop for the duration',
    note: 'A stop nobody is there to press is not a control.',
  },
];

const REQUIRED_IDS = new Set(PRE_FLIGHT_CHECKLIST.map((item) => item.id));

/** Items still unticked or absent. Empty means the gate is satisfied. */
export function missingPreFlightItems(confirmations: Record<string, boolean>): string[] {
  return PRE_FLIGHT_CHECKLIST.filter((item) => confirmations[item.id] !== true).map(
    (item) => item.id,
  );
}

/** Ids the caller sent that are not on the list, so a typo fails loudly rather than silently. */
export function unknownPreFlightItems(confirmations: Record<string, boolean>): string[] {
  return Object.keys(confirmations).filter((id) => !REQUIRED_IDS.has(id));
}
