/**
 * The ten steps of an engagement, from the first call to the deletion confirmation. Shown on
 * /how-we-work as a scroll-linked walkthrough, and again in condensed form on each service page.
 *
 * Every step names what the client does, what Attestor does, and the artefact that exists
 * afterwards. Steps without an artefact do not belong in this list.
 */

export interface TimelineStep {
  number: number;
  title: string;
  when: string;
  clientDoes: string;
  attestorDoes: string;
  artefact: string;
}

export const engagementTimeline: TimelineStep[] = [
  {
    number: 1,
    title: 'Scoping call',
    when: 'Day −7 to −3',
    clientDoes:
      'Describes the application, the roles, the environments and what is driving the deadline.',
    attestorDoes:
      'Asks the questions that change the price, and says plainly if the work is not worth doing yet.',
    artefact: 'A written scope and a fixed quote, usually the same day.',
  },
  {
    number: 2,
    title: 'Proposal and authorisation',
    when: 'Day −3',
    clientDoes:
      'Signs the statement of work and the authorisation to test, naming the exact assets and the test window.',
    attestorDoes:
      'Records the signer, the asset list and the window in the platform. Nothing can run outside them.',
    artefact: 'Signed statement of work, signed authorisation, data processing agreement.',
  },
  {
    number: 3,
    title: 'Access and credentials',
    when: 'Day −2',
    clientDoes:
      'Submits test accounts through a one-time link, two per role, and allowlists our source address.',
    attestorDoes:
      'Verifies every account works, confirms the environment, and sets the retention period.',
    artefact: 'Verified credential set with an expiry date, held encrypted.',
  },
  {
    number: 4,
    title: 'Pre-flight checks',
    when: 'Day 0, morning',
    clientDoes:
      'Confirms backups exist and nominates a contact who can stop the test at any moment.',
    attestorDoes:
      'Runs the engagement in dry-run first, showing exactly which targets and checks will run, and confirms the rate limits.',
    artefact: 'Pre-flight checklist, signed off before anything is sent.',
  },
  {
    number: 5,
    title: 'Automated discovery and scanning',
    when: 'Day 0',
    clientDoes: 'Nothing. This runs unattended, inside the agreed window and rate limits.',
    attestorDoes:
      'Enumerates the attack surface, runs the tool suite, and captures the evidence with masking applied as it is written.',
    artefact: 'Asset inventory and a queue of candidate findings, none of them reported yet.',
  },
  {
    number: 6,
    title: 'Triage',
    when: 'Day 1',
    clientDoes: 'Nothing.',
    attestorDoes:
      'Validates every candidate by hand, kills the false positives, and merges what several tools found separately.',
    artefact: 'A confirmed finding list. Anything not reproduced is discarded, not reported.',
  },
  {
    number: 7,
    title: 'Manual testing',
    when: 'Days 1 to 4',
    clientDoes:
      'Answers occasional questions about how a workflow is supposed to behave. This is worth the interruption.',
    attestorDoes:
      'Tests access control across every role pair, the business logic, the multi-step flows, and chains what is chainable. This is the part a scanner cannot do and the part the fee is for.',
    artefact: 'Manual findings with reproduction steps and a written attack narrative.',
  },
  {
    number: 8,
    title: 'Critical findings raised immediately',
    when: 'As they are found',
    clientDoes: 'Acts on it.',
    attestorDoes:
      'Contacts the nominated escalation contact as soon as a critical finding is validated, ahead of the report, with the reproduction steps.',
    artefact: 'An out-of-band notification, logged with a timestamp.',
  },
  {
    number: 9,
    title: 'Report and walkthrough',
    when: 'Day 5',
    clientDoes: 'Reads it, then brings the engineers who will fix it to a 30-minute call.',
    attestorDoes:
      'Delivers the report, the attestation letter and the portal access, then walks the developers through each finding.',
    artefact:
      'Assessment report, attestation letter, portal access, and a remediation order that reflects effort as well as severity.',
  },
  {
    number: 10,
    title: 'Retest and evidence deletion',
    when: 'Within 30 days, then at retention expiry',
    clientDoes: 'Requests the retest from the portal once the fixes are deployed.',
    attestorDoes:
      'Re-verifies each finding, issues the retest report, and deletes the evidence when retention expires.',
    artefact: 'Retest report, updated attestation letter, written deletion confirmation.',
  },
];
