# Checklists

The checklists the firm actually runs on. Some are enforced by the platform; those say so and name
the code that enforces them. The rest are human procedure, which means they only work if they are
short enough to be used — so nothing here is padded.

A checklist item is either mechanically checkable or a judgement a person has to make. Where it is
mechanical, the platform checks it and the item exists here for the reader's understanding, not for
someone to tick twice.

Contents:

1. [Pre-engagement](#1-pre-engagement) — before anything runs
2. [Engagement kickoff](#2-engagement-kickoff)
3. [Before a live run](#3-before-a-live-run)
4. [Daily during testing](#4-daily-during-testing)
5. [Finding quality](#5-finding-quality-per-finding)
6. [Pre-release](#6-pre-release-enforced-by-the-platform)
7. [Report delivery](#7-report-delivery)
8. [Retest](#8-retest)
9. [Engagement closure](#9-engagement-closure)
10. [Incident: something broke](#10-incident-something-broke-at-the-client)
11. [Incident: we may be compromised](#11-incident-we-may-be-compromised)
12. [Deployment](#12-deployment)
13. [Adding a tool](#13-adding-a-tool)
14. [Quarterly platform review](#14-quarterly-platform-review)

---

## 1. Pre-engagement

Nothing runs until every line is true. Not "mostly true".

- [ ] Scoping call held. Notes written up **and sent back to the client for correction**.
- [ ] Asset list received in writing from the client. We do not assemble a scope from a scan and
      then ask them to confirm it — that is the wrong way round and it is how third parties get
      tested.
- [ ] Ownership confirmed for every asset. Where an asset is on shared or third-party hosting, the
      hosting party's written acknowledgement is on file, not just the client's.
- [ ] Cloud provider testing policy read and acknowledged, if any cloud asset is in scope.
- [ ] Authorisation form signed by a named individual with the authority to sign it, with a
      valid-from and a valid-until date.
- [ ] Our fixed egress IP given to the client and allowlisted at their end.
- [ ] Emergency contacts exchanged both ways, including out of hours.
- [ ] Test window agreed and entered into the engagement policy.
- [ ] Never-touch list agreed in writing: production payment flows, anything that sends real mail or
      SMS to real people, anything with a third-party rate ceiling, anything the client says.
- [ ] Data handling agreed: what we may store, for how long, and what happens at closure.
- [ ] Rate limits agreed, and the client told what they will see in their monitoring.
- [ ] The client has been told, in the words the report will use, what "critical" means to us.

**Platform enforcement:** the scope guard refuses every launch without a signed, unexpired,
unrevoked authorisation, and refuses any never-touch item **before** it checks authorisation — so a
signature does not unlock the payment flow.

## 2. Engagement kickoff

- [ ] Engagement created; client, dates, test type and CVSS version set.
- [ ] Scope entered — included and excluded, one item per line, wildcards deliberate.
- [ ] Policy profile chosen and any deviation from it written down with a reason.
- [ ] Credentials received **through the vault link**, never by email or chat. Test accounts, not
      real user accounts. Two accounts per role where access control will be tested.
- [ ] Credential expiry set to the end of the engagement.
- [ ] **Dry run performed and read.** Every check runs and nothing is sent. If the list of targets
      is not exactly what you expected, stop and fix the scope.
- [ ] Kickoff message sent: start date, what the client will see, who to call.

## 3. Before a live run

- [ ] Inside the agreed test window.
- [ ] Authorisation still valid today, not just when the engagement started.
- [ ] Dry run of this specific tool and target set reviewed.
- [ ] Rate limit appropriate to the target, not just to the policy ceiling. A staging box on a
      shared host is not a production cluster.
- [ ] Client told if this run is materially louder than the last one.
- [ ] Somebody is available to press the panic stop for the duration.

**Platform enforcement:** window, authorisation validity, scope, never-touch list, panic-stop state,
and rate ceilings are all checked in `runToolForEngagement` before a container starts. If any target
fails, the **whole run** is refused rather than filtered.

## 4. Daily during testing

- [ ] Job queue checked for failures.
- [ ] Refusals reviewed. A repeated refusal means a scope item is wrong or somebody is arguing with
      the guard; both need a person.
- [ ] Any critical finding notified out of band **the day it is confirmed**, not at report time.
- [ ] Client's monitoring questions answered same day. They are paying partly for the reassurance.

## 5. Finding quality (per finding)

Before a finding leaves triage:

- [ ] Manually verified. A tool's opinion is a candidate, not a finding.
- [ ] Evidence attached, masked at capture, and sufficient for the client to reproduce.
- [ ] Reproduction steps numbered, specific, and actually followed once from a clean state.
- [ ] Business impact stated in the client's terms, not "an attacker could execute arbitrary code".
- [ ] Attacker prerequisites stated. "Requires an authenticated staff account" changes the whole
      conversation.
- [ ] Likelihood stated honestly, including when it is low.
- [ ] Remediation is specific to their stack — a version number, a configuration line, a code
      change — not a link to a general article.
- [ ] CVSS vector present, not just a score. Any override of the computed severity carries a written
      reason.
- [ ] Reference is quotable and current.
- [ ] Duplicate check done against the engagement's other findings and the previous report.
- [ ] Nothing invented. No CVE, reference, metric or vector that has not been checked.

## 6. Pre-release (enforced by the platform)

These are the eighteen items the console runs before it will release a report. Fifteen are checked
mechanically; three require a person, and the API re-runs the whole list at release time so that a
green screen is not the gate.

**Checked mechanically:**

- [ ] Every finding carries evidence
- [ ] Every finding carries specific remediation
- [ ] Every finding states a business impact, not just a technical one
- [ ] Every finding has numbered reproduction steps
- [ ] Every finding has a quotable reference
- [ ] No unconfirmed candidate has reached the report
- [ ] Every finding carries a CVSS vector, not just a score
- [ ] Every severity override carries a written justification
- [ ] The coverage matrix explains everything not fully tested
- [ ] No unfilled placeholder remains in the legal text
- [ ] No draft marker or placeholder prose remains in the body
- [ ] The client name appears and is not a leftover from another engagement
- [ ] The executive summary is written and is not a list of findings
- [ ] Positive observations are recorded
- [ ] A prioritised remediation roadmap is present

**Requires a person to confirm:**

- [ ] Every critical finding was notified out of band before the report
- [ ] Evidence has been reviewed and contains no unmasked personal data
- [ ] I have read every line of this report

The last one is worded as a claim rather than a box on purpose. It is the only item where the
system is trusting a statement, and it should feel like one.

## 7. Report delivery

- [ ] Peer review by someone who did not write it. If the firm is one person today, this is the
      point at which that becomes a real limitation, and it should be said to the client rather than
      quietly skipped.
- [ ] Report released in the portal. **Nothing is emailed as an attachment.**
- [ ] Notification drafted, read by a human, and sent by a human. The platform queues it; it does
      not send it.
- [ ] Debrief call offered, and offered to the technical team as well as to the buyer.
- [ ] Retest window explained: one retest included within thirty days of release.
- [ ] Client told how long we will hold their evidence and what happens at the end of it.

## 8. Retest

- [ ] Retest request received in the portal, with the client's note.
- [ ] Within the free window? If not, quoted as a separate engagement **before** anything runs.
- [ ] Authorisation still valid, or re-signed.
- [ ] Only findings the client has marked fixed are verified. Verifying everything again is a new
      assessment, and charging for one while calling it the other is dishonest.
- [ ] Each retested finding gets an explicit outcome: verified fixed, still open, regressed, risk
      accepted, or not retested — with a reason for the last one.
- [ ] Retest report references the original report version, so the two can be read together.

## 9. Engagement closure

- [ ] All findings have a final status.
- [ ] Client has downloaded what they need from the portal.
- [ ] Client credentials **rotated at their end**, and the date recorded.
- [ ] Our copy shredded: closing the engagement destroys the key salt, and after that no key opens
      those credentials — not for an attacker, not for us.
- [ ] Evidence retention date set and the retention worker confirmed to be scheduled.
- [ ] Lessons written down: what the tooling missed, what took too long, what the client found
      confusing in the report.

## 10. Incident: something broke at the client

**Press the panic stop first.** Diagnose second. An unnecessary stop costs an hour; a run that
should have been stopped and was not costs the firm.

- [ ] Panic stop pressed, with a reason.
- [ ] Client called — called, not emailed.
- [ ] Audit log read: what was running, since when, against what, with which command.
- [ ] Timeline sent to the client. Facts only. No speculation about causation before you have it.
- [ ] Root cause established: was it us, was it a coincidence, or was it a real fragility in their
      environment? All three happen, and the third is a finding.
- [ ] Written up honestly, including in the report if it is relevant to their risk.
- [ ] Stop cleared deliberately, with a reason. Stops do not expire on their own, because "it timed
      out" is not a decision anybody made.

## 11. Incident: we may be compromised

Assume the worst ordering: an attacker who reaches this platform gets several clients' credentials
and their unfixed vulnerabilities at once.

- [ ] Isolate: stop the worker, kill every run container, block egress.
- [ ] Preserve: snapshot the host before changing anything. Copy logs off the host **first** —
      an attacker who owns the host can edit the record of owning it.
- [ ] Assess: which engagements, which credentials, which reports.
- [ ] Notify every affected client **the same day**, with what is known and what is not. A firm that
      writes disclosure findings for a living does not get to be slow about its own.
- [ ] Instruct clients to rotate every credential they gave us.
- [ ] Rotate `VAULT_MASTER_KEY`, `SESSION_SECRET`, database passwords, WireGuard keys.
- [ ] Rebuild the host from scratch. Do not clean it.
- [ ] Post-incident review, written, published internally, with dated actions.

## 12. Deployment

- [ ] `pnpm check` green: lint, typecheck, unit and property tests, claim check.
- [ ] Integration suite green against the local vulnerable stack.
- [ ] Migrations reviewed by eye. A migration that drops a column is read twice.
- [ ] Backup taken **and restored somewhere** before a migration that is not reversible.
- [ ] Deployed. Health checks green. A real page loaded on both surfaces.
- [ ] Security headers checked on the portal after the deploy, not before it.
- [ ] Rollback plan known before starting, not improvised afterwards.

## 13. Adding a tool

- [ ] Licence checked. Free or open source only. No paid tool, no trial key, nothing cracked, and
      nothing whose licence forbids commercial use — including the tool's rule or template packs,
      which sometimes carry a different licence from the tool.
- [ ] Image added to `tool-images.ts` with an honest timeout and memory limit.
- [ ] `node scripts/pin-tool-images.mjs --pull` run. Without a pinned digest the tool will not start.
- [ ] Adapter written: `buildInvocation` plus a **pure** `parse`.
- [ ] `coversCheckIds` claims only what the tool actually tests. This feeds the coverage matrix, and
      overclaiming here is how a report ends up lying about coverage.
- [ ] Real sample output saved as a fixture, plus hostile samples: empty, `{}`, truncated JSON, a
      string where the schema says array.
- [ ] Command asserted to contain no flag capable of producing load beyond the policy ceiling.
- [ ] Rate limits read from the resolved policy, never hardcoded in the adapter.

## 14. Quarterly platform review

- [ ] Restore drill from the off-site backup, onto a scratch host.
- [ ] Dependency review: `pnpm outdated -r`, and read what changed.
- [ ] Tool images re-pinned deliberately, in a batch, never mid-engagement.
- [ ] Portal access reviewed with each client: anyone who has left should be deactivated.
- [ ] Audit log sampled: does it actually answer "who did what, when"?
- [ ] Threat model re-read. Are the accepted risks still the ones we would accept today?
- [ ] ASVS self-assessment re-checked against any chapter whose subject matter changed.
- [ ] The two open gaps checked for progress: off-host log shipping, and alerting.
