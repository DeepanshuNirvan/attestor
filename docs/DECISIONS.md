# Decisions

One line of reasoning per decision. Newest at the bottom.

## Toolchain

- **pnpm workspace, single TypeScript toolchain.** One lint config, one naming convention, no Python/JS style split; third-party security tools stay in pinned containers.
- **Node 22 LTS in `engines`, dev machine is on Node 20.14.** Build and CI target 22; the runbook lists the upgrade as step one of provisioning.
- **Astro 7.2.x, not the 5.x named in the brief.** The brief requires verifying versions before pinning; 5.x is two majors stale as of Aug 2026 and the content-layer API used here landed in 5 and is unchanged in 7.
- **Next.js 16.3.x, not 15.** Same reason. App Router, React 19.
- **Fastify 5.12.x + zod for edge validation.** Fastify 5 requires Node 20+, which the target already exceeds.
- **Drizzle ORM 0.45.x (stable), not the 1.0 beta.** A beta ORM under a system that holds client credentials is not a trade worth making; the upgrade path is a single migration-config change.
- **`ae-cvss-calculator` for CVSS 3.1 and 4.0 scoring.** CVSS 4.0 scoring is a 270-entry MacroVector lookup, not "a few lines"; hand-rolling it would be a correctness liability. Vector strings are still parsed and validated by our own grammar so a malformed vector fails at the edge.
- **Plain CSS with custom properties on the website, no Tailwind.** The brief permits Tailwind only with a bespoke token scale; plain CSS reaches the same place with fewer moving parts and no default palette to leak.
- **Vitest for unit and integration, Playwright for e2e, fast-check for the scope guard.** Already the brief's choice; no substitutions.

## Architecture

- **Single choke point for container execution.** `runToolForEngagement` is the only caller of the Docker client. An ESLint `no-restricted-imports` rule plus an architecture test fail the build if `dockerode` is imported anywhere else.
- **Scope guard returns a typed refusal, never a boolean.** Callers cannot accidentally treat `false` as "warn and continue", and the refusal carries the exact rule id for the audit log.
- **DNS resolution happens inside the guard and resolved IPs are re-checked against scope.** A scoped hostname pointing at someone else's shared host is the realistic way a legal engagement becomes an illegal one.
- **Wildcard scope matching is label-wise, never string-suffix.** `*.example.com` matching `notexample.com` or `example.com.attacker.net` is the failure mode that puts the founder in court; the guard splits on dots and compares labels.
- **Evidence masking at capture time, not render time.** Once raw personal data is on disk it is a DPDP problem regardless of what the report shows.
- **Portal is a separate Fastify app with its own database role and deployment.** It is the only public surface; it must not be able to import a console route or read the credential vault.
- **Append-only audit log enforced in Postgres, not by application discipline.** `UPDATE` and `DELETE` on `audit_log` raise an exception from a trigger.
- **Findings from tools and agents land as `candidate`.** Nothing reaches a report without a human confirming it; that is the difference between a report and a scanner export.
- **Correlation groups by root cause before the report renders.** One missing header across 40 endpoints is one finding with 40 affected assets.
- **AI layer off by default and the whole system functional without it.** `AI_ENABLED=false` removes every third-party model call; no code path degrades.
- **Secrets are sealed with libsodium `crypto_secretbox` under a per-engagement subkey derived from a master key in the environment.** Closing an engagement destroys the subkey material, which shreds every credential for that engagement without touching anyone else's.
- **Rate limiting is enforced in the outbound request layer, in code, with the policy able only to lower it.** A configuration mistake must not be able to produce flood-shaped traffic.

## Product

- **Prices live in `apps/website/src/data/pricing.ts`, one typed file.** The estimator, both pricing pages and the JSON-LD read from it, so the owner edits numbers once.
- **INR and USD pricing are separate pages with separate numbers, not a converter.** A live FX conversion would advertise the arbitrage and would misprice the international engagement, which is genuinely different work (timezone overlap, contract, turnaround commitment).
- **Website ships zero third-party runtime requests except the form endpoint and Cal.com on `/contact`.** A firm selling data hygiene cannot load a tracker.
- **No CERT-In empanelment claim anywhere.** `pnpm check:claims` greps the whole repo for banned claim strings and fails CI.
- **Legal text lives in `packages/report/legal/` as versioned templates with a review flag.** Until a block is marked lawyer-reviewed the console shows a banner and the website legal pages carry a draft notice.
- **Sample report is generated against OWASP Juice Shop, not a redacted client.** No consent problem, no redaction risk, and a reader can verify every finding themselves.

## Owner questions answered by default

These are PART E items with an obvious professional default. Each is a one-line placeholder the
owner overrides in `apps/website/src/data/site.ts` or `packages/report/legal/`.

- **Accent colour: deep green `#1F5F47`.** Navy reads as generic financial services; green is the less-used half of the security palette and pairs better with the warm off-white ground.
- **Booking: Cal.com free tier.** Self-hostable later without changing the link contract.
- **Evidence retention: 90 days**, per-engagement override.
- **AI layer: off by default, enabled per engagement.** Two switches, both required; the engagement flag alone does nothing without the deployment flag.
- **AI output is checked for grounding, not trusted to be grounded.** Hosts, URLs and CVE identifiers in a draft are compared against the evidence, and a draft that introduces one is discarded rather than shown with a warning. A warning is something a tired person clicks past.
- **AI budget is per engagement per calendar month**, defaulting to zero. A shared pool would let one noisy engagement spend another's.
- **Screenshots are never sent to a model**, only named. There is no reason to put a client's screen in front of a third party.
- **Agentic testing: refused in code, not merely unset.** The flag exists and a call returns a typed refusal naming what would have to be built first. A flag nothing reads is worse than no flag.
- **CVSS default: 4.0**, 3.1 selectable per engagement because many 2026 auditor templates still expect it.
- **Report spelling: British.** The firm is Indian and the international buyers are US/EU/Gulf; British spelling is the neutral choice and is what Indian corporate English already uses.
- **Client report downloads: allowed for `clientOwner` and `clientMember`, watermarked; `clientViewer` reads in-browser only.**
- **Advance-payment gate: enforced, but a documented override with a written reason.** Blocking scanning on an unreceived payment is a business rule, not a legal one; the audit log records who overrode it.
- **Staff accounts at launch: 1 owner + capacity for 2 testers.** No code assumes a single user.
