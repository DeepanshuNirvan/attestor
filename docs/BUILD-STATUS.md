# Build status

Resume point for this build. Update it whenever a milestone lands, so a new session can pick up
from here without re-reading the whole repository.

**Last updated:** 2026-08-23, after the AI-assist layer landed and both surfaces were run in a browser.

---

## The gate, right now

| Check | Command | State |
| --- | --- | --- |
| Lint | `pnpm lint` | passing |
| Typecheck (workspaces) | `pnpm typecheck` | passing |
| Typecheck (root project) | `pnpm exec tsc -p tsconfig.json --noEmit` | passing |
| Unit and property tests | `pnpm test` | **334 passing, 23 files** |
| Claim check | `pnpm check:claims` | passing, 267 files scanned |
| Marketing site build | `pnpm --filter @attestor/website build` | passing, 22 pages indexed |
| Console build | `ATTESTOR_SURFACE=console pnpm --filter @attestor/console build` | passing |
| Portal build | `ATTESTOR_SURFACE=portal pnpm --filter @attestor/console build` | passing |
| XSS corpus integration | `ATTESTOR_TEST_NETWORK_ONLY=1 pnpm test:integration -- xss-corpus` | **26 passing, verified in a real browser** |
| Both surfaces in a browser | `pnpm --filter @attestor/console dev` | **every page rendered against a stub API; all 200, no CSP violations** |

Everything above has been run. Nothing in this table is an expectation.

---

## Done

### PART A — the marketing site (`apps/website`)

Astro 7 static site: pages, content collections, four zero-JS islands, Pagefind search, build-time
OG images via satori, self-hosted OFL fonts, strict headers, published prices, sample report page.
Builds clean and typechecks clean.

### PART B — the platform

- **`packages/shared`** — redaction, masking (Luhn + Verhoeff), logging, config, ids
- **`packages/findings`** — 210-check catalogue, CVSS 3.1 + 4.0, dedupe, diff, coverage matrix
- **`packages/core`** — scope guard, engagement state machine, container runner, audit log,
  AI-assist layer, architecture test
- **`packages/policy`** — schema, resolution, five profiles, cloud provider testing policies
- **`packages/scanners`** — adapters with pure parsers, fixtures, hostile-input tests
- **`packages/report`** — renderer, legal blocks, pre-release checklist, PDF, golden file
- **`apps/api`** — console API, portal API, workers, queue, services. Route modules: ai, auth,
  client, engagement, finding, report, platform
- **`apps/console`** — Next 16, both surfaces from one codebase, gated by `ATTESTOR_SURFACE`

### Console surface pages

`/`, `/engagements`, `/engagements/[id]`, `/engagements/[id]/triage`, `/engagements/[id]/report`,
`/clients`, `/clients/new`, `/clients/[id]`, `/queue`, `/legal`, `/settings`, `/login`, `/login/mfa`

Every one rendered against a stub API and returned 200. The shell renders, the pages hydrate, there
are no CSP violations, and the portal's route prefixes return 404 on this surface.

### Portal surface pages

`/`, `/findings`, `/findings/[id]`, `/reports`, `/reports/[id]`, `/reports/[id]/download`,
`/retest`, `/questionnaire`, `/account`, `/invitation/[token]`, `/login`, `/login/mfa`

The same, in the other direction — every page 200, and the console's route prefixes return 404 on
this surface. Two specific checks worth keeping:

- A finding whose evidence body is `<script>alert(1)</script>` renders it as visible text, with zero
  script elements inside the evidence block and nothing executed.
- The in-portal report view is a `srcdoc` frame with `sandbox=""`. The parent page cannot read into
  it at all — the frame has an opaque origin.

Each page was rendered against a throwaway stub API (in the scratchpad, not the repository). The
three failures it surfaced were all wrong shapes in the stub, not in the pages; the pages matched
the real route handlers in every case.

### The AI-assist layer (M11)

Off by default and off unless a specific engagement turns it on. Input redacted before the request
is built; output checked against the evidence and discarded if it introduces a host, URL or CVE that
is not there; every request recorded with model, purpose, tokens, cost and a prompt hash; every
output a draft, with release blocked until a person approves it. Agentic testing returns a typed
refusal naming the four things that would have to exist first. 18 tests, none of which touch a
network or need a key.

### Documentation

`README.md`, and in `docs/`: `USER-GUIDE.md`, `ARCHITECTURE.md`, `DEPLOYMENT.md`, `COMMANDS.md`,
`POLICY-COOKBOOK.md`, `SALES-PLAYBOOK.md`, `RUNBOOK.md`, `THREAT-MODEL.md`, `CHECKLISTS.md`,
`ASVS-SELF-ASSESSMENT.md`, `DECISIONS.md`, `RESEARCH-NOTES.md`, and this file.

### CI

`.github/workflows/ci.yml` — lint, typecheck (both projects), tests, claim check, three builds; a
separate integration job that starts the vulnerable stack and runs the suite behind the network
guard.

---

## Bugs found and fixed during the build

Kept because each one is a class of mistake worth not repeating.

1. **Panic stop killed nothing.** `killAllRunContainers` filters by label, but `createContainer`
   never set any. Fixed, plus a unit test asserting the labels are on every run.
2. **Portal tenancy.** A status update and a comment checked ownership but not finding status,
   letting a client act on an unconfirmed candidate. Found by the structural test.
3. **Client TOTP secrets stored in the clear.** The column is named `totpSecretSealed` but the
   portal wrote raw base32 into it, while staff secrets were sealed. Now sealed under a separate
   `PORTAL_TOTP_KEY`, with three structural tests to stop it coming back.
4. **The seeded demo account could not sign in.** The seed wrote a plaintext TOTP secret that the
   login route tried to `JSON.parse`. Now sealed the same way the bootstrap route seals it.
5. **A half-made client account on invite.** The console pre-created a `clientUser` row with no
   password, which then blocked the portal's `onConflictDoNothing` insert on acceptance. The row is
   now created once, at acceptance, with the password and the authenticator together.
6. **`satori` typing.** Installing `@types/react` for the console made the OG route fail
   typecheck. Fixed with a named conversion at the boundary rather than by adding React to a
   JSX-free project.
7. **The console's own CSP blocked the console.** `script-src 'self'` as a static header in
   `next.config.ts` blocked Next's inline bootstrap and flight payload, so every page rendered and
   then did nothing — no hydration, no server actions. Only visible by loading a page in a browser;
   the build, the typecheck and the tests were all green. Now a per-request nonce issued by
   `src/proxy.ts`, with eleven tests in `src/lib/csp.test.ts` covering the static version coming
   back and the two-policies-intersect version of the same mistake.
8. **A failed API call showed a Next error page.** Added `app/error.tsx` and `app/not-found.tsx`,
   which say what happened and show only the digest — no message, no stack.
9. **The report list linked "Read" for documents that have no readable version.** An attestation
   letter is a PDF; the portal now offers a download for those and a reader only for the ones that
   have rendered HTML.
10. **The console could not ask for two documents the API can produce.** The attestation letter and
    the deletion confirmation had routes and no buttons.

---

## Not done

Ranked by what should happen next.

> Note: `apps/console/.env.local` is currently set to `ATTESTOR_SURFACE=console`. It is a gitignored
> local-development file; flip it to `portal` and restart the dev server to work on that surface.

1. **A live run has never been executed.** Docker is not running on this machine, so
   `apps/api/src/engagement-run.integration.test.ts` has been written and typechecked but not run.
   It needs `docker compose -f infra/docker-compose.test.yml up -d --wait`.
2. **The stack has never been booted end to end.** Same reason. `docker compose -f
   infra/docker-compose.yml up -d`, then migrate, then seed, then click through both surfaces.
3. **`infra/tool-images.lock.json` does not exist yet.** `node scripts/pin-tool-images.mjs --pull`
   writes it, and until then no tool will start — by design.
4. **Off-host log shipping and alerting.** The two real gaps in the ASVS self-assessment, in V16.
5. **Legal text is not lawyer-reviewed.** Every block carries `lawyerReviewedAt: null` and documents
   render with a visible draft banner until that changes. Tracked by the pre-release checklist.
6. **A model has never actually been called.** The AI layer is fully implemented and fully tested
   against an injected transport, but no request has gone to a provider — there is no key here, and
   the default configuration refuses everything anyway. The first real call should be made on a
   scratch engagement with a low budget ceiling.
7. **Notification sending is deliberately manual.** There is no SMTP client anywhere. Approving
   records the decision; a person sends the message and marks it sent. If that ever changes, it is a
   design decision, not a feature.

---

## Conventions a new session must not break

- Node 22 with `--experimental-strip-types`. No transpiler. Import specifiers end in `.ts`.
- No `any`, no leading-underscore names, no dead or commented-out code. Unused parameters are
  prefixed `unused`.
- Exactly one module may import `dockerode`. Enforced by ESLint and by an architecture test.
- Nothing in the policy schema may express a denial-of-service test.
- No claim of CERT-In empanelment, CREST accreditation or any certification the firm does not hold.
  `pnpm check:claims` fails the build on one.
- Nothing is ever sent to a client automatically.
- zod v4: `.prefault({})` for nested defaults, not `.default({})`.
- British spelling throughout, including in identifiers such as `authorisation`.
