# Build status

Resume point for this build. Update it whenever a milestone lands, so a new session can pick up
from here without re-reading the whole repository.

**Last updated:** 2026-08-25, after the platform was run end to end against a real Postgres and both
surfaces were driven through their real APIs in a browser. Eleven defects were found and fixed; they
are listed under "Bugs found and fixed" below, starting at number 11.

---

## The gate, right now

| Check | Command | State |
| --- | --- | --- |
| Lint | `pnpm lint` | passing |
| Typecheck (workspaces) | `pnpm typecheck` | passing |
| Typecheck (root project) | `pnpm exec tsc -p tsconfig.json --noEmit` | passing |
| Unit and property tests | `pnpm test` | **354 passing, 27 files** |
| Claim check | `pnpm check:claims` | passing, 279 files scanned |
| Marketing site build | `pnpm --filter @attestor/website build` | passing, 22 pages indexed |
| Console build | `ATTESTOR_SURFACE=console pnpm --filter @attestor/console build` | passing |
| Portal build | `ATTESTOR_SURFACE=portal pnpm --filter @attestor/console build` | passing |
| XSS corpus integration | `ATTESTOR_TEST_NETWORK_ONLY=1 pnpm test:integration -- xss-corpus` | **26 passing, verified in a real browser** |
| Both surfaces in a browser | `pnpm --filter @attestor/console dev` | **every page rendered against a stub API; all 200, no CSP violations** |
| End-to-end flows against real Postgres | see "Running it without Docker" below | **110 checks passing across four flows** |
| Portal signed into in a browser, real API | `next start` on the portal build | **sign-in, MFA, dashboard and findings verified; page hydrates, no CSP violations** |

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

Eleven more, found on 2026-08-25 by running the platform end to end for the first time — a real
Postgres 16, the real API processes, the real migrations and seed, and the portal driven through a
browser. Every one of these passed lint, typecheck and the whole test suite beforehand.

11. **The portal API could not connect to its own database.** Migration `0001` creates
    `attestor_portal` as `NOLOGIN` with no password, while compose hands `portal-api` a password
    connection string. `docker compose up` crash-loops the portal on `password authentication
    failed`, so the documented five-minute quickstart cannot work. The password is now set by
    `migrate.ts` from `PORTAL_DB_PASSWORD`, which is the one step every deployment path already
    runs as the owner.
12. **Client onboarding was impossible.** `0001` revokes `client_invitation` from the portal role
    and grants no `INSERT` on `client_user`, but `/invitations/accept` is a portal route that needs
    both — it was correct when the console pre-created the account, and became wrong when bug 5
    moved creation to acceptance. Every acceptance failed with a permission error, so no client
    could ever reach the portal. Migration `0003` grants exactly what that route needs.
13. **Nobody could sign in through either UI.** The API issues its session cookie in a
    `Set-Cookie` header; `apps/console/src/lib/api.ts` read the body and dropped the header, so the
    browser never received `attestor_session` and the second factor was answered with "not signed
    in". Invisible to the build, the typecheck and the tests, and invisible to the stub API the
    pages were previously rendered against, because a stub has no session to issue.
14. **Bug 7 again, by another route.** The nonce fix works only on pages rendered per request. A
    statically prerendered page is built before any request exists, so its scripts carry no nonce,
    and `'strict-dynamic'` tells the browser to ignore `'self'` and refuse them — `/login`,
    `/login/mfa` and `/clients/new` rendered and then did nothing. Only visible in a production
    build, because the development policy is looser. The root layout is now `force-dynamic`.
15. **A TOTP code worked more than once.** `verifyTotp` accepted any code inside its window, so the
    same six digits authenticated repeatedly for up to ninety seconds — the one property a second
    factor exists to deny. Codes are now spent against a recorded timestep in the database, so the
    rule holds across processes rather than in one process's memory.
16. **Scope accepted what the platform exists to refuse.** `validateScopeItem` checked syntax only:
    `127.0.0.1`, `10.0.0.5`, `169.254.169.254`, `*.gov.in` and `*.com` were all accepted into an
    engagement's scope. The run-time guard still refused them, so nothing would have been scanned —
    but one bad entry refuses the *entire* run on test day, which is exactly what validating at
    entry is for. Entry validation now applies the same rules, including a client's declared
    private ranges.
17. **A staff session on the portal was a 500.** `resolveSession` looks up `staff_user`, which the
    portal role is correctly denied, so the guard raised a database error instead of returning the
    403 it intended — and the 500 distinguished a real staff token from a meaningless one on a
    public surface. It now refuses on the session row, before the lookup.
18. **A mistyped id was a 500.** Postgres rejects a malformed uuid with a type error, so any
    non-uuid in a path reached the database and came back as an unhandled error. A single guard now
    refuses id-shaped parameters that are not uuids, with the same body a missing row gets.
19. **Cross-site request forgery protection was registered and never applied.**
    `@fastify/csrf-protection` only adds `reply.generateCsrf()` and `app.csrfProtection`; neither
    was used by any route, so nothing checked a token anywhere — while the portal's own comment
    claimed every state-changing method was protected. Replaced with an origin check that cannot be
    forgotten by a route author, and the dependency removed.
20. **Saving any finding was a 500.** `ae-cvss-calculator` is CommonJS, and Node puts its exports
    on `default` while Vite hoists them onto the namespace. The namespace form passed all ten CVSS
    tests under Vite and threw `Cvss3P1 is not a constructor` under Node on the first finding
    anybody saved. Fixed to work under both, with a test that runs the module under plain Node —
    the only way that class of divergence is visible before production.
21. **The panic stop reported failure while succeeding.** The kill sweep talks to the container
    daemon, and when that daemon is unreachable — which is precisely when a stop matters — the
    error propagated out of the route, skipping the audit record and answering the operator with
    "internal error" even though the stop was in force and new runs were already refused. It now
    engages, reports what it could not confirm, and still writes the audit entry.

Two more that are documentation rather than code, both worth fixing before anyone follows the
instructions:

- `docs/RUNBOOK.md` and `infra/.env.example` tell the reader to generate passwords with
  `openssl rand -base64 32`. Base64 emits `/` and `+`, and compose interpolates the value straight
  into `postgres://attestor:${POSTGRES_PASSWORD}@…`, where those characters end the password early.
  Use a URL-safe alphabet for anything that lands in a connection string.
- The seed printed the demo account's enrolment URL through the logger, which redacts anything
  shaped like a secret — so it arrived as `secret=[REDACTED]` and the demo account could never be
  enrolled. It now writes `.seed-credentials.txt` (gitignored) and logs the path.

---

## Not done

Ranked by what should happen next.

> Note: `apps/console/.env.local` is currently set to `ATTESTOR_SURFACE=console`. It is a gitignored
> local-development file; flip it to `portal` and restart the dev server to work on that surface.

1. **A live tool run has never been executed.** This is now the only part of the platform that has
   not been exercised. It needs a container daemon:
   `docker compose -f infra/docker-compose.test.yml up -d --wait`, then
   `apps/api/src/engagement-run.integration.test.ts`. Everything the run depends on either side of
   the container — scope guard, policy resolution, run records, queueing, evidence capture — has
   been run for real.
2. **The stack has never been booted under compose.** Docker Desktop on this machine is broken: the
   `docker-desktop` WSL distribution is missing and only `docker-desktop-data` remains, so the
   daemon does not start. The platform itself has been run end to end without it — see below — but
   the compose file, the Dockerfile and the image build are still unexercised.

### Running it without Docker

Everything except tool containers runs against a real Postgres with no daemon, which is how the
defects above were found. A real Postgres 16 matters rather than a stub: migration `0001` creates
the least-privilege portal role, and it is the role grants that make the portal's isolation real.

- `npm i embedded-postgres@16` in a scratch directory gives real Postgres 16 binaries. Initialise
  with `--encoding=UTF8 --data-checksums` to match compose, and start it on a spare port.
- Point `DATABASE_URL` and `PORTAL_DATABASE_URL` at it, then run the repository's own
  `apps/api/src/db/migrate.ts` and `apps/api/src/db/seed.ts` unchanged.
- `buildConsoleServer(context, queues)` and `buildPortalServer(context)` both take their
  dependencies as arguments, so the API runs unmodified with an in-process stand-in for the queue
  and a small S3-compatible listener in place of MinIO. Nothing in `apps/` or `packages/` has to
  change to do this.
- Passwords that end up in a connection string must use a URL-safe alphabet. See the note at the
  end of the bug list.

Verified this way: the portal role cannot read `credential_set`, `staff_user`, `authorisation`,
`panic_stop`, `ai_usage` or `client_invitation` beyond what migration `0003` grants; the audit log
refuses `UPDATE`, `DELETE` and `TRUNCATE` even to the owner role; one tenant cannot read, comment
on, change the status of, or request a retest against another tenant's findings or engagements by
direct id or by filter; and a finding whose every free-text field carries `<script>` renders as
text in the report HTML, in the portal, and inside Next's flight payload, where `<` arrives as
`<`.
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
