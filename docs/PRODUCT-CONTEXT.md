# Product context

The file to read first in a new session. It says what this is, what it is not, how it is built, how
to run it, what has actually been verified, and the mistakes that are easy to make in it.

`docs/BUILD-STATUS.md` is the live state of the work. This document is the stable picture behind it.
`docs/OPERATOR-HANDBOOK.md` is the same ground in plain English, for running the firm rather than
changing the code — read that one for client onboarding and for how to verify a client owns what
they gave you.

---

## 1. What this repository contains

**Two products, one repository.** They share nothing at runtime and are hosted in completely
different ways. Confusing them is the most common mistake a new session makes.

| | `apps/website` | Everything else |
| --- | --- | --- |
| What it is | The marketing site — the public showcase | **Attestor Console**, the platform engagements run on |
| Stack | Astro, static output | Fastify APIs, Next.js UIs, Postgres, Redis, MinIO, a worker |
| Server | **None.** Files on a CDN | One VPS |
| Database, object store, login | **None of them** | All of them |
| If compromised | A page is defaced | Everything |

So: `DATABASE_URL`, `S3_*`, `REDIS_URL`, `VAULT_MASTER_KEY` belong to the *platform*. The website
never sees any of them and has nothing to attack. That is the point of building it that way.

### The platform, in one paragraph

A firm runs penetration tests. Attestor Console is the machinery around that: it decides whether a
target may be touched at all, starts security tools in hardened containers, turns their output into
candidate findings that a human confirms, and produces the report — with a coverage matrix generated
from what actually ran rather than from what was intended. Clients read the result in a portal
instead of receiving an emailed PDF.

---

## 2. The shape of it

```
apps/website/     Astro static site. Services, published prices, sample report, insights, legal
apps/api/         Fastify: console API (8080), portal API (8081), workers
apps/console/     Next.js. BOTH UI surfaces from one codebase, gated by ATTESTOR_SURFACE
packages/shared/  Redaction, masking, logging, config, ids. Depends on nothing
packages/findings/ 235-check catalogue, CVSS 3.1 + 4.0, OWASP risk rating, dedupe, diff, coverage
packages/policy/  Policy schema, layer resolution, five profiles
packages/core/    Scope guard, state machine, container runner, audit log, AI assist
packages/scanners/ One adapter per tool. `parse` is a pure function over a string
packages/report/  Renderer, legal blocks, release checklist, PDF
infra/            Compose, Dockerfile, migrations, deliberately vulnerable test targets
```

Dependencies point one way: apps depend on packages, packages depend on packages below them, and
nothing depends on an app.

### The console and the portal are the same code, deployed twice

`ATTESTOR_SURFACE=console` or `portal`, baked in at **build** time, not chosen at run time. A
middleware returns 404 for the other surface's routes, so a misconfiguration fails closed. Two
images rather than one with a switch, because one image is a single environment variable away from
serving the staff console to a client.

---

## 3. How an engagement actually flows

Fourteen states. Two are gates.

```
draft → scoped → authorised → advancePaid → readyToRun → running → triage
      → manualTesting → reportDraft → reportReview → released
      → retestPending → retestComplete → closed
```

- **Nothing runs before `authorised`.** Not overridable, ever. Testing without signed, scoped,
  in-window authorisation is a criminal offence in India under the IT Act s.66.
- **Nothing runs before `advancePaid`.** Overridable with a written reason recorded against your
  name. It is a business rule, not a legal one.
- **`advancePaid → readyToRun` needs the pre-flight checklist**, which has no override, because the
  things on it are what stop a run harming someone.
- **`reportReview → released` needs the balance recorded and the release checklist green**, and the
  API re-runs that checklist server-side. A green screen is not the gate; the server is.

What each step needs, as HTTP:

| Step | Call |
| --- | --- |
| First staff account | `POST /auth/bootstrap`, then `/auth/bootstrap/confirm` with a TOTP code |
| Sign in | `POST /auth/login`, then `POST /auth/mfa`. The session does nothing until the second factor |
| Client | `POST /clients` |
| Engagement | `POST /engagements` — takes `testType`, `startsAt`, `endsAt`, `profileId` |
| Revise it | `PATCH /engagements/:id` |
| Scope | `POST /engagements/:id/scope` |
| Authorisation | `POST /engagements/:id/authorisation` — returns the asset-list diff. **Read it** |
| Policy | `PUT /engagements/:id/policy` |
| Payment | `POST /engagements/:id/payment` |
| Pre-flight | `PUT /engagements/:id/pre-flight-checklist` |
| Dry run | `POST /engagements/:id/runs` with `dryRun: true` |
| Live run | the same, `dryRun: false` |
| Triage | `GET /engagements/:id/review-queue`, `POST /engagements/:id/findings/bulk` |
| Report prose | `PUT /engagements/:id/report/sections/:key` |
| The gate | `GET /engagements/:id/report/preflight` |
| Generate | `POST /engagements/:id/report` |
| Release | `POST /reports/:reportId/release` |

`docs/COMMANDS.md` §8 has the whole thing as copy-pasteable `curl`.

---

## 4. Running it

```bash
docker compose -f infra/docker-compose.yml up -d --build
```

Migrations, buckets, the workspace, the nuclei template pack and the httpx classification model are
all init containers the stack depends on, so this one command is the whole boot.

```bash
node scripts/pin-tool-images.mjs --pull
```

**Until this has run, no tool will start.** The runner refuses an image with no pinned digest,
because a report that names a tool version has to mean it.

| Surface | Where |
| --- | --- |
| Staff console | http://localhost:3000 — over WireGuard in production, never the internet |
| Client portal | http://localhost:3100 — the only thing that faces the internet |
| Console API | http://127.0.0.1:8080 — loopback; the API refuses to bind `0.0.0.0` |
| Portal API | http://127.0.0.1:8081 |

The deliberately vulnerable targets for integration work:

```bash
docker compose -f infra/docker-compose.test.yml up -d
```

They sit on a network with `internal: true`, so a container on it has **no route off the machine**.
The integration suite refuses to start without `ATTESTOR_TEST_NETWORK_ONLY=1`.

### The gate

```bash
pnpm lint && pnpm typecheck && pnpm test && pnpm check:claims
```

`pnpm exec tsc -p tsconfig.json --noEmit` additionally covers the root project, which `pnpm
typecheck` does not.

---

## 5. Things that are true and non-obvious

Read this section before changing anything in the run path. Every line here cost somebody an hour.

- **A tool container reaches targets over ordinary egress**, on a fresh per-run bridge network. It
  is *not* on the compose network and it cannot reach the `internal: true` test-target network.
  Driving a real run against those targets means publishing them on the host and scoping the host
  address as a client-declared private range.
- **`/tmp/attestor` must be a host bind at an identical path**, never a named volume. The worker
  writes a tool's input files there and then asks the daemon to bind the same path into the tool
  container — and the daemon resolves bind sources on the *host*. As a volume the two are different
  directories and every tool starts blind.
- **The per-run directory is `chmod 0777`** because the tool runs as uid 65532 and the worker, as
  uid 1000, cannot chown to it. It sits inside a workspace root that is 0700 and is deleted after
  the run.
- **The worker needs the Docker socket's group** (`DOCKER_SOCKET_GID`, 0 on Docker Desktop). It runs
  as uid 1000 and the socket is 0660 root-owned.
- **`HOME` is set for tool containers** by the runner. UID 65532 has no passwd entry, so a tool that
  keeps config under `$HOME` otherwise falls back to `/`, which is read-only.
- **`HOME` is not enough for ZAP.** The JVM reads `user.home` from the passwd file, not from the
  environment, so under uid 65532 it is `?` and ZAP resolves its home to `/zap/?/.ZAP/` against a
  read-only root filesystem and exits before reading its plan. The adapter passes
  `-dir /tmp/zap-home`, which also keeps ZAP's session database — containing the login request, and
  so the client's password — in memory rather than on a disk.
- **A secret reaches a tool only through the container's environment.** `ToolRunRequest.secrets` is
  the one path: the runner registers each value with the redaction filter for the life of the run
  and puts it in the container's environment. Never the command line — the audit log records the
  command of every launch. An adapter sees `${ENV_NAME}` references and never a value, which is what
  makes `buildInvocation` output safe to write to disk.
- **ZAP substitutes `${...}` in a user's credentials and nowhere else.** Verified by running it: the
  same placeholder in a `replacer` job's `replacementString` is sent to the target literally. That is
  why an API key or bearer token is stored but not presented — carrying one would mean writing the
  value into the plan file.
- **nuclei ships no templates** and `-disable-update-check` stops it fetching any. The pack is
  provisioned once into the shared workspace and mounted read-only at `/templates`.
- **httpx fetches a 92.6 MB model from huggingface at startup whenever `-json` is asked for**, which
  the adapter always asks for. It is provisioned the same way and mounted read-only at the tool's
  `$HOME/.dit`. Both packs live in `DATA_PACK_MOUNTS` in the scan worker, and both exist so that
  nothing inside a tool container talks to a third party in the middle of a client engagement.
- **A policy that trims `info` off `nucleiSeverities` removes a whole class of check.** Every
  exposure, metafile and exposed-panel template nuclei ships carries that severity. `resolvePolicy`
  warns about it and no shipped profile does it, but a hand-written layer still can.
- **A probe that reports `skipped` is an aborted run, not a completed one.** The same rule as a tool
  that exits non-zero, for the same reason: a run recorded as completed hands its `coversCheckIds`
  to the coverage matrix as tested.
- **A non-zero exit is a failure unless the adapter says otherwise.** `successExitCodes` is the
  exception, and only schemathesis has one: it exits 1 exactly when its checks fail, so the ordinary
  rule threw away every run that found something and kept only the quiet ones.
- **A tool that cannot run under this policy says so and does not start.** `cannotRunBecause` returns
  a sentence — schemathesis with no `checks.openApiSchemaPath`, for instance — and the run is aborted
  carrying it, so the client reads why rather than finding a hole where the API testing should be.
- **The probes read crawled endpoints, narrowed to this run's targets.** `discovered_asset`
  accumulates across an engagement, so without the filter one URL from a host that has since left
  the target list makes the scope guard refuse the whole probe, and nothing gets tested at all.
- **Every finding may carry an OWASP risk rating beside its CVSS vector.** Sixteen factor answers,
  stored raw; the rating is derived by `owaspRiskRating` and never stored, so the two cannot
  disagree. An unanswered factor is left out of its average rather than scored zero — a half-filled
  form must not argue the risk is lower than anybody has established.
- **A non-zero exit is `failed`, not `completed`.** A tool that never started must not have its
  `coversCheckIds` counted as tested — that is how a report ends up lying about coverage.
- **Playwright ignores `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH`.** The PDF pipeline reads
  `CHROMIUM_EXECUTABLE_PATH` and passes it to `launch()`, because Playwright publishes no musl build
  and the image uses Alpine's Chromium.
- **Rate limits above the ceiling are refused, not clamped.** The policy is not saved. Nothing is
  silently reduced, so the number in the policy is the number the run uses. `politeMode` halves what
  you did set, and that halving is clamped too.
- **A refused run appears in the coverage matrix** as an aborted run with its reason, so "the run
  was refused because the target resolves outside the authorised range" reaches the client rather
  than a generic "not tested".

---

## 6. What it will not do

Stated plainly so it is never promised. These are structural, not policy.

- **No denial of service, in any form.** The policy schema cannot express it, ceilings are clamped,
  `DENIAL_OF_SERVICE_CAPABILITY = false`, an architecture test greps for DoS-shaped symbols, and
  every adapter's built command is asserted to contain no flood flag. Four things would have to be
  edited together.
- No destructive payloads, no data deletion, no state change beyond what the policy permits.
- No social engineering, no phishing, no physical testing.
- No autonomous agent against a client. Strix ships disabled and is **refused in code**, with a typed
  refusal naming what would have to exist first.
- No claim of any certification the firm does not hold. `pnpm check:claims` fails the build on a
  first-person claim of CERT-In empanelment, CREST accreditation, ISO certification of the firm, a
  guarantee of security, or a promise to certify a system as secure.
- No guarantee that a system is secure. No such report exists honestly.
- Nothing reaches a client automatically. **There is no SMTP client anywhere in this codebase.**
  Approving a notification records a decision; a person sends it.
- No client data to a third-party model unless that engagement explicitly turned it on, and even
  then only redacted findings text — never a screenshot.

---

## 7. The safety rails, and why they are shaped that way

The pattern throughout: **two independent mechanisms for anything whose failure is catastrophic.**
A control with a single enforcement point is a control that eventually gets moved.

| Rail | Enforced by |
| --- | --- |
| Only one module starts a container | An ESLint `no-restricted-imports` rule **and** an architecture test |
| A refusal refuses the whole run, never a subset | `runToolForEngagement`, the single choke point |
| Never-touch is checked **before** authorisation | Ordering inside `checkScope`. Signing a form does not unlock the payment flow |
| Resolved addresses are re-checked after DNS | Inside the guard, not inside the tool |
| Every portal route scopes by session | A structural test that parses `portal-routes.ts` and fails the build |
| Every console route has a session guard | The same, over the console route files |
| Client TOTP secrets are never plaintext | Three structural tests, and a separate key from the vault |
| The audit log cannot be edited | A Postgres trigger that raises on UPDATE and DELETE |
| The report renders attacker text inertly | A 25-payload corpus fired through every string field, in a real browser |

Cryptographic shredding is real: credentials are sealed under a per-engagement subkey derived from
the master key, a random salt and the engagement id. **Closing an engagement destroys the salt**, and
after that no key opens that ciphertext — not for an attacker, not for you, not from a backup.
Operators must be told this in advance or they will file it as a restore failure.

---

## 8. Conventions that must not be broken

- Node 22, `--experimental-strip-types`. No transpiler, no build output. Import specifiers end `.ts`.
- TypeScript strict, `noUncheckedIndexedAccess`. **No `any`** — it is a lint error. No
  leading-underscore names; unused parameters are prefixed `unused`.
- No dead or commented-out code.
- Exactly one module may import `dockerode`.
- Nothing in the policy schema may express a denial-of-service test.
- zod v4: `.prefault({})` for nested defaults, not `.default({})`.
- **British spelling throughout**, including in identifiers — `authorisation`, not `authorization`.
- Adapters: `buildInvocation` builds a command from a fixed vocabulary; `parse` is a **pure function
  over a string** — no network, no clock, no filesystem. Rate limits come from the resolved policy,
  never from the adapter.
- `coversCheckIds` claims only what the tool actually tests. Overclaiming there is how a report ends
  up lying about coverage.
- A new tool needs a real output fixture **and hostile ones**: empty, `{}`, truncated JSON, a string
  where the schema says array. A missing hostile fixture is how the gitleaks adapter shipped a crash.

---

## 9. What has been verified, and what has not

### Verified by running it

- The whole stack under `docker compose`: nine services healthy, both UIs 200, migrations applied.
- A complete engagement through the real API: bootstrap, MFA, client, engagement, scope,
  authorisation with asset-list diff, policy, payment, pre-flight checklist, the state machine, a
  dry run, a live run, triage, report prose, the release gate, PDF generation, portal invitation.
- **Live tool runs in hardened containers** against deliberately vulnerable targets, producing real
  findings and a real asset inventory.
- The scope guard refusing, for real: loopback, cloud metadata, registry-wide wildcards, public
  suffixes at entry; and out-of-state, unauthorised targets at run time.
- The release gate refusing a report and naming exactly what blocked it.
- Surface gating in both directions, the CSP with its per-request nonce, all security headers.
- Security regression across authentication, session, MFA, TOTP single-use, origin, malformed input,
  rate limiting, portal isolation and error bodies.
- **Credential intake, end to end**: the console mints a link, the client fills the portal page with
  no account, the value is sealed, the console lists it without a value, and revoking it takes it out
  of the next run. Refusals checked too — a missing box, a field the form never offered, a bad token,
  and the page 404ing on the console surface.
- **An authenticated ZAP scan**, using the plan the product generates, in a container with the same
  hardening the runner applies — uid 65532, read-only root, tmpfs, per-run network. It signed into a
  live Juice Shop with the password from the vault, crawled as that user, exited 0 and produced a
  report. The password appears in neither the plan file on disk nor the report.
- 377 unit and property tests, and the 31-test integration suite including the live run; lint, both
  typechecks, the claim check, all three builds.

### Not verified

- **A model has never been called.** The AI layer is fully implemented and tested against an injected
  transport; there is no provider key and the default configuration refuses everything anyway.
- **Legal text is not lawyer-reviewed.** Every block carries `lawyerReviewedAt: null` and documents
  render with a visible draft banner. This is the one thing you cannot ship without.
- **Eleven of forty-one tool images cannot be pulled** — the tags do not resolve. Those tools are
  silently absent from every run because the runner refuses an unpinned image.
- **The whole of the OWASP Web Security Testing Guide is accounted for**: 106 of 109 covered, three
  recorded as deliberate decisions with reasons a client can read, and no unexplained gap. The
  catalogue-integrity test holds that at zero and fails the build if it rises.
- **The OWASP Risk Rating calculator reproduces the worked example in the client's own copy of the
  workbook**, to the second decimal place, which is the only test of it that matters.
- **An API key, bearer token or session cookie is stored but never presented by a tool**, and
  nothing verifies a credential before a run — a mistyped password shows up as an empty
  authenticated scan.
- **The authenticated scan has not been driven through the worker against a live target.** The plan
  the product generates was run against one, in a container configured exactly as the runner
  configures it; what has not been exercised together is that plus the worker's own container
  networking, because a tool container cannot reach the internal test-target network.
- Off-host log shipping and alerting: the two real gaps in the ASVS self-assessment, in V16.
- Mobile, cloud, code and LLM modules have not been driven end to end against a live target. Recon,
  web and network have.

---

## 10. Working on this

- Read `docs/BUILD-STATUS.md` first. It is the live state.
- Prefer running the thing over reasoning about it. Every serious defect in this codebase was found
  by starting it, not by reading it — including several that passed lint, typecheck and the whole
  test suite.
- When a control looks like it works, check that its test asserts what its name claims. Two did not.
- A gate that can never fire is worse than no gate. Two were found: one checked for candidates in a
  collection candidates are filtered out of, another checked a checklist the caller could satisfy
  with an invented key.
- Do not add an abstraction for one caller. When a second tool needs a data pack, generalise then.
