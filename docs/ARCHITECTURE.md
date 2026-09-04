# Architecture

The technical picture: what is built on what, where every file lives, how a request travels, and why
the boundaries sit where they do.

---

## 1. The stack

### 1.1 The marketing website

| Layer | Choice | Why |
| --- | --- | --- |
| Framework | **Astro 7.2** | Ships HTML. No framework runtime reaches the browser |
| Output | `output: 'static'` | Files on a CDN. Nothing to exploit server-side because there is no server |
| Content | Astro content collections + **MDX 7** | Services, insights and legal pages are files, type-checked at build |
| Interactivity | Four plain `<script>` islands | Currency switcher, scope estimator, catalogue filter, search |
| Search | **Pagefind 1.5** | Index built at build time, downloaded in fragments. No search server |
| OG images | **satori 0.33** + **@resvg/resvg-js 2.6** | Generated at build from a typographic template. No stock art pipeline |
| Fonts | Self-hosted OFL WOFF2 | Source Serif 4, Public Sans. No CDN, no third party learning who reads the site |
| Styling | Plain CSS with custom properties | No utility framework. The site is small enough that a framework is a dependency, not a saving |
| Validation | **zod 4** on the content schemas | A malformed service page fails the build |
| Headers | Custom Astro integration | Writes `_headers` after the build, with CSP **hashes computed from the built output** |

That last row is the interesting one. `apps/website/src/integrations/security-headers.ts` walks the
built HTML, hashes every inline block, and writes the policy with those hashes. The CSP therefore
cannot silently drift out of date when the content changes — there is no `unsafe-inline` to hide
behind.

### 1.2 The platform

| Layer | Choice | Why |
| --- | --- | --- |
| Runtime | **Node 22 LTS**, `--experimental-strip-types` | TypeScript runs directly. No transpile step, no build output to keep in sync with source |
| Language | **TypeScript 5.9**, strict, `noUncheckedIndexedAccess` | `any` is a lint error. Import specifiers end in `.ts` |
| API | **Fastify 5** | Two apps from one codebase: console API and portal API |
| Validation | **zod 4** at every route boundary | An unparsed body never reaches a handler |
| Database | **PostgreSQL 16** + **Drizzle ORM 0.45** | Parameterised everywhere; no string-built SQL exists |
| Queue | **BullMQ 6** on **Redis 7** | One tool run per worker process, three-hour lock |
| Objects | **MinIO** (S3 API) | Evidence and reports, two buckets, server-side reads only |
| Containers | **dockerode**, one importer | The single choke point for starting a tool |
| Crypto | **libsodium-wrappers-sumo** | Credential vault, per-engagement subkeys |
| Passwords | **@node-rs/argon2** | Argon2id |
| MFA | **otpauth** | TOTP, mandatory |
| UI | **Next.js 16** App Router, **React 19** | Server components; no token ever reaches the browser |
| PDF | **Playwright** headless Chromium | The browser view and the PDF are the same document |
| Tests | **Vitest 3** + **fast-check 4** | 334 unit and property tests, plus integration suites |

### 1.3 Deliberate absences

No Tailwind. No Redux. No tRPC. No GraphQL. No ORM migrations generated at runtime. No SMTP client.
No vendor SDK for the model provider. No agentic framework. Each one was considered and left out
because the thing it replaces is smaller than the dependency.

---

## 2. The monorepo

pnpm workspaces. `apps/*` are deployables, `packages/*` are libraries. Dependencies point one way:
apps depend on packages, packages depend on packages below them, and nothing depends on an app.

```
attestor/
├── apps/
│   ├── website/          Astro static site
│   ├── api/              Fastify: console API, portal API, workers
│   └── console/          Next.js: staff console AND client portal
├── packages/
│   ├── shared/           No dependencies. Redaction, masking, logging, config, types
│   ├── findings/         Depends on shared. Catalogue, CVSS, dedupe, coverage
│   ├── policy/           Depends on shared. Schema, resolution, profiles
│   ├── core/             Depends on shared + policy. Scope guard, runner, audit, AI
│   ├── scanners/         Depends on shared + findings + policy. Tool adapters
│   └── report/           Depends on shared + findings. Renderer, legal, checklist, PDF
├── infra/                Compose, Dockerfile, migrations, vulnerable targets
├── docs/                 Everything in this directory
└── scripts/              Image pinning, claim checking, screenshots
```

### 2.1 `packages/shared`

The bottom of the stack. Nothing depends on anything else.

| File | What it holds |
| --- | --- |
| `redaction.ts` | `SecretRegistry`, and patterns for headers, JSON, query strings, form bodies and shaped secrets. Every log and every tool output passes through it |
| `masking.ts` | Card and identifier masking with **Luhn and Verhoeff** checks, so masking does not mangle unrelated digits |
| `logger.ts` | Structured JSON logging, redacted |
| `config.ts` | The whole environment, as a zod schema. Missing required value = the process does not start |
| `types.ts` | `ENGAGEMENT_STATES`, `MODULES`, `Severity`, `TestType` and the severity helpers |
| `ids.ts` | Engagement references (`ATT-2026-014`), finding references |

### 2.2 `packages/findings`

| Path | What it holds |
| --- | --- |
| `catalogue/` | **235 checks** across eight module files, plus the types and the index |
| `standards/catalogues.ts` | ASVS 5.0.0 chapters, WSTG 4.2 categories, OWASP lists, MASVS groups |
| `standards/compliance.ts` | ISO 27001 Annex A, SOC 2, PCI DSS 4.0.1, DPDP Act mappings |
| `model.ts` | The `Finding` shape everything else agrees on |
| `cvss.ts` | CVSS 3.1 and 4.0 — own grammar validation, `ae-cvss-calculator` for scoring |
| `dedupe.ts` | Dedupe keys and root-cause correlation across tools |
| `diff.ts` | New, fixed, regressed, still-open between two engagements |
| `coverage.ts` | The coverage matrix, built from what actually ran |

### 2.3 `packages/core` — the security heart

| Path | What it holds |
| --- | --- |
| `scope/hostname.ts` | Label-wise wildcard matching. `*.example.com` excludes the apex, deliberately |
| `scope/ip.ts` | Forbidden ranges, IPv4-mapped IPv6 handling, cloud metadata named explicitly |
| `scope/never-touch-list.ts` | Checked **before** authorisation |
| `scope/scope-guard.ts` | `checkScope()` → `ScopeAllowed` or `ScopeRefused` with one of 18 typed rules |
| `engagement/state-machine.ts` | 14 states, declared transitions, two gates |
| `runner/container-runner.ts` | **The only module that imports dockerode.** All hardening lives here |
| `runner/run-tool-for-engagement.ts` | The choke point. Scope, audit, launch, redact |
| `runner/tool-images.ts` | 41 images with limits, modules and purpose |
| `runner/rate-limiter.ts` | Token bucket with jitter and adaptive back-off |
| `audit/audit-log.ts` | The closed union of audit actions |
| `panic-stop.ts` | Engagement-scoped and platform-wide stops |
| `ai/ai-assist.ts` | Two switches, redaction, grounding check, usage record |
| `architecture.test.ts` | Fails the build if dockerode moves or a DoS-shaped symbol appears |

### 2.4 `packages/scanners`

`adapter.ts` defines the contract. Everything else is one file per tool family, and each adapter is
two functions: `buildInvocation` (build a command) and `parse` (a **pure function over a string**).
That purity is why the fixtures in `fixtures/tool-output.ts` can test every adapter without Docker,
a network or a target.

### 2.5 `packages/report`

| Path | What it holds |
| --- | --- |
| `render.ts` | The renderer. Every interpolation goes through `escapeHtml`. No clock is read, so output is byte-stable |
| `legal/blocks.ts` | Versioned legal text with `lawyerReviewedAt` |
| `checklist.ts` | The 18-item release gate |
| `documents.ts` | Attestation letter, deletion confirmation |
| `pdf.ts` | Playwright, watermark applied per download |
| `__golden__/` | The golden file the render test diffs against |

### 2.6 `apps/api`

```
src/
├── server.ts          Console API — binds to loopback, refuses 0.0.0.0
├── portal-server.ts   Portal API — the only internet-facing service
├── worker.ts          BullMQ workers: scan, retention, retainer
├── queue.ts           Queue definitions and job schemas
├── context.ts         Dependency container. Portal context has NO vault, NO container runner
├── db/
│   ├── schema.ts      27 tables
│   ├── client.ts      Two pools: console role, portal role
│   ├── migrate.ts     seed.ts     rewrap-credentials.ts     rewrap-totp-secrets.ts
├── routes/            ai, auth, client, engagement, finding, platform, report
│   └── session-guard.ts   MFA checked here, client scope from the session only
├── portal/
│   ├── portal-routes.ts       Every client-facing route
│   └── portal-scoping.test.ts Parses the route file; fails the build on a missing scope check
├── services/          credential-vault, evidence-store, auth, audit, run-service,
│                      findings-service, report-service, panic-stop-store, tool-digests,
│                      ai-transport
└── workers/           scan-worker, retention-worker, retainer-worker
```

`context.ts` is worth reading. `ConsoleContext` has a vault and a container runner; `PortalContext`
has neither. The portal cannot decrypt a credential or start a container because it was never handed
the ability to.

### 2.7 `apps/console`

One Next application, two deployments.

```
src/
├── proxy.ts           Surface gating + the CSP with its per-request nonce
├── lib/
│   ├── api.ts         Server-side fetch, forwards the session cookie
│   ├── surface.ts     console | portal — separate so client components can read it
│   ├── csp.ts         The policy, testable without the edge runtime
│   └── form.ts        FormData → string, refusing a File
├── app/
│   ├── layout.tsx  globals.css  error.tsx  not-found.tsx  actions.ts
│   ├── login/                       both surfaces
│   ├── engagements/  clients/  queue/  legal/  settings/      console only
│   └── findings/  reports/  retest/  questionnaire/  account/  invitation/   portal only
└── components/        shell, run-controls, stop-control, state-control, scope-editor,
                       triage-queue, report-workbench, finding-actions, client-controls,
                       queue-controls, accept-invitation, retest-request, copyable-answer
```

---

## 3. How a request travels

### 3.1 A client reads a finding

```
browser  ──▶  portal (Next, server component)
                │  proxy.ts: is /findings allowed on this surface? yes
                │  proxy.ts: mint a nonce, set the CSP
                ▼
              lib/api.ts  ──▶  portal API (Fastify)
                                 │  session-guard: cookie valid? MFA satisfied?
                                 │  clientIdOf(request) — from the session, never the URL
                                 ▼
                               Postgres as attestor_portal
                                 WHERE finding.id = ? AND engagement.client_id = ?
```

Two things make cross-tenant access structurally hard rather than merely checked: the client id is
part of the `WHERE` clause instead of a separate guard, so forgetting it returns nothing rather than
everything; and a structural test parses `portal-routes.ts` and fails the build if any authenticated
route does not call `clientIdOf(request)`.

No token ever reaches the browser. The session cookie is `HttpOnly`, `SameSite=strict`, and the page
does its fetching server-side — an XSS in the portal has no credential to steal.

### 3.2 A tool runs against a target

```
console  ──▶  POST /engagements/:id/runs   { modules, dryRun }
                │
                ▼
              run-service: expand modules → tools → targets
                │
                ▼
              BullMQ  ──▶  scan-worker
                             │
                             ▼
                    runToolForEngagement()        ← THE CHOKE POINT
                             │
                             ├─ checkScope() for EVERY target
                             │    state? authorisation signed, unexpired, unrevoked?
                             │    inside the window? panic stop clear?
                             │    never-touch? forbidden IP range?
                             │    resolve DNS, then check the addresses too
                             │
                             ├─ ANY failure → refuse the WHOLE run, audit it, stop
                             │
                             ├─ dryRun → audit it and return. No packet is sent
                             │
                             ├─ audit tool.launched with targets, resolved IPs, digest
                             │
                             ▼
                    ContainerRunner.run()          ← the only dockerode importer
                             uid 65532 · read-only rootfs · CapDrop ALL
                             no-new-privileges · per-run network · mem/PID/CPU caps
                             labelled so the panic stop can find it · wall-clock kill
                             │
                             ▼
                    stdout/stderr → redactText() → adapter.parse() → candidates
```

The refusal semantics matter: a failing target refuses the **run**, not the target. A partially
scoped run is how something gets tested by accident.

### 3.3 A report is released

```
console  ──▶  POST /reports/:id/release
                │
                ├─ rebuild the report data from the database
                ├─ read which sections are unapproved AI drafts
                ├─ runChecklist() — all 18 items, server-side
                │
                ├─ not releasable → 409 with the exact blocking list
                │
                └─ releasable → mark released, queue a notification for a HUMAN to send
```

The console's checklist panel is a view of this. The gate is the server.

---

## 4. The data model

27 tables. The ones that carry the design:

| Table | Note |
| --- | --- |
| `client` → `engagement` | `onDelete: restrict` — a client with engagements cannot be deleted by accident |
| `authorisation` | The signed document's hash, its asset list, valid-from/until, revocation |
| `scope_item` | Included and excluded, by kind |
| `credential_set` | **No column holds a plaintext credential.** Sealed value, key salt, nonce |
| `scan_run` | One row per tool per run, with the digest that actually ran |
| `finding` → `evidence` | Evidence carries a sha256 and the masking rules that fired |
| `report` / `report_section` | Sections carry `isAiDraft` and `approvedAt` |
| `audit_log` | **Append-only, enforced by a database trigger** that raises on UPDATE and DELETE |
| `client_user` / `client_invitation` / `session` | Portal identity; invitations store only a hash |
| `report_download` | Who took which copy, when, with which watermark |
| `panic_stop` | Engagement-scoped and platform-wide |

The audit trigger is the important one. A record that can be edited is not a defence.

---

## 5. Deployment topology

```
                    ┌──────────────────────── the internet ────────────────────────┐
                    │                                                              │
            attestorsecurity.com                                  portal.attestorsecurity.com
                    │                                                              │
              ┌─────▼─────┐                                                  ┌─────▼─────┐
              │    CDN    │  static files, _headers                          │   Caddy   │  TLS, HSTS
              │  (Pages)  │  no server, no database                          └─────┬─────┘
              └───────────┘                                                        │
                                                                             ┌─────▼─────┐
                                                                             │  portal   │ :3100
                                                                             │  (Next)   │
                                                                             └─────┬─────┘
                                                                                   │
   staff laptop ──WireGuard──▶ 10.88.0.1                                     ┌─────▼─────┐
                                    │                                        │portal-api │ :8081
                              ┌─────▼─────┐                                  └─────┬─────┘
                              │  console  │ :3000  loopback only                   │
                              │  (Next)   │                              Postgres as attestor_portal
                              └─────┬─────┘                                (least privilege, cannot
                                    │                                       read credential_set)
                              ┌─────▼─────┐
                              │    api    │ :8080  loopback only
                              └─────┬─────┘
                                    │
              ┌──────────┬──────────┼──────────┬───────────┐
              │          │          │          │           │
         Postgres      Redis      MinIO     worker ──▶ Docker ──▶ tool container
        (owner role)                          │                      per-run network
                                              └── the only thing with the Docker socket
```

Four properties this shape buys:

1. The marketing site cannot leak client data, because it has none.
2. The console is not on the internet. The API refuses to bind to `0.0.0.0`.
3. The portal, which is on the internet, connects as a role that cannot read the credential vault.
4. Only the worker has the Docker socket. The API does not.

---

## 6. The rules the build enforces

Not conventions. Things that fail CI.

| Rule | Enforced by |
| --- | --- |
| Only one module imports `dockerode` | ESLint `no-restricted-imports` **and** `architecture.test.ts` |
| No DoS-shaped symbol anywhere | `architecture.test.ts` greps the source |
| No adapter command contains a flood flag | Every adapter's built command is asserted |
| Every portal route scopes by session | `portal-scoping.test.ts` parses the route file |
| Every console route has a session guard | `console-auth.test.ts` parses the route files |
| Client TOTP secrets are never plaintext | Three structural tests |
| The CSP is issued once, with a nonce | `csp.test.ts` checks both the policy and `next.config.ts` |
| No `any`, no leading underscores | ESLint |
| No claim the firm cannot make | `scripts/check-claims.mjs` |
| The report renders attacker text inertly | 25-payload corpus in a real browser |

The pattern: **two independent mechanisms for anything whose failure is catastrophic.** A control
with a single enforcement point is a control that eventually gets moved.
