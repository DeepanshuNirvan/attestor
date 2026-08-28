# End-to-end regression, 28 August 2026

The first regression run with a working container daemon. The platform was booted under compose,
driven through its real APIs as an operator would, and made to run real security tools in real
containers against deliberately vulnerable targets — then through triage, report generation and the
release gate.

Twenty-five defects were found. Every one was found by **running the platform**, not by reading it.
All twenty-five passed `pnpm lint`, `pnpm typecheck` and the full test suite beforehand.

Defect numbering continues from `docs/BUILD-STATUS.md`, which ended at 21.

**Outcome:** the platform now runs an engagement end to end. `apps/api/src/engagement-run.integration.test.ts`
passes for the first time — 31 of 31, with nuclei producing real findings against a live target — and a
complete engagement was driven from bootstrap through a live scan, triage, report generation, the
release gate and into the client portal, with zero failures.

---

## 1. What was exercised

| Area | How |
| --- | --- |
| The stack | `docker compose up -d --build` — nine services, migrations, buckets, workspace, template pack |
| Staff authentication | Bootstrap, TOTP enrolment, sign-in, second factor, session rotation |
| Client lifecycle | Client, engagement, scope, authorisation with asset-list diff, policy, payment, pre-flight |
| Scope guard | Entry validation and run-time refusal, both against real targets |
| The runner | Real tool containers, hardened, on per-run networks |
| Tools | subfinder, httpx, naabu, tlsx, nmap, nuclei, trufflehog, ZAP, dalfox |
| Findings pipeline | Tool output → candidate → triage → confirmed finding, with evidence |
| Report | Prose, coverage matrix, the eighteen-item gate, HTML and PDF |
| Portal | Surface gating, headers, tenancy, invitation flow |
| Platform security | Authentication, session, MFA replay, origin, malformed input, rate limits |

## 2. Severity of what was found

Four defects made the product **unable to perform its core function**, and each was invisible to
every existing check:

1. **No engagement could ever run.** `advancePaid → readyToRun` gates on a pre-flight checklist that
   had no writer anywhere in the API or console — and that gate has no override (**29**).
2. **The live tool path had never worked.** The container runner handed `demuxStream` two `Readable`
   streams; it writes into what it is given, so the first byte of tool output threw
   `stderr.write is not a function` asynchronously and took the worker down (**27**).
3. **Tool input and output went to a directory the tool never saw.** The worker wrote into a named
   volume and asked the daemon to bind the same path, which the daemon resolves on the host (**31**).
4. **No report could be produced or released.** Playwright ignores the environment variable the
   Dockerfile set (**40**); the test dates the legal blocks quote had no writer (**39**); and
   tool-derived findings carried no evidence, which the gate correctly refused (**42**).

Two defects were **controls that could never fire** — worse than no control, because they read as
green:

- The "no unconfirmed candidate has reached the report" gate checked a collection candidates are
  filtered out of upstream. It passed on every engagement, including one released with a queue full
  of unreviewed tool output (**41**).
- A tool that exited non-zero was recorded as `completed`, so its `coversCheckIds` fed the coverage
  matrix as *tested*. nuclei — which could not start at all — was indistinguishable from a clean
  scan (**28b**).

One was a **control that did the opposite of what its test claimed**:

- nmap ran `--script safe,default,discovery`. `discovery` is not a safe category and includes
  `whois-ip`, `whois-domain` and `targets-*`, which send the client's hostnames to third parties
  that authorised nothing. The unit test was named *"nmap only ever runs safe script categories"* and
  asserted the command contained `discovery` (**34**).

## 3. Every defect

The appendix has each one in full, with the command that surfaced it and the fix. In summary:

| # | Defect | Class |
| --- | --- | --- |
| 22 | Stale lockfile — every Docker build and CI run failed | Deploy |
| 23 | No `.dockerignore`; host `node_modules` overwrote the image's | Deploy |
| 24 | The console image stage could never build on a clean checkout | Deploy |
| 25 | Integration targets pinned `webgoat:v2025.4`, a tag that never existed | Test infra |
| 26 | `docker compose up` died at the migration step | Deploy |
| 27 | **The container runner crashed the worker on the first byte of tool output** | Run path |
| 28a | `HOME` unset for uid 65532, so nuclei died on the read-only root | Run path |
| 28b | **A non-zero exit counted as coverage** | Report honesty |
| 28c | nuclei ships no templates and could never produce a finding | Run path |
| 29 | **Three state gates had no writer — no engagement could run, no report could release** | Lifecycle |
| 30 | The worker could not reach the Docker socket | Deploy |
| 31 | **Tool input and output went to a directory the tool never saw** | Run path |
| 32 | A tool that found nothing failed the whole scan job | Run path |
| 33 | The tlsx adapter built a command tlsx refuses to start with | Adapter |
| 34 | **nmap ran the `discovery` category while claiming "safe only"** | Safety rail |
| 35 | Eleven of forty-one tool images cannot be pulled | Tooling |
| 36 | Reconnaissance output was parsed and thrown away | Report content |
| 37 | Evidence could not be stored at all — MinIO had no KMS key | Run path |
| 38 | Raw ANSI escapes stored and shown to the operator | Presentation |
| 39 | **Test dates and assessment type could not be set** | Lifecycle |
| 40 | **No report could be produced in the deployed stack** | Report |
| 41 | **The "no unconfirmed candidate" gate could never fire** | Report honesty |
| 42 | **Tool findings carried no evidence, so no scan-driven report could release** | Report |
| 43 | `Origin: null` treated as an absent Origin header | Hardening |
| 44 | Port scanners were given URLs and refused to run | Adapter |
| 45 | The nuclei parser crashed on a real classification block containing nulls | Adapter |
| 46 | A killed worker leaked its run container and its per-run network, with nothing to reclaim them | Operational |

Also corrected: the documentation stated in four places that a rate limit above the ceiling is
"clamped, with a warning". The schema **refuses** it and the policy is not saved — which is the
safer behaviour and the one the code comments describe. The documentation now says so.

## 4. What was built

Features that were missing rather than broken:

- **`PUT`/`GET /engagements/:id/pre-flight-checklist`** with a `PRE_FLIGHT_CHECKLIST` catalogue in
  `packages/core`, so the *server* decides the gate. The previous check accepted any object with one
  true key. Unknown ids are refused rather than ignored.
- **`POST /engagements/:id/payment`** for the advance and the balance, with the invoice reference
  recorded, because "who said this was paid, and against which invoice" is the question asked later.
- **`PATCH /engagements/:id`** for the test window, assessment type, title, timezone and quote. The
  reference, the client and the state are deliberately not editable.
- **A `discovered_asset` table** (migration `0004`) and the worker call that fills it, so the report's
  ports-and-services appendix and asset inventory describe the estate that was found rather than the
  scope somebody typed.
- **Per-finding evidence from tool output** — `evidenceText` on `RawFinding`, populated across the
  httpx, tlsx, nuclei, ZAP, dalfox, Schemathesis and nmap paths, captured through the same masking
  layer as any other evidence and linked to the finding.
- **Two console panels** for the checklist and payments, so none of the above is API-only.
- **A provisioned nuclei template pack**, mounted read-only, refreshed deliberately rather than
  downloaded per run.

## 5. Report quality

The document is the deliverable, so it was read rather than assumed.

**Fixed:**

- **Section numbering was broken.** The rendered report went 1–9, then 11–13: there was no section
  10, and the risk-overview callout cross-referenced it. Two sections are conditional, so any report
  without an attack narrative had a second hole. Numbers are now derived once, in document order,
  and the contents list and every cross-reference read from the same map.
- **The tool inventory listed every scan-run row**, including dry runs, scope refusals and crashes,
  under a heading reading "Tools used" — a claim about work that was not done. It now lists only
  tools that completed a live run, with the full pinned digest rather than a twelve-character slice,
  and each tool's real purpose instead of a pointer to an appendix that does not exist.
- **The ports-and-services appendix** said "No port scanning was performed in this engagement" on
  engagements where nmap and naabu had both run.
- **A refused run vanished from the coverage matrix.** It now appears as an aborted run carrying its
  reason, so "the run was refused because the target resolves outside the authorised range" reaches
  the client instead of a generic "not tested".

**Confirmed good, by inspection of real output:** finding prose is genuinely of professional
standard — business impact in business terms, attacker prerequisites, honest likelihood, numbered
reproduction steps, stack-specific remediation, CVSS vector printed beside the score. Evidence
renders attacker-controlled text inertly: a 25-payload corpus fires through every string field, is
opened in a real browser, and nothing executes while the payload stays visible as text.

**Standards mapping is complete.** All ten OWASP Top 10 2025 categories, all ten API Security Top 10
2023, all ten LLM Top 10 2025 and all twenty-four MASVS 2.1 controls are present in the catalogue and
referenced by checks. Nothing was missing.

## 6. Platform security regression

Twenty-four cases against the running APIs. All pass.

| Property | Result |
| --- | --- |
| MFA gates every route, not just the login page | A password-only session is refused |
| A TOTP code is single use | The same code fails on a second session |
| Session cookie is `HttpOnly`, `SameSite=Strict` | Confirmed on the wire |
| Cross-origin writes refused | Including `Origin: null` after **43** |
| Failed sign-ins throttled | 429 with `Retry-After` |
| A malformed uuid is a 4xx, never a 500 | Confirmed |
| Scope refuses loopback, metadata, registry wildcards, public suffixes | At entry, with the reason |
| Portal and console expose none of each other's routes | 404 both directions |
| A staff session on the portal is refused, not a 500 | Confirmed |
| No route returns a credential | Confirmed |
| Error bodies carry no stack trace | Confirmed |
| CSP with a per-request nonce, plus the full header set | Confirmed in a browser |

## 7. Still open

- **Eleven of forty-one tool images cannot be pulled** — `gau`, `whatweb`, `nikto`, `commix`,
  `kiterunner`, `cloudsplaining`, `apktool`, `jadx`, `garak`, `promptfoo`, `strix`. The runner
  refuses an unpinned image, so each is silently absent from every run. Each needs a working image
  reference or removal from the catalogue; leaving them listed overstates what the platform can do.
- **Legal text is not lawyer-reviewed.** Unchanged, and still the one thing that cannot ship.
- **A model has never been called.** Unchanged.
- **Mobile, cloud, code and LLM modules** have not been driven end to end against a live target.
- **Off-host log shipping and alerting** — the two real gaps in the ASVS self-assessment, in V16.

---

# Appendix: every defect in full

Each entry names the command that surfaced it, quotes what it said, and states the fix.

## 22. Stale lockfile — every Docker build and every CI run fails
**Found by:** `docker compose -f infra/docker-compose.yml build`
Bug 19's fix removed `@fastify/csrf-protection` from `apps/api/package.json` and never regenerated
`pnpm-lock.yaml`. The Dockerfile and CI both install with `--frozen-lockfile`, which refuses a
lockfile that disagrees with a manifest:

```
ERR_PNPM_OUTDATED_LOCKFILE  Cannot install with "frozen-lockfile" because pnpm-lock.yaml
is not up to date with <ROOT>/apps/api/package.json
* 1 dependencies were removed: @fastify/csrf-protection@^8.0.1
```

The documented five-minute quickstart could not run. **Fixed:** `pnpm install --lockfile-only`.

## 23. No `.dockerignore` — host `node_modules` overwrote the image's own
**Found by:** the same build; 128 MB of build context transferred per stage.
The console stage does `COPY --from=dependencies /app/node_modules` and then `COPY . .`. With no
`.dockerignore`, the second copy lands the *build machine's* `node_modules` on top of the image's,
replacing linux-musl native binaries — `@node-rs/argon2`, `sharp`, `esbuild` — with whatever the
build host is. On Windows and macOS the image builds green and dies at start-up. It also shipped
`.git`, `.next` and `infra/.env` into the image.

**Fixed:** added `.dockerignore`.

## 24. The console image stage has never been able to build
**Found by:** the build, once 23 stopped masking it — `sh: next: not found`.
pnpm workspaces put a `node_modules` in *every* workspace directory, not only the root.
`apps/console/node_modules/.bin/next` is where `next` lives. The stage copied only the root
`node_modules`, so the build only ever succeeded by accident, on a machine whose host
`apps/console/node_modules` was dragged in by the unignored `COPY . .`. On a clean checkout — which
is what CI and any real deploy is — it fails.

**Fixed:** `COPY . .` first, then the root, console and packages `node_modules` from the
dependencies stage.

## 25. The integration target stack pins an image tag that has never existed
**Found by:** `docker compose -f infra/docker-compose.test.yml up -d`

```
Error response from daemon: failed to resolve reference
"docker.io/webgoat/webgoat:v2025.4": not found
```

Docker Hub's highest `v2025` tag for `webgoat/webgoat` is `v2025.3`. Compose aborts the whole `up`
on one unresolvable image, so *no* target started and the integration suite has never had anything
to run against.

**Fixed:** pinned `v2025.3`.

## 26. `docker compose up` dies at the migration step
**Found by:** `docker compose -f infra/docker-compose.yml up -d`

```
Error: invalid configuration: REDIS_URL: Invalid input: expected string, received undefined;
S3_ENDPOINT: ...; S3_ACCESS_KEY_ID: ...; S3_SECRET_ACCESS_KEY: ...
```

`migrate.ts` calls `loadConfig()`, which validates the entire environment, but the migration opens
Postgres and nothing else — it reads exactly `DATABASE_URL` and `LOG_LEVEL`. The one-shot `migrate`
service is the only one in the compose file without Redis and S3 variables, so it could never start,
and the restore drill in `RUNBOOK.md` §3.3 could not apply a migration without inventing an object
store first.

**Fixed** at the root rather than in compose: `loadMigrationConfig` / `loadSeedConfig` in
`packages/shared/src/config.ts` parse the subset each tool actually opens. Patching only the compose
file would have left every shell and CI caller broken.

## 27. The live tool path had never worked — `demuxStream` was given Readable streams
**Found by:** the first ever run of `engagement-run.integration.test.ts`

```
TypeError: stderr.write is not a function
  at processData docker-modem/lib/modem.js:486
```

`ContainerRunner.run` built two `Readable` streams and handed them to `modem.demuxStream`, which
*writes* the de-multiplexed halves into the sinks it is given. `Readable` has no `.write`. The throw
came from inside docker-modem's HTTP response handler, asynchronously, so it did not reject the run —
it took the worker process down. Every live tool run crashed as soon as the container produced
output, which is why no scan had ever completed.

**Fixed:** `Writable` sinks that collect chunks.

## 28. nuclei could not run at all, and the failure was silent
**Found by:** running nuclei by hand under the platform's own hardening.

Three defects, one after another:

- **28a** UID 65532 has no passwd entry in the tool images, so `HOME` was unset and nuclei fell back
  to `/`, which is the read-only root: `mkdir /.config: read-only file system`. Fixed by setting
  `HOME` to the tmpfs in the runner — with the rest of the hardening, so no adapter can forget it.
- **28b** A tool that exits non-zero was recorded as `completed`, so a tool that never started was
  indistinguishable from a clean scan — and `coversCheckIds` then fed the coverage matrix as
  *tested*. This is the "report lying about coverage" failure the docs warn against. Fixed: non-zero
  exit is `failed`, with the stderr tail as the reason, which `coverageFromRuns` reads as an aborted
  run so the matrix carries the reason.
- **28c** The image ships **no templates**, and `-disable-update-check` stops nuclei fetching any:
  `Could not run nuclei: no templates provided for scan`. The platform's highest-volume web scanner
  could never produce a finding. Fixed by provisioning the template pack once into the shared
  workspace (`nuclei-templates-init`) and mounting it read-only at `/templates`.

## 29. Three state-machine gates had no writer — no engagement could ever run
**Found by:** driving the documented lifecycle through the real API.

`preFlightChecklist`, `advancePaidAt` and `finalPaidAt` are read by the transition rules and were
written **only by the seed**. No route and no console control set any of them. So:

- `advancePaid → readyToRun` requires the pre-flight checklist, and that gate has no override.
  **No engagement created through the API could ever reach `running`.** This is why a live tool run
  had never been executed: the path to it did not exist.
- `reportReview → released` requires the final payment. **No report could ever be released.**

**Built:** `PUT/GET /engagements/:id/pre-flight-checklist`, `POST /engagements/:id/payment`, a
`PRE_FLIGHT_CHECKLIST` catalogue in `packages/core` so the server decides the gate rather than
trusting the caller's keys, two audit actions, and two console panels. The state route previously
accepted any checklist with one true key; it now requires the catalogue.

## 30. The worker could not reach the Docker socket
**Found by:** the first live run after 29 was fixed — `connect EACCES /var/run/docker.sock`.

The socket is `root:root` mode 0660; the worker image runs as uid 1000 with no matching group. The
worker is the only service that may start a tool container, and under the documented compose
deployment it could not start any. **Fixed:** `group_add` with the socket's group, configurable via
`DOCKER_SOCKET_GID`. The process still runs as a non-root user.

## 31. Tool input and output went to a directory the tool never saw
**Found by:** the next live run — `open /out/targets.txt: no such file or directory`.

The worker writes a tool's input files to `/tmp/attestor/<run>` and then asks the daemon to bind that
same path into the tool container. The daemon resolves bind sources **on the host**. With
`/tmp/attestor` as a named volume the two were different directories: the worker wrote into the
volume, the daemon created an empty host directory, and every tool started with no input file and
wrote its output where nothing would read it.

**Fixed:** a host bind at an identical path, plus a `workspace-init` container to fix the ownership
the daemon creates it with, plus `chmod 0777` on the per-run directory — the tool container runs as
uid 65532 and the worker is not root, so it cannot chown to it.

## 32. A tool that found nothing failed the whole scan job
**Found by:** the same run — `evidence capture needs either text or binary content`.

`EvidenceStore.capture` guarded with `if (!input.text && !input.binary)`, so an **empty string** —
what a tool writes when it finds nothing, the most ordinary outcome there is — was rejected as "no
content" and threw. **Fixed:** absent, not falsy.

## 33. The tlsx adapter built a command tlsx refuses to start with
**Found by:** the same run.

```
FTL cause="san or cn flag cannot be used with other probes"
```

`-san` is a display probe in tlsx and cannot be combined with the certificate probes the adapter also
passes. The parser never reads `subject_an`, so the flag bought nothing. **Fixed:** removed.

## 34. nmap ran the `discovery` script category while claiming "safe categories only"
**Found by:** inspecting the command of a live nmap container.

The adapter passed `--script safe,default,discovery`. `discovery` is not a safe category and includes
scripts (`whois-ip`, `whois-domain`, `targets-*`) that send the client's hostnames to third parties
that authorised nothing — against both the never-touch principle and the claim printed in the tool
inventory and the report. The unit test was named *"nmap only ever runs safe script categories"* and
asserted the command contained `safe,default,discovery`.

**Fixed:** `--script safe`, and the test now asserts the selection whole and rejects six unsafe
categories by name.

## 35. Eleven of forty-one tool images cannot be pulled
**Found by:** `node scripts/pin-tool-images.mjs --pull` — 28 pinned, 11 failed.

`gau`, `whatweb`, `nikto`, `commix`, `kiterunner`, `cloudsplaining`, `apktool`, `jadx`, `garak`,
`promptfoo`, `strix`. Each is a tool the website and the user guide list as available. The runner
refuses an unpinned tool, so each is silently absent from every run rather than failing loudly.

## 36. Reconnaissance output was parsed and thrown away
**Found by:** the first live run that produced output, then reading the report it fed.

Every adapter may implement `parseAssets`, and five do — hosts, open ports, service banners,
endpoints, certificates, technologies. **Nothing ever called it.** Two consequences in the report:

- The ports-and-services appendix rendered "No port scanning was performed in this engagement" on
  engagements where nmap and naabu had both run.
- The asset inventory was a copy of the scope the tester typed in, not the estate that was found.

**Built:** migration `0004_discovered_asset`, the table in the schema, the worker call that persists
it, and both appendices now reading real data. Verified live: 8 assets from one run, including the
Juice Shop technology stack (`jQuery:2.2.4`, `Nginx:1.27.5`, `Onsen UI`).

## 37. Evidence could not be stored at all
**Found by:** the first run that got as far as capturing evidence.

```
NotImplemented: Server side encryption specified but KMS is not configured
```

`EvidenceStore.capture` sends `ServerSideEncryption: AES256`; MinIO refuses that unless it has a key,
and the compose file configured none. Every completed tool run failed at evidence capture, so no run
could ever finish. **Fixed:** `MINIO_KMS_SECRET_KEY` in compose and both env files, keeping the
encryption rather than dropping it.

## 38. Raw ANSI escapes were stored and shown to the operator
**Found by:** reading the console's run table in a browser — `[[34mINF[0m] Targets loaded`.

Tool stderr is coloured, and the codes went into `abort_reason` verbatim. **Fixed:** stripped where
the reason is built.

## 39. Engagement dates and assessment type could not be set — no report could be released
**Found by:** the pre-release gate, which refused with
`no-placeholders: unfilled: TEST END DATE, TEST START DATE`.

`startsAt`, `endsAt` and `testType` are read in six places — the report, the portal, three console
lists — and written **only by the seed**. The create route accepts none of them and there was no
update route, although the user guide says you choose them when creating the engagement. So every
engagement was `greyBox` with no test window, the console showed "—" for every date, and the legal
blocks that quote the test dates could never be filled, which blocks release permanently.

**Built:** `testType`, `startsAt` and `endsAt` on create with a window-ordering check, and
`PATCH /engagements/:id` for the fields an operator legitimately revises. The reference, the client
and the state are deliberately not editable.

## 40. No report could be produced in the deployed stack
**Found by:** `POST /engagements/:id/report` → 500.

```
browserType.launch: Executable doesn't exist at
/home/node/.cache/ms-playwright/chromium_headless_shell-1234/...
```

The Dockerfile installs Alpine's Chromium — Playwright publishes no musl build — and set
`PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH`, which **Playwright does not read**. The path has to be passed
to `launch()`. **Fixed:** `pdf.ts` reads `CHROMIUM_EXECUTABLE_PATH` and passes it through; the
Dockerfile sets that name. Verified: a 537 KB PDF now renders in the container.

## 41. The "no unconfirmed candidate" gate could never fire
**Found by:** releasing a report while a candidate sat in the review queue.

The item checked `data.findings` for `status === 'candidate'` — but `buildReportData` filters to
confirmed statuses, so by construction there is never a candidate there. The check passed on every
engagement, including one with a queue full of unreviewed tool output, which is the exact situation
it exists to stop.

**Fixed:** the count comes from the review queue through `ChecklistContext`, supplied at both the
preflight and the release call sites, with a test that fails if the gate stops firing.

## 42. Tool-derived findings carried no evidence, so a scan-driven report could never be released
**Found by:** the gate — `findings-have-evidence: no evidence attached to: ATT-2026-001-001`.

`RawFinding` has an `evidence` array keyed by `objectKey`, but adapters are pure functions with no
access to object storage, so nothing could ever populate it. Every tool-derived finding reached
triage with nothing attached, and the checklist correctly refused to release the report.

**Built:** `evidenceText` on `RawFinding` — the record the adapter parsed, which is what the tool
actually said — populated across the httpx, tlsx, nuclei, ZAP, dalfox, Schemathesis and nmap paths;
`ingestFindings` now returns the findings it created; the worker captures that text through the same
masking layer as any other evidence and links it to the finding. It is a starting point for the
tester, not a substitute for the evidence a person attaches when they reproduce the issue.

## 43. `Origin: null` was treated as an absent Origin header
**Found by:** the security regression script.

The origin guard allowed `Origin: null` alongside a missing header. A missing header means a
server-to-server caller; `null` is what a sandboxed iframe or a `data:` document sends, which is a
browser context an attacker can arrange. `SameSite=strict` still covered it, so this is hardening
rather than a hole — but it costs nothing. **Fixed**, and the test that asserted the old behaviour
now asserts the new one.

## 44. Port scanners were given URLs and refused to run
**Found by:** a live run whose scope was entered as URL items.

```
naabu failed — [FTL] Could not run enumeration: no valid ipv4 or ipv6 targets were found
```

`POST /runs` passes its target strings verbatim to every adapter, and `loadRunContext` builds them
from scope items — which are frequently `url` items. httpx and nuclei take a URL; naabu, tlsx and
nmap take a host or an address and refuse a URL outright. So an engagement scoped by URL silently
lost its port and TLS coverage, and because those runs merely *failed* the coverage matrix recorded
the checks as untested rather than anyone noticing why.

**Fixed:** a `hostList` helper reduces targets to distinct bare hosts, used by the three adapters
that scan hosts rather than URLs, with a test asserting no `://` reaches their target file and that
two URLs on one host collapse to one host.

## 45. The nuclei parser crashed on real output
**Found by:** the first nuclei run that reached a live target, once 28a–c let it start.

```
scan job failed — Cannot read properties of null (reading 'toUpperCase')
```

`asArray` passed a template's `classification` values straight through, and template authors write
that block by hand: a good number of templates emit `"cve-id": null` or an array containing a null.
`cve.toUpperCase()` then threw and took the whole scan job with it. Every fixture in the repository
was well formed, so the adapter suite's "never crashes on empty, truncated or hostile output" test
never reached this.

**Fixed:** `asArray` drops anything that is not a non-empty string, once, rather than guarding each
of the four places it feeds. A fixture with a null-bearing classification block is now in the corpus
and the count assertion covers it.

## 46. A killed worker leaked its container and its network
**Found by:** the integration suite's own "leaves no container behind" assertion, after a session of
restarting the worker mid-run.

`ContainerRunner.run` removes its container in a `finally`, and `runToolForEngagement` removes the
per-run network in another — which covers a tool that fails, times out or is killed. Neither covers
**the worker itself** being killed: a crash, a restart, a deploy. A clean run was verified to leave
nothing behind, so the runner is correct; but across restarts the leak is unbounded, and Docker
allows 31 bridge networks by default before it runs out of address space.

**Fixed:** `reclaimOrphans()` on the runner, called once at worker start-up. It removes only
containers that have exited and only networks that are no longer attached to anything — a running
container belongs to a worker that is still alive, and killing another worker's run is the one thing
this must never do.
