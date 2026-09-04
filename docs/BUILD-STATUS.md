# Build status

Resume point for this build. Update it whenever a milestone lands, so a new session can pick up
from here without re-reading the whole repository.

**Read `docs/PRODUCT-CONTEXT.md` alongside this file.** That one is the stable picture — what the
product is, how it is built, and the non-obvious things that are true about the run path. This one
is the live state. `docs/OPERATOR-HANDBOOK.md` is the same ground in plain English, for running the
firm rather than changing the code: client onboarding, proving a client owns what they gave you, and
what to avoid.

**Last updated:** 2026-08-29, after the WSTG footprint was closed to zero unexplained gaps, the
OWASP Risk Rating calculator was built beside CVSS, schemathesis was made to run for the first time,
and a third in-process probe was added. Earlier the same day: the access control matrix and the rate
limit probe were wired into real runs, ffuf and dnsx were given adapters, and three known defects
were fixed. Twelve further
defects were found doing it, numbered 51 to 62 below; two of them were controls that could never
fire, one was a tool that had never run, and one fabricated a finding from a connection that had been
refused. Before that, on 2026-08-28, credential intake was built and wired into a run. Before that
the vault had no way in: the console minted a one-time link pointing at a portal page that did not
exist, nothing ever wrote a row into `credential_set`, and `credentialSetId` in a policy referred to
something that could not exist — so no authenticated testing was possible at all. A client can now
hand over a test account through a page that asks only for the boxes that kind of login needs, and
ZAP signs in with it. Four defects were found doing it, numbered 47 to 50 below; one of them meant
**no ZAP run had ever started** in the platform's history.

Before that, the same day: the first regression run with a working container daemon. The
stack was booted under compose for the first time, real security tools were run in real containers
against deliberately vulnerable targets, and the engagement was driven through triage, report
generation and the release gate. **Twenty-five further defects were found and fixed** — all of them
passing lint, typecheck and the full suite beforehand. They are written up in
`docs/REGRESSION-2026-08-28.md`, numbered 22 to 46.

Four of them meant the product could not do its job at all: no engagement could ever reach a
runnable state, the container runner crashed the worker on the first byte of tool output, tool input
and output went to a directory the tool never saw, and no report could be produced or released.

---

## The gate, right now

| Check | Command | State |
| --- | --- | --- |
| Lint | `pnpm lint` | passing |
| Typecheck (workspaces) | `pnpm typecheck` | passing |
| Typecheck (root project) | `pnpm exec tsc -p tsconfig.json --noEmit` | passing |
| Unit and property tests | `pnpm test` | **483 passing, 34 files** |
| Claim check | `pnpm check:claims` | passing |
| Marketing site build | `pnpm --filter @attestor/website build` | passing |
| Console build | `ATTESTOR_SURFACE=console pnpm --filter @attestor/console build` | passing |
| Portal build | `ATTESTOR_SURFACE=portal pnpm --filter @attestor/console build` | passing |
| Integration suite | `ATTESTOR_TEST_NETWORK_ONLY=1 pnpm test:integration` | **31 passing** — the live run suite passes for the first time |
| **Credential intake, end to end** | `apps/api/tmp-creds.mjs` against the running stack | **link → client page → sealed row → console → revoke, no failures** |
| **A recon module end to end** | the real API, worker and containers, live Juice Shop | **ten tools, real findings, no third-party egress** |
| **An API module end to end** | the same, against a live VAmPI | **nuclei, ZAP and schemathesis all completed and kept; two probes reported why they did nothing; one probe examined the target** |
| **The three in-process probes end to end** | queue → worker → probe → findings | **the rate limit probe sent its full 30-request burst to two live endpoints; the access control matrix refused itself because the policy had switched it off, and recorded why; the request manipulation probe examined a live API** |
| **WSTG footprint** | `pnpm test` (catalogue integrity) | **109 of 109 accounted for: 106 covered, 3 explained decisions, no unexplained gap** |
| **Catalogue** | the same | **235 checks — 91 automated, 75 assisted, 69 manual** |
| **An authenticated ZAP scan** | the product's own plan, real ZAP, live Juice Shop | **signed in, crawled as that user, exit 0, no secret on disk** |
| **The whole stack under compose** | `docker compose -f infra/docker-compose.yml up -d --build` | **nine services healthy, both UIs 200** |
| **A live tool run** | see `docs/REGRESSION-2026-08-28.md` | **real containers, real targets, real findings** |
| **A whole engagement through the real API** | the same | **zero failures, from bootstrap to the release gate** |
| **Platform security regression** | the same | **24 cases passing** |

Everything above has been run. Nothing in this table is an expectation.

---

## Done

### PART A — the marketing site (`apps/website`)

Astro 7 static site: pages, content collections, four zero-JS islands, Pagefind search, build-time
OG images via satori, self-hosted OFL fonts, strict headers, published prices, sample report page.
Builds clean and typechecks clean.

### PART B — the platform

- **`packages/shared`** — redaction, masking (Luhn + Verhoeff), logging, config, ids
- **`packages/findings`** — 235-check catalogue, CVSS 3.1 + 4.0, OWASP risk rating, dedupe, diff, coverage matrix
- **`packages/core`** — scope guard, engagement state machine, container runner, audit log,
  AI-assist layer, architecture test
- **`packages/policy`** — schema, resolution, five profiles, cloud provider testing policies
- **`packages/scanners`** — adapters with pure parsers, fixtures, hostile-input tests
- **`packages/report`** — renderer, legal blocks, pre-release checklist, PDF, golden file
- **`apps/api`** — console API, portal API, workers, queue, services. Route modules: ai, auth,
  client, engagement, finding, report, platform
- **`apps/console`** — Next 16, both surfaces from one codebase, gated by `ATTESTOR_SURFACE`

### Credential intake and authenticated scanning

The client-facing half of the vault, and the part that makes a stored credential worth storing.

- **Seven kinds of login** in `packages/core/src/engagement/credential-kinds.ts` — email and
  password, username and password, mobile number with a code, single sign-on, API key, bearer token,
  session cookie. Each names the fields it needs, the help text under each box, whether the field is
  a secret, and the policy `authProfiles.type` it satisfies.
- **The tester asks** from the engagement page: name each account, its role, and how it signs in.
  `POST /engagements/:id/credential-link` returns a one-time URL, shown once, stored only as a hash.
- **The client submits** at `/credentials/<token>` on the portal — no account, no password, one small
  form per account showing only the boxes that login needs. Each account is sent on its own and can
  be replaced later from the same link.
- **The console API seals it.** The page is served by the portal because that is the surface a client
  can reach, but the submission goes to the console, which is the only service holding the vault key;
  the portal's database role is granted nothing on the credential tables.
- **The run uses it.** `openRunCredentials` matches credentials to the policy's auth profiles by role
  — no uuids to paste — opens them in the worker, and gives the adapter `${ENV}` references while the
  values go to the container's environment and the redaction filter. ZAP then drives a real browser
  at the login page, signs in, and runs the spider, the AJAX spider and the active scan as that user.
  The plan file written to disk never holds a secret; nor does the command line, nor the audit log.
- **Nothing is silent.** A credential with no matching profile, a profile whose type disagrees with
  the kind submitted, and whether the run was signed in at all are recorded in the run's stats.
- **Withdrawing one** is `POST /engagements/:id/credentials/:credentialSetId/revoke`, or **Stop
  using** in the console. Closing the engagement still destroys the key salt.

Not done here: an API key, bearer token or session cookie is stored but not presented by a tool —
ZAP substitutes environment variables into user credentials and not into job parameters, so carrying
one would mean writing it into the plan file. Nothing verifies a credential before a run either.

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

The twenty-five found on 2026-08-28, in the first regression run with a working container daemon,
are written up in full in `docs/REGRESSION-2026-08-28.md` — numbers 22 to 46. Four of them meant the
product could not perform its core function, two were controls that could never fire, and one was a
safety rail whose test asserted the opposite of its name.

Four more were found later the same day, while building credential intake and wiring it into a run.
Numbered on from that file:

47. **Every ZAP run failed before it read its plan.** The container runs as uid 65532, which has no
    passwd entry, so the JVM reports `user.home` as `?` and ZAP resolved its home directory to
    `/zap/?/.ZAP/` against a read-only root filesystem — "Unable to create home directory", exit 1,
    no request sent. Every web run in the platform's history had failed this way and the run table
    recorded it as a tool failure rather than a configuration one. Fixed with `-dir /tmp/zap-home`,
    which points ZAP's home at the tmpfs it already gets: memory-backed, so the session database —
    which holds the login request, and so the client's password — never reaches a disk.
48. **The credential upsert could never succeed.** `credential_set` has a *partial* unique index on
    `(engagement_id, intake_slot)`, and an `ON CONFLICT` naming those columns without repeating the
    index's `WHERE` matches no index at all. Postgres refused the whole statement, so every
    submission returned 500. Fixed with `targetWhere`, and the drizzle schema now declares the index
    as partial too, which is what it always was in the migration.
49. **Two intake links for one engagement shared slot names.** The slot was derived from the
    account's position and role, so asking a client for a support account under the same role
    silently overwrote the standard user account from an earlier link. Slots are now random per
    account; a resubmission within one link still replaces, which is the behaviour that matters.
50. **A credential could sit in the vault unused with nothing said about it.** Credentials are
    matched to policy auth profiles by role; an engagement with credentials and no `authProfiles`
    entry, or with a profile whose type disagrees with the kind of login the client submitted,
    produced a scan that browsed signed out and looked exactly like an authenticated one. Both now
    produce a named warning, recorded in the run's stats beside `authenticatedAs`.

Twelve more were found on 2026-08-29, over two streams: the WSTG coverage audit, and wiring the two
in-process probes into a real engagement. The first four were found building the access control
matrix; the last eight were found by running a recon and an API module end to end against a live Juice
Shop and reading what the run rows actually said. Every one of them passed lint, typecheck and the
whole suite first.

51. **dalfox never ran, twice over.** `hahwul/dalfox` declares no ENTRYPOINT, so the adapter's first
    argument `file` was exec'd as a binary; and its v2 flags (`--skip-bav`, `--worker`) do not exist
    in 3.2.1. Its defaults are 50 workers and no rate cap, so the policy limits now go on the line.
52. **katana returns zero endpoints for a single-label hostname.** `http://intranet` crawls nothing
    and exits 0; `http://intranet:80` crawls normally. Internal engagements are full of such names,
    and an empty crawl reads exactly like a one-page application.
53. **A login POST was refused in read-only mode**, so an authenticated replay test could never run
    in the configuration recommended for production. `ProbeRequest.purpose: 'authenticate'` now
    exempts the verb check and nothing else.
54. **The credential resolver picked the oldest credential for a role.** A second intake link makes a
    new row, so a client asked again for a corrected account went on being tested with the one they
    had already replaced. Now newest first.
55. **Every shipped profile threw away a whole class of nuclei check.** The schema default was fixed
    to include `info`, and the three profiles that name `nucleiSeverities` went on overriding it —
    including `standard-web-app`, the default web engagement. Every exposure, metafile and
    exposed-panel template nuclei ships is `info`, so those checks never ran while the catalogue went
    on claiming nuclei automated them. The overrides are gone, `resolvePolicy` now warns when any
    layer drops `info`, and a test asserts no profile can do it again. Verified by running it: the
    same engagement that had produced nothing of the kind returned ten informational findings —
    security.txt, robots.txt, missing security headers, an exposed Swagger endpoint, missing
    subresource integrity — plus a medium for exposed Prometheus metrics.
56. **httpx fetched 92.6 MB from huggingface on every run.** From v1.10 it downloads a page
    classification model at startup whenever `-json` is asked for, which the adapter always asks for
    — unannounced third-party egress from inside a tool container in the middle of a client
    engagement. It could not even keep what it downloaded: the container's home is a 64 MB tmpfs, so
    it paid for the transfer again on every single run. Provisioned once now by an init service into
    the shared workspace and mounted read-only at the tool's home, exactly as the nuclei template
    pack already was. Measured in the runner's own container configuration: 11 seconds and a
    huggingface fetch before, 4 seconds and no third-party request after, and the model's own output
    now present in the results rather than silently absent.
57. **One duplicate asset failed the whole run.** Every tool's inventory went into a single insert
    with `ON CONFLICT DO UPDATE`, and Postgres refuses such a statement when its own VALUES list
    reaches the same row twice — which nuclei does routinely, because a dozen templates match at `/`.
    The insert threw, the run was recorded as `failed`, and every check it had genuinely covered was
    reported to the client as untested. Found by running it: fixing it turned the same nuclei run
    from `failed` into `completed` with nineteen results. Made much more likely by fix 55, which is
    the order these two should be read in.
58. **The policy switch that turns cross-role replay off was never read.** `accessControlMatrix`
    supplied its threshold, its budget and its role pairs to the probe, and `enabled` was consulted
    nowhere — so an engagement that had said no to cross-identity testing got it anyway. Two shipped
    profiles say no, one of them `quick-external`, which is the profile described as gentle enough to
    run against production without a conversation.
59. **schemathesis had never run.** The adapter passed `--report json --report-json-path`, and the
    pinned image has no such option — `Error: No such option '--report-json-path'`, exit 2, on the
    first argument, exactly like dalfox at 51. It was worse than that: the first positional argument
    was `/out/openapi.json` and **nothing in the platform ever wrote that file**, and `parse`
    expected a JSON report shape that version no longer produces. So API schema testing had never
    once happened while the catalogue claimed schemathesis automates it. Fixed on all three counts:
    the schema is fetched from a path the policy names on the target itself (`checks.openApiSchemaPath`,
    empty by default, and the tool refuses to run rather than guessing at `/openapi.json`); the report
    is NDJSON, which is what this version produces; and the parser reads the events the tool actually
    emits, deduplicated to one finding per failure per operation. Verified against a live VAmPI: 30
    raw failures became 25 findings with the severities schemathesis itself assigns.
60. **A probe that did no work was recorded as having done it.** `rateLimitProbe` with no endpoint
    named, and the access control matrix with the switch above turned off, both report a `skipped`
    reason and did nothing — and the worker wrote the run down as `completed`, which hands its
    `coveredCheckIds` to the coverage matrix as tested. The same rule a container tool has always had
    now applies to a probe: it lands as `aborted` with the reason on the row, so the client reads why
    rather than a silent gap. Both halves verified through the product: the access control matrix run
    landed `aborted` reading "Cross-role access control testing is switched off in this engagement
    policy", and the rate limit probe beside it completed having actually sent 30 requests to each of
    two endpoints.
61. **A refused connection was reported as an absence of rate limiting.** The rate limit probe breaks
    its burst on a transport failure — correctly, because a target falling over is not a throttle —
    and then filed the observation as an ordinary result. Against a Juice Shop that had crashed under
    the previous tool, one refused connection produced a medium-severity finding reading "No
    throttling on /rest/user/login within 1 requests ... every one was answered normally", about a
    request nobody answered. A burst that could not be completed is now reported as unmeasured and
    produces no finding at all. Found by reading a run's stats and noticing `requestsSent: 1` against
    a burst of 30.
62. **dnsx wrote its answers nowhere.** Its command carried no `-o`, so the output file the worker
    reads never existed and the parser was handed an empty string — a tool that ran, resolved every
    record it was asked for, and told nobody. The evidence record looked fine, because that one
    already fell back to stdout; only the parser did not. So `recon-mail-authentication` was reported
    as covered on every run and no SPF, DKIM or DMARC record was ever read. Verified against a real
    domain: the same output goes from zero assets to four, and the SPF and DMARC records the parser
    needs are there. The fallback now happens in one place, so the next adapter to forget cannot lose
    its results silently.

Five more were found on 2026-08-29 while closing the WSTG footprint and making schemathesis run.
Four of the five are the same shape as the ones before them: a control that looked like it worked.

63. **The catalogue claimed WSTG tests it did not perform, while the tests it did perform read as
    gaps.** Six mappings were simply wrong, and each wrong one hid a real capability: host header
    handling was filed under the HSTS test, so `WSTG-INPV-17` was a gap while a check for it existed;
    response splitting claimed `INPV-16`, which is reviewing the application's own inbound traffic
    and is not testable from outside; concurrent sessions and session puzzling both claimed
    `SESS-08`, so one counted for nothing and `SESS-11` read as a gap; default credentials claimed
    the HTTP methods test; and the access control matrix, the GraphQL check, the cloud storage check
    and the network service enumeration performed `APIT-02`, `APIT-99`, `CONF-11` and `CONF-01`
    without ever saying so. Sixteen of the thirty-one gaps were closed by writing down what was
    already true; the rest by naming the ZAP release rule that performs each one, or by holding the
    test as manual work so a person does it and the matrix records that they did.
64. **A tool that reports findings through its exit code had those runs thrown away.** Schemathesis
    exits 1 exactly when its checks fail. The worker treats a non-zero exit as a run that did not
    happen — correctly, for every other tool — so the runs that found something were discarded and
    only the quiet ones were kept, which is the precise opposite of the tool's purpose. Adapters now
    declare `successExitCodes`, and only schemathesis has one.
65. **A probe refused a whole run over an endpoint left behind by an earlier one.**
    `discovered_asset` accumulates across an engagement, so the two probes that read crawled
    endpoints picked up a URL from a container that had since been replaced. The scope guard refused
    the probe — correctly — and the result was a run that tested nothing while the real target sat
    there untouched. The endpoints are now narrowed to the hosts of this run's targets before the
    guard sees them, so a probe tests what it may and stays silent about the rest. Found by running
    it; the run row read `tried to reach 172.18.0.12, which is not one of the approved targets`.
66. **A failed tool's output was discarded.** Evidence was captured after the exit code was judged,
    so a run that failed kept nothing but the last three lines of stderr — and those are rarely the
    three that explain it. ZAP exiting 2 with only a Java preferences warning was undiagnosable. The
    output is now read and stored before the exit code decides anything, and a failed run carries its
    `rawOutputKey` like any other.

67. **The denial-of-service safety rail broke every ZAP active scan, and excluded nothing.** Four
    lines of the ZAP plan turned off the resource-exhaustion rules. All four were wrong, in three
    independent ways, and any one of them alone was enough:

    - the ids named were `20000` and `20001`, the retired alpha denial-of-service rules, which are
      not in the release rule set the plan enables and have not been for years;
    - `strength: off` and `threshold: off` were unquoted, and YAML 1.1 reads a bare `off` as the
      boolean `false`;
    - ZAP's strength enum has no `off` at all — Low, Medium, High, Insane, Default is the whole of
      it. A rule is disabled by its threshold.

    ZAP does not ignore any of that quietly. It finishes the plan, writes a complete report, and
    exits 2 with `Unrecognised active scan rule ID`. The worker reads a non-zero exit as a run that
    did not happen — correctly — so **every ZAP active scan in the platform's history was recorded
    as failed and its findings discarded**, while the exclusion it existed to enforce was excluding
    nothing. Its unit test asserted the plan *contained* `id: 20000`, so the control passed a test
    that proved only that the mistake was still there.

    Now one rule, `40044` (Exponential Entity Expansion, the billion-laughs XML bomb — the one rule
    in the release set that attacks availability), disabled by a quoted threshold. Verified against
    the pinned image: the run prints `set rule 40044 threshold to OFF` and exits zero, where the
    same plan exited 2 three times running as each fault was uncovered.

---

## Not done

Ranked by what should happen next.

1. **A token is stored but never presented.** An API key, a bearer token and a session cookie can be
   submitted, sealed and revoked, but no tool sends them: ZAP substitutes environment variables into
   a user's credentials and not into job parameters, so a header rule would have to carry the value
   in the plan file on disk. An API-only assessment authenticates by hand today.
2. **Nothing checks a credential before a run.** `lastVerifiedAt` and `verificationError` exist on
   the row and are never written, and the `credentialSet.verified` audit action can never fire. A
   mistyped password is discovered from an empty authenticated scan.
3. **Eleven of forty-one tool images cannot be pulled.** `gau`, `whatweb`, `nikto`, `commix`,
   `kiterunner`, `cloudsplaining`, `apktool`, `jadx`, `garak`, `promptfoo`, `strix`. The runner
   refuses an unpinned image, so each is silently absent from every run while the website and the
   user guide list it as available. Each needs a working image reference or removal from the
   catalogue — leaving them listed overstates what the platform does.
4. **Legal text is not lawyer-reviewed.** Every block carries `lawyerReviewedAt: null` and documents
   render with a visible draft banner until that changes. Still the one thing that cannot ship.
5. **A model has never actually been called.** The AI layer is fully implemented and fully tested
   against an injected transport, but no request has gone to a provider — there is no key here, and
   the default configuration refuses everything anyway. The first real call should be made on a
   scratch engagement with a low budget ceiling.
6. **Mobile, cloud, code and LLM modules have not been driven end to end** against a live target.
   Recon, web and network have.
7. **Off-host log shipping and alerting.** The two real gaps in the ASVS self-assessment, in V16.
8. **Notification sending is deliberately manual.** There is no SMTP client anywhere. Approving
   records the decision; a person sends the message and marks it sent. If that ever changes, it is a
   design decision, not a feature.

### Running a live tool run

`docs/PRODUCT-CONTEXT.md` §5 has the things that are true and non-obvious about the run path, and
they are all load-bearing. The one that catches everybody: **a tool container is on a fresh per-run
bridge network and cannot reach the `internal: true` test-target network.** In production it reaches
targets over ordinary egress. To drive a real run against the local vulnerable stack, publish the
targets on the host and scope the host address as a client-declared private range with a `cidr`
scope item — which is the internal-engagement path, and worth exercising for its own sake.

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
