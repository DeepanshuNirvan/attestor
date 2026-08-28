# Attestor

Two things live in this repository:

- **`apps/website`** — the public marketing site for Attestor Security, an Indian security testing
  firm. Static, editorial, published prices, no login, no database, no uploads.
- **Everything else** — **Attestor Console**, the platform the firm runs engagements on: scope
  guard, tool orchestration, findings pipeline, report engine, client portal, retainer engine.

The design idea, in one line: **make the dangerous thing structurally impossible rather than
forbidden by policy.** The platform cannot perform a denial-of-service test — not because a setting
is off, but because no field in the policy schema can express it, no adapter can build the command,
and two independent tests fail the build if either becomes untrue.

---

## What is here

```
apps/
  website/        Astro 7 static site — the public marketing site
  api/            Fastify 5 — console API, portal API, workers
  console/        Next.js 16 — staff console and client portal, one codebase, two deployments
packages/
  shared/         Redaction, masking, logging, config, ids
  findings/       210-check catalogue, CVSS 3.1 + 4.0, dedupe, diff, coverage matrix
  core/           Scope guard, engagement state machine, container runner, audit log
  policy/         Policy schema, resolution, five profiles, cloud provider testing policies
  scanners/       Tool adapters — one file per tool, pure parsers
  report/         Report renderer, legal blocks, pre-release checklist, PDF
infra/            Compose files, Dockerfile, migrations, vulnerable test targets
docs/             Decisions, research notes, runbook, threat model, checklists, ASVS
scripts/          Image pinning, claim checking, screenshots
```

189 source files, 290 unit and property tests, plus integration suites that only ever run against
local targets.

---

## Requirements

- Node 22 LTS. The API and workers run TypeScript directly with `--experimental-strip-types`; there
  is no transpile step and no build output to keep in sync.
- pnpm 10.
- Docker, for the tool runner and the local stack.

## Getting started

```bash
pnpm install
cp infra/.env.example infra/.env
```

Fill in `infra/.env`. Nothing there has a working default, deliberately — a secret with a default is
a secret that ships. The generation commands are written at the top of the file.

```bash
docker compose -f infra/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml exec api pnpm --filter @attestor/api migrate
node scripts/pin-tool-images.mjs --pull
```

`pin-tool-images.mjs` writes `infra/tool-images.lock.json`. Until it has run, **no tool will
start**: the runner refuses any image without a pinned digest, because a report that names a tool
version has to mean it.

The compose stack brings up the platform. The marketing site is static and is not part of it — run
it with `pnpm --filter @attestor/website dev`.

| Service | URL |
| --- | --- |
| Marketing site (separate) | http://localhost:4321 |
| Staff console | http://localhost:3000 |
| Client portal | http://localhost:3100 |
| Console API | http://localhost:8080 |
| Portal API | http://localhost:8081 |
| Mail capture | http://localhost:8025 |

## Everyday commands

```bash
pnpm check
```

Lint, typecheck, unit and property tests, and the claim check — the whole gate in one command.

```bash
pnpm test                 # 290 unit and property tests
pnpm lint
pnpm typecheck
pnpm check:claims         # fails on any claim the firm cannot make
```

Integration tests need the vulnerable stack, and refuse to start without the flag that says it is
up:

```bash
docker compose -f infra/docker-compose.test.yml up -d --wait
ATTESTOR_TEST_NETWORK_ONLY=1 pnpm test:integration
```

That flag is not decoration. The targets sit on a Docker network with `internal: true` — no route
off the machine — and the suite installs a guard that throws if any test tries to reach a host
outside it. A scanner integration test that hits a live host is an unauthorised scan, and "it was
an accident" is not a defence.

---

## The parts worth knowing about

### One way to start a container

`packages/core/src/runner/run-tool-for-engagement.ts` is the only path to execution. It checks scope
for every target, records the decision, and only then hands to the container runner. If **any**
target fails, the whole run is refused — not filtered, because a partially-scoped run is how a
target gets tested by accident.

Exactly one module imports `dockerode`. That is enforced by an ESLint rule **and** by
`packages/core/src/architecture.test.ts`, because a control with a single enforcement point is a
control that eventually gets moved.

### A dry run performs every check and sends nothing

It is the recommended first action on any new engagement, and it is what you read before a live run.

### No denial of service, structurally

The policy schema has no field for it. Rate ceilings are clamped. `DENIAL_OF_SERVICE_CAPABILITY` is
`false`. An architecture test greps the source for DoS-shaped symbols. Every adapter's built command
is asserted to contain no flood flag. Four independent things would have to be edited together.

### Cryptographic shredding

Credentials are sealed under a per-engagement subkey derived from the master key, a random salt and
the engagement id. Closing an engagement destroys the salt, and after that no key opens the
ciphertext — not for an attacker, not for us, not from a backup. This is why restoring the database
without `VAULT_MASTER_KEY` gives engagement records and unreadable credentials: the design working,
not a failure.

### The coverage matrix is generated from what actually ran

It is not a list of what the tools could theoretically find. Everything not fully tested carries a
reason, and manual coverage is recorded per check by the person who did it.

### Reports are byte-stable

The renderer reads no clock, so the golden-file test means something. Fonts are embedded as data
URIs, so a report never phones home when a client opens it — and an integration suite proves it, by
firing a 25-payload XSS corpus through every string field, rendering it, opening it in a real
browser, and asserting that nothing ran and no request was made.

### The AI layer is off, and cannot assert what the evidence does not say

Two switches, both required: the deployment flag and a per-engagement flag. Input is redacted before
the request is built. Output is checked against the evidence — a draft that introduces a hostname,
URL or CVE the evidence never mentioned is discarded, not flagged. Everything it returns is a draft,
and the pre-release checklist refuses to release a report while any section is still an unapproved
one. Agentic testing is refused in code with a reason, because a flag nothing reads is worse than no
flag at all.

### The Content-Security-Policy carries a per-request nonce

It is issued by `apps/console/src/proxy.ts`, not as a static header, because Next emits inline
scripts and the only way to allow exactly those is a nonce. A static `script-src 'self'` produces a
page that renders and then does nothing — which is what the first version of this did, and which
neither the build nor the test suite noticed. `src/lib/csp.test.ts` covers both ways back into it.

### The portal cannot read the credential vault

Not by convention — by database grant. `attestor_portal` is a separate least-privilege role. Every
portal query filters on the client id from the session, and a structural test parses the route file
and fails the build if any authenticated route forgets to.

---

## The marketing site

```bash
pnpm --filter @attestor/website dev
pnpm --filter @attestor/website build
```

Astro 7, static output, four small interactive islands written as plain `<script>` tags. No
framework runtime ships to the browser. Pagefind provides search at build time; OG images are
generated at build time with satori. Fonts are self-hosted OFL WOFF2.

After deploying, check the headers at <https://securityheaders.com>. A security firm's own site
scoring anything less than A+ is a conversation nobody wants to have, and the target configuration
is in the runbook.

---

## Documentation

| Document | What it is for |
| --- | --- |
| [docs/USER-GUIDE.md](docs/USER-GUIDE.md) | **Start here.** What everything is, how to run an engagement, what it tests, which tools, how to customise it |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | The stack, the folder architecture, how a request travels, the data model, the topology |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Hosting the website and the platform, with exact commands |
| [docs/COMMANDS.md](docs/COMMANDS.md) | Every command, plus a whole engagement driven by curl |
| [docs/POLICY-COOKBOOK.md](docs/POLICY-COOKBOOK.md) | Policy YAML reference and nine worked examples |
| [docs/SALES-PLAYBOOK.md](docs/SALES-PLAYBOOK.md) | Positioning, pricing, objections, and the lines never to say |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | Provisioning, DNS and mail, backup and restore, key rotation, the panic stop, onboarding |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | What we are defending, from whom, and the risks we have accepted |
| [docs/CHECKLISTS.md](docs/CHECKLISTS.md) | The fourteen checklists the firm runs on |
| [docs/ASVS-SELF-ASSESSMENT.md](docs/ASVS-SELF-ASSESSMENT.md) | ASVS 5.0.0 Level 2, chapter by chapter, including the two real gaps |
| [docs/DECISIONS.md](docs/DECISIONS.md) | One line per decision, with the reason |
| [docs/RESEARCH-NOTES.md](docs/RESEARCH-NOTES.md) | Standards editions and dates checked, library versions, provider policies |

---

## Two things this repository will not do

**It will not claim a certification the firm does not hold.** `scripts/check-claims.mjs` runs in CI
and fails the build on any first-person claim of CERT-In empanelment, CREST accreditation, ISO
certification of the firm itself, any guarantee of security, or any promise to certify a system as
secure. This is a build failure rather than a review habit because the cost of getting it wrong is
not a bug.

**It will not send anything to a client on its own.** Releasing a report publishes it in the portal
and queues a notification for a person to read and send. There is no code path in which the platform
emails a client without a human in between.
