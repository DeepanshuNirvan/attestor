# Attestor: the user guide

Everything you need to run the firm on this software: what it is, what it tests, how to use it, how
to change it, and what it deliberately will not do.

Written for the owner. Where a section is for a client, it says so.

**Contents**

1. [What you actually have](#1-what-you-actually-have)
2. [Is it ready](#2-is-it-ready)
3. [The marketing website](#3-the-marketing-website)
4. [The console: running an engagement, start to finish](#4-the-console-running-an-engagement-start-to-finish)
5. [The client portal](#5-the-client-portal)
6. [What the platform tests](#6-what-the-platform-tests)
7. [The tools](#7-the-tools)
8. [Customising everything](#8-customising-everything)
9. [Reports](#9-reports)
10. [The safety rails](#10-the-safety-rails)
11. [What it will not do](#11-what-it-will-not-do)
12. [Where everything lives](#12-where-everything-lives)

**The companion documents.** This guide is the overview; each of these is the detail.

| Document | What it covers |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | The tech stack, the folder architecture, how a request travels, the data model, the deployment topology |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Hosting the website and the platform, with the exact commands. Updating and rolling back |
| [COMMANDS.md](COMMANDS.md) | Every command, plus a whole engagement driven by `curl` |
| [POLICY-COOKBOOK.md](POLICY-COOKBOOK.md) | The full policy YAML reference and nine worked examples |
| [SALES-PLAYBOOK.md](SALES-PLAYBOOK.md) | How to pitch it, what is included, objections, and the lines never to say |
| [RUNBOOK.md](RUNBOOK.md) | Provisioning, DNS and mail, backups, key rotation, the panic stop, incidents |
| [CHECKLISTS.md](CHECKLISTS.md) | The fourteen checklists the firm runs on |

---

## 1. What you actually have

Two products in one repository.

**The marketing website** — `apps/website`. A static site: services, published prices in five
currencies, a sample report, insights, legal pages, contact. No login, no database, no uploads, no
admin panel. It is HTML and CSS on a CDN, which is why there is almost nothing on it to attack.

**Attestor Console** — everything else. The platform you run engagements on:

| Piece | What it does |
| --- | --- |
| Scope guard | Decides whether a target may be touched. Refuses the run if any target fails. |
| Tool runner | Starts scanners in hardened containers, one at a time, on a per-run network. |
| Findings pipeline | Normalises tool output, deduplicates, correlates, tracks status across retests. |
| Report engine | Produces the assessment report, retest report, attestation letter, deletion confirmation. |
| Client portal | Where clients read findings, mark them fixed, request a retest, download documents. |
| Retainer engine | Schedules recurring engagements as drafts a person then starts. |
| AI assist | Optional, off by default, drafts prose from evidence with a grounding check. |

The console and the portal are the **same codebase deployed twice**, gated by `ATTESTOR_SURFACE`.
That is on purpose: one set of components, two deployments, and a middleware that returns 404 for
the other surface's routes so a misconfiguration fails closed.

---

## 2. Is it ready

**Working and verified:**

- 334 tests pass; lint, typecheck and the claim check are clean.
- Both surfaces build and every page has been rendered in a browser.
- The marketing site builds: 22 pages, search index, OG images.
- The report renderer survives a 25-payload XSS corpus in a real browser.

**Not yet done, and honest about why:**

| Thing | Why |
| --- | --- |
| A real scan has never run | Docker was not running on the build machine. The end-to-end test is written; it needs `docker compose -f infra/docker-compose.test.yml up -d --wait`. |
| The stack has never booted end to end | Same reason. |
| `infra/tool-images.lock.json` does not exist | `node scripts/pin-tool-images.mjs --pull` writes it. **Until it runs, no tool will start** — by design. |
| A model has never been called | The AI layer is fully tested against an injected transport. No provider key exists here. |
| Legal text is not lawyer-reviewed | Every block is marked `lawyerReviewedAt: null` and documents carry a visible draft banner until a lawyer signs it off. This is the one thing you cannot ship without. |
| Off-host log shipping, alerting | The two real gaps in `docs/ASVS-SELF-ASSESSMENT.md`. |

So: the software is finished, and the **operational** steps that need a machine with Docker and a
lawyer are not. `docs/BUILD-STATUS.md` is the live checklist.

---

## 3. The marketing website

### 3.1 What is on it

| Page | Purpose |
| --- | --- |
| `/` | The pitch, the proof, the prices |
| `/services` and `/services/<slug>` | Six services: web and API, mobile, cloud review, LLM red teaming, compliance testing, continuous testing |
| `/what-we-test` | The check catalogue, in public. This is the page that wins technical buyers |
| `/how-we-work` | The engagement timeline, week by week |
| `/pricing` and `/pricing/usd` | Published prices, INR and USD |
| `/sample-report` | A real report against OWASP Juice Shop, not a mock-up |
| `/insights` | Three articles, RSS, full-text search |
| `/legal/*` | Terms, privacy, responsible disclosure |
| `/contact` | Booking link and email. No form that stores anything |

Four interactive islands: the pricing currency switcher, the scope estimator, the catalogue filter,
and search. All plain `<script>`, no framework in the browser.

### 3.2 What to edit, and where

| To change | Edit |
| --- | --- |
| Company name, email, booking link, social handles | `apps/website/src/data/site.ts` |
| Prices, currencies, what each package includes | `apps/website/src/data/pricing.ts` |
| The engagement timeline on `/how-we-work` | `apps/website/src/data/engagement-timeline.ts` |
| A service page | `apps/website/src/content/services/<slug>.mdx` |
| An article | Add `apps/website/src/content/insights/<slug>.mdx` |
| Legal pages | `apps/website/src/content/legal/*.mdx` |
| Colours, type, spacing | `apps/website/src/styles/` |

Prices are typed and tested. `apps/website/src/data/pricing.test.ts` fails the build if a package
loses a currency or a required field, so a half-edited price cannot reach the site.

### 3.3 Running and deploying it

```bash
pnpm --filter @attestor/website dev
```

```bash
pnpm --filter @attestor/website build
```

Output is static files in `apps/website/dist`. The build also writes `dist/_headers` with a
Content-Security-Policy whose hashes were computed from the HTML just produced, so the policy cannot
drift out of date.

Hosting, with the exact commands for Cloudflare Pages, Netlify and S3: **[DEPLOYMENT.md](DEPLOYMENT.md) §1**.
Then check the result at <https://securityheaders.com>. Anything below A+ is a conversation you do
not want to have with a prospect.

---

## 4. The console: running an engagement, start to finish

### 4.1 First run, once

```bash
cp infra/.env.example infra/.env
```

Fill in every value. Nothing has a working default, deliberately — a secret with a default is a
secret that ships. The generation commands are at the top of the file.

```bash
docker compose -f infra/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml exec api pnpm --filter @attestor/api migrate
node scripts/pin-tool-images.mjs --pull
```

Create your staff account. `/auth/bootstrap` works exactly once — after the first account exists it
returns 409 and everyone else arrives by invitation:

```bash
curl -sS -X POST http://127.0.0.1:8080/auth/bootstrap -H 'content-type: application/json' -d '{"email":"you@attestorsecurity.com","name":"Your name","password":"a-long-passphrase-you-choose"}'
```

It returns an `otpauthUrl` **once**. Add it to your authenticator, then confirm — the account does
not work until you do:

```bash
curl -sS -X POST http://127.0.0.1:8080/auth/bootstrap/confirm -H 'content-type: application/json' -d '{"email":"you@attestorsecurity.com","code":"123456"}'
```

To see the whole flow with demo data first:

```bash
docker compose -f infra/docker-compose.yml exec api pnpm --filter @attestor/api seed
```

That gives you one client, one engagement in `reportDraft` with findings already confirmed and the
report prose written, plus a portal invitation link printed in the log.

| Surface | Where |
| --- | --- |
| Staff console | http://localhost:3000 — over WireGuard in production, never the internet |
| Client portal | http://localhost:3100 — the only thing that faces the internet |

### 4.2 The engagement lifecycle

Fourteen states. Two of them are gates:

```
draft → scoped → authorised → advancePaid → readyToRun → running → triage
      → manualTesting → reportDraft → reportReview → released
      → retestPending → retestComplete → closed
```

- **Nothing runs before `authorised`.** Not overridable. Testing without signed, scoped, in-window
  authorisation is a criminal offence in India under the IT Act s.66, and has equivalents elsewhere.
- **Nothing runs before `advancePaid`.** Overridable, with a written reason recorded against your
  name in the audit log. It is a business rule, not a legal one.

### 4.3 Step by step

**1. Create the client** — *Clients → Add a client*. The registered legal name matters: it goes on
the contract, the authorisation and the report cover, and it has to match their registration rather
than their brand.

**2. Create the engagement.** Reference is generated (`ATT-2026-014`) and the client will quote it
for years. Choose the type, the test type (black, grey or white box), the dates and the timezone.

**3. Enter the scope.** One item per line, included or excluded, as domains, wildcards, IPs, CIDRs,
URLs or repositories. Wildcards match label-wise: `*.example.com` matches `app.example.com` but
**not** the apex `example.com` — if you want the apex, add it.

**4. Record the authorisation.** Upload the signed form and record the signatory, their role, the
valid-from and valid-until dates, the asset list as written in the document, and your egress IP.
The platform diffs the asset list in the document against the scope you entered and shows you what
differs. That diff is the single most useful thing on the page.

**5. Take credentials through the vault.** *Send a credential link* generates a one-time link the
client submits into. Credentials never arrive by email or chat. Ask for test accounts, and two per
role if you will test access control — which you will.

**6. Choose a policy profile**, then adjust. Five ship: `quick-external`, `standard-web-app`,
`deep-web-app`, `cloud-review`, `llm-only`. The console has a form for common knobs and a raw YAML
editor with schema validation for everything else. See §8.

**7. Dry run. Always.** Tick nothing else and press run: every check executes — scope, authorisation,
window, never-touch, rate ceilings — and **no packet is sent**. Read what it says it would do. If
the target list is not exactly what you expected, stop and fix the scope. This is the cheapest
thirty seconds in the whole engagement.

**8. Live run.** Untick "dry run" — the live option is a deliberate action, never a default. Watch
the queue. The panic stop is on the engagement page: press it first and diagnose second, because an
unnecessary stop costs an hour and a run that should have been stopped costs the firm.

**9. Triage.** *Engagement → Triage*. Everything a tool produced is a **candidate**, never a
finding. The queue is keyboard-driven:

| Key | Action |
| --- | --- |
| `↑` `↓` | Move |
| `space` | Select |
| `a` | Select all |
| `c` | Confirm as a finding |
| `d` | Discard |
| `f` | Mark false positive, with a reason |
| `esc` | Clear selection |

A false-positive reason is remembered, so the same wrong result from the same tool does not cost you
the same minute on the next engagement.

**10. Manual testing.** The part the tools cannot do: access control between roles, business logic,
workflow bypass, chaining. Record what you did per catalogue check in the report's *Manual coverage*
box — one line each, `check-id: what you did`. That is what makes the coverage matrix honest.

**11. Write the report.** *Engagement → Report*. Prose on the left, the pre-release checklist on the
right. See §9.

**12. Release**, then **retest**, then **close**. Closing destroys the engagement's key salt, which
makes its stored credentials unrecoverable by anyone, including you.

### 4.4 The other console screens

- **Job queue** — what is running, what failed and why, and the outbox. Retrying a failed job re-runs
  the scope guard; retry is for a tool that crashed, not a way past a refusal.
- **Outbox** — every client-facing message the platform drafted. You approve, you send it yourself,
  you mark it sent. **There is no SMTP client anywhere in this codebase**, so nothing can be emailed
  to a client by accident.
- **Legal text** — the versioned blocks that go into documents, and which are still unreviewed.
- **Settings** — the egress address, the rate ceilings, whether AI is on, and every tool with its
  pinned digest. A tool without a digest shows as not runnable, because it is.

---

## 5. The client portal

Give this section to a client if it helps.

**Getting in.** You issue an invitation from *Clients → the client → Invite someone*. The link is
shown **once** and expires in seven days; the platform stores only a hash of it and has no endpoint
that reads it back, so send it yourself through a channel you trust. If it is lost, issue another.

The client sets a password, enrols an authenticator and confirms a code. The account does not work
until all three are done — a second factor a client can postpone is a second factor a client never
enables.

**Three roles:**

| Role | Can |
| --- | --- |
| Owner | Everything, plus managing their own team |
| Member | Read, comment, change finding status, request a retest, download reports |
| Read-only | Read reports in the browser; **cannot download them** |

**What they do there:**

- **Dashboard** — their engagements in plain language, open findings by severity, the oldest
  unfixed critical, and what is waiting on them. Internal state names never reach a client.
- **Findings** — filterable, each with impact in business terms, reproduction steps, remediation,
  CVSS with the vector, and the evidence.
- **Status** — acknowledged, in progress, fixed, or risk accepted. Risk acceptance requires a
  written justification and records their name and the date; it is their audit record, not yours.
- **Comments** — a conversation per finding, on the record.
- **Reports** — released documents only. Read in the browser, or download a PDF **watermarked with
  the reader's name, email and the time**, with every download logged so they can answer "who has
  this document?" if they are ever asked.
- **Retests** — one is included within thirty days of release. The page shows what will be verified:
  exactly the findings they have marked fixed. Requesting one records a request; a person schedules
  it.
- **Questionnaire answers** — ready-made answers to the security questions their own customers ask
  them, with a copy button. This is the feature clients mention to other clients.

---

## 6. What the platform tests

**210 checks** in a catalogue that drives both the coverage matrix and the public
`/what-we-test` page. They are the same list, which is the point.

| Module | Checks |
| --- | --- |
| Web | 84 |
| API | 52 |
| LLM and AI | 30 |
| Cloud | 25 |
| Mobile | 23 |
| Code and supply chain | 18 |
| Recon | 15 |
| Network | 11 |

By how they are done: **85 automated, 99 tool-assisted with human judgement, 26 purely manual**. The
manual ones are the access control, business logic and chaining checks — the ones that find the
findings people remember.

Every check maps to the standards a buyer's auditor will ask about: OWASP WSTG 4.2, ASVS 5.0.0,
OWASP Top 10 2021, API Security Top 10 2023, LLM Top 10 2025, MASVS 2.1.0, CWE, and the compliance
frameworks — ISO 27001 Annex A, SOC 2, PCI DSS 4.0.1, DPDP Act 2023.

**The coverage matrix is generated from what actually ran**, not from what the tools could
theoretically find. Anything not fully tested carries a reason. That table is the most defensible
page in the report and the one that separates this from a scan report.

---

## 7. The tools

41 images, all free or open source, every one pinned by digest. Nothing paid, nothing cracked,
nothing whose licence forbids commercial use.

**Recon** — subfinder, OWASP Amass, dnsx, httpx, naabu, tlsx, katana, gau, WhatWeb

**Web** — OWASP ZAP, nuclei, Nikto, testssl.sh, ffuf, dalfox, Arjun, sqlmap *(read-only settings
only)*, commix *(guarded)*

**API** — Schemathesis, kiterunner, mitmproxy, plus ZAP and nuclei

**Code and supply chain** — Semgrep, gitleaks, TruffleHog, Trivy, Syft, Grype, Checkov

**Cloud** — Prowler, Cloudsplaining, kube-bench, Kubescape, Trivy, Checkov

**Network** — Nmap *(safe script categories only)*, naabu, tlsx, nuclei

**Mobile** — MobSF, apktool, jadx

**LLM** — garak, promptfoo, PyRIT, DeepTeam

**Agentic** — Strix, **shipped disabled**, and refused in code with a reason rather than merely left
unset.

Every one runs as UID 65532, with a read-only root filesystem, all capabilities dropped,
`no-new-privileges`, a per-run network, memory and PID and CPU limits, and a wall-clock kill. That
hardening lives in the runner, not per tool, so a new adapter cannot forget it.

---

## 8. Customising everything

### 8.1 The policy, which is where most customisation happens

One YAML document, schema-validated, resolved in layers: **global defaults → client → engagement →
single run**. Later layers override earlier ones.

| Key | Controls |
| --- | --- |
| `modules` | Which of recon, web, api, mobile, cloud, code, network, llm run — any subset |
| `checks` | Include or exclude by check id, WSTG id, ASVS requirement, nuclei tag or severity, OWASP category. Allowlist or denylist |
| `intensity` | `safe`, `standard`, `thorough` — crawl depth, payload sets, fuzz iterations, timeouts |
| `phases` | `preLogin`, `postLogin`, or both |
| `authProfiles` | Which credential set maps to which role, how login works, how session death is detected |
| `accessControlMatrix` | Which role pairs to test and which id fields to mutate |
| `rateLimits` | Global rps, per-target rps, concurrency, backoff, polite mode, adaptive abort |
| `windows` / `blackouts` | Allowed test windows in the client's timezone |
| `readOnlyMode` | Suppress every state-changing request |
| `forbiddenActions` | URL patterns and form actions never to touch |
| `exclusions` | Paths, parameters, hosts, file types |
| `llm` | Target config, probe packs, attempt counts, budget cap, teardown |
| `ai` | `aiAssistEnabled`, `agenticEnabled`, model, token ceiling |
| `evidence` | What to capture, masking rules, retention days |
| `report` | Template, branding, CVSS version, which compliance mappings, which sections, tone |
| `notifications` | Who is told what, and how quickly for a critical |

Rate limits are **clamped to hard ceilings** — 40 requests per second globally, 10 per target, 12
concurrent. A policy asking for more is clamped and warns. There is no field anywhere that expresses
a load test.

Five profiles ship in `packages/policy/src/profiles/`. Copy one to make your own.

**Full reference and nine worked examples — production read-only, three-role authenticated web, API
by tenant, cloud, LLM, retainer, client-level: [POLICY-COOKBOOK.md](POLICY-COOKBOOK.md).**

### 8.2 Branding and templates

| To change | Edit |
| --- | --- |
| Report wordmark, legal entity, contact, jurisdiction | `brandingFor()` in `apps/api/src/routes/report-routes.ts` |
| Report layout, typography, sections | `packages/report/src/render.ts` |
| Legal wording in documents | `packages/report/src/legal/blocks.ts` |
| Which sections the workbench asks for | `SECTION_ORDER` in `apps/console/src/app/engagements/[id]/report/page.tsx` |
| The pre-release checklist | `packages/report/src/checklist.ts` |

Legal text is versioned **in code**, not editable in a form. A clause that can be changed in a text
box is a clause nobody can later prove the wording of.

After changing a template: regenerate the golden file, read the diff by eye, and fire the XSS corpus
at it.

```bash
pnpm --filter @attestor/report generate:sample
```

### 8.3 Adding a check

Add it to the right file in `packages/findings/src/catalogue/`, with its standards mappings and
whether it is automated, assisted or manual. It appears in the coverage matrix and on the public
`/what-we-test` page automatically.

### 8.4 Adding a tool

Six steps, in `docs/RUNBOOK.md` §5. The short version: check the licence, add the image, pin the
digest, write an adapter whose `parse` is a pure function over a string, register it, and save real
tool output as a fixture with hostile variants — empty, `{}`, truncated JSON. A missing hostile
fixture is how the gitleaks adapter shipped a crash.

Be conservative in `coversCheckIds`. Overclaiming there is how a report ends up lying about coverage.

---

## 9. Reports

### 9.1 What can be produced

| Document | When |
| --- | --- |
| Assessment report | The main deliverable |
| Retest report | After a retest; references the original version so the two read together |
| Attestation letter | A one-page letter for a client's own customers |
| Deletion confirmation | Proof that evidence was destroyed, with counts |

### 9.2 Writing it

*Engagement → Report*. Fifteen prose blocks, each with a note on what belongs in it. The findings,
coverage matrix, compliance mappings and appendices are generated; the prose is yours.

The executive summary is not a list of findings. The checklist enforces a minimum length because a
summary that cannot stand alone is a summary nobody reads.

### 9.3 The gate

Eighteen checks. Fifteen are mechanical:

evidence, remediation, business impact, reproduction steps, references, no unconfirmed candidates,
CVSS vectors, justified severity overrides, complete coverage matrix, no unfilled legal
placeholders, no draft markers, correct client name, executive summary written, positive
observations present, roadmap present — plus, when AI assist is used, every AI-drafted section
approved by a person.

Three need a human: every critical was notified out of band, evidence contains no unmasked personal
data, and **"I have read every line of this report"**. That last one is worded as a claim rather
than a box on purpose.

**The API re-runs the whole checklist at release.** A green screen is not the gate; the server is.

### 9.4 Releasing

Releasing publishes the report in the portal and queues a notification for a person to read and
send. Nothing is emailed. Downloads are watermarked per reader and logged.

---

## 10. The safety rails

The things that would end the firm, made structurally impossible rather than merely forbidden.

- **No denial of service, in any form.** The policy schema cannot express it, ceilings are clamped,
  `DENIAL_OF_SERVICE_CAPABILITY = false`, an architecture test greps for DoS-shaped symbols, and
  every adapter's built command is asserted to contain no flood flag. Four things would have to be
  edited together.
- **One way to start a container.** Exactly one module imports `dockerode`, enforced by a lint rule
  **and** an architecture test, because a control with one enforcement point gets moved.
- **A refusal refuses the whole run**, never a filtered subset. A partially scoped run is how a
  target gets tested by accident.
- **Never-touch is checked before authorisation.** Signing a form does not unlock the payment flow.
- **Loopback, link-local, RFC1918, CGNAT, TEST-NET, multicast and cloud metadata are refused** by
  default. An internal engagement authorises its own ranges explicitly, as a signed decision.
- **No credential is ever displayed.** There is no read-for-display path in the vault.
- **Logs, tool output, findings and reports pass through a redaction filter**, so a credential in a
  log is a bug with a test rather than routine.
- **Nothing reaches a client without a person.** No SMTP client exists.
- **No claim the firm cannot make.** `pnpm check:claims` fails the build on any first-person claim of
  CERT-In empanelment, CREST accreditation, ISO certification of the firm, any guarantee of
  security, or any promise to certify a system as secure.

---

## 11. What it will not do

Stated plainly so you never promise it.

- No DoS, stress or volumetric testing. Not a setting.
- No destructive payloads, no data deletion, no state changes beyond what the policy permits.
- No social engineering or phishing.
- No physical testing.
- No autonomous agent running against a client — Strix is shipped disabled and refused in code.
- No claim of any certification the firm does not hold.
- No guarantee that a system is secure. No such report exists honestly.
- No paid, trial-key or cracked tooling.
- No client data to a third-party model unless that engagement explicitly turned it on.
- No raw client personal data kept as evidence; masking happens at capture.

---

## 12. Where everything lives

```
apps/website/          The marketing site
apps/api/              Console API, portal API, workers
  src/routes/          ai, auth, client, engagement, finding, platform, report
  src/portal/          The portal API — separate role, separate deployment
  src/services/        Vault, evidence store, auth, audit, reports, AI transport
  src/workers/         scan, retention, retainer
apps/console/          Both UI surfaces, gated by ATTESTOR_SURFACE
packages/core/         Scope guard, state machine, container runner, audit log, AI assist
packages/findings/     210-check catalogue, CVSS, dedupe, diff, coverage matrix
packages/policy/       Schema, resolution, five profiles, cloud provider policies
packages/scanners/     One adapter per tool, pure parsers, fixtures
packages/report/       Renderer, legal blocks, checklist, PDF, golden file
packages/shared/       Redaction, masking, logging, config, ids
infra/                 Compose files, Dockerfile, migrations, vulnerable test targets
docs/                  This guide, runbook, threat model, checklists, ASVS, decisions
```

**The other documents:**

| Document | Read it when |
| --- | --- |
| `docs/BUILD-STATUS.md` | Picking the work back up. It is the live state of everything |
| `docs/RUNBOOK.md` | Provisioning, DNS and mail, backups, key rotation, the panic stop, incidents |
| `docs/CHECKLISTS.md` | Running the business. Fourteen checklists, from pre-engagement to closure |
| `docs/THREAT-MODEL.md` | Someone asks how you protect their data — or you are deciding what to build next |
| `docs/ASVS-SELF-ASSESSMENT.md` | A buyer asks for a security self-assessment of your own platform |
| `docs/DECISIONS.md` | Wondering why something is the way it is |
| `docs/RESEARCH-NOTES.md` | Checking whether a standard edition or a provider policy has moved |
