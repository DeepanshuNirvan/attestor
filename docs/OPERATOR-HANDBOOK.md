# Operator handbook

Plain English. What the product is, how to run it, and exactly what to do when a client asks you to
test their application.

If you read one thing before your first real client, read **§6 (a client arrives)** and
**§7 (proving they own it)**.

**Contents**

1. [The two halves of this product](#1-the-two-halves-of-this-product)
2. [The website](#2-the-website)
3. [The portal — and why it is the only public thing](#3-the-portal--and-why-it-is-the-only-public-thing)
4. [Running everything locally](#4-running-everything-locally)
5. [Developing on it](#5-developing-on-it)
6. [A client arrives — the full sequence](#6-a-client-arrives--the-full-sequence)
7. [Proving the client owns what they gave you](#7-proving-the-client-owns-what-they-gave-you)
8. [Credentials and client configuration](#8-credentials-and-client-configuration)
9. [What it tests](#9-what-it-tests)
10. [Reports](#10-reports)
11. [Running it automatically — retainers](#11-running-it-automatically--retainers)
12. [AI assistance and LLM testing](#12-ai-assistance-and-llm-testing)
13. [Testing against a real client application](#13-testing-against-a-real-client-application)
14. [What is still missing](#14-what-is-still-missing)
15. [What to avoid](#15-what-to-avoid)
16. [FAQ](#16-faq)

---

## 1. The two halves of this product

One repository, two completely separate things. People confuse them constantly.

### The website — your shop window

`apps/website`. A static site. Services, prices, the check catalogue, a sample report, articles,
legal pages.

- **No server. No database. No login. No uploads.**
- It is HTML and CSS files sitting on a CDN.
- If someone hacks it, they change a page. They get nothing else, because it holds nothing.

### Attestor Console — the machine you do the work on

Everything else. This is the actual product: it decides whether a target may be touched, runs the
security tools, turns their output into findings a human confirms, and produces the report.

It has a database, an object store, a queue, and two web interfaces.

**So when you see `DATABASE_URL`, `S3_*`, `VAULT_MASTER_KEY` — those belong to the platform. The
website never sees any of them.** That separation is deliberate: your marketing site can never leak
a client's findings, because it has never heard of them.

---

## 2. The website

### Run it while you edit

```bash
pnpm --filter @attestor/website dev
```

Opens on <http://localhost:4321>. Edits reload immediately.

### Build it

```bash
pnpm --filter @attestor/website build
```

Produces static files in `apps/website/dist`. The build also writes a `_headers` file with a
Content-Security-Policy whose hashes are computed from the HTML it just produced — so the security
policy can never drift out of date with the content.

### Put it live

Recommended: Cloudflare Pages, because `_headers` is a Cloudflare Pages file.

```bash
pnpm --filter @attestor/website build
wrangler pages deploy apps/website/dist --project-name attestor
```

Then check it at <https://securityheaders.com>. Aim for A+. A security firm whose own site scores a
B has an awkward first meeting.

Full hosting instructions, including Netlify and S3: `docs/DEPLOYMENT.md` §1.

### What to edit

| To change | Edit this file |
| --- | --- |
| Company name, email, booking link | `apps/website/src/data/site.ts` |
| Prices | `apps/website/src/data/pricing.ts` |
| A service page | `apps/website/src/content/services/<name>.mdx` |
| An article | add `apps/website/src/content/insights/<name>.mdx` |
| Legal pages | `apps/website/src/content/legal/*.mdx` |
| Colours and type | `apps/website/src/styles/` |

Prices are type-checked. A half-edited price fails the build instead of reaching the site.

---

## 3. The portal — and why it is the only public thing

There are **two** web interfaces, built from the same code, deployed twice.

| | Console | Portal |
| --- | --- | --- |
| Who uses it | You and your testers | Your clients |
| Where | `localhost:3000` locally | `localhost:3100` locally |
| On the internet? | **Never** | **Yes — this is the only public one** |
| How you reach it in production | Over WireGuard VPN | Normal HTTPS |

### Why is the portal public?

Because the client has to be able to reach it. They need to read findings, mark things fixed, ask
questions, and download their report. If it were behind your VPN they could not.

### Why is the console *not* public?

Because it can do everything: start scans, read every client's data, open the credential vault. That
must not be reachable from the internet. The console API refuses to start if you try to bind it to
`0.0.0.0`.

### Is it safe to have the portal public?

It is built on the assumption that it will be attacked.

- It connects to the database as a **separate, restricted user** (`attestor_portal`). That user is
  denied read access to the credential vault at the *database* level — not by a check in the code
  that someone could forget, but by a permission grant. Even if the portal were completely taken
  over, it cannot read a client credential.
- It has **no ability to start a container**. That capability was never handed to it.
- Every query filters on the client id taken from the login session, never from the URL. Asking for
  another company's finding returns "not found" — it does not even confirm the thing exists.
- A build-time test reads the portal's route file and **fails the build** if any route forgets that
  filter.
- Login needs a password *and* an authenticator app. There is no way round the second factor.
- Reports downloaded from it are watermarked with the reader's name and email, and every download is
  logged — so a client can answer "who has this document?" if they are ever asked.

### Why the same code deployed twice, rather than one app?

Because one app with a switch is one wrong environment variable away from serving your staff console
to a client. The surface is chosen when the image is **built**, and each build returns "not found"
for the other side's pages.

---

## 4. Running everything locally

### First time

```bash
cp infra/.env.example infra/.env
```

Fill in every value. Nothing has a working default on purpose — a secret with a default is a secret
that ships. The generation commands are written at the top of that file.

> **Important:** passwords that end up in a database connection string must not contain `/` or `+`.
> Generate them with `openssl rand -base64 48 | tr -d '/+=' | head -c 32`.

```bash
docker compose -f infra/docker-compose.yml up -d --build
```

That one command brings up everything: database, cache, object store, both APIs, both web
interfaces, the worker, migrations, storage buckets, the nuclei template pack and the httpx model.

```bash
node scripts/pin-tool-images.mjs --pull
```

**Until this has run, no tool will start.** It downloads every security tool image and records the
exact version. The runner refuses any tool without a recorded version, because a report that names a
tool version has to actually mean it.

### Create your account

Works exactly once — after the first account exists, everyone else arrives by invitation.

```bash
curl -sS -X POST http://127.0.0.1:8080/auth/bootstrap \
  -H 'content-type: application/json' \
  -d '{"email":"you@attestorsecurity.com","name":"Your name","password":"a-long-passphrase"}'
```

It returns an `otpauthUrl` **once**. Put it in your authenticator app, then confirm:

```bash
curl -sS -X POST http://127.0.0.1:8080/auth/bootstrap/confirm \
  -H 'content-type: application/json' \
  -d '{"email":"you@attestorsecurity.com","code":"123456"}'
```

### Where things are

| What | Address |
| --- | --- |
| Staff console | <http://localhost:3000> |
| Client portal | <http://localhost:3100> |
| Console API | <http://127.0.0.1:8080> |
| Portal API | <http://127.0.0.1:8081> |
| Object store (look at files) | <http://localhost:9001> |
| Captured mail | <http://localhost:8025> |

### Stop it

```bash
docker compose -f infra/docker-compose.yml down
```

Add `-v` to also wipe the database and start clean next time.

---

## 5. Developing on it

You do not need Docker for the code — only for running actual security tools.

```bash
pnpm install
```

Run the pieces you are working on:

```bash
pnpm --filter @attestor/api dev            # console API, restarts on change
pnpm --filter @attestor/api start:portal   # portal API
pnpm --filter @attestor/api worker         # the job worker
pnpm --filter @attestor/console dev        # whichever surface you point it at
pnpm --filter @attestor/website dev        # the marketing site
```

For the console/portal, create `apps/console/.env.local` (it is gitignored):

```
ATTESTOR_SURFACE=console
ATTESTOR_API_URL=http://127.0.0.1:8080
ATTESTOR_PORTAL_API_URL=http://127.0.0.1:8081
```

Change `console` to `portal` and restart to work on the other side.

### Before you commit anything

```bash
pnpm lint && pnpm typecheck && pnpm test && pnpm check:claims
```

Plus `pnpm exec tsc -p tsconfig.json --noEmit`, which covers config files that belong to no package.

`check:claims` fails the build if the repository ever claims a certification the firm does not hold
— CERT-In empanelment, CREST, ISO certification of the firm, or a guarantee of security. That is a
build failure rather than a review habit because getting it wrong is not a bug, it is a lawsuit.

### Testing against deliberately broken applications

```bash
docker compose -f infra/docker-compose.test.yml up -d
ATTESTOR_TEST_NETWORK_ONLY=1 pnpm test:integration
```

These targets (Juice Shop, DVWA, WebGoat, VAmPI, crAPI) sit on a network with **no route off your
machine**, so a mistake in a test physically cannot reach a stranger's server.

### Two things that will waste your afternoon

Both are in `docs/PRODUCT-CONTEXT.md` §5, and both are about how tools actually run:

- A tool container is on its own fresh network. It **cannot** reach the `internal: true` test-target
  network. In real life it reaches the client over normal internet egress.
- `/tmp/attestor` must be a **host folder mounted at the same path**, never a Docker named volume.
  The worker writes a tool's input there and asks Docker to mount that same path into the tool — and
  Docker resolves that path on the host. Get this wrong and every tool starts with no input.

---

## 6. A client arrives — the full sequence

A client emails: *"Please test https://app.acme.com, here are the logins."*

**Do not start.** Work through this in order. Steps 1–4 happen before you touch anything.

### Step 1 — Scoping call (20 minutes)

Ask:

1. What is the application, and who logs into it? *(Number of roles drives the price more than page count.)*
2. Is there a staging environment that matches production?
3. Multi-tenant? Payment flows? Approval workflows?
4. Is there anything a test must never touch?
5. When do you need the report, and who is it for?
6. Have you been tested before? May I see the report?

Write the notes up and **send them back for correction**. Their reply is your evidence of what was
agreed.

### Step 2 — Confirm they own it

This is §7. Do not skip it. It is the step that keeps you out of court.

### Step 3 — Create the client and the engagement

In the console: *Clients → Add a client*. Use their **registered legal name**, not their brand — it
goes on the contract, the authorisation and the report cover.

Then create the engagement. You choose the type, the test type (black / grey / white box), the test
window dates and the timezone. The reference (`ATT-2026-014`) is generated and the client will quote
it for years.

### Step 4 — Enter the scope

One item per line. Domains, wildcards, IPs, ranges, URLs, repositories.

- `*.acme.com` matches `app.acme.com` but **not** `acme.com`. If you want the apex, add it separately.
- Mark anything out of bounds as an exclusion.
- Bad entries are refused as you type: loopback addresses, cloud metadata endpoints, and wildcards
  broad enough to cover an entire country's registry (`*.co.in`) are rejected with a reason.

### Step 5 — Record the signed authorisation

Upload the signed form and record: who signed it, their role, their email, the dates it is valid
between, the asset list **exactly as written in the document**, and your fixed egress IP.

**The platform then shows you a diff between the asset list in the signed document and the scope you
typed in.** Read that diff. It is the cheapest protection you have against testing something nobody
signed for.

Nothing can run before this exists, and that gate cannot be overridden by anyone.

### Step 6 — Take credentials through the vault

See §8. **Never accept credentials by email, chat or a shared document.**

### Step 7 — Choose a policy profile

Five ship: `quick-external`, `standard-web-app`, `deep-web-app`, `cloud-review`, `llm-only`. Start
with one and adjust. Full reference: `docs/POLICY-COOKBOOK.md`.

For anything touching production, set:

```yaml
intensity: safe
readOnlyMode: true
rateLimits:
  globalRequestsPerSecond: 3
  perTargetRequestsPerSecond: 1
  politeMode: true
windows:
  - daysOfWeek: [1, 2, 3, 4]
    start: '22:00'
    end: '04:00'
```

### Step 8 — Record the advance payment

*Payments* panel on the engagement page. 50% before testing starts is the norm; the platform will
not move to a runnable state without it, though you can override that with a written reason recorded
against your name.

### Step 9 — Complete the pre-flight checklist

Six items on the engagement page. **This gate has no override**, because the things on it are what
stop a run harming someone: are you inside the agreed window, is the authorisation still valid
*today*, have you read the dry run, is the rate limit right for this target, have you warned them if
this run is louder than the last, and is somebody around to press stop.

### Step 10 — Dry run. Always.

Tick nothing, press run. **Every check executes and no packet is sent.** Read the list of targets it
says it would contact. If it is not exactly what you expected, fix the scope and do it again.

This is the cheapest thirty seconds in the whole engagement.

### Step 11 — Live run

Untick "dry run" — the live option is always a deliberate action, never a default. Watch the queue.

The red **stop** control is on the engagement page. Press it first and diagnose second: an
unnecessary stop costs an hour, a run that should have been stopped costs the firm.

### Step 12 — Triage

*Engagement → Triage*. Everything a tool produced is a **candidate**, never a finding. You confirm
each one by hand, or discard it, or mark it a false positive with a reason (which is remembered, so
the same wrong result does not cost you the same minute next time).

Keyboard: `↑` `↓` move, `space` select, `a` select all, `c` confirm, `d` discard, `f` false positive.

### Step 13 — Manual testing

The part tools cannot do: access control between roles, business logic, workflow bypass, chaining
two small issues into one real one. Record what you did per check in the report's *Manual coverage*
box — one line each, `check-id: what you did`. That is what makes the coverage matrix honest.

### Step 14 — Write the report

*Engagement → Report*. Fifteen prose blocks on the left, the release checklist on the right. See §10.

### Step 15 — Release

Record the balance payment, tick the three items only a person can confirm, and release. The API
re-runs the whole eighteen-item checklist server-side — a green screen is not the gate, the server
is. If it refuses, it tells you exactly what is blocking.

### Step 16 — Invite them to the portal

*Clients → the client → Invite someone*. The link is shown **once** and expires in seven days. Only
a hash is stored and no endpoint can read it back, so you send it yourself through a channel you
trust. Lost link means a new invitation, which is the correct trade.

### Step 17 — Retest and close

One retest is included within thirty days. Only findings the client has marked fixed get verified —
verifying everything again is a new assessment, and charging for one while calling it the other is
dishonest.

**Closing the engagement destroys its key salt.** After that, no key opens its stored credentials.
Not yours, not an attacker's, not from a backup. Tell your operations people this in advance or they
will file it as a restore failure.

---

## 7. Proving the client owns what they gave you

This is the section that keeps you out of prison. Testing a system you are not authorised to test is
a criminal offence in India under the IT Act s.66, and has an equivalent almost everywhere.

**The rule: you never test what a client *says* they own. You test what they have signed for, on a
form, naming assets, with dates.**

### The checks, in order

**1. Get the asset list from them, in writing.**

Never assemble a scope from your own scan and ask them to confirm it. That is backwards, and it is
how third parties get tested. The list comes from them first.

**2. Check who actually owns each domain.**

For each domain in the list:

```bash
whois acme.com | grep -i "registrant\|org"
```

Does the registrant match the company on your contract? If it is behind privacy protection, ask them
to prove control instead — see check 4.

**3. Check where it actually points.**

```bash
dig +short app.acme.com
```

Then look up who owns that address:

```bash
whois 203.0.113.10 | grep -i "orgname\|netname\|descr"
```

If it resolves to AWS, Cloudflare, Vercel, Shopify or any shared host, **the client does not own that
machine**. You need either the hosting provider's testing policy acknowledged (AWS, Azure and GCP all
publish one and the platform stores them for acknowledgement), or written permission from whoever
does own it. The platform will refuse a host that resolves to several addresses until a human ticks
the third-party acknowledgement, precisely because that usually means shared hosting.

**4. Ask them to prove control of the domain.**

The strongest cheap proof. Pick one:

- Ask them to put a DNS TXT record on it: `attestor-verification=<random string you generate>`.
- Or ask them to serve a file you name at `https://app.acme.com/.well-known/attestor-<random>.txt`.

Someone who cannot do either does not control the domain. This takes them five minutes and it is the
single best evidence you have.

**5. Check the signatory has the authority to sign.**

The form must be signed by a named individual with a role that plausibly carries the authority — a
CTO, a CISO, a director. Not "the intern who emailed you". Check them on the company website or
LinkedIn. For an Indian private limited company you can check the directors on the MCA portal.

**6. Diff the signed asset list against what you typed in.**

The platform does this for you when you record the authorisation. **Read the diff.** Anything in your
scope that is not in the signed document must come out, or a new form must be signed.

**7. Make the platform enforce it.**

Once the authorisation is recorded, the scope guard checks every single target before every single
tool launch:

- Is it in the signed scope?
- Is the authorisation signed, unexpired, unrevoked, and valid **today**?
- Are you inside the agreed window?
- Is it on the never-touch list? *(Checked before authorisation — signing a form does not unlock a
  payment flow.)*
- After DNS resolution, do the **actual addresses** still pass? A name in scope pointing at somebody
  else's server is the realistic way a legal engagement becomes an illegal one.

**If any target fails, the whole run is refused — not filtered.** A partially scoped run is how
something gets tested by accident.

### When a client says "just test everything"

Say no, politely, and explain why.

> "I can only test assets named on a signed authorisation with dates on it. That protects you as
> much as me — if something breaks during a test, the form is what shows it was authorised work and
> not an intrusion. Send me the list of hostnames you want covered and I'll put them on the form."

If they push back, that is itself information about the engagement.

### Red flags — stop and ask more questions

- They will not put the asset list in writing.
- The domain's registrant is a different company and they cannot explain why.
- They want you to test something they describe as "our partner's" or "our client's" system.
- They ask you to skip the authorisation form to save time.
- The person signing has no role that carries authority.
- They ask for testing outside the window, or for the never-touch list to be removed.
- Payment terms are unusual *and* they are in a hurry.

Any two of those together: walk away. The engagement is not worth the risk.

---

## 8. Credentials and client configuration

### The rule

Credentials never arrive by email, chat, a spreadsheet or a shared document. They go into the vault.

They are sealed with libsodium under a key derived from your master key, a random salt and the
engagement id. **No route in the whole API returns a credential value** — there is no
read-for-display path at all. They are opened in memory, in the worker, at the moment a tool needs
them.

Ask for **test accounts, not real user accounts**, and **two accounts per role** if you are testing
access control — which you are, because comparing what user A can see of user B's data is the whole
technique.

### Taking a credential

In the console, open the engagement and use **Ask for test accounts**. Name each account, give it a
role, and say how it signs in — email and password, username and password, mobile number with a
code, sign-in with Google or Microsoft, an API key, a bearer token, or a session cookie. The same
thing over the API:

```bash
curl -sS -b jar -X POST :8080/engagements/<id>/credential-link   -H 'content-type: application/json'   -d '{"expiresInHours":72,"accounts":[
        {"label":"Standard user","roleName":"user","kind":"emailPassword"},
        {"label":"Second standard user","roleName":"user","kind":"emailPassword","isSecondary":true},
        {"label":"Administrator","roleName":"admin","kind":"usernamePassword"}
      ]}'
```

You get a one-time link back **once**. Only its hash is stored, so nothing can show it to you again
— send it to the client yourself, through whatever channel you already use with them. A lost link
means issuing a new one, which costs nothing.

What the client sees at that link is one page with one small form per account, showing only the two
or three boxes that kind of login actually needs, with a line under each saying what to put in it.
Each account is sent on its own, so getting one wrong does not lose the others, and they can come
back to the same link later to finish. They need no account and no password to use it: the token in
the link is the authorisation.

The submission goes to the **console** API, not the portal's. The portal serves the page because it
is the surface a client can reach, but only the console holds the vault key, and the portal's
database role is granted nothing on the credential tables. A portal compromise still cannot read or
write a credential.

Resubmitting the same account replaces the earlier value rather than adding a second row, so a
client who mistyped a password just sends it again.

### Making the credential actually get used

Storing a credential does not make a scan use it. The engagement policy has to say which role signs
in where:

```yaml
authProfiles:
  - id: customer
    roleName: user          # the same role you asked the client for
    type: formLogin
    loginUrl: https://app.acme.com/login
    sessionIndicator:
      loggedOutText: 'Sign in'
```

The match is by **role name**, so you do not have to paste credential ids into the policy; a
`credentialSetId` still wins if you set one. A second account submitted for the same role is picked
up automatically for access control testing.

ZAP then drives a real browser at `loginUrl`, signs in as that account, and runs the crawl and the
scan as that user. The password reaches the tool as an environment variable and never appears in the
plan file, the command line or the audit log.

Two things to check on the first authenticated run:

- The run's stats record `authenticatedAs`. If it is empty, the scan browsed signed out.
- `credentialWarnings` in the same stats names anything that was submitted but could not be used —
  most often a policy with no `authProfiles` entry, or a role name that does not match.

`sessionIndicator.loggedOutText` is worth setting. Without it a session that dies halfway through a
scan is not detected, and the second half of the run is unauthenticated while looking exactly like
the first half.

### Kinds that are stored but not yet driven

An API key, a bearer token and a session cookie are accepted, sealed and shown in the console, but
nothing presents them to a tool automatically — they are a header to send, not a login to perform,
and the automation plan cannot carry one without writing it to disk. Use them by hand for now.

### Withdrawing one

**Stop using** on the credentials table revokes it: no run will open it again. The row and its audit
trail stay until the engagement closes, and closure is what destroys the key salt and makes the
value unreadable for good.

### Client-level configuration

Some things are true of every engagement for a client — their blackout windows, hosts they never
want touched, their own identifier formats that need masking. Put those on the **client** rather than
repeating them per engagement:

```yaml
blackouts:
  - daysOfWeek: [5]
    start: '12:00'
    end: '20:00'          # their Friday release, every week, forever
exclusions:
  hosts: [mail.acme.com, status.acme.com]
evidence:
  extraMaskingPatterns:
    - id: acme-customer-id
      pattern: 'AC-[0-9]{10}'
      replacement: 'AC-**********'
  retentionDays: 60
```

Policy resolves in four layers, each overriding the last: **built-in defaults → client → engagement
→ this single run.**

### At the end of the engagement

- Client rotates the credentials **at their end**. Record the date.
- Closing the engagement destroys the key salt, so your copy becomes unreadable to everyone.
- Evidence is deleted automatically after the retention period (90 days by default).

---

## 9. What it tests

**235 checks.** The same list drives the coverage matrix in the report and the public
`/what-we-test` page on your website — which is the point: what you advertise and what you measure
are one list.

| Module | Checks | Roughly |
| --- | --- | --- |
| Web | 84 | Injection, access control, authentication, session, headers, TLS, business logic |
| API | 52 | Object-level authorisation, mass assignment, rate limits, GraphQL, inventory |
| LLM and AI | 30 | Prompt injection, data leakage, tool abuse, excessive agency |
| Cloud | 25 | IAM, storage exposure, logging, Kubernetes posture |
| Mobile | 23 | Storage, crypto, transport, platform, resilience |
| Code and supply chain | 18 | Static analysis, secrets, dependencies, IaC |
| Recon | 15 | Subdomains, ports, technology, certificates |
| Network | 11 | Services, versions, exposed management interfaces |

By how they are done: **85 automated, 99 tool-assisted with human judgement, 26 purely manual.** The
manual ones are the access control, business logic and chaining checks — the ones that find the
findings people remember.

Everything maps to what a buyer's auditor asks about: OWASP Top 10 2025, API Top 10 2023, LLM Top 10
2025, ASVS 5.0, WSTG 4.2, MASVS 2.1, CWE, plus ISO 27001, SOC 2, PCI DSS 4.0.1 and the DPDP Act.
**All of those mappings are complete** — every category in all four OWASP lists is covered.

### The tools

41 images, all free or open source, every one pinned to an exact version.

Recon: subfinder, Amass, dnsx, httpx, naabu, tlsx, katana, gau, WhatWeb ·
Web: ZAP, nuclei, Nikto, testssl.sh, ffuf, dalfox, Arjun, sqlmap *(read-only settings)* ·
API: Schemathesis, kiterunner, mitmproxy · Code: Semgrep, gitleaks, TruffleHog, Trivy, Syft, Grype,
Checkov · Cloud: Prowler, Cloudsplaining, kube-bench, Kubescape · Network: Nmap *(safe scripts only)*
· Mobile: MobSF, apktool, jadx · LLM: garak, promptfoo, PyRIT, DeepTeam.

Every one runs as a non-root user, with a read-only filesystem, all Linux capabilities dropped, its
own network, memory and CPU limits, and a hard time limit. That hardening lives in one place, so a
new tool cannot forget it.

> **Eleven of the 41 cannot currently be downloaded** — their image references are wrong or the
> images are gone. See §14.

---

## 10. Reports

### What you can produce

| Document | When |
| --- | --- |
| Assessment report | The main deliverable |
| Retest report | After a retest, referencing the original so the two read together |
| Attestation letter | A one-page letter your client shows *their* customers |
| Deletion confirmation | Proof their evidence was destroyed, with counts |

### Where they come from

Generated from the database when you press generate. HTML and PDF are the same document. The PDF
lands in the object store; the client reads it in the portal or downloads it watermarked with their
own name.

You write fifteen prose blocks. The findings, coverage matrix, compliance mappings and appendices are
generated for you.

### The release gate — eighteen checks

Fifteen are mechanical: every finding has evidence, specific remediation, a business impact,
numbered reproduction steps, a quotable reference and a CVSS vector; no unconfirmed candidate is left
in the queue; the coverage matrix explains every gap; no placeholder text remains; the client name is
right; the executive summary is written; positive observations are recorded; there is a prioritised
roadmap.

Three need a person:

- Every critical finding was notified out of band **before** the report.
- Evidence contains no unmasked personal data.
- **"I have read every line of this report."**

That last one is worded as a claim rather than a tick box on purpose.

### The coverage matrix

The most defensible page in the report and the one an auditor reads first. It is generated from what
**actually ran**, never from what you intended. A check counts as tested only if a completed run or a
recorded manual test covered it; anything less carries a written reason, including "the run was
refused because the target resolved outside the authorised range".

Nobody else's report admits what was not tested. That is why yours is worth more.

---

## 11. Running it automatically — retainers

For a client on a monthly or quarterly arrangement:

```bash
curl -sS -b jar -X POST :8080/clients/<client-id>/retainers \
  -H 'content-type: application/json' \
  -d '{"cadence":"monthly","modules":["recon","web"],"startsAt":"2026-09-01T02:00:00Z"}'
```

**What happens automatically:** at the due date a **draft engagement is created**, and the previous
run is diffed against the new one — new findings, resolved findings, and regressions.

**What does not happen automatically:** the scan. Nothing runs until a person confirms the
authorisation is still valid and starts it.

That is deliberate. An authorisation has an end date. A scan that fires itself six months after the
form expired is an unauthorised scan, whatever your scheduler thought.

Regressions are called out loudly and separately: a finding that was fixed and has come back is not a
security problem, it is a release-process problem, and fixing it again without fixing the process
means seeing it a third time.

---

## 12. AI assistance and LLM testing

These are two completely different things. People mix them up.

### 12a. AI assistance — a model helping *you* write

Drafts finding prose and report sections from evidence you already have.

**Off by default, and it takes two switches to turn on:**

1. Deployment level, in `infra/.env`:

   ```
   AI_ENABLED=true
   AI_PROVIDER=anthropic
   AI_API_KEY=<your key>
   AI_MONTHLY_BUDGET_USD=10
   ```

2. Per engagement, in that engagement's policy:

   ```yaml
   ai:
     aiAssistEnabled: true
     model: claude-sonnet-5
     tokenCeiling: 500000
     spendCeilingUsd: 10
   ```

The engagement flag alone does nothing without the deployment flag. One client turning it on never
turns it on for another.

**What protects the client:**

- Input is **redacted before the request is built**, not after.
- Output is checked against the evidence: if the draft introduces a hostname, URL or CVE that is not
  in the evidence, it is **discarded**, not shown with a warning. A warning is something a tired
  person clicks past.
- **Screenshots are never sent.** There is no reason to put a client's screen in front of a third
  party.
- Every request is logged with model, purpose, tokens, cost and a hash of the prompt.
- Every output is a **draft**. The report cannot be released while an AI-drafted section is
  unapproved by a person.
- Budget is per engagement per calendar month, defaulting to zero, so one noisy engagement cannot
  spend another's.

**A model has never actually been called from this codebase.** Make the first call on a throwaway
engagement with a $1 ceiling.

**Agentic testing — an AI driving the tools itself — is shipped disabled and refused in code**, with
a message naming what would have to exist first. Do not offer it.

### 12b. LLM testing — testing *the client's* AI

This is a service you sell: red-teaming a client's chatbot, RAG application or agent. 30 checks
against the OWASP LLM Top 10 2025.

Set it up in the engagement policy:

```yaml
modules: [llm]
llm:
  targetType: ragApplication      # or rawEndpoint, chatUi, agentic, embeddedBot
  endpoint: https://app.acme.com/api/chat
  promptPath: 'messages[-1].content'
  answerPath: 'reply'
  intendedPurpose: 'Answer questions about orders and returns.'
  declaredGuardrails: [system-prompt, output-filter]
  declaredTools: [order-lookup, refund-issue]
  topicsItMustRefuse: [medical advice, competitor pricing]
  probePacks: [attestor-core, garak-broad, promptfoo-owasp, deepteam-owasp]
  attemptsPerProbe: 30
  budget:
    maxSpendUsd: 40
    maxTokens: 3000000
    estimatedCostPerRequestUsd: 0.003
    clientAcknowledgedCostTesting: true
  teardown:
    enabled: true
    verifyRemoval: true
```

Three things matter here:

- **`declaredTools` is the field to fill in carefully.** A model that can issue a refund is a model
  whose prompt-injection finding is a *financial* finding, and the severity should say so.
- **`attemptsPerProbe`.** One successful jailbreak is a curiosity. Thirty attempts giving a success
  rate is a finding with a severity.
- **`teardown` tracks every artefact you inject into their RAG corpus and removes it, then verifies
  the removal.** Leaving a poisoned document in a client's production knowledge base is the one
  mistake in LLM testing a client will not forgive.

You cannot run cost-abuse testing without a spend ceiling **and** the client's written
acknowledgement. The schema refuses it.

---

## 13. Testing against a real client application

The first time you point this at a real system, go slowly.

### Before

- [ ] Signed authorisation on file, valid for today's date, asset list diffed and read.
- [ ] Ownership verified — §7, all seven checks.
- [ ] Your egress IP given to them and allowlisted at their end.
- [ ] Emergency contacts exchanged **both ways**, including out of hours.
- [ ] Test window agreed and entered in the policy.
- [ ] Never-touch list agreed in writing: production payment flows, anything that sends real mail or
      SMS to real people, anything with a third-party rate ceiling.
- [ ] They know what they will see in their monitoring, and roughly when.
- [ ] Staging if it exists. Production only if it must be, and then read-only and out of hours.

### The run

1. **Dry run first.** Read the target list out loud if you have to.
2. Start with `modules: [recon]` and `intensity: safe` only. Nothing else.
3. Watch the queue. Watch their response times.
4. Only when recon is clean and understood, add `web`.
5. Be at your desk. The stop button needs somebody near it.

### The adaptive brake

The platform watches what the target does back. If median latency climbs 50% it slows down. If it
doubles, or if 15% of responses are server errors, or if 20 server errors arrive in a row, **it
aborts the run and tells you**. A client's site going slow during your test is your problem to
notice, not theirs to report.

### If something breaks

1. **Press stop first.** Diagnose second.
2. Call them. Call, do not email.
3. Read the audit log: what was running, since when, against what, with which command.
4. Send them the timeline. Facts only, no speculation about cause until you have it.
5. If a tool did cause it, that is a finding about their environment *and* an incident about yours.
   Write up both honestly.
6. Clear the stop deliberately, with a reason. Stops never expire on their own, because "it timed
   out" is not a decision anybody made.

### What is proven to work, and what is not

Verified against real targets: **recon, web and network** modules, the whole engagement lifecycle,
report generation and release, and the client portal.

**Not yet driven end to end against a live target: mobile, cloud, code and LLM.** They are built and
unit-tested, but the first real run of each will find things. Do the first one on your own
infrastructure, not a client's.

---

## 14. What is still missing

Be honest with yourself about these. Nothing here is hidden.

### Blocking — fix before you take money

1. **Legal text is not lawyer-reviewed.** Every block is marked unreviewed and every document renders
   with a visible draft banner until that changes. You cannot send a client a report with a draft
   banner on it.

### Important

2. **Authenticated scanning has been proven for a password login and nothing else.** A form or
   single-page login, with or without an authenticator app, is driven by ZAP as a real browser and
   is verified working against a live target. An **API key, bearer token or session cookie is stored
   but never presented by a tool** — see §8 — and `mtls` is not handled at all. If you sell an
   API-only assessment, that authentication is manual work today.
3. **Nothing checks a credential before the run.** If the client mistypes a password you find out
   from an empty authenticated scan, not from the console: the `Verified` state a credential can
   hold is never set by anything. Do the first authenticated run early enough to notice.
4. **Eleven of 41 tool images cannot be downloaded** — `gau`, `whatweb`, `nikto`, `commix`,
   `kiterunner`, `cloudsplaining`, `apktool`, `jadx`, `garak`, `promptfoo`, `strix`. The runner
   refuses unpinned tools, so each is silently absent from every run while your website lists it.
   Either fix the image reference or take it off the catalogue — listing them overstates what you do.
   Note `garak` and `promptfoo` are two of the four LLM tools.
5. **No model has ever been called.** The AI layer is fully built and tested against a fake
   transport. First real call on a throwaway engagement with a $1 ceiling.
6. **Mobile, cloud, code and LLM have never run end to end** against a live target.

### Worth doing

7. **Logs are not shipped off the machine.** An attacker who owns the host can edit the record of
   owning it.
8. **No alerting.** A human reading refusals daily is a process, not a control, and it will not
   survive a busy week.
9. **No WebAuthn.** TOTP is fine for now; hardware keys are what you would recommend to a client of
   your size, so get there yourself.
10. **One server.** Fine at your size. `docs/RUNBOOK.md` §10 says when it stops being fine.

---

## 15. What to avoid

### Never, under any circumstances

- **Never test anything not on a signed, in-date authorisation.** No exceptions, no verbal
  agreements, no "they said it's fine on the call".
- **Never accept credentials by email or chat.** Once it is in their mailbox and yours, it is in two
  breach scopes.
- **Never email a report as an attachment.** Release it in the portal. There is no SMTP client
  anywhere in this codebase precisely so this cannot happen by accident.
- **Never claim a certification you do not hold** — CERT-In empanelment, CREST, ISO. The build fails
  if the repository says it; do not say it out loud either.
- **Never promise a system is secure.** No honest report says that. You say what you tested, what you
  found, and what you did not test.
- **Never run a denial-of-service, load or stress test.** The platform cannot express one and never
  will. If a client asks, tell them it is a different service from a different supplier.
- **Never put the console on the internet.** WireGuard or nothing.
- **Never turn off the never-touch list** because a client asked. It is checked *before*
  authorisation for that reason.

### Bad habits that creep in

- Skipping the dry run because you have done this before. That is exactly when scope drifts.
- Confirming candidates in bulk without reading them. That is how a scanner dump gets your name on
  it.
- Writing remediation as a link to a general article instead of a version number, a configuration
  line or a code change for *their* stack.
- Copying an executive summary from the last engagement. The client-name check will catch the obvious
  case; it will not catch a summary that describes someone else's architecture.
- Running a tool update mid-engagement. Re-pin images deliberately, in a batch, between engagements.
- Letting a retainer run without re-checking the authorisation date.
- Testing production during business hours because staging "isn't quite ready".

### Business habits

- Take 50% up front. The report is your leverage; once it is delivered you have none.
- Peer review by someone who did not write it. If the firm is one person today, say that to the
  client rather than quietly skipping it.
- Offer the debrief call to the engineers, not just the buyer who signed.
- Do not compete on price. Compete on turnaround, evidence quality and the coverage matrix — the
  things a cheap scan shop cannot copy.

---

## 16. FAQ

**A client wants me to test their whole company. What do I do?**
Ask for a written list of hostnames. Put those on the form. If they cannot produce a list, they do not
know what they own, and helping them find out is a separate, billable piece of work — an asset
discovery exercise, done from data they give you, not by scanning the internet.

**They gave me a domain that resolves to Cloudflare / AWS / Vercel. Can I test it?**
Not without a further step. The client owns the application, not the machine. Read that provider's
testing policy (the platform stores AWS, Azure and GCP policies for acknowledgement) and confirm what
they permit. Cloudflare and most PaaS providers require you to test the origin, not their edge.

**What if the target is on shared hosting?**
You need the hosting provider's written acknowledgement too, not just the client's. Your test will
touch a machine other people's sites are on. The platform will stop and ask you to acknowledge this
when a host resolves to several addresses.

**Can I test a staging environment instead?**
Prefer it, and say so in the report. But check it actually matches production — a staging box with
debug mode on and different credentials produces findings that do not exist in production, and misses
ones that do.

**The client wants the report today and testing takes five days.**
Say no. A report with a date on it is a professional document. Offer the external surface check
instead, which is a genuinely quick piece of work with an honest scope, and price it as such.

**Can I reuse a client's authorisation from six months ago?**
No. It has a valid-until date, and the platform checks it on every single tool launch, not at
engagement creation. Get a new one.

**A finding is a false positive but the tool keeps reporting it.**
Mark it a false positive with a reason. The reason is remembered per client, so the same wrong result
from the same tool is suppressed on their next engagement.

**The client says a critical finding is not a real risk.**
They can mark it risk-accepted in the portal, which requires a written justification and records
their name and the date. That is *their* audit record, not yours. Your finding stays in the report
with their acceptance next to it.

**Can a client see another client's data?**
No. Every portal query filters on the client id from their login session, and asking for someone
else's object returns "not found" rather than "forbidden" — which does not even confirm it exists. A
build-time test fails the build if any route forgets. Verified by driving it live.

**What happens to their data at the end?**
Evidence is deleted after the retention period, 90 days by default. Closing the engagement destroys
the key that opens their stored credentials. You can issue a deletion confirmation document with
counts.

**I lost the portal invitation link.**
Issue a new one. Only a hash is stored and nothing can read the original back. That is the correct
trade.

**A tool failed. Does that mean the check passed?**
No, and the platform will not pretend it did. A tool that exits with an error is recorded as failed,
and the checks it would have covered appear in the coverage matrix as not tested, with the reason.
This used to be wrong and is the kind of thing that makes a report a lie.

**Can I run two engagements at once?**
Yes, but the worker runs one tool at a time by design. They will queue. If that becomes a real
constraint, run a second worker — but a second worker on a second machine means a second egress IP,
which means every authorisation form changes. It is a client-facing change, not just an
infrastructure one.

**Where do I look when something goes wrong?**

| Question | Where |
| --- | --- |
| Is anything running right now? | `docker ps --filter label=com.attestor.purpose=engagement-run` |
| Why did a run fail? | The Queue page, or `GET /queue` |
| What was refused this week, and why? | `GET /audit/refusals?sinceDays=7` |
| Who downloaded that report? | The report's download log |
| Which tools cannot run? | The Settings page — anything with no pinned version |
| What has AI cost this month? | The Settings page |

---

**Related reading**

| Document | For |
| --- | --- |
| `docs/PRODUCT-CONTEXT.md` | The technical picture, and the non-obvious things about how runs work |
| `docs/COMMANDS.md` | Every command, and a whole engagement driven by `curl` |
| `docs/POLICY-COOKBOOK.md` | The full policy reference and nine worked examples |
| `docs/CHECKLISTS.md` | The fourteen checklists, including finding quality |
| `docs/RUNBOOK.md` | Servers, backups, key rotation, incidents |
| `docs/SALES-PLAYBOOK.md` | Pricing, objections, and the lines never to say |
| `docs/BUILD-STATUS.md` | The live state of the build |
