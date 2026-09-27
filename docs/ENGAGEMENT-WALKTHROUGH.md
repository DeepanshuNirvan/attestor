# Running a real engagement, start to finish

curl -sS -c /tmp/attestor.jar -X POST http://127.0.0.1:8080/auth/bootstrap -H 'content-type: application/json' -d '{"email":"ddnirvan@gmail.com","password":"Deepanshu@123","name":"Deepanshu Nirvan"}'

curl -sS -c /tmp/attestor.jar -X POST http://127.0.0.1:8080/auth/bootstrap -H 'content-type: application/json' -d '{"email":"ddnirvan@gmail.com","password":"Deepanshu@123","name":"Deepanshu Nirvan"}'

curl -sS -X POST http://127.0.0.1:8080/auth/bootstrap/confirm -H 'content-type: application/json' -d '{"email":"ddnirvan@gmail.com","code":"794387"}'

A worked example against one application, step by step, in the browser.

You type terminal commands only to set up and start the platform (Phase 0) and to make your app
reachable (Phase 3). **Every engagement step after that is a button in the console.**

The example client is **Northwind Retail**, whose application you are testing at
`http://192.168.29.249:5174`. It has email-and-password login and several roles. Substitute your own
values; everything else is literal.

Read `docs/HOW-A-TEST-RUNS.md` first if you have not. It is one page and explains why these steps
are in this order.

> **The one thing that will trip you up.** Your application runs on `localhost:5174`. Security tools
> run inside containers, and inside a container `localhost` is the container itself, not your
> machine. `localhost` is refused at scope entry for exactly this reason. **Phase 3** fixes it.

---

## Contents

| Phase | What happens | Who does it |
| --- | --- | --- |
| 0 | Start Attestor | you |
| 1 | Scoping call | you and the client |
| 2 | Prove the client owns the target | you |
| 3 | Make the application reachable | client's ops, or you locally |
| 4 | Create the client and the engagement | you |
| 5 | Enter the scope | you |
| 6 | Record the signed authorisation | you, after the client signs |
| 7 | Collect the test accounts | the client |
| 8 | Tell it how to log in to the app | you |
| 9 | Payment, dry run, pre-flight | you |
| 10 | Live run | you |
| 11 | Triage | you |
| 12 | Manual testing | you |
| 13 | Write the report | you |
| 14 | Release, and the client portal | you, then the client |
| 15 | Retest | client asks, you run |
| 16 | Close | you |

---

# Phase 0 — Start Attestor

## 0.1 — Things you need installed once

| Tool | Why | Check |
| --- | --- | --- |
| Docker Desktop | Runs the platform and every security tool | `docker version` |
| Node 22+ | Pins the tool images | `node --version` |
| An authenticator app | Both surfaces require a second factor | on your phone |

## 0.2 — Create `infra/.env`

**Compose will not start without this.** Five variables are declared as required, and the error you
get without them names the variable but not this step.

```bash
cp infra/.env.example infra/.env
```

Now fill in the blanks. Generate each value with the command in the comment above it in that file.
The three kinds:

**Passwords that end up inside a connection string** — `POSTGRES_PASSWORD`, `PORTAL_DB_PASSWORD`,
`REDIS_PASSWORD`, `MINIO_ROOT_PASSWORD`. These must not contain characters that mean something in a
URL, so use a URL-safe alphabet:

```bash
openssl rand -base64 48 | tr -d '/+=' | head -c 32; echo
```

**Keys that never appear in a URL** — `SESSION_SECRET`, and append one to the `attestor-key:` prefix
already on `MINIO_KMS_SECRET_KEY`:

```bash
openssl rand -base64 32
```

**The two 32-byte vault keys** — `VAULT_MASTER_KEY` and `PORTAL_TOTP_KEY`. Generate each separately;
they must not be the same value:

```bash
node -e "import('libsodium-wrappers-sumo').then(async s=>{await s.default.ready;console.log(s.default.to_base64(s.default.randombytes_buf(32),s.default.base64_variants.ORIGINAL))})"
```

Leave `CONSOLE_ORIGIN`, `PORTAL_ORIGIN`, the ports and `DOCKER_SOCKET_GID=0` exactly as they come.

> **Back up `VAULT_MASTER_KEY` separately from the database.** Every stored client credential is
> derived from it. Losing it makes them unrecoverable, which is by design.

## 0.3 — Start everything

```bash
docker compose -f infra/docker-compose.yml up -d --build
```

The first run builds images and takes several minutes. Wait for all nine services to report healthy:

```bash
docker compose -f infra/docker-compose.yml ps
```

That one command starts everything, including both browser surfaces. There are two, and they are
separate deployments of the same code:

| Surface | URL | Who signs in |
| --- | --- | --- |
| **Staff console** | http://localhost:3000 | You |
| **Client portal** | http://localhost:3100 | Your client |
| Console API | http://127.0.0.1:8080 | — |
| Portal API | http://127.0.0.1:8081 | — |
| Mailpit (captured mail) | http://localhost:8025 | — |

Check both surfaces answer:

```bash
curl -sS -o /dev/null -w 'console %{http_code}\n' http://localhost:3000/login
```

```bash
curl -sS -o /dev/null -w 'portal  %{http_code}\n' http://localhost:3100/login
```

Both should be `200`. The portal is the **only** surface a client ever sees. It runs from the same
codebase with `ATTESTOR_SURFACE=portal` baked in at build time, and a middleware returns 404 for the
other surface's routes — so a misconfiguration fails closed rather than serving your staff console
to a client.

## 0.4 — Pin the tool images

**Until this has run, no tool will start** — the runner refuses an image with no pinned digest,
because a report that names a tool version has to mean it.

```bash
node scripts/pin-tool-images.mjs --pull
```

This pulls a lot of images and takes a while on a first run. It writes
`infra/tool-images.lock.json`.

Expect exactly two `FAIL` lines: `garak` and `promptfoo`. Those are the LLM tools, parked on
purpose (no trustworthy image, and third-party data flow). They do not affect a web, API or recon
engagement. Any **other** `FAIL` is a real problem.

## 0.5 — Create your staff account

Only needed once, on a brand new install. It works only while no staff account exists. This is
the one engagement-side step with no screen, because there is nobody signed in yet to press a
button. Run both commands in **Git Bash** (not Windows `cmd`, which breaks the quotes).

```bash
curl -sS -X POST http://127.0.0.1:8080/auth/bootstrap \
  -H 'content-type: application/json' \
  -d '{"email":"you@attestorsecurity.com","password":"a-long-passphrase","name":"Your Name"}'
```

That returns an `otpauth://` URL. Add it to your authenticator app, then confirm with the code it
shows:

```bash
curl -sS -X POST http://127.0.0.1:8080/auth/bootstrap/confirm \
  -H 'content-type: application/json' \
  -d '{"email":"you@attestorsecurity.com","code":"123456"}'
```

The **email is required** — bootstrap sets no session, so the email is how the server finds the
account. The answer is `{"ok":true}`. A code works once and only for about 30 seconds; if it is
refused, wait for the next one. Until this succeeds the account cannot sign in.

## 0.6 — Sign in

Open **http://localhost:3000/login** → email → password → **Continue** → the six-digit code from
your authenticator → **Sign in**.

**From here on everything is done in the browser.** No terminal commands are needed for a normal
engagement. (If you ever want the same steps as API calls for scripting, see Appendix C.)

## 0.7 — Stopping

Stop the platform, keeping all data:

```bash
docker compose -f infra/docker-compose.yml down
```

**Destroy the database, object store and every engagement in it** — only when you want a clean slate:

```bash
docker compose -f infra/docker-compose.yml down -v
```

---

# Phase 1 — Scoping call

Thirty minutes on a call. Ask these, in this order, and write the answers down.

1. **What is the application, and who logs into it?** The number of roles drives the price more than
   the number of pages.
2. **List every role.** Write them down by name. You need **two accounts for every role** — more on
   this in Phase 7.
3. **Is there a staging environment that matches production?** Staging is better. If it has to be
   production, say so now.
4. **Is it multi-tenant?** Can one customer organisation's users see another's data?
5. **Are there payment, approval or quota flows?**
6. **Is there anything a test must never touch?** A billing run, a live payment gateway, an SMS
   sender that costs money per message.
7. **Who is the emergency contact during the test window, and what is their mobile number?**
8. **When do you need the report, and who is it for?**
9. **Have you been tested before? May I see the report?**

Then **send your notes back to the client and ask them to correct them**. Their reply in writing is
your evidence of what was agreed.

---

# Phase 2 — Prove the client owns the target

Do not skip this. Testing a system without the owner's permission is an offence in India under the
IT Act s.66. Full detail is in `docs/OPERATOR-HANDBOOK.md` §7.

For a domain, ask them to publish a DNS TXT record you name, or serve a file you name at a path you
choose, and check it yourself. Either proves control of the thing you are about to test.

For a private IP range this is not possible, so the signed authorisation (Phase 6) does the work: the
client declares the range as theirs in writing.

---

# Phase 3 — Make the application reachable

Your app is on `localhost:5174`. Tool containers cannot reach that — inside a container,
`localhost` is the container itself.

Start your app listening on all interfaces. Most dev servers take a host flag:

```bash
npm run dev -- --host 0.0.0.0 --port 5174
```

Check a container can reach it on your LAN address. This is the test that matters:

```bash
docker run --rm curlimages/curl:latest -sS -o /dev/null -w '%{http_code}\n' http://192.168.29.249:5174/
```

Any HTTP status (200, 302, 404) means the tools will reach it. `000` or a hang means the Windows
firewall is blocking it. Allow it once, in an **admin PowerShell**:

```powershell
New-NetFirewallRule -DisplayName "Attestor target 5174" -Direction Inbound -LocalPort 5174 -Protocol TCP -Action Allow -Profile Private
```

**For a real client** you do none of this. They give you a hostname on the internet (or a private
range plus a VPN), and your fixed egress IP goes on the authorisation form for them to allowlist.

---

# Phase 4 — Create the client and the engagement

### Add the client

**Clients → Add a client.**

| Field | What to put |
| --- | --- |
| Name we use day to day | `Northwind Retail` |
| Registered legal name | `Northwind Retail Private Limited` — their registered name, not their brand. It goes on the report cover |
| Country | `IN` |
| Notes | anything useful |

Press **Create**. You land on the client's page.

### Create the engagement

**Engagements → New engagement.**

| Field | What to put |
| --- | --- |
| Client | Northwind Retail |
| Title | `Web application and API assessment` |
| Type | `webApplication` |
| Test type | Grey box — you have test accounts, not source code |
| Test window starts / ends | the dates you agreed. **Include today** if you are testing today — nothing runs outside the window |
| Policy profile | `standard-web-app` |
| Currency, quoted amount | as agreed |
| Timezone | `Asia/Kolkata` |

Press **Create engagement**. You land on the **engagement page**. Everything from here to Phase 10 is
done on this one page — each step below names the **section** of the page to scroll to.

The reference (for example `ATT-2026-001`) is generated. The client will quote it for years.

---

# Phase 5 — Enter the scope

Section **Scope**. You add one *kind* at a time.

**First entry — the address the client declares as theirs:**

- Kind: `cidr`
- Values: `192.168.29.249/32`
- Press **Add to scope**

**Second entry — the application, every address it answers on:**

- Kind: `url`
- Values, one per line:
  ```
  http://192.168.29.249:5174
  http://192.168.29.249:8080
  ```
- Press **Add to scope**

List the frontend **and** the API. Web and API runs test only the URLs listed here. With only the
frontend (`:5174`) listed, the API behind it (`:8080`) gets no web or API testing at all. The
frontend's calls to it are out of scope for the crawler. If recon later finds a web service you
did not list, the Report page and the report both show it under **Found but not tested**; add it
here and run the web and API modules again.

The `cidr` entry is what makes a private address legal to test; without it the address is refused.
Use `/32` — one address, not your whole network. Anything invalid is refused with the reason shown
under the box.

To exclude something, tick **Add these as exclusions rather than inclusions** before pressing the
button.

Then section **Lifecycle** → Move to: `scoped` → **Change stage**.

**For a real client** the entries look like `app.northwind.example` (domain),
`*.staging.northwind.example` (wildcard — matches `app.staging…` but not `staging…` itself), and
exclusions such as `mail.northwind.example`.

---

# Phase 6 — Record the signed authorisation

**Nothing runs before this exists. It cannot be overridden by anyone.**

1. Open **Legal text** in the console menu. The block **Authorisation for security testing** is the form
   text. Put it into a PDF with the client's details and send it for signature to someone who can
   bind the company — a director, CTO or CISO, not a developer.
2. When the signed PDF comes back, go to the engagement page, section **Authorisation**. Fill in:

| Field | What to put |
| --- | --- |
| Signed authorisation (PDF) | the signed file. It is stored with the engagement and fingerprinted |
| Signed by, Their role, Their email, Date signed | as on the form |
| Testing allowed from / until | the window written on the form. Must include today to test today |
| Assets | pre-filled from your scope. **Change it to match the signed document exactly** |
| Exclusions | as written in the document |
| Your testing IP addresses | your egress IP as named on the form |
| Emergency contact | name, role, mobile, email — the person you ring if something goes wrong |
| Notify a critical finding within | hours, as agreed (usually 24) |

Press **Record authorisation**.

It then shows whether **the signed asset list matches your scope exactly**. If it lists differences,
stop: fix the scope or get a corrected form signed. That comparison is the cheapest protection you
have against testing something nobody signed for.

Then **Lifecycle** → Move to: `authorised` → **Change stage**.

---

# Phase 7 — Collect the test accounts

Credentials never arrive by email or chat. You create a one-time link, the client types the
accounts into it, and they are sealed in a vault. **Nobody can read them back** — not you, not the
console.

### Ask for two accounts per role

For access control testing you need **two accounts for every role**. Half the job is checking
whether customer A can read customer B's data, which is impossible with one account per role. Admin,
manager and user means **six accounts**.

Section **Ask for test accounts**:

- Row 1: What to call it `Admin A`, Role `admin`, How they sign in `Email and password`
- Press **Add another account** → `Admin B`, role `admin`, tick **Second account for this role**
- Repeat for `Manager A` / `Manager B` and `User A` / `User B`
- Link works for (hours): `72`
- Press **Create the link**

The **role names must match the `roleName` values you put in the policy in Phase 8** — that is how an
account is matched to a login.

The link appears **once**, looking like `http://localhost:3100/credentials/<token>`. Copy it and send it
to the client yourself. Lost link means a new link.

### What the client does

They open the link — no account or login needed — see one box per account you asked for, fill them
in, and submit. On the engagement page, section **Credentials**, you then see each account's label
and role, never its password. **Stop using** withdraws one.

Tell the client: **use throwaway accounts, and change their passwords when we finish.**

---

# Phase 8 — Tell it how to log in to the app

Section **Policy**. The box already holds the policy from the profile you chose. You add one
`authProfiles` entry **per role**, telling the tools how your app's login works. Without this,
everything is tested as an anonymous visitor.

Find your app's login details first: open your app in the browser, press **F12 → Network**, log in,
and click the login request. Note the **URL** it posted to, the **JSON field names** it sent (for
example `email` and `password`), and **where the token is** in the response (for example `token`,
or `data.accessToken`). If the app uses a cookie instead of a token, leave `tokenPath` out.

Add this at the end of the policy box, adjusted to what you saw:

```yaml
readOnlyMode: true
authProfiles:
  - id: admin
    roleName: admin
    type: formLogin
    loginUrl: http://192.168.29.249:5174/login
    apiLogin:
      url: http://192.168.29.249:5174/api/auth/login
      usernameField: email
      passwordField: password
      tokenPath: token
  - id: manager
    roleName: manager
    type: formLogin
    loginUrl: http://192.168.29.249:5174/login
    apiLogin:
      url: http://192.168.29.249:5174/api/auth/login
      usernameField: email
      passwordField: password
      tokenPath: token
  - id: user
    roleName: user
    type: formLogin
    loginUrl: http://192.168.29.249:5174/login
    apiLogin:
      url: http://192.168.29.249:5174/api/auth/login
      usernameField: email
      passwordField: password
      tokenPath: token
checks:
  rateLimitEndpoints:
    - url: http://192.168.29.249:5174/api/auth/login
      method: POST
      description: the sign-in endpoint
```

If the box already has a `readOnlyMode:` or `checks:` line, change that one rather than adding a
second.

### If the login request body is encrypted

Some apps encrypt the login in the browser, so the request body is something like
`{"nonce": "...", "ciphertext": "..."}` instead of an email and password. Then:

- **Leave out `apiLogin` and `rateLimitEndpoints`.** Both send plain JSON, which such a backend
  rejects. Keep `type: formLogin` and `loginUrl` (the frontend page with the login form).
- **ZAP still logs in**: it drives a real browser, so the app's own JavaScript does the encryption.
  It logs in as the **first** role listed, so put the highest-privilege role first.
- **Access control between roles and login rate limiting become manual** (Phase 12), because the
  probes that do them automatically log in without a browser.
- Check whether **other** requests are encrypted too. If every request body is, ZAP's injection
  tests land in ciphertext and test little; tell the client this limits the assessment.
- Look for where the key comes from. **A key shipped in the JavaScript protects nothing over HTTPS**
  — anyone can decrypt with it — and is worth reporting as a low or informational finding.

Press **Save policy**. It shows **Saved** and any **warnings** — read every one. A rate limit above the
ceiling is refused and nothing is saved.

What the three settings do:

- **`readOnlyMode: true`** — no state-changing requests. Always on for the first pass against
  production. Logging in still works. The cost: ZAP's **active scan** (the injection and attack
  tests) is skipped entirely, and only passive checks run. Against a copy of the app with
  disposable data, set it to `false` for a much deeper test. Never do that against data the client
  cannot lose.
- **`authProfiles`** — one per role; each picks up the two accounts of that role from Phase 7.
- **`rateLimitEndpoints`** — throttling is only measured on endpoints you name, because repeating a
  request thirty times at an OTP or password-reset endpoint costs the client money or emails a real
  person.

---

# Phase 9 — Payment, dry run, pre-flight

### Record the advance

Section **Payments** → Payment: `Advance`, invoice reference, amount → **Record payment**.

Then **Lifecycle** → Move to: `advancePaid` → **Change stage**. (If the advance has not arrived and you
start anyway, the Lifecycle section lets you give an override reason, recorded against your name. The
authorisation gate has no such override.)

### Dry run — always first

Section **Run**:

- Tick modules **Recon and attack surface**, **Web application**, **API**
- **Leave "Send packets" unticked** — that is the dry run. Every check is evaluated against the scope
  and nothing is sent to the target
- Press **Queue**

Section **Runs** then lists what *would* run, per tool and target. The menu item **Job queue** shows the
same. **If the targets are not exactly what you expected, fix the scope and dry run again.**

### Pre-flight checklist

Section **Before a live run**. Tick all six — each one is a real check, and there is no override:

| Item | What you are confirming |
| --- | --- |
| Inside the agreed test window | The window on file is the one the client agreed |
| The authorisation is valid today | Valid **today**, not only on the start date |
| A dry run has been performed | You did the dry run above and read the list |
| The rate limit suits this target | A laptop dev server is not a production cluster |
| The client has been told if this run is louder | No surprises in their monitoring |
| Somebody is available to press the panic stop | Ring the emergency contact before ticking this |

Press **Save checklist**. Then **Lifecycle** → Move to: `readyToRun` → **Change stage**.

---

# Phase 10 — Live run

Tell the client you are starting. **Lifecycle** → Move to: `running` → **Change stage**.

Section **Run**:

- Tick **Recon and attack surface** only first
- **Tick "Send packets"**
- Press **Queue**

Let recon finish (watch section **Runs**, or the **Job queue** page). The crawler records the app's
endpoints, and everything after reads that list — running Web before anything is discovered gives a
thin test.

Then tick **Web application** and **API**, tick **Send packets**, press **Queue** again.

The **Job queue** page shows what is running and, for anything that failed, why.

### If something goes wrong

Section **Stop** → **Stop everything**, with a reason. Every running job for this engagement halts.
It does not expire on its own — **Clear the stop**, with a reason, when it is safe.

---

# Phase 11 — Triage

**Lifecycle** → `triage` → **Change stage**. Then press **Triage** at the top of the engagement page.

For **every** candidate finding:

- **Confirm** — only after you have reproduced it yourself, not after reading the tool's description
- **Discard** — not a real issue
- **False positive** — with a reason. The reason is remembered, so the same wrong result does not
  cost you time again

Nothing may stay a candidate; the release gate blocks on it.

**A critical finding:** telephone the emergency contact **now**, within the hours on the
authorisation. You confirm you did this on the report checklist in Phase 13.

---

# Phase 12 — Manual testing

**Lifecycle** → `manualTesting` → **Change stage**. This is what the client is paying for, and no tool
does it.

### Access control, every pair of roles, both directions

| As | Try to reach | Expect |
| --- | --- | --- |
| User A | admin pages and admin API routes | refused |
| User A | **User B's** records, by changing an id | refused |
| Manager A | admin pages | refused |
| Manager A | **Manager B's** records | refused |
| Admin A | another tenant's data, if multi-tenant | refused |
| logged out | every logged-in page and API route | refused |

### Business logic

Skip a step in a workflow · change a price, quantity or total in the request · reuse a coupon ·
fire two requests at the same moment at anything with a limit · check limits are enforced by the
server, not the browser.

### Sessions

Log out, then replay an old request — does the session still work? Log in as the same user in two
browsers — do both work, and does changing the password end the other one? Does the session id
change when you log in?

### Record what you found

Press **Record a finding** at the top of the engagement page for each issue you find by hand. Fill
in the title, severity, the affected URL, what you found, the business impact, the steps (one per
line), the fix, and the evidence: paste the request and the response that prove it, and add a
screenshot if you have one. Leave the CVSS vector blank to use a standard one for the severity.
Press **Save as a candidate**. It then appears in **Triage**, and once you **Confirm** it there it is
in the report.

### Record what you did

Open **Report** (top of the engagement page), section **Manual coverage**, one line per check:

```
web-horizontal-access-control: replayed User A's requests as User B across 34 endpoints
web-concurrent-sessions: two sessions at once; password change did not end the other
```

Press **Save**. A check with no line here and no tool behind it appears in the report as **not
tested**, with the reason — which is honest, and is why the report is worth something.

---

# Phase 13 — Write the report

**Lifecycle** → `reportDraft` → **Change stage**, then press **Report**.

1. **Draft the whole report** → **Draft every section**. It needs AI switched on in two places:
   `AI_ENABLED`/`AI_PROVIDER` in `infra/.env`, and **Allow AI drafting** in the engagement page's
   **AI drafting** section (which shows whether both are on). If either is off, each section says
   so and you write the text yourself in the boxes below. Either way, press **Approve
   this draft** (or **Save**) on each section once you have read it. The report itself — findings,
   evidence, coverage, CVSS — is generated from what ran and never needs AI.
2. Fill the four sections only you know: **Environments**, **Roles and accounts used**,
   **Client-imposed constraints**, **Manual coverage**. Also fill **Positive observations**
   (controls you found working). Release is blocked while it is empty.
3. **Write up each finding.** Tools write little of this, so release stays blocked until you do.
   Open **Findings in this report** at the top of the Report page and click each title. Under
   **Write-up**, fill **Business impact** (more than a line, in business terms), **Reproduction
   steps** (one per line, at least two) and **Remediation** (the specific fix), then press **Save**.
   For tool noise that is not a real issue (duplicates, "robots.txt file", a DMARC finding on an
   IP address), press **Not a real issue** and give a reason. It leaves the report. **Back to the
   report** returns you to the list.
4. **Pre-release checklist** (right-hand side) lists anything still blocking. Tick the three manual
   items — critical findings notified, evidence reviewed for personal data, **I have read every line
   of this report** — and press **Save confirmations**.
5. **Documents → Generate assessment report.** It is stored, not downloaded automatically: the new
   version appears in the table below with a **Download PDF** button. Open it and read it. Each press
   makes a new version (1.0, 1.1, …); release the latest one.

Then **Lifecycle** → `reportReview` → **Change stage**.

---

# Phase 14 — Release, and the client portal

## 14.1 — Record the balance

Engagement page, section **Payments** → Payment: `Balance`, invoice reference, amount → **Record
payment**. Release is blocked until it is recorded.

## 14.2 — Release

**Report → Documents →** the report row **→ Release** → type the recipient email address(es).

The server re-runs the whole checklist. If it refuses, **Release refused** lists exactly what is
blocking. **No email is sent automatically** — the notification is queued. Open the **Job queue** page,
**Outbox**: read it, **Approve**, send it yourself, then **I have sent this**.

Locally, any mail the platform sends lands in **Mailpit at http://localhost:8025**, never a real inbox.

## 14.3 — Invite the client to the portal

**Clients → Northwind Retail → Invite someone to the portal** → their email, role `Owner` → **Create
invitation**.

The link appears **once** — `http://localhost:3100/invitation/<token>`. Copy it, send it to the client
yourself, then press **I have copied it**. Lost link means a new invitation.

Roles: **Owner** can do everything including inviting colleagues; **Member** can read, comment and
request a retest; **Read-only** can only read.

## 14.4 — What the client does

Walk a real client through this on the phone the first time; it takes about three minutes.

1. Opens the link. No account needed yet.
2. **Choose a password** — name, email, password twice → **Continue**.
3. **Add this to your authenticator** — the page shows a key. **There is no QR code**: in the
   authenticator app they choose *Enter a setup key* and type it. Type the **Key** line only,
   never the setup URL. The key uses only letters and the digits 2–7, so every O is the letter O
   and every I is the letter I. A zero or a one gives *"illegal character"*.
4. Types the six-digit code → **Confirm**. The account does not exist until this succeeds.
5. **You are set up** → sign in at **http://localhost:3100** with email, password, then a code.
6. **I accept these terms** — once.

## 14.5 — What the client sees

| Menu | What is on it |
| --- | --- |
| **Dashboard** | open findings by severity, engagement stage, what needs them |
| **Findings** | every confirmed finding, with evidence, reproduction steps and the fix. They set a status (acknowledged, in progress, fixed, risk accepted) and press **Update**, or ask you a question and press **Send** |
| **Reports and documents** | the released report — view in the browser or download the PDF — and the attestation letter |
| **Retests** | **Request a retest** |
| **Questionnaire answers** | ready-made answers for their customers' security questionnaires, with **Copy answer** |
| **Account** | change password, see sessions, **Sign out everywhere**, manage colleagues |

They never see an unreleased engagement, a finding you discarded, another client's data, or the
console.

To see exactly what they see, open a **private window**, invite an email address you control, and go
through 14.4 yourself.

## 14.6 — The attestation letter

**Report → Documents → Generate attestation letter.** One page saying an assessment was done, by
whom, when and against what — **no finding detail**. Generate the assessment report first: the
letter names it by version (the latest released one, or the latest generated if none is released
yet), and generating a letter before any report is refused. It is added to the Documents table as an
**attestation** row with **Download PDF**. Like the report, the client sees it only after you press
**Release** on that row; it then appears in their **Reports and documents**. It is what they
forward to their own customers instead of the vulnerability list.

---

# Phase 15 — Retest

1. The client fixes things, marks those findings **fixed** in the portal, and presses **Request a
   retest**.
2. You: **Lifecycle** → `retestPending` → **Change stage**, then run the same modules as before
   (Run → same boxes → Send packets → Queue). Same scope and policy, or the retest proves nothing.
3. Check each previously open finding by hand: open it from **Report → Findings in this report**,
   repeat its reproduction steps, and under **Retest** press **Verified fixed** or **Still open**.
   The retest report prints that verdict against each finding. The attestation letter counts a
   high or critical finding as fixed only after you press **Verified fixed**; the client marking it
   fixed is not enough.
4. **Report → Documents → Generate retest report**, then release it as in 14.2.

---

# Phase 16 — Close

Remind the client to change the test accounts' passwords. Then **Lifecycle** → `closed` → **Change
stage**.

**Closing destroys the key for this engagement's stored credentials.** After that nothing can open
them — not you, not an attacker, not from a backup. It cannot be undone.

Evidence is deleted automatically 90 days after release. **Report → Documents → Generate deletion
confirmation** produces the written confirmation for the client; it asks for the counts the
retention job reports.

---

# Appendix A — Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `"localhost" is the loopback interface` | Containers cannot reach your loopback | Phase 3 |
| `is inside 192.168.0.0/16, which is not authorised` | No client-owned CIDR declared | Add the `cidr` scope item |
| Every tool fails with connection refused | App bound to loopback only, or firewall | Re-run the `docker run curl` check in Phase 3 |
| `no templates provided for scan` (nuclei) | Template pack not provisioned | `docker compose -f infra/docker-compose.yml run --rm nuclei-templates-init` |
| A tool will not start at all | No pinned digest | `node scripts/pin-tool-images.mjs --pull` |
| Run refused before any packet | Scope guard. Read the reason | Usually the scope, occasionally DNS |
| Everything tested as anonymous | No `authProfiles` in the policy | Phase 8 |
| Rate limit probe found nothing | No `rateLimitEndpoints` named | Phase 8, and this is by design |
| Release refused | Checklist. The response says what | Fix what it names |
| Report says "not tested" everywhere | No manual coverage recorded | Phase 12 |

| Lifecycle refuses a stage change | A gate is not met. The message says which | Do what it names |
| `a submitted test account failed to sign in` | A credential is known to be wrong | Ask the client for a replacement, or **Stop using** it |

Where to look when something is unclear:

- The engagement page **Runs** section and the **Job queue** page — every failed or refused job
  with its reason.
- **Settings** — which tools are runnable.
- The worker's own log, in a terminal:

```bash
docker compose -f infra/docker-compose.yml logs -f worker
```

---

# Appendix B — What is different for a real client

Everything above is the real procedure. Only these change:

| Local | Production |
| --- | --- |
| Console on `localhost:3000` | Console over WireGuard only, never the internet |
| Portal on `localhost:3100` | `https://portal.attestorsecurity.com` — the only public surface |
| Target is your LAN address | A hostname on the internet, or a private range plus a VPN |
| A `cidr` scope item makes the private address legal | Only for a genuinely internal engagement |
| Egress IP is whatever your ISP gives you | A **fixed** IP the client allowlists, on every authorisation form |
| `AI_ENABLED=false` | Your choice, per engagement, and off by default |

And two things that do not change, ever: nothing runs before a signed authorisation, and no report is
released before a person has read every line of it.

---

# Appendix C — The same steps by API

Everything in Phases 4–16 can also be done with `curl` against `http://127.0.0.1:8080`, which is
useful for scripting. `docs/COMMANDS.md` §8 has every call. You then need a session cookie first:

```bash
curl -sS -c /tmp/attestor.jar -X POST http://127.0.0.1:8080/auth/login -H 'content-type: application/json' -d '{"email":"you@attestorsecurity.com","password":"your-password"}'
```

```bash
curl -sS -b /tmp/attestor.jar -c /tmp/attestor.jar -X POST http://127.0.0.1:8080/auth/mfa -H 'content-type: application/json' -d '{"code":"123456"}'
```

You never need this for a normal engagement.
