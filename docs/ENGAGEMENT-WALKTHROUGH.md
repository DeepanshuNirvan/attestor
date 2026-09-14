# Running a real engagement, start to finish

A worked example against one application, with every command and every button.

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
| 7 | Collect credentials through the vault | the client |
| 8 | Write the policy | you |
| 9 | Pre-flight and dry run | you |
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
| `jq` | Reads JSON out of the API responses below | `jq --version` |
| An authenticator app | Both surfaces require a second factor | on your phone |

**`jq` is not installed on Windows by default and every API command below pipes through it.**

```powershell
winget install jqlang.jq
```

Close and reopen your terminal afterwards, then confirm:

```bash
jq --version
```

If you would rather not install it, drop the `| jq ...` from the end of any command and read the raw
JSON. Nothing depends on `jq` except readability.

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

## 0.5 — Create your staff account

Only needed once, on a brand new install. It works only while no staff account exists.

```bash
curl -sS -c /tmp/attestor.jar -X POST http://127.0.0.1:8080/auth/bootstrap \
  -H 'content-type: application/json' \
  -d '{"email":"you@attestorsecurity.com","password":"a-long-passphrase","name":"Your Name"}'
```

That returns an `otpauth://` URL. Add it to your authenticator app, then confirm with the code it
shows:

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/auth/bootstrap/confirm \
  -H 'content-type: application/json' -d '{"code":"123456"}'
```

## 0.6 — Sign in

**In the browser:** http://localhost:3000/login — email, password, then the six-digit code.

**For the commands in this document**, you also need a cookie file. Every `curl` below sends
`-b /tmp/attestor.jar`, and that file is created by signing in. Two calls, because the session does
nothing until the second factor is satisfied:

```bash
curl -sS -c /tmp/attestor.jar -X POST http://127.0.0.1:8080/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"you@attestorsecurity.com","password":"a-long-passphrase"}'
```

```bash
curl -sS -b /tmp/attestor.jar -c /tmp/attestor.jar -X POST http://127.0.0.1:8080/auth/mfa \
  -H 'content-type: application/json' \
  -d '{"code":"123456"}'
```

Use the code your authenticator is showing at that moment. The first call answers
`{"mfaRequired":true}` and the second answers with your account. Confirm it worked:

```bash
curl -sS -b /tmp/attestor.jar http://127.0.0.1:8080/auth/me
```

Three possible answers, and each tells you what to do:

| Response | Meaning |
| --- | --- |
| Your account details | Signed in. Every command in this document will work |
| `{"error":"not signed in"}` | No cookie file. Run both calls above |
| `{"error":"multi-factor authentication is required"}` | The second call did not happen, or the code was stale. Run it again |

Sessions expire. When a command starts returning `401`, run those two calls again.

**In production:** the console is reachable only over WireGuard, never from the internet. Only the
portal faces the internet.

## 0.7 — Finding the ids the commands need

Commands below say `<client-id>`, `<id>` (the engagement) and `<report-id>`. Each is returned when
you create the thing, and you can always look them up again:

```bash
curl -sS -b /tmp/attestor.jar http://127.0.0.1:8080/clients | jq -r '.clients[] | "\(.id)  \(.name)"'
```

```bash
curl -sS -b /tmp/attestor.jar http://127.0.0.1:8080/engagements | jq -r '.engagements[] | "\(.id)  \(.reference)  \(.state)"'
```

```bash
curl -sS -b /tmp/attestor.jar http://127.0.0.1:8080/engagements/<id>/reports | jq -r '.reports[] | "\(.id)  \(.kind) v\(.version)  releasedAt=\(.releasedAt)"'
```

They are also in the URL bar when you open the thing in the console.

## 0.8 — Stopping

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
8. **When do you need the report, and who is it for?** An auditor reads differently from a customer's
   security team.
9. **Have you been tested before? May I see the report?**

Then **send your notes back to the client and ask them to correct them**. Their reply in writing is
your evidence of what was agreed. Do not skip this; it takes five minutes and it is the thing you
will be glad of if there is a dispute.

---

# Phase 2 — Prove the client owns the target

Do not skip this. It is the step that keeps you out of court. Testing a system without the owner's
permission is an offence in India under the IT Act s.66.

Full detail is in `docs/OPERATOR-HANDBOOK.md` §7. The short version, for a domain:

**Either** ask them to publish a DNS TXT record you name:

```bash
dig +short TXT _attestor-verify.northwind.example
```

**Or** ask them to serve a file you name at a path you choose:

```bash
curl -sS https://app.northwind.example/.well-known/attestor-verify.txt
```

Either proves control of the thing you are about to test. Save the output.

For a private IP range, this is not possible, so the authorisation form does the work instead: the
client declares the range as theirs in writing, signed by someone who can bind the company. That is
what Phase 6 records.

---

# Phase 3 — Make the application reachable

Your app is on `localhost:5174`. Tool containers cannot reach that. Pick one of these.

### Option A — bind the app to your LAN address (recommended locally)

Your machine's LAN address is `192.168.29.249`. Start your app listening on all interfaces rather
than only loopback.

Most dev servers take a host flag:

```bash
npm run dev -- --host 0.0.0.0 --port 5174
```

Confirm it answers on the LAN address, not just loopback:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://192.168.29.249:5174/
```

Then check a container can reach it too. This is the test that matters:

```bash
docker run --rm curlimages/curl:latest -sS -o /dev/null -w '%{http_code}\n' http://192.168.29.249:5174/
```

A `200` (or any HTTP status) means the tools will reach it. A hang or `000` means your firewall is
blocking it — allow inbound TCP 5174 on the Wi-Fi profile:

```powershell
New-NetFirewallRule -DisplayName "Attestor target 5174" -Direction Inbound -LocalPort 5174 -Protocol TCP -Action Allow -Profile Private
```

### Option B — `host.docker.internal`

Docker Desktop resolves this name to your host. Accepted at scope entry with no extra declaration.

```bash
docker run --rm curlimages/curl:latest -sS -o /dev/null -w '%{http_code}\n' http://host.docker.internal:5174/
```

Simpler, but the name is meaningless to the client and looks wrong on a report, so prefer Option A
even locally. It is useful as a fallback when your firewall will not cooperate.

### What this looks like for a real client

You do none of the above. The client gives you a hostname on the internet, or a private range plus
a VPN. Your fixed egress IP goes on the authorisation form and they allowlist it:

```bash
curl -sS https://ifconfig.me
```

That address must not change. Clients allowlist it and it goes on every authorisation form, so
changing it means re-issuing every authorisation.

---

# Phase 4 — Create the client and the engagement

### In the console

**Clients → Add a client.** Use their **registered legal name**, not their brand. It goes on the
contract, the authorisation and the report cover.

Fill in: legal name, country, a primary contact, and an **emergency contact with a mobile number**.
Mark the emergency contact as such.

Then **Engagements → New engagement**. Choose:

- **Type** — `webApplication`
- **Test type** — `greyBox` (you have credentials but not source code)
- **Test window** — the start and end dates you agreed. These are printed in the report and the
  release gate blocks without them.
- **Timezone** — `Asia/Kolkata`
- **Policy profile** — `standard-web-app`

The reference, `ATT-2026-014`, is generated. The client will quote it for years.

### Or by API

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/clients \
  -H 'content-type: application/json' \
  -d '{
    "name": "Northwind Retail",
    "legalName": "Northwind Retail Private Limited",
    "country": "IN",
    "contacts": [
      { "name": "A. Person", "email": "cto@northwind.example", "role": "CTO",
        "phone": "+91 90000 00000", "isEmergencyContact": true }
    ],
    "billingDetails": { "gstin": "29ABCDE1234F1Z5", "currency": "INR", "paymentTermsDays": 15 }
  }'
```

Copy the `id` from the response into the next call.

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements \
  -H 'content-type: application/json' \
  -d '{
    "clientId": "<client-uuid>",
    "title": "Web application and API assessment",
    "type": "webApplication",
    "testType": "greyBox",
    "startsAt": "2026-09-15T00:00:00Z",
    "endsAt": "2026-09-19T23:59:59Z",
    "timezone": "Asia/Kolkata",
    "currency": "INR",
    "quotedAmount": 185000,
    "profileId": "standard-web-app"
  }'
```

Available profiles: `standard-web-app`, `deep-web-app`, `quick-external`, `cloud-review`,
`llm-only`.

Copy the engagement `id`. Everything below uses it.

---

# Phase 5 — Enter the scope

**Engagements → your engagement → Scope.** One item per line.

For the local example, you need **two** items. The CIDR is what makes the private address legal.

| Kind | Value | Included |
| --- | --- | --- |
| `cidr` | `192.168.29.249/32` | yes |
| `url` | `http://192.168.29.249:5174` | yes |

The CIDR item is the client declaring that range as their own. Without it the address is refused as
a private range, because a private address is only a legitimate target when the client has said in
writing that it is theirs.

Use `/32` — one address, not the whole subnet. Your neighbours' devices are not in scope.

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/scope \
  -H 'content-type: application/json' \
  -d '{
    "items": [
      { "kind": "cidr", "value": "192.168.29.249/32", "included": true },
      { "kind": "url",  "value": "http://192.168.29.249:5174", "included": true }
    ]
  }'
```

### For a real client

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/scope \
  -H 'content-type: application/json' \
  -d '{
    "items": [
      { "kind": "domain", "value": "app.northwind.example",      "included": true },
      { "kind": "wildcard", "value": "*.staging.northwind.example", "included": true },
      { "kind": "url",    "value": "https://api.northwind.example/v2", "included": true },
      { "kind": "domain", "value": "mail.northwind.example",     "included": false },
      { "kind": "path",   "value": "/admin/billing",             "included": false }
    ]
  }'
```

Things to know:

- `*.staging.northwind.example` matches `app.staging.northwind.example` but **not**
  `staging.northwind.example`. Add the apex separately if you want it.
- Mark anything out of bounds as an exclusion (`"included": false`). Being explicit is better than
  being silent.
- Bad entries are refused as you type, with a reason: loopback names and addresses, cloud metadata
  endpoints, government domains, cloud provider control planes, and wildcards broad enough to cover
  a whole country's registry.

---

# Phase 6 — Record the signed authorisation

**Nothing runs before this exists. It cannot be overridden by anyone, ever.**

Get a signed authorisation form from someone who can bind the company — a director, CTO or CISO.
Not a developer. The form must name:

- the exact assets
- the exact dates
- your egress IP
- an emergency contact
- how quickly you will notify a critical finding

Generate the form from the platform, then send it for signature:

```bash
curl -sS -b /tmp/attestor.jar http://127.0.0.1:8080/legal-blocks | jq -r '.[] | select(.id=="authorisation-form") | .text'
```

When it comes back signed, hash the PDF so the report can prove which document was signed:

```bash
sha256sum ~/Downloads/ATT-2026-014-authorisation.pdf
```

Upload it in the console (**Engagements → Authorisation**), or:

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/authorisation \
  -H 'content-type: application/json' \
  -d '{
    "signedBy": "A. Person",
    "signerRole": "Chief Technology Officer",
    "signerEmail": "cto@northwind.example",
    "signedAt": "2026-09-12T09:00:00Z",
    "documentObjectKey": "authorisations/ATT-2026-014.pdf",
    "documentSha256": "<64 hex chars from sha256sum>",
    "assetList": ["192.168.29.249/32", "http://192.168.29.249:5174"],
    "exclusionList": [],
    "sourceAddresses": ["203.0.113.10"],
    "emergencyContact": {
      "name": "A. Person", "role": "CTO",
      "phone": "+91 90000 00000", "email": "cto@northwind.example"
    },
    "criticalNotificationHours": 24,
    "validFrom": "2026-09-15T00:00:00Z",
    "validUntil": "2026-09-19T23:59:59Z"
  }'
```

### Read the diff

The response contains a **diff between the asset list in the signed document and the scope you
typed**. Read it, every time. That diff is the cheapest protection you have against testing
something nobody signed for. If it shows anything you did not expect, stop and fix the scope.

---

# Phase 7 — Collect credentials through the vault

Credentials never arrive by email or chat. You send the client a one-time link; they type the
credentials into a page; the values are sealed in a vault. **No route in the API returns a
credential value** — not to you, not to anyone.

### Ask for two accounts per role

This is the single most important thing to get right for a multi-role app.

Half of access control testing is checking whether customer A can read customer B's data. That is
impossible with one account per role. If your app has **admin, manager and user**, ask for **six**
accounts.

Mark the second account of each role as `isSecondary: true`.

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/credential-link \
  -H 'content-type: application/json' \
  -d '{
    "expiresInHours": 72,
    "accounts": [
      { "label": "Admin A",   "roleName": "admin",   "kind": "emailPassword", "isSecondary": false },
      { "label": "Admin B",   "roleName": "admin",   "kind": "emailPassword", "isSecondary": true  },
      { "label": "Manager A", "roleName": "manager", "kind": "emailPassword", "isSecondary": false },
      { "label": "Manager B", "roleName": "manager", "kind": "emailPassword", "isSecondary": true  },
      { "label": "User A",    "roleName": "user",    "kind": "emailPassword", "isSecondary": false },
      { "label": "User B",    "roleName": "user",    "kind": "emailPassword", "isSecondary": true  }
    ]
  }'
```

Credential kinds available: `emailPassword`, `usernamePassword`, `mobileOtp`, `oauth2`, `apiKey`,
`bearerToken`, `sessionCookie`. Yours is `emailPassword`.

The response contains a `url`, built from `PORTAL_ORIGIN`. Locally that is:

```
http://localhost:3100/credentials/<token>
```

**Send it to the client yourself.** It is shown once; only a hash is stored and no endpoint reads
it back. A lost link means a new link, which is the correct trade.

### What the client does

They open the link in a browser. **No account and no login is needed** — the token in the URL is
the authorisation, which is why it expires and is single-use.

They see one box per account you asked for, and only the fields that kind of login needs. For
`emailPassword` that is an email and a password; for `mobileOtp` it is a number and a note about
who to call for the code. They fill in the six accounts and submit.

After that you can see in the console that the credential set exists, its label, and its role.
**You never see the values**, and no route in either API returns them. The only thing that ever
opens them is the worker, in memory, at run time.

Check they arrived:

```bash
curl -sS -b /tmp/attestor.jar http://127.0.0.1:8080/engagements/<id> | jq '.credentialSets'
```

Tell the client: **use throwaway accounts, and rotate them when we finish.** You will remind them
again at closure.

---

# Phase 8 — Write the policy

The profile you picked gives you a working default. What you must add by hand is the part that is
specific to this client: how to log in, and which endpoints are safe to measure throttling on.

**Engagements → Policy**, or by API. This is the policy for the example app:

```bash
curl -sS -b /tmp/attestor.jar -X PUT http://127.0.0.1:8080/engagements/<id>/policy \
  -H 'content-type: application/json' \
  --data-binary @- <<'JSON'
{"yaml": "modules: [recon, web, api]\nintensity: thorough\nreadOnlyMode: true\nrateLimits:\n  globalRequestsPerSecond: 4\n  politeMode: true\nauthProfiles:\n  - id: admin-a\n    roleName: admin\n    type: formLogin\n    loginUrl: http://192.168.29.249:5174/login\n    apiLogin:\n      url: http://192.168.29.249:5174/api/auth/login\n      usernameField: email\n      passwordField: password\n      tokenPath: token\n  - id: user-a\n    roleName: user\n    type: formLogin\n    loginUrl: http://192.168.29.249:5174/login\n    apiLogin:\n      url: http://192.168.29.249:5174/api/auth/login\n      usernameField: email\n      passwordField: password\n      tokenPath: token\naccessControlMatrix:\n  enabled: true\n  testUnauthenticated: true\nchecks:\n  rateLimitEndpoints:\n    - url: http://192.168.29.249:5174/api/auth/login\n      method: POST\n      description: the sign-in endpoint\n"}
JSON
```

That call returns `{ "ok": true, "warnings": [...] }`. **Read the warnings.** Pipe it through
`jq .warnings` and look at every line. A warning is the platform telling you something is
probably wrong before the run rather than during it — a check id matching nothing, an auth
profile with no session indicator, a severity list that silently removes a whole class of check.

To see the policy the engagement is actually running, open **Engagements → Policy** in the
console. There is no GET for it on the API; the console renders the resolved policy after the
profile, client and engagement layers have been merged.

### The three settings that matter most

**`readOnlyMode: true`** — suppresses every state-changing request. Always use it for the first pass
against production. Logging in is exempt, so authenticated testing still works.

**`authProfiles`** — without these, everything is tested as an anonymous visitor and you will find
missing headers and nothing else. `apiLogin` is what lets the access control probe replay one role's
requests as another. Get the field names right: look at your app's login request in the browser's
network tab and copy the exact JSON field names.

**`checks.rateLimitEndpoints`** — throttling is only measured on endpoints you name here, plus the
login from the auth profile. This is deliberate: thirty requests at a one-time-code endpoint costs
the client money per message, and at a password reset it emails a real person. Name the endpoints
where repetition is the attack and nothing else.

A rate limit above the ceiling is **refused**, not clamped, and the policy is not saved. Anything
merely suspect comes back in `warnings` — read them.

---

# Phase 9 — Pre-flight and dry run

### The checklist

**Engagements → Pre-flight checklist.** Every item, by hand. **There is no override.** The things on
it are what stop a run harming someone.

Read the six items and what each one means:

```bash
curl -sS -b /tmp/attestor.jar http://127.0.0.1:8080/engagements/<id>/pre-flight-checklist | jq
```

All six are required and none can be skipped:

| Item | What you are confirming |
| --- | --- |
| `inside-test-window` | The window on file is the one the client agreed to |
| `authorisation-valid-today` | Valid **today**, not only on the start date. Windows expire mid-engagement |
| `dry-run-reviewed` | You have done a dry run and read the target list |
| `rate-limit-suits-target` | Suits *this* target. A staging box on shared hosting is not a production cluster |
| `client-told-if-louder` | The client knows if this run is louder than the last |
| `someone-can-stop-it` | Somebody is available to press the panic stop for the whole run |

One of them is `dry-run-reviewed`, so do the dry run further down this phase **first**, then
come back and tick these.

```bash
curl -sS -b /tmp/attestor.jar -X PUT http://127.0.0.1:8080/engagements/<id>/pre-flight-checklist \
  -H 'content-type: application/json' \
  -d '{
    "inside-test-window": true,
    "authorisation-valid-today": true,
    "dry-run-reviewed": true,
    "rate-limit-suits-target": true,
    "client-told-if-louder": true,
    "someone-can-stop-it": true
  }'
```

Ring the emergency contact before you tick `someone-can-stop-it`. A stop nobody is there to press
is not a control.

### Move the engagement to a runnable state

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/state \
  -H 'content-type: application/json' \
  -d '{"to":"authorised","reason":"signed form on file, asset list diffed, ownership verified"}'
```

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/state \
  -H 'content-type: application/json' \
  -d '{"to":"advancePaid","reason":"invoice INV-2026-031 settled"}'
```

If the advance has not arrived and you have decided to start anyway, the gate can be overridden —
and the reason is recorded against your name:

```bash
  -d '{"to":"advancePaid","advanceGateOverrideReason":"long-standing client, PO issued"}'
```

The authorisation gate has no equivalent and cannot be overridden.

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/state \
  -H 'content-type: application/json' \
  -d '{"to":"readyToRun","reason":"pre-flight complete"}'
```

### Dry run — always first

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/runs \
  -H 'content-type: application/json' \
  -d '{"modules":["recon","web","api"],"dryRun":true}'
```

Every check runs. **No packet is sent.** Read the queued list:

```bash
curl -sS -b /tmp/attestor.jar http://127.0.0.1:8080/queue | jq '.queued'
```

If the targets are not **exactly** what you expected, fix the scope and dry run again. This costs
thirty seconds and catches the mistake that would otherwise be a phone call from an angry client.

---

# Phase 10 — Live run

Tell the client you are starting. Then:

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/runs \
  -H 'content-type: application/json' \
  -d '{"modules":["recon","web","api"],"dryRun":false}'
```

### Watch it

```bash
curl -sS -b /tmp/attestor.jar http://127.0.0.1:8080/queue | jq '.running, .failed'
```

```bash
docker ps --filter label=com.attestor.purpose=engagement-run
```

The console's **Queue** page shows the same thing with the reasons attached.

### Order matters

Run `recon` first and let it finish. The crawler records the endpoints it finds, and the web and API
tools, the access control probe and the personal-data probe all read that list. Running `web` before
anything has been discovered gives you a thin test.

### If something goes wrong

The console has a red **panic stop**. Use it — it records a reason.

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/panic-stop \
  -H 'content-type: application/json' \
  -d '{"scope":"engagement","reason":"client reports 502s on the checkout path"}'
```

From the shell, when the console is unreachable:

```bash
docker kill $(docker ps -q --filter label=com.attestor.purpose=engagement-run)
```

Stops do not expire on their own. Clear it deliberately, with a reason:

```bash
curl -sS -b /tmp/attestor.jar -X DELETE http://127.0.0.1:8080/engagements/<id>/panic-stop \
  -H 'content-type: application/json' \
  -d '{"scope":"engagement","reason":"cause was an unrelated deploy; client confirmed"}'
```

---

# Phase 11 — Triage

Move the engagement on, then open the review queue.

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/state \
  -H 'content-type: application/json' -d '{"to":"triage","reason":"runs complete"}'
```

**Engagements → Triage.** Or:

```bash
curl -sS -b /tmp/attestor.jar http://127.0.0.1:8080/engagements/<id>/review-queue | jq '.total, .byTool'
```

For **every** candidate, do one of two things.

**Confirm it** — but only after you have reproduced it by hand. Not after reading the tool's
description of it.

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/findings/bulk \
  -H 'content-type: application/json' \
  -d '{"findingIds":["<uuid>","<uuid>"],"action":"confirm"}'
```

**Mark it a false positive**, with a reason:

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/findings/<finding-id>/false-positive \
  -H 'content-type: application/json' \
  -d '{"reason":"the header is set by the CDN in front of this origin; verified by hand"}'
```

Those reasons are remembered, so the same wrong result from the same tool does not cost you the same
minute next time.

**Nothing may stay a candidate.** The release gate blocks on it, deliberately.

### Notify critical findings immediately

If you find something critical, telephone the emergency contact **now** — before the report, and
within the notification window written on the authorisation form.

There is no single API call for this, deliberately. Record it in two places a person has to touch:

1. A note on the finding itself, saying who you called, when, and what you told them.

   ```bash
   curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/findings/<finding-id>/evidence \
     -H 'content-type: application/json' \
     -d '{"kind":"note","text":"Telephoned A. Person (CTO) 2026-09-17 11:30 IST. Described the issue and the interim mitigation. They acknowledged."}'
   ```

2. The `critical-notified` item on the report checklist in Phase 13. It is a manual tick with no
   automated check behind it, and release is blocked until you tick it. Ticking it without having
   made the call is you signing your name to something untrue.

---

# Phase 12 — Manual testing

This is what the client is paying for, and no tool does it.

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/state \
  -H 'content-type: application/json' -d '{"to":"manualTesting","reason":"triage complete"}'
```

### Access control, every pair of roles, both directions

With three roles you have six ordered pairs, plus unauthenticated, plus same-role. Work through them
as a grid:

| As | Try to reach | Expect |
| --- | --- | --- |
| user A | admin's pages and admin API routes | refused |
| user A | **user B's** records, by changing an id | refused |
| manager A | admin's pages | refused |
| manager A | **manager B's** records | refused |
| admin A | another tenant's data, if multi-tenant | refused |
| nobody | every authenticated route | refused |

The probe does the mechanical part of this and finds the obvious cases. You are looking for the ones
it cannot: a route that checks *authentication* but not *authorisation*, an id in a POST body rather
than a URL, a role check done in the front end only.

### Business logic

Ten checks in the catalogue, all manual, because they need somebody who understands what the
application is for:

- Workflow bypass — can you skip step 2 and go straight to step 3?
- Price and quantity manipulation — does the server trust a total sent by the browser?
- Coupon and promotion abuse — can one code be used twice, or combined?
- Race conditions — fire two requests at the same moment at anything with a limit.
- Transaction limits — is the limit enforced server-side?
- Payment flow integrity.
- Process timing and ordering.

### Session handling

- Does logout invalidate the session **server-side**, or only clear the cookie? Capture a token, log
  out, replay it.
- Idle and absolute timeouts.
- **Concurrent sessions** — log in as the same user from two browsers. Do both work? Can the user
  see and revoke the other? Does changing the password end the other session? Whether concurrent
  sessions *should* be allowed is a business decision, which is why this is a manual check and not a
  rule — but a password change that leaves other sessions alive is a finding on any application.
- Session fixation — does the session id change when you log in?

### Record what you did

This is what makes the coverage matrix honest. **Engagements → Report → Manual coverage**, one line
per check:

```
web-horizontal-access-control: replayed user A's requests as user B across 34 endpoints, ids mutated
web-concurrent-sessions: two simultaneous sessions confirmed; password change did not end the other
web-price-and-quantity-manipulation: total and unit price altered in the checkout POST; server recalculated
```

A check with no line here and no tool run behind it appears in the report as **not tested**, with a
reason. That is the correct outcome, and it is why the matrix is worth something.

---

# Phase 13 — Write the report

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/state \
  -H 'content-type: application/json' -d '{"to":"reportDraft","reason":"manual testing complete"}'
```

**Engagements → Report.**

### 1. Draft the prose

Press **Draft every section**. It writes the executive summary, headline actions, attack narrative,
positive observations and roadmap from the findings you confirmed.

Everything it writes is an **unapproved draft**. Read each one against the evidence, edit it, then
press **Approve**. Release is blocked until every draft is approved.

If AI is switched off (`AI_ENABLED=false`), the button reports a refusal per section and you type the
prose yourself. The report itself does not need AI at all — findings, evidence, the coverage matrix,
CVSS vectors and the compliance mapping are all generated from what actually ran.

Four sections are **never** drafted, because only you know them: environments, roles and accounts
used, client-imposed constraints, and manual coverage. Fill those in by hand.

### 2. Check the gate

```bash
curl -sS -b /tmp/attestor.jar http://127.0.0.1:8080/engagements/<id>/report/preflight | jq '.blocking, .awaitingHuman'
```

### 3. Tick the three manual items

The ones a machine cannot decide:

```bash
curl -sS -b /tmp/attestor.jar -X PUT http://127.0.0.1:8080/engagements/<id>/report/checklist \
  -H 'content-type: application/json' \
  -d '{"critical-notified":true,"evidence-masked":true,"read-every-line":true}'
```

`read-every-line` is worded as a claim, not a box. Mean it.

### 4. Generate

Press **Generate report**, or:

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/report \
  -H 'content-type: application/json' -d '{"kind":"assessment"}'
```

You get HTML and a PDF. Read the PDF. Then move to review:

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/state \
  -H 'content-type: application/json' -d '{"to":"reportReview","reason":"draft complete"}'
```

---

# Phase 14 — Release, and the client portal

Up to now the client has seen nothing. Releasing is what makes the report appear in their portal.

## 14.1 — Record the balance

The release gate blocks until the balance is recorded.

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/payment \
  -H 'content-type: application/json' \
  -d '{"kind":"balance","amount":92500,"reference":"INV-2026-044"}'
```

## 14.2 — Release the report

In the console: **Engagements → your engagement → Report → Release**. Enter the recipient addresses.

Or:

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/reports/<report-id>/release \
  -H 'content-type: application/json' \
  -d '{"recipients":["cto@northwind.example"]}'
```

Release re-runs the **entire checklist server-side**. A green screen is not the gate; the server is.
If it refuses, the response lists exactly what is blocking.

**Nothing is emailed.** The notification is queued for a person to read and send. Check the queue:

```bash
curl -sS -b /tmp/attestor.jar http://127.0.0.1:8080/notifications | jq
```

Approve it, and mark it sent once you have actually sent it:

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/notifications/<id>/approve
```

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/notifications/<id>/mark-sent
```

Locally, anything the platform does send goes to **Mailpit** rather than a real inbox. Open
**http://localhost:8025** to read what would have gone out. Nothing leaves your machine during
development, which matters because the notification queue holds client-facing drafts.

## 14.3 — Invite the client to the portal

This is a separate step from releasing. Releasing publishes the report; the invitation is what gives
a human an account to read it with.

In the console: **Clients → Northwind Retail → Invite a user.** Or:

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/clients/<client-id>/invitations \
  -H 'content-type: application/json' \
  -d '{"email":"cto@northwind.example","role":"clientOwner"}'
```

The response contains `acceptUrl`, built from `PORTAL_ORIGIN`. Locally:

```
http://localhost:3100/invitation/<token>
```

**It is returned once.** Only a hash is stored and no endpoint reads it back, so copy it now and
send it to the client through a channel you trust. Lost link means a new invitation.

Roles you can invite:

| Role | Can do |
| --- | --- |
| `clientOwner` | Everything, including inviting and deactivating their own colleagues |
| `clientMember` | Read findings and reports, comment, request a retest |

## 14.4 — What the client does, step by step

This is the part to walk a real client through on the phone the first time. It takes about three
minutes.

**Step 1 — they open the link.** `http://localhost:3100/invitation/<token>`. No account needed yet;
the token in the URL is the authorisation. It expires in seven days and is single-use.

**Step 2 — they choose a password.** The form asks for their name, their email address (the one the
invitation was sent to) and a password twice.

**Step 3 — they enrol an authenticator.** The page shows a **base32 key and an `otpauth://` URL**.
There is **no QR code** — tell them to open their authenticator app, choose "enter a setup key
manually", and type the key shown.

**Step 4 — they enter a six-digit code** to prove the authenticator works.

**The account does not exist until step 4 completes.** A second factor a client can postpone is a
second factor a client never enables, so there is no way to skip it.

**Step 5 — they land on the sign-in page** and log in properly for the first time:
email, password, then a six-digit code. Portal login is two calls under the hood, exactly like the
console: the session does nothing until the second factor is satisfied.

**Step 6 — they accept the portal terms.** A one-time screen. Until they accept, the portal shows
the terms and nothing else.

## 14.5 — What the client sees once they are in

**http://localhost:3100**

| Section | Page | What is on it |
| --- | --- | --- |
| Your security | **Dashboard** | Open findings by severity, engagement state, what needs them |
| | **Findings** | Every confirmed finding, with evidence, reproduction steps and the fix |
| | **Reports and documents** | The released report as HTML and PDF, and the attestation letter |
| Working with us | **Retests** | Request a retest once findings are marked fixed |
| | **Questionnaire answers** | Pre-written answers for the security questionnaires their customers send |
| | **Account** | Change password, see active sessions, sign out everywhere, manage colleagues |

They see the released report, every confirmed finding with its evidence, the coverage matrix, and
the attestation letter.

They do **not** see: anything from an unreleased engagement, any candidate finding you discarded,
any other client's data, or the console. The portal API scopes every query to their own client id —
there is a test suite dedicated to exactly that (`portal-scoping.test.ts`).

### Reading and downloading the report

**Reports and documents → the report → View** renders it in the browser.
**Download** streams the PDF.

Every download is recorded. You can see who read what and when:

```bash
docker compose -f infra/docker-compose.yml exec postgres \
  psql -U attestor -d attestor -c "select * from report_download order by created_at desc limit 10;"
```

That record is worth having. "We never received it" is a conversation the log ends.

## 14.6 — Checking the client experience yourself

You cannot easily be both staff and client in one browser — the two surfaces set their own session
cookies on different ports, so they do not actually collide, but it is confusing.

The clean way: open the portal in a **private window** and accept an invitation you sent to an
address you control. That is the client experience exactly, with no shortcuts, and it is worth doing
once before you send a real client a link.

If you want the portal without the whole engagement, the seed builds one:

```bash
docker compose -f infra/docker-compose.yml exec api pnpm --filter @attestor/api seed
```

It prints a line like `open /invitation/<token> on the portal to accept it`. That token is minted
**only on a fresh seed** — if the demo engagement already exists, the seed stops early and mints
nothing. Use 14.3 to issue a new one instead.

## 14.7 — The attestation letter

A one-page letter saying an assessment was performed, by whom, when, and against what. **No finding
detail at all.** This is what the client forwards to their own customers instead of sending somebody
their vulnerability list.

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/attestation-letter
```

It appears in the client's **Reports and documents** page beside the report.

---

# Phase 15 — Retest

Every engagement includes one free retest inside the agreed window. This is the half of the job an
auditor cares most about, because it is the evidence that findings were actually closed.

## 15.1 — The client asks, from the portal

They fix things, then on the portal go to **Findings**, mark the ones they believe are fixed, and
then **Retests → Request a retest**, with a note saying what changed.

The portal checks they are eligible first — there is no point requesting a retest with nothing
marked fixed, and the free window has an end date.

That lands in your console under **Retests**, and in your notification queue.

## 15.2 — You run it

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/state \
  -H 'content-type: application/json' -d '{"to":"retestPending","reason":"client reports fixes deployed"}'
```

Re-run the same modules you ran the first time, with the same policy. Using a different scope or a
lighter policy makes the retest meaningless as evidence.

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/runs \
  -H 'content-type: application/json' \
  -d '{"modules":["recon","web","api"],"dryRun":false}'
```

Then verify each previously-open finding **by hand** and set its status:

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/findings/<finding-id>/confirm \
  -H 'content-type: application/json' \
  -d '{"status":"fixed","note":"Re-tested 2026-10-02. The endpoint now returns 403 for a user outside the tenant."}'
```

A finding is `fixed`, `partiallyFixed` or still `open`. Say which, with a sentence of evidence. "The
client says it is fixed" is not a retest.

## 15.3 — The retest report

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/report \
  -H 'content-type: application/json' -d '{"kind":"retest"}'
```

Release it the same way as Phase 14.2. It appears in the client's portal beside the first report.

This is the document an ISO 27001 or PCI DSS auditor actually wants. ISO 27001 A.8.8 asks to see the
finding, the decision, the fix **and the verification**. Without a retest report, PCI DSS 11.4.4 is
not satisfied at all.

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/state \
  -H 'content-type: application/json' -d '{"to":"retestComplete","reason":"retest report released"}'
```

---

# Phase 16 — Close

Remind the client to rotate the test credentials. Then:

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/state \
  -H 'content-type: application/json' \
  -d '{"to":"closed","reason":"retest complete, client confirmed"}'
```

**Closing destroys the engagement's key salt.** After that no key opens its credentials — not yours,
not an attacker's, not from a backup. It is not reversible.

Evidence is deleted 90 days after release, automatically, and the client gets a written deletion
confirmation:

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/deletion-confirmation \
  -H 'content-type: application/json' \
  -d '{"evidenceObjects":412,"credentialSets":6}'
```

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

Useful one-liners:

```bash
curl -sS -b /tmp/attestor.jar 'http://127.0.0.1:8080/audit/refusals?sinceDays=7' | jq
```

```bash
curl -sS -b /tmp/attestor.jar http://127.0.0.1:8080/settings | jq '.tools[] | select(.runnable == false)'
```

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
