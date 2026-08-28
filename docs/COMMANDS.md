# Command reference

Every command, with what it does and when you want it. The second half is a whole engagement driven
by `curl`, which is also the fastest way to understand what the console is doing on your behalf.

---

## 1. Development

```bash
pnpm install
```

```bash
pnpm --filter @attestor/website dev
```
Marketing site on <http://localhost:4321>.

```bash
pnpm --filter @attestor/console dev
```
Console or portal on <http://localhost:3000>, depending on `ATTESTOR_SURFACE`. For local work put it
in `apps/console/.env.local` (gitignored):

```
ATTESTOR_SURFACE=console
ATTESTOR_API_URL=http://127.0.0.1:8080
ATTESTOR_PORTAL_API_URL=http://127.0.0.1:8081
```

Change it to `portal` and restart to work on the other surface. The two are the same code and never
run from the same process.

```bash
pnpm --filter @attestor/api dev
```
Console API with `--watch`. `pnpm --filter @attestor/api start:portal` for the portal API,
`pnpm --filter @attestor/api worker` for the job worker.

```bash
pnpm -r --parallel dev
```
Everything at once.

---

## 2. The gate

```bash
pnpm check
```
Lint, typecheck, tests, claim check. Run it before every commit and before every deploy.

Individually:

```bash
pnpm lint
```
```bash
pnpm typecheck
```
```bash
pnpm exec tsc -p tsconfig.json --noEmit
```
The last one covers the root project — `vitest.config.ts`, `eslint.config.js`, `infra/*.ts` — which
`pnpm typecheck` does not, because those files belong to no workspace package.

```bash
pnpm test
```
334 unit and property tests, about seven seconds.

```bash
pnpm test -- packages/core
```
One package.

```bash
npx vitest run packages/core/src/scope/hostname.test.ts
```
One file.

```bash
pnpm test:watch
```

```bash
pnpm check:claims
```
Fails on any first-person claim of CERT-In empanelment, CREST accreditation, ISO certification of
the firm, a guarantee of security, or a promise to certify a system as secure. This is a build
failure rather than a review habit because the cost of getting it wrong is not a bug.

```bash
pnpm format
```

---

## 3. Integration tests

They need the deliberately vulnerable targets, and they refuse to start without the flag that says
those targets are up.

```bash
docker compose -f infra/docker-compose.test.yml up -d --wait
```

```bash
ATTESTOR_TEST_NETWORK_ONLY=1 pnpm test:integration
```

```bash
ATTESTOR_TEST_NETWORK_ONLY=1 pnpm test:integration -- xss-corpus
```
The XSS suite alone — no Docker needed for that one, it only needs Chromium.

```bash
docker compose -f infra/docker-compose.test.yml down -v
```

The targets sit on a network with `internal: true`, so a container on it has no route off the
machine, and the suite installs a guard that throws on any host outside the allow-list. A scanner
integration test that reaches a live host is an unauthorised scan.

---

## 4. Database

```bash
docker compose -f infra/docker-compose.yml exec api pnpm --filter @attestor/api migrate
```

```bash
docker compose -f infra/docker-compose.yml exec api pnpm --filter @attestor/api seed
```
One client, one engagement in `reportDraft` with findings confirmed and prose written, plus a portal
invitation link in the log. Idempotent.

```bash
docker compose -f infra/docker-compose.yml exec postgres psql -U attestor -d attestor
```

```bash
docker compose -f infra/docker-compose.yml exec postgres \
  psql -U attestor -d attestor -c 'select action, count(*) from audit_log group by action order by 2 desc;'
```

---

## 5. Tools

```bash
node scripts/pin-tool-images.mjs --pull
```
Pulls every image and writes `infra/tool-images.lock.json`. Without it, nothing runs.

```bash
node scripts/pin-tool-images.mjs
```
Re-reads digests already present locally, without pulling.

```bash
docker ps --filter label=com.attestor.purpose=engagement-run
```
What is running right now.

```bash
docker kill $(docker ps -q --filter label=com.attestor.purpose=engagement-run)
```
**The panic stop from the shell**, when the console is unreachable. Use the console's red control
when it is — that one records a reason.

---

## 6. Keys

Both rotations need the old and new keys present at once, and both are documented step by step in
`docs/RUNBOOK.md` §4.

```bash
VAULT_MASTER_KEY_PREVIOUS=<old> VAULT_MASTER_KEY=<new> \
  docker compose -f infra/docker-compose.yml exec api \
  node --experimental-strip-types apps/api/src/db/rewrap-credentials.ts
```

```bash
PORTAL_TOTP_KEY_PREVIOUS=<old> PORTAL_TOTP_KEY=<new> \
  docker compose -f infra/docker-compose.yml exec api \
  node --experimental-strip-types apps/api/src/db/rewrap-totp-secrets.ts
```

Both stop on the first row that will not open and change nothing further. Sign in as a test user
before you walk away — a rotation that silently failed looks exactly like one that worked.

---

## 7. Reports

```bash
pnpm --filter @attestor/report generate:sample
```
Regenerates the golden sample report against the Juice Shop fixture. Read the diff by eye; it is the
document a prospect will judge you on.

---

## 8. A whole engagement, by hand

Everything the console does, as HTTP. Useful for scripting, for understanding, and for the day the
UI is broken and a client is waiting.

### 8.1 Sign in

```bash
curl -sS -c /tmp/attestor.jar -X POST http://127.0.0.1:8080/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"you@attestorsecurity.com","password":"your-passphrase"}'
```

```bash
curl -sS -b /tmp/attestor.jar -c /tmp/attestor.jar -X POST http://127.0.0.1:8080/auth/mfa \
  -H 'content-type: application/json' \
  -d '{"code":"123456"}'
```

The session does nothing until the second factor is satisfied. Every call below sends
`-b /tmp/attestor.jar`.

### 8.2 Create the client

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/clients \
  -H 'content-type: application/json' \
  -d '{
    "name": "Northwind Retail",
    "legalName": "Northwind Retail Private Limited",
    "country": "IN",
    "contacts": [
      { "name": "A. Person", "email": "ciso@northwind.example", "role": "CISO",
        "phone": "+91 90000 00000", "isEmergencyContact": true }
    ],
    "billingDetails": { "gstin": "29ABCDE1234F1Z5", "currency": "INR", "paymentTermsDays": 15 }
  }'
```

Returns the client, with its `id`.

### 8.3 Create the engagement

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements \
  -H 'content-type: application/json' \
  -d '{
    "clientId": "<client-uuid>",
    "title": "External web application and API assessment",
    "type": "webApplication",
    "timezone": "Asia/Kolkata",
    "currency": "INR",
    "quotedAmount": 185000,
    "profileId": "standard-web-app"
  }'
```

`profileId` loads that profile as the engagement's starting policy. The reference — `ATT-2026-014` —
is generated and is what the client will quote for years.

### 8.4 Enter the scope

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/scope \
  -H 'content-type: application/json' \
  -d '{
    "items": [
      { "kind": "domain", "value": "app.northwind.example",     "included": true },
      { "kind": "domain", "value": "*.staging.northwind.example","included": true },
      { "kind": "url",    "value": "https://api.northwind.example/v2", "included": true },
      { "kind": "domain", "value": "mail.northwind.example",     "included": false },
      { "kind": "path",   "value": "/admin/billing",             "included": false }
    ]
  }'
```

`*.staging.northwind.example` matches `app.staging.northwind.example` but **not**
`staging.northwind.example`. If you want the apex, add it as its own item.

### 8.5 Record the authorisation

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/authorisation \
  -H 'content-type: application/json' \
  -d '{
    "signedBy": "A. Person",
    "signerRole": "Chief Technology Officer",
    "signerEmail": "cto@northwind.example",
    "signedAt": "2026-08-18T09:00:00Z",
    "documentObjectKey": "authorisations/ATT-2026-014.pdf",
    "documentSha256": "3b1f...64 hex chars...9ac2",
    "assetList": ["app.northwind.example", "*.staging.northwind.example", "api.northwind.example"],
    "exclusionList": ["mail.northwind.example"],
    "sourceAddresses": ["203.0.113.10"],
    "emergencyContact": {
      "name": "A. Person", "role": "CTO",
      "phone": "+91 90000 00000", "email": "cto@northwind.example"
    },
    "criticalNotificationHours": 24,
    "validFrom": "2026-08-24T00:00:00Z",
    "validUntil": "2026-09-24T00:00:00Z"
  }'
```

The response includes a **diff between the asset list in the signed document and the scope you
entered**. Read it. That diff is the cheapest protection you have against testing something nobody
signed for.

### 8.6 Credentials, through the vault

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/credential-link \
  -H 'content-type: application/json' \
  -d '{"label":"Standard user","roleName":"user","expiresInHours":72}'
```

Send the returned one-time link to the client. Credentials never arrive by email or chat, and no
route in this API returns a credential value.

### 8.7 Adjust the policy

```bash
curl -sS -b /tmp/attestor.jar -X PUT http://127.0.0.1:8080/engagements/<id>/policy \
  -H 'content-type: application/json' \
  --data-binary @- <<'JSON'
{"yaml": "modules: [recon, web, api]\nintensity: thorough\nreadOnlyMode: true\nrateLimits:\n  globalRequestsPerSecond: 4\n  politeMode: true\n"}
JSON
```

Returns any warnings — a value clamped to a ceiling comes back as a warning rather than an error, so
you find out before the run rather than during it. `docs/POLICY-COOKBOOK.md` has the full reference.

### 8.8 Move to a runnable state

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/state \
  -H 'content-type: application/json' \
  -d '{"to":"authorised","reason":"signed form on file, asset list diffed"}'
```

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/state \
  -H 'content-type: application/json' \
  -d '{"to":"advancePaid","reason":"invoice INV-2026-031 settled"}'
```

If the advance has not arrived and you have decided to start anyway:

```bash
  -d '{"to":"advancePaid","advanceGateOverrideReason":"long-standing client, PO issued"}'
```

That reason is recorded against your name. The authorisation gate has no equivalent and cannot be
overridden.

### 8.9 Dry run — always first

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/runs \
  -H 'content-type: application/json' \
  -d '{"modules":["recon","web","api"],"dryRun":true}'
```

Every check runs. No packet is sent. Read the queued list: if the targets are not exactly what you
expected, fix the scope and do it again.

### 8.10 Live run

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/runs \
  -H 'content-type: application/json' \
  -d '{"modules":["recon","web","api"],"dryRun":false}'
```

Watch it:

```bash
curl -sS -b /tmp/attestor.jar http://127.0.0.1:8080/queue | jq '.running, .failed'
```

### 8.11 Stop everything

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/panic-stop \
  -H 'content-type: application/json' \
  -d '{"scope":"engagement","reason":"client reports 502s on the checkout path"}'
```

`"scope":"platform"` stops every engagement. Clear it deliberately, with a reason — stops do not
expire on their own, because "it timed out" is not a decision anybody made:

```bash
curl -sS -b /tmp/attestor.jar -X DELETE http://127.0.0.1:8080/engagements/<id>/panic-stop \
  -H 'content-type: application/json' \
  -d '{"scope":"engagement","reason":"cause was an unrelated deploy; client confirmed"}'
```

### 8.12 Triage

```bash
curl -sS -b /tmp/attestor.jar http://127.0.0.1:8080/engagements/<id>/review-queue | jq '.total, .byTool'
```

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/findings/bulk \
  -H 'content-type: application/json' \
  -d '{"findingIds":["<uuid>","<uuid>"],"action":"confirm"}'
```

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/findings/<finding-id>/false-positive \
  -H 'content-type: application/json' \
  -d '{"reason":"the header is set by the CDN in front of this origin; verified by hand"}'
```

False-positive reasons are remembered, so the same wrong result from the same tool does not cost you
the same minute next time.

### 8.13 Write and release the report

```bash
curl -sS -b /tmp/attestor.jar -X PUT \
  http://127.0.0.1:8080/engagements/<id>/report/sections/executiveSummary \
  -H 'content-type: application/json' \
  -d '{"markdown":"Two paragraphs that stand alone...\n\nSecond paragraph."}'
```

```bash
curl -sS -b /tmp/attestor.jar http://127.0.0.1:8080/engagements/<id>/report/preflight | jq '.blocking, .awaitingHuman'
```

```bash
curl -sS -b /tmp/attestor.jar -X PUT http://127.0.0.1:8080/engagements/<id>/report/checklist \
  -H 'content-type: application/json' \
  -d '{"critical-notified":true,"evidence-masked":true,"read-every-line":true}'
```

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/report \
  -H 'content-type: application/json' -d '{"kind":"assessment"}'
```

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/reports/<report-id>/release \
  -H 'content-type: application/json' \
  -d '{"recipients":["ciso@northwind.example"]}'
```

Release runs the full checklist **server-side**. If it refuses, the response lists exactly what is
blocking. Nothing is emailed: the notification is queued for a person to read and send.

### 8.14 Invite the client to the portal

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/clients/<client-id>/invitations \
  -H 'content-type: application/json' \
  -d '{"email":"ciso@northwind.example","role":"clientOwner"}'
```

Returns `acceptUrl` **once**. Only a hash is stored and no endpoint reads it back, so send it
yourself. Lost link means a new invitation, which is the correct trade.

### 8.15 Close it

```bash
curl -sS -b /tmp/attestor.jar -X POST http://127.0.0.1:8080/engagements/<id>/state \
  -H 'content-type: application/json' \
  -d '{"to":"closed","reason":"retest complete, client confirmed"}'
```

Closing destroys the engagement's key salt. After that no key opens its credentials — not yours, not
an attacker's, not from a backup.

---

## 9. Quick answers

| Question | Command |
| --- | --- |
| Is anything running? | `docker ps --filter label=com.attestor.purpose=engagement-run` |
| Why did a run fail? | `curl -sS -b jar :8080/queue \| jq .failed` |
| What was refused this week, and why? | `curl -sS -b jar ':8080/audit/refusals?sinceDays=7' \| jq` |
| Who downloaded that report? | `select * from report_download where report_id = '<id>';` |
| Which tools cannot run? | `curl -sS -b jar :8080/settings \| jq '.tools[] \| select(.runnable == false)'` |
| Is a legal block still unreviewed? | `curl -sS -b jar :8080/settings \| jq .legal.unreviewed` |
| What has AI cost this month? | `curl -sS -b jar :8080/settings \| jq .aiUsage` |
