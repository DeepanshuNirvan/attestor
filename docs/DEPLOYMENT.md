# Deployment and hosting

How to get both halves live, with the exact commands. Provisioning detail — server hardening,
WireGuard, backups, key rotation — is in `docs/RUNBOOK.md`; this document is the deploy path.

Two things are hosted in completely different ways, on purpose:

| | Marketing website | The platform |
| --- | --- | --- |
| Where | A static CDN | One VPS in India |
| What runs | Nothing | Postgres, Redis, MinIO, two APIs, two UIs, a worker |
| If it is compromised | A page is defaced | Everything |
| Cost | Free tier | ₹3,000–6,000 a month |

---

## 1. The marketing website

### 1.1 Run it locally

```bash
pnpm install
```

```bash
pnpm --filter @attestor/website dev
```

Opens on <http://localhost:4321>. Edits reload. Content lives in
`apps/website/src/content/` and data in `apps/website/src/data/`.

### 1.2 Build it

```bash
pnpm --filter @attestor/website build
```

Two things happen: Astro writes static files to `apps/website/dist`, then Pagefind indexes them into
`dist/_pagefind`. The build also writes `dist/_headers`, containing a Content-Security-Policy whose
hashes were computed from the HTML that was just produced.

Check the output before shipping it:

```bash
pnpm --filter @attestor/website preview
```

### 1.3 Host it on Cloudflare Pages — the recommended path

`_headers` is a Cloudflare Pages file, which is why this is the default.

**One-off setup**

```bash
npm install -g wrangler
wrangler login
wrangler pages project create attestor --production-branch main
```

**Every deploy**

```bash
pnpm --filter @attestor/website build
wrangler pages deploy apps/website/dist --project-name attestor
```

Then in the Cloudflare dashboard: **Workers & Pages → attestor → Custom domains**, add
`attestorsecurity.com` and `www.attestorsecurity.com`. TLS and HTTP/3 are automatic.

Turn off what you do not need: Web Analytics off (it injects a script your CSP will block, and you
do not need to track visitors to sell an audit), Email Obfuscation off, Rocket Loader **off** — it
rewrites scripts and breaks a hash-based CSP.

**Deploy on push instead**, if you prefer:

- Build command: `pnpm install --frozen-lockfile && pnpm --filter @attestor/website build`
- Build output directory: `apps/website/dist`
- Root directory: `/`
- Environment variable: `NODE_VERSION=22`

### 1.4 Host it somewhere else

**Netlify** — `_headers` works identically. Publish directory `apps/website/dist`.

**S3 + CloudFront** — `_headers` does **not** work. You must set the same headers on a CloudFront
response-headers policy by hand, and re-check the CSP hashes after every content change. Doable, but
it is the option that will eventually ship a stale policy.

```bash
aws s3 sync apps/website/dist s3://attestorsecurity.com --delete
aws cloudfront create-invalidation --distribution-id ABC123 --paths '/*'
```

**Your own VPS with Caddy** — fine, but put it on a *different* machine from the platform. The whole
point of a static marketing site is that its compromise reaches nothing.

### 1.5 After the first deploy

```bash
curl -sSI https://attestorsecurity.com | grep -i 'content-security\|strict-transport\|x-content-type\|referrer'
```

Then run it through <https://securityheaders.com>. Target A+. A security firm whose own site scores
a B has an awkward first meeting.

Confirm the extras exist:

```bash
curl -sS https://attestorsecurity.com/robots.txt
curl -sS https://attestorsecurity.com/sitemap-index.xml | head -5
curl -sS https://attestorsecurity.com/rss.xml | head -5
```

---

## 2. The platform

### 2.1 What you need

- A VPS in Mumbai or Bangalore: 8 vCPU, 16 GB RAM, 200 GB SSD, Ubuntu 24.04.
- **A static IPv4 address.** Clients allowlist it and it goes on every authorisation form. Changing
  it means re-issuing every authorisation.
- A domain with `portal.` pointed at that address.

Provision and harden it first: `docs/RUNBOOK.md` §1.

### 2.2 Configure

```bash
git clone <repository> /opt/attestor
cd /opt/attestor
cp infra/.env.example infra/.env
```

Generate the secrets. Nothing has a working default:

```bash
openssl rand -base64 32   # POSTGRES_PASSWORD
openssl rand -base64 32   # PORTAL_DB_PASSWORD
openssl rand -base64 32   # REDIS_PASSWORD
openssl rand -base64 32   # MINIO_ROOT_PASSWORD
openssl rand -base64 32   # SESSION_SECRET
```

The two crypto keys need libsodium-shaped 32 bytes:

```bash
node -e "import('libsodium-wrappers-sumo').then(async s=>{await s.default.ready;console.log(s.default.to_base64(s.default.randombytes_buf(32),s.default.base64_variants.ORIGINAL))})"
```

Run it twice: once for `VAULT_MASTER_KEY`, once for `PORTAL_TOTP_KEY`.

**Back both keys up somewhere that is not the server, before you go any further.** Losing
`VAULT_MASTER_KEY` makes every stored credential unrecoverable — which is the design working, and no
comfort at all when it happens by accident.

Set the rest:

```
EGRESS_IP=<the VPS static address>
CONSOLE_ORIGIN=http://10.88.0.1:3000
PORTAL_ORIGIN=https://portal.attestorsecurity.com
API_BIND_ADDRESS=127.0.0.1
PORTAL_BIND=0.0.0.0
NODE_ENV=production
```

### 2.3 Bring it up

```bash
docker compose -f infra/docker-compose.yml up -d --build
```

Seven services: `postgres`, `redis`, `minio`, `api`, `portal-api`, `console`, `portal`, plus
one-shot `migrate` and `minio-init`. Migrations run automatically as a dependency of the API.

```bash
docker compose -f infra/docker-compose.yml ps
docker compose -f infra/docker-compose.yml logs -f api
```

### 2.4 Pin the tool images

```bash
node scripts/pin-tool-images.mjs --pull
```

Pulls all 41 images and writes `infra/tool-images.lock.json`. **Until this has run, no tool will
start** — the runner refuses any image without a pinned digest, because a report that names a tool
version has to mean it. Expect 20–40 GB of pulls and a long first run.

Commit the lock file. Re-run it deliberately, in a batch, never mid-engagement.

### 2.5 Create your account

```bash
curl -sS -X POST http://127.0.0.1:8080/auth/bootstrap \
  -H 'content-type: application/json' \
  -d '{"email":"you@attestorsecurity.com","name":"Your name","password":"a-long-passphrase"}'
```

Returns an `otpauthUrl` **once**. Add it to your authenticator, then confirm:

```bash
curl -sS -X POST http://127.0.0.1:8080/auth/bootstrap/confirm \
  -H 'content-type: application/json' \
  -d '{"email":"you@attestorsecurity.com","code":"123456"}'
```

`/auth/bootstrap` works exactly once. After that it returns 409 and everyone else arrives by
invitation.

### 2.6 TLS for the portal

Only the portal faces the internet. Caddy, in `/etc/caddy/Caddyfile`:

```
portal.attestorsecurity.com {
	encode zstd gzip
	reverse_proxy localhost:3100
	header {
		Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
		X-Content-Type-Options "nosniff"
		Referrer-Policy "strict-origin-when-cross-origin"
		-Server
	}
}
```

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

**Do not add a Content-Security-Policy here.** The application issues one with a per-request nonce;
a second policy at the proxy intersects with it, strips the nonce, and breaks every script on the
page. That exact bug has already been found once in this codebase.

### 2.7 Verify

```bash
curl -sS http://127.0.0.1:8080/health
curl -sS http://127.0.0.1:8081/health
curl -sSI https://portal.attestorsecurity.com | head -20
```

The console API must **not** answer from outside:

```bash
curl -sS --max-time 5 http://<public-ip>:8080/health   # must fail
```

If that succeeds, stop and fix the bind address before anything real touches this machine.

### 2.8 Start on boot

```ini
# /etc/systemd/system/attestor.service
[Unit]
Description=Attestor platform
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/attestor
ExecStart=/usr/bin/docker compose -f infra/docker-compose.yml up -d
ExecStop=/usr/bin/docker compose -f infra/docker-compose.yml down

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now attestor
```

---

## 3. Updating

```bash
cd /opt/attestor
git pull
pnpm install --frozen-lockfile
pnpm check
docker compose -f infra/docker-compose.yml up -d --build
```

`pnpm check` before the rebuild, not after. If lint, typecheck, tests or the claim check fail, the
deploy stops there.

**Before a migration that is not reversible**, take a backup *and restore it somewhere* — a backup
that has never been restored is a hypothesis. Read every migration that drops a column twice.

### 3.1 Rolling back

```bash
git log --oneline -10
git checkout <previous-sha>
docker compose -f infra/docker-compose.yml up -d --build
```

Code rolls back cleanly. **A migration does not.** If the release included one, restore the database
from the pre-migration backup — `docs/RUNBOOK.md` §3.3.

---

## 4. Zero to first client, in order

- [ ] VPS provisioned and hardened — `docs/RUNBOOK.md` §1
- [ ] WireGuard up, staff device enrolled
- [ ] DNS: A records, SPF, DKIM, DMARC at `p=none`, CAA — `docs/RUNBOOK.md` §2
- [ ] Website deployed, headers A+ on securityheaders.com
- [ ] `infra/.env` complete, both crypto keys backed up **off the server**
- [ ] Compose stack up, health checks green
- [ ] Console API confirmed unreachable from the internet
- [ ] `pin-tool-images.mjs --pull` run, lock file committed
- [ ] Staff account created, authenticator enrolled
- [ ] Caddy serving the portal over TLS with HSTS
- [ ] Nightly backup script installed and its first restore tested
- [ ] Integration suite run once against the vulnerable stack
- [ ] **Legal blocks reviewed by a lawyer**, `lawyerReviewedAt` set
- [ ] DMARC moved to `p=reject` after two weeks of clean reports
- [ ] A dry run performed against your own infrastructure, end to end, before any client's

That last one matters more than it looks. Be your own first client: run the full flow against your
own website and portal, produce a real report, read it, and fix what embarrasses you. It is the
cheapest quality bar available, and the resulting report is a genuine sample.
