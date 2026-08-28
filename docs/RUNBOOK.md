# Runbook

Operational procedures for Attestor Console. Written for the person on call at 2am, which means
every procedure states what to do, in order, with the commands. Where a step is dangerous it says
so before the command rather than after it.

Everything below assumes a single VPS. That is the deliberate architecture: one machine, one fixed
egress address, one place to look. Scaling out is a decision for later and is discussed at the end.

---

## 1. Provisioning a new server

### 1.1 What to buy

A VPS in India (Mumbai or Bangalore) with:

- 8 vCPU, 16 GB RAM, 200 GB SSD — enough to run the platform plus two concurrent tool containers.
  ZAP alone is allowed 4 GB.
- A **static IPv4 address**. This is not optional. Clients allowlist it, and it goes on every
  authorisation form. Changing it means re-issuing every authorisation.
- Ubuntu 24.04 LTS.

Record the address in `EGRESS_IP` and in the client-facing onboarding pack. If the provider ever
migrates the instance and the address changes, treat that as an incident: see §7.

### 1.2 Base hardening

```bash
adduser --disabled-password --gecos "" attestor
usermod -aG sudo attestor
install -d -m 700 -o attestor -g attestor /home/attestor/.ssh
```

Copy your public key into `/home/attestor/.ssh/authorized_keys`, then in `/etc/ssh/sshd_config`:

```
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowUsers attestor
```

```bash
systemctl restart ssh
```

Firewall. The console API and the console UI are **never** exposed to the internet; they are
reached over WireGuard. Only the portal and its API face the world.

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 51820/udp comment 'WireGuard'
ufw allow 443/tcp comment 'portal'
ufw allow 80/tcp comment 'ACME only'
ufw limit 22/tcp comment 'SSH'
ufw enable
```

Automatic security updates:

```bash
apt install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
```

### 1.3 WireGuard

The console is only reachable through it. Server config at `/etc/wireguard/wg0.conf`:

```
[Interface]
Address = 10.88.0.1/24
ListenPort = 51820
PrivateKey = <server private key>

[Peer]
# One block per staff device. No shared keys.
PublicKey = <device public key>
AllowedIPs = 10.88.0.2/32
```

```bash
systemctl enable --now wg-quick@wg0
```

Then bind the console services to the WireGuard address, not to `0.0.0.0`. `API_BIND_ADDRESS`
defaults to `127.0.0.1` and the API refuses to start on `0.0.0.0` — that check exists because this
is the single mistake that would expose every client's engagement data.

### 1.4 Docker

```bash
curl -fsSL https://get.docker.com | sh
usermod -aG docker attestor
```

Adding `attestor` to the `docker` group is equivalent to giving it root. That is accepted here
because the platform's whole job is to start containers, and the mitigation is that exactly one
module can do it — `packages/core/src/runner/container-runner.ts`, enforced by a lint rule and by
`packages/core/src/architecture.test.ts`.

### 1.5 The application

```bash
git clone <repository> /opt/attestor
cd /opt/attestor
cp infra/.env.example infra/.env
```

Fill in every value in `infra/.env`. None of them has a working default; that is deliberate.
Generate secrets with the commands written at the top of the file.

```bash
docker compose -f infra/docker-compose.yml up -d --build
docker compose -f infra/docker-compose.yml exec api pnpm --filter @attestor/api migrate
node scripts/pin-tool-images.mjs --pull
```

`pin-tool-images.mjs` writes `infra/tool-images.lock.json`. **Until it has run, no tool will
start**: the runner refuses any image without a pinned digest, because a report that names a tool
version has to mean it.

### 1.6 TLS and the reverse proxy

Caddy is the least work and gets the headers right:

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

The application sets its own Content-Security-Policy; do not add a second one at the proxy, because
two policies intersect and the result is rarely what either author intended.

---

## 2. DNS and mail

### 2.1 Records

| Name | Type | Value | Note |
| --- | --- | --- | --- |
| `attestorsecurity.com` | A | static site host | The marketing site is static; a CDN is fine. |
| `portal.attestorsecurity.com` | A | VPS address | The only service on the VPS facing the internet. |
| `attestorsecurity.com` | MX | provider | |
| `attestorsecurity.com` | TXT | `v=spf1 include:<provider> -all` | `-all`, not `~all`. |
| `_dmarc` | TXT | `v=DMARC1; p=reject; rua=mailto:dmarc@attestorsecurity.com; adkim=s; aspf=s` | |
| `<selector>._domainkey` | TXT | provider DKIM key | |
| `attestorsecurity.com` | CAA | `0 issue "letsencrypt.org"` | |

### 2.2 Getting to `p=reject` without losing mail

Do not start at `p=reject`. The sequence is:

1. `p=none` with `rua` reporting. Wait two weeks. Read the aggregate reports.
2. Fix every legitimate source that fails alignment — the CRM, the invoicing tool, the mail
   provider's own bounce address.
3. `p=quarantine; pct=25`, then 50, then 100. Wait a week between each.
4. `p=reject`.

A security firm whose own DMARC record is `p=none` has an awkward conversation ahead of it every
time it writes that finding in a client report. Get to `reject`.

---

## 3. Backup and restore

### 3.1 What is backed up

| Data | Where | Backed up | Recovery point |
| --- | --- | --- | --- |
| Postgres | `postgres-data` volume | Nightly `pg_dump`, encrypted, off-site | 24 hours |
| Evidence and reports | MinIO buckets | Nightly, encrypted, off-site | 24 hours |
| `VAULT_MASTER_KEY` | `infra/.env` | **Manually, separately, offline** | On change |
| `PORTAL_TOTP_KEY` | `infra/.env` | **Manually, separately, offline** | On change |
| Engagement salts | Postgres | With the database | 24 hours |

### 3.2 Nightly backup

```bash
#!/usr/bin/env bash
set -euo pipefail
stamp=$(date -u +%Y%m%dT%H%M%SZ)
cd /opt/attestor

docker compose -f infra/docker-compose.yml exec -T postgres \
  pg_dump -U attestor -Fc attestor \
  | age -r "$BACKUP_AGE_RECIPIENT" > "/var/backups/attestor/db-$stamp.dump.age"

docker compose -f infra/docker-compose.yml exec -T minio \
  mc mirror --quiet local/attestor-evidence "/var/backups/attestor/evidence-$stamp"

find /var/backups/attestor -mtime +30 -delete
```

The database dump is encrypted **before** it leaves the process, with a key the backup host does
not hold. A backup of an evidence store is an evidence store.

### 3.3 Restore

```bash
age -d -i /path/to/identity db-<stamp>.dump.age > /tmp/restore.dump
docker compose -f infra/docker-compose.yml exec -T postgres \
  pg_restore -U attestor -d attestor --clean --if-exists < /tmp/restore.dump
shred -u /tmp/restore.dump
```

Then verify before telling anyone it worked:

```bash
docker compose -f infra/docker-compose.yml exec api node --experimental-strip-types \
  -e "import('./apps/api/src/db/client.ts').then(async m => { const rows = await m.database.execute('select count(*) from engagement'); console.log(rows); })"
```

**Restoring the database without `VAULT_MASTER_KEY` gives you engagement records with no readable
credentials.** That is the design working, not a failure. The key is backed up separately for
exactly this reason, and it is the one thing that must never be in the same place as the database.

### 3.4 Testing the restore

Quarterly, on a scratch VPS, from the off-site copy only. A backup that has never been restored is
a hypothesis. Record the date in `docs/DECISIONS.md`.

---

## 4. Key rotation

### 4.1 `SESSION_SECRET`

Rotating it invalidates every session. Do it during a quiet hour and tell the team first.

```bash
openssl rand -base64 32   # put in infra/.env
docker compose -f infra/docker-compose.yml up -d api portal-api
```

### 4.2 `VAULT_MASTER_KEY`

This is the dangerous one. Every stored client credential is encrypted under a subkey derived from
it. Rotating it requires re-wrapping every credential, which means decrypting with the old key and
encrypting with the new one in a single pass, with both keys present.

1. Announce a maintenance window. No runs may be in flight.
2. Back up the database and verify the backup restores.
3. Set `VAULT_MASTER_KEY_PREVIOUS` to the current key and `VAULT_MASTER_KEY` to the new one.
4. Run the re-wrap:

   ```bash
   docker compose -f infra/docker-compose.yml exec api \
     node --experimental-strip-types apps/api/src/db/rewrap-credentials.ts
   ```

5. Confirm the count of re-wrapped rows matches the count of stored credentials.
6. Remove `VAULT_MASTER_KEY_PREVIOUS`. Restart. Store the new key in the offline backup.

If step 4 fails halfway, do not improvise — restore from step 2 and start again. A partially
re-wrapped vault has credentials that no key opens.

### 4.3 `PORTAL_TOTP_KEY`

Client authenticator secrets are sealed under this key. Rotating it without re-wrapping them locks
every client out of the portal — their password still works and their second factor never will,
which looks exactly like an attack from where they are sitting.

Same shape as the vault rotation: both keys present, one pass, verified counts.

1. Announce a maintenance window.
2. Back up the database and verify the backup restores.
3. Set `PORTAL_TOTP_KEY_PREVIOUS` to the current key and `PORTAL_TOTP_KEY` to the new one.
4. Run the re-wrap:

   ```bash
   docker compose -f infra/docker-compose.yml exec api      node --experimental-strip-types apps/api/src/db/rewrap-totp-secrets.ts
   ```

5. Remove `PORTAL_TOTP_KEY_PREVIOUS`. Restart the portal API. Store the new key offline.
6. **Sign in as a test client before you walk away.** A rotation that silently failed looks
   identical to a rotation that worked until the first client tries to sign in.

### 4.4 Database roles

`attestor_portal` is a least-privilege role created by migration `0001`. Rotate its password with:

```sql
ALTER ROLE attestor_portal WITH LOGIN PASSWORD '<new>';
```

Update `PORTAL_DB_PASSWORD` and restart `portal-api`. The console API keeps its own role; the two
must never share a password, because the point of the split is that a portal compromise cannot
write to engagement data.

### 4.5 Client credentials

Stored credentials belong to the client, not to us. Rotate them **at the client's end** at the end
of every engagement, and record the date. Our copy is destroyed with the engagement's evidence.

---

## 5. Adding a tool adapter

The whole point of the adapter contract is that this list is short.

1. Add the image to `packages/core/src/runner/tool-images.ts` — id, image, tag, modules, purpose,
   timeout, memory, whether it needs a writable `/tmp`.
2. Run `node scripts/pin-tool-images.mjs --pull`. Without a digest the tool will not start.
3. Write `packages/scanners/src/adapters/<tool>.ts` implementing `ScannerAdapter`:
   - `buildInvocation` returns the command, any input files, and the output filename.
   - `parse` is a **pure function over a string**. No network, no clock, no filesystem.
   - `coversCheckIds` lists the catalogue checks it contributes to. This is what makes the coverage
     matrix honest, so be conservative: claim only what the tool actually tests.
4. Register it in `packages/scanners/src/index.ts`.
5. Save a real sample of the tool's output in `packages/scanners/src/fixtures/tool-output.ts` and
   write tests against it. Include a hostile sample: empty output, `{}`, truncated JSON, a field
   that is a string where the schema says array. The gitleaks adapter shipped a crash because
   nobody had tried `{}`.
6. Confirm the command contains no flag that could produce load beyond the policy ceiling. The
   adapter test suite asserts this for every adapter; a new tool must pass it.

Rate limits come from the resolved policy, never from the adapter. An adapter that hardcodes a
thread count is a bug.

## 6. Adding a report template

1. Add the template id to the report data model and the section list in
   `apps/console/src/app/engagements/[id]/report/page.tsx`.
2. Add the rendering in `packages/report/src/render.ts`. Every interpolation goes through
   `escapeHtml`. There is no exception to this: evidence is attacker-controlled text.
3. Regenerate the golden file and read the diff by eye:

   ```bash
   pnpm --filter @attestor/report generate:sample
   ```

4. Run the XSS corpus against it:

   ```bash
   ATTESTOR_TEST_NETWORK_ONLY=1 pnpm test:integration -- xss-corpus
   ```

5. If the template contains legal wording, add it to `packages/report/src/legal/blocks.ts` with
   `lawyerReviewedAt: null`. Documents that contain unreviewed legal text render with a visible
   draft banner, and the pre-release checklist reports it.

---

## 7. The panic stop

**Use it first and diagnose afterwards.** A stop that turns out to be unnecessary costs an hour. A
run that should have been stopped and was not costs the firm.

### 7.1 From the console

The red control on the engagement page. It takes a reason, which is mandatory, and it kills every
container labelled with that engagement.

### 7.2 From the server, when the console is unreachable

```bash
docker ps --filter label=com.attestor.purpose=engagement-run --format '{{.Names}}'
docker kill $(docker ps -q --filter label=com.attestor.purpose=engagement-run)
```

Platform-wide, including queued work:

```bash
docker compose -f infra/docker-compose.yml stop worker
docker kill $(docker ps -q --filter label=com.attestor.purpose=engagement-run)
```

### 7.3 After a stop

1. Record what happened on the engagement, in writing, before memory fades.
2. Tell the client the same day, even when nothing broke. Especially when nothing broke.
3. Clear the stop from the console with a reason. The stop stays in force until someone does; there
   is no timeout, because "it expired on its own" is not a decision anybody made.

### 7.4 If a client reports an outage during a test

1. Panic stop.
2. Confirm from the audit log what was running, when it started, and against what.
3. Send the client the timeline. Do not speculate about causation before you have it.
4. If a tool did cause it, that is a finding about their environment as well as an incident about
   ours. Write both up honestly.

---

## 8. Client onboarding checklist

Do not start work until every box is ticked. This is the order they happen in.

- [ ] Scoping call held; notes written up and sent back for correction.
- [ ] Asset list received **from the client in writing**, not assembled by us from a scan.
- [ ] Every asset confirmed as owned by the client, or third-party hosting acknowledged in writing
      by the party that owns it. Shared hosting means the hosting provider's permission too.
- [ ] Authorisation form signed by someone with the authority to sign it. Named individual, dated,
      valid-from and valid-until.
- [ ] Our egress IP given to the client and allowlisted at their end.
- [ ] Emergency contacts exchanged, both directions, including out-of-hours numbers.
- [ ] Test window agreed and recorded in the engagement policy.
- [ ] Never-touch list agreed: production payment flows, anything that sends real mail or SMS to
      real people, anything with a third-party rate ceiling.
- [ ] Cloud provider testing policy acknowledged if the engagement includes cloud assets.
- [ ] Credentials received through the vault, not email. Test accounts, not real user accounts.
- [ ] Scope entered into the console and a **dry run** performed. Read what it says it would do.
- [ ] Client told, in the same words that will appear in the report, what "critical" means.

---

## 9. Routine operations

### 9.1 Daily

- Check the job queue for failed runs.
- Check the audit log for refusals. A refusal is the system working, but a repeated refusal means
  a scope item is wrong and somebody is fighting it.

### 9.2 Weekly

- `pnpm outdated -r`, and read the changelogs for anything security-relevant.
- Confirm nightly backups exist and are non-empty.
- `node scripts/pin-tool-images.mjs --pull` to pick up tool updates deliberately, in a batch, with
  the digests recorded — never mid-engagement.

### 9.3 Monthly

- Retention worker report: what was deleted, what is due.
- Review portal access: anyone who has left a client's team should be deactivated.
- Restore drill (quarterly, but the first one within a month of going live).

---

## 10. When to stop using one server

The single-VPS design holds until one of these is true:

- Two engagements routinely want to run heavy tools at the same time and queue behind each other.
- A client contractually requires their data on separate infrastructure.
- Uptime on the portal becomes a contractual commitment rather than a courtesy.

The first is solved by adding a second worker host with its own egress IP — which means a second
address on every authorisation, so it is a client-facing change, not just an infrastructure one.
The second is solved by a separate deployment, not by a tenant flag. The third needs a second of
everything, and at that point the operational model in this document is no longer the right one.
