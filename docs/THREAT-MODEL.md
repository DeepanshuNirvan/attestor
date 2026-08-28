# Threat model

A security firm's own platform is a concentrated target: it holds several clients' credentials,
their unfixed vulnerabilities, and the ability to launch tools at their infrastructure. Anyone who
takes it gets all of that at once, and gets it from a party those clients chose to trust.

This document says what we are defending, from whom, what we have actually done about it, and —
the part most threat models omit — what we have decided not to do and why.

Method: STRIDE per trust boundary, plus a set of abuse cases specific to running offensive tools
for other people. Reviewed when the architecture changes; last reviewed at the initial build.

---

## 1. What is worth taking

Ranked by what the loss would actually cost, not by how interesting the data is.

| Asset | Why an attacker wants it | Worst case |
| --- | --- | --- |
| Client credentials in the vault | Direct authenticated access to several companies at once | Multi-client compromise traced to us |
| Unreleased findings | A list of working exploits against named, unpatched targets | Every client breached before they could fix |
| The ability to launch tools | Our egress IP is allowlisted by clients; traffic from it is trusted | Attacks from a trusted source that the client's own controls will not stop |
| The Docker socket | Root on the host, and everything above | Total |
| `VAULT_MASTER_KEY` | Opens every stored credential | Same as the first row, without needing the application |
| `PORTAL_TOTP_KEY` | Opens every client authenticator secret | Second factor defeated for every portal user |
| Reports and evidence | Saleable, embarrassing, and useful for a later attack | Client relationships end |
| Authorisation records | Forge one and an unauthorised test looks authorised | Legal exposure for us and the client |
| Audit log | Not for taking — for editing, to hide the above | We cannot answer "what happened" |

---

## 2. Trust boundaries

```
   internet ──▶ [ marketing site ]            static; no server, no database, no login
                                              a compromise defaces a page and nothing else

   internet ──▶ [ portal ] ──▶ [ portal API ] ──▶ Postgres as attestor_portal
                                              least-privilege role; cannot read credential_set

   WireGuard ─▶ [ console ] ──▶ [ console API ] ─▶ Postgres as owner
                                              staff only; never bound to 0.0.0.0

                [ worker ] ──▶ Docker ──▶ [ tool container ] ──▶ client asset
                                              one choke point, scope-checked before every launch
```

Four boundaries, in order of exposure:

1. **Internet → portal.** The only client-facing authenticated surface.
2. **Internet → marketing site.** Static files. Deliberately has nothing to attack.
3. **Staff → console.** Reachable only over WireGuard; the API refuses to bind to a public address.
4. **Platform → client infrastructure.** The one where a mistake harms someone else.

---

## 3. STRIDE

### 3.1 Internet → portal

| Threat | Concrete form | What is in place |
| --- | --- | --- |
| Spoofing | Credential stuffing against a client account | Argon2id; TOTP mandatory before an account works; generic failures that do not reveal whether an address exists; per-route rate limits |
| Tampering | A client changing another client's finding status | Client id comes from the session and is part of every `WHERE`; a cross-tenant request is a 404, not a 403 |
| Repudiation | "We never accepted that risk" | Risk acceptance stores the justification, the user and the time; downloads are recorded per user |
| Information disclosure | Reading another client's report | Same as tampering; plus a structural test that parses `portal-routes.ts` and fails the build if any authenticated route omits `clientIdOf(request)` |
| Denial of service | Flooding the portal | Rate limits; a portal outage does not affect the console or a run in flight |
| Elevation of privilege | A viewer downloading a watermarked PDF | Role checked server-side per route; the viewer role is refused at the API, not hidden in the UI |

The portal is the surface a client's own attacker will reach first, so it holds the least. It
cannot read the credential vault at the **database role** level — not by convention, by grant.

### 3.2 Stored XSS through evidence

Worth its own section because it is the most likely serious bug in a platform of this shape.

Evidence bodies are attacker-controlled by definition: they are what the tested application
returned, and in a web assessment that is frequently whatever an attacker put there. The same is
true of finding titles produced by tools, of affected URLs, and of anything a scanner echoes back.

- The report renderer escapes every interpolation. There is no raw-HTML path in it.
- The portal renders evidence as text in a `<pre>`, never as a document.
- The in-portal report view is a fully sandboxed `srcdoc` frame: opaque origin, no scripts.
- An integration suite fires a 25-payload corpus through **every string field** of a real report,
  renders it, opens it in a real browser, and asserts that nothing executed, that the document
  contains zero scripts, and that it made no outbound request. It also asserts the payload is still
  visible as text, because evidence that gets silently stripped is evidence that lies.

### 3.3 Staff → console

| Threat | Concrete form | What is in place |
| --- | --- | --- |
| Spoofing | Stolen staff session | Session cookie is HttpOnly, `SameSite=strict`, and only reachable over WireGuard |
| Tampering | Editing a report after release | Released reports are immutable; a change is a new version with its own record |
| Repudiation | "I didn't start that run" | Every launch is in the audit log with actor, targets, resolved addresses and digest |
| Information disclosure | Credentials on screen | The vault has no read-for-display path. `open()` is called in the worker, at run time, in memory |
| Denial of service | Not the primary concern behind WireGuard | Queue backpressure; per-run resource limits |
| Elevation of privilege | A junior releasing a report | Release runs the checklist server-side; the button being enabled is not the gate |

### 3.4 Platform → client infrastructure

This is the boundary where we are the threat, and it is modelled that way.

| Abuse case | What stops it |
| --- | --- |
| Testing an asset the client does not own | Scope guard: label-wise wildcard matching, DNS re-checked **after** resolution, and the whole run refused — not filtered — if any target fails |
| A hostname that resolves to something else mid-run | Addresses are resolved and checked at launch and recorded in the audit entry |
| Reaching cloud metadata or the operator's own network | Loopback, link-local, RFC1918, CGNAT, benchmarking, TEST-NET and multicast ranges refused by default; metadata endpoints named explicitly so the refusal says why |
| Testing outside the agreed window | Test windows in the resolved policy, evaluated in the engagement timezone |
| Testing after authorisation expired or was revoked | Authorisation validity checked on every launch, not at engagement creation |
| Denial of service against a client | **No code path can express it.** The policy schema has no field for it, rate ceilings are clamped, `DENIAL_OF_SERVICE_CAPABILITY = false`, an architecture test greps for DoS-shaped symbols, and every adapter's built command is asserted to contain no flood flag |
| A destructive payload | Read-only mode in the policy; adapters build commands from a fixed vocabulary |
| A second path around the scope guard | Exactly one module imports `dockerode`. Enforced twice, by an ESLint rule and by an architecture test, because a control with one enforcement point is a control that gets moved |

The never-touch list is checked **before** authorisation, so an item on it is refused even on a
fully authorised engagement. Signing a form does not make it safe to test the payment flow.

### 3.5 The Docker socket

Mounting it is equivalent to giving the worker root on the host. This is accepted because starting
containers is the platform's function. What follows from accepting it:

- One module talks to Docker, and it is the one that applies hardening: non-root `65532`,
  `ReadonlyRootfs`, `CapDrop: ALL`, `no-new-privileges`, per-run network, memory, PID and CPU
  limits, no host network, and a wall-clock kill.
- Hardening lives in the runner rather than per-tool, so a new adapter cannot forget it.
- Containers carry labels, and the panic stop finds them by label. A container started without them
  could not be stopped, which is why a unit test asserts they are set.

Rootless Docker would reduce this. It is on the list below rather than in the build because several
tool images assume capabilities that rootless mode changes, and shipping a half-working runner is
worse than a documented accepted risk.

---

## 4. Cryptographic shredding, and what it means when it works

Credentials are sealed under a per-engagement subkey derived from the master key, a random salt and
the engagement id. Closing an engagement destroys the salt. There is then no key that opens the
ciphertext — not for an attacker, not for us, not with a court order, not from a backup.

Two consequences, both intended:

- A database backup from before closure is still just ciphertext without the master key, which is
  stored somewhere else entirely.
- Restoring the database without `VAULT_MASTER_KEY` gives engagement records and unreadable
  credentials. Operators must be told this in advance, or they will file it as a restore failure.

---

## 5. Third parties

| Dependency | Trusted with | If it turns hostile |
| --- | --- | --- |
| Tool images | Execution inside a hardened container, on a per-run network | Pinned by digest; no host network; read-only root; no host mounts beyond one output directory |
| npm packages | Build and runtime | Lockfile committed; `onlyBuiltDependencies` allowlists which packages may run install scripts |
| VPS provider | Physical and hypervisor access | Accepted. Disk encryption does not help against a hypervisor, and this is the residual risk of not owning hardware |
| Mail provider | Outbound mail | Nothing client-confidential is emailed. Reports are published in the portal; the notification is a link |
| AI provider | Nothing, by default | Off unless enabled per engagement; only redacted findings text is ever sent; usage is logged with a cost |

---

## 6. Accepted risks

Stated plainly, because an unstated accepted risk is an unnoticed one.

1. **The Docker socket is root.** Mitigated by a single choke point and container hardening. Not
   eliminated. Rootless Docker is the upgrade path.
2. **One server.** A compromise of the host is a compromise of everything on it. Accepted for the
   firm's current size; §10 of the runbook says when it stops being acceptable.
3. **The egress IP is allowlisted by clients.** Anyone who runs code on our host inherits that
   trust. This is why the console is not internet-facing and why the panic stop exists.
4. **Staff devices are in scope for the attacker and out of scope for this document.** WireGuard
   keys live on laptops. Device compromise is handled by policy — full-disk encryption, screen lock,
   no shared keys, immediate key revocation on loss — not by the platform.
5. **Legal text is not yet lawyer-reviewed.** Every block carries `lawyerReviewedAt: null` and
   documents render with a visible draft banner until it is. This is a business risk, tracked in the
   pre-release checklist so it cannot be forgotten.

---

## 7. What would tell us we were wrong

Detection is thin, and pretending otherwise would be the worst thing in this document. What exists:

- Every tool launch, refusal, credential access, report release and portal download is in the audit
  log with an actor.
- The daily check includes reading refusals: a repeated refusal means somebody is fighting the
  scope guard, which is either a wrong scope item or a person who should be asked why.
- Logs go through a redaction filter, so a log that leaks a credential is itself a bug with a test.

What does not exist yet, and should:

- Alerting on anomalies rather than a human reading a list.
- Off-host log shipping, so an attacker who owns the host cannot edit the record of owning it.
- A tested incident response plan with named roles.

These are the next three pieces of security work on the platform, in that order.
