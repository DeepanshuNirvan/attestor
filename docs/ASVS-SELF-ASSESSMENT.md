# ASVS 5.0.0 self-assessment

Target: **Level 2**, assessed against OWASP ASVS 5.0.0 (May 2025) for the two authenticated
surfaces — the client portal and the staff console, including the APIs behind them. The marketing
site is out of scope for this assessment because it has no server, no login and no database; the
things ASVS Level 2 asks about do not exist there.

This is a self-assessment by the people who wrote the code. It is not an audit, it is not a
certification, and nobody should treat it as one. Its value is that it is honest about the gaps: a
self-assessment that scores itself full marks is worth nothing to the reader.

**Assessed:** at initial build. **Re-assess:** whenever a chapter's subject matter changes, and in
full before the first external penetration test of this platform.

Legend: **Met** — implemented and verified by a test or by inspection. **Partial** — implemented
for the paths that exist, with a named gap. **Not met** — a real gap. **N/A** — the feature does
not exist in this system.

---

## V1 Encoding and Sanitization — Met

The class of bug this chapter exists to prevent is the one most likely to be serious here, because
evidence bodies are attacker-controlled by definition.

- Output encoding is contextual and central: `escapeHtml` in `packages/report/src/render.ts` wraps
  every interpolation, and the renderer has no raw-HTML path.
- React escapes by construction in both surfaces; evidence renders into a `<pre>` as text.
- The in-portal report view is a fully sandboxed `srcdoc` frame — opaque origin, no scripts.
- SQL is parameterised throughout by Drizzle. There is no string-built query.
- Tool arguments are built from a fixed vocabulary per adapter, never concatenated from user text.
- **Verified by:** a 25-payload corpus fired through every string field of a real report, rendered,
  and opened in a real browser, asserting nothing executed, zero scripts exist in the document, and
  no outbound request was made (`packages/report/src/xss-corpus.integration.test.ts`).

## V2 Validation and Business Logic — Met

- Every request body is parsed by a zod schema at the route boundary. An unparsed body does not
  reach a handler.
- The engagement state machine permits only declared transitions, tested exhaustively.
- Tool execution is refused outside the executable states, and the check is in the choke point
  rather than in each caller.
- Business-logic sequencing that matters — authorisation before launch, checklist before release,
  retest window before a free retest — is enforced server-side, with the UI reflecting the decision
  rather than making it.

## V3 Web Frontend Security — Met

- CSP: `default-src 'none'` with an explicit allowlist per directive; no `unsafe-inline` for
  scripts. `frame-ancestors 'none'` and `X-Frame-Options: DENY`.
- Cookies: `HttpOnly`, `Secure`, `SameSite=strict`, `path=/`.
- CSRF: `@fastify/csrf-protection` with a signed cookie; `SameSite=strict` is the second layer.
- `Referrer-Policy: strict-origin-when-cross-origin`, `X-Content-Type-Options: nosniff`,
  `Permissions-Policy` denying camera, microphone, geolocation, payment and USB.
- No token is readable by browser JavaScript: the session cookie is HttpOnly and every API call is
  made server-side, so an XSS in the frontend has no credential to steal.
- **Gap accepted:** `style-src` allows `'unsafe-inline'`. Removing it would need nonces threaded
  through server-rendered inline styles for a benefit that inline-style injection does not deliver
  here, given `script-src` is already locked down.

## V4 API and Web Service — Met

- Content type is enforced; a body that is not JSON is rejected before parsing.
- Rate limits per route, tighter on authentication routes.
- HTTP methods are explicit per route; there is no catch-all handler.
- Errors are generic to the caller and detailed in the log. The portal's authentication failures
  deliberately do not distinguish "no such account" from "wrong password".

## V5 File Handling — N/A on the marketing site, Partial elsewhere

- The marketing site accepts no uploads at all. That is a deliberate design constraint, not an
  omission.
- The portal accepts no uploads.
- The console accepts inputs for code and mobile testing as operator-supplied paths mounted
  read-only into a container. They are not user uploads over HTTP.
- **Gap:** if client-supplied artefact upload is ever added to the portal, this chapter needs
  revisiting in full — content-type verification, size limits, storage outside the web root, and
  scanning. Nothing here should be read as covering that feature in advance.

## V6 Authentication — Met

- Argon2id via `@node-rs/argon2` with parameters at the current OWASP guidance.
- TOTP is mandatory: an account is not usable until enrolment completes. Invitations require it
  before first sign-in.
- Generic failure messages; no user enumeration through timing or wording.
- Rate limiting and lockout on repeated failure.
- Password change revokes every session in the same transaction as the change, so there is no window
  in which the old session still works.
- **Gap accepted:** no WebAuthn. TOTP meets L2; WebAuthn is the upgrade path and is what we would
  recommend to a client at this size, so we should get there ourselves.

## V7 Session Management — Met

- Server-side sessions with an opaque identifier; nothing about the user is carried in the cookie.
- Rotation on privilege change; invalidation on logout, on password change, and on demand via
  "sign out everywhere".
- Absolute and idle timeouts.
- Deactivating a client user revokes their sessions in the same transaction as the deactivation.

## V8 Authorization — Met

- Every portal query filters on the client id taken from the session; it is part of the `WHERE`
  clause rather than a check beside the query.
- A request for another tenant's object is a 404, not a 403 — the object's existence is not
  disclosed.
- Role checks are server-side per route. The viewer role's inability to download is enforced at the
  API; hiding the button is presentation, not authorisation.
- **Verified by:** a structural test that parses `portal-routes.ts` and fails the build if any
  authenticated route does not call `clientIdOf(request)`. It caught two real bugs during the build,
  where a status update and a comment checked ownership but not finding status, letting a client
  act on a candidate finding.

## V9 Self-contained Tokens — N/A

No JWTs, no self-contained tokens. Sessions are opaque and server-side. This chapter has no surface
here, which is itself the strongest position available in it.

## V10 OAuth and OIDC — N/A

No OAuth, no OIDC, no third-party identity provider. If SSO is added for enterprise clients, this
chapter becomes live and must be assessed before that feature ships.

## V11 Cryptography — Met

- libsodium (`crypto_secretbox`, XSalsa20-Poly1305) for the credential vault. No hand-rolled
  primitives and no algorithm choice exposed as configuration.
- Per-engagement subkeys derived with keyed Blake2b over a random salt **and the engagement id**, so
  a salt copied between engagements does not open the other's data.
- Random values come from `randombytes_buf` / `crypto.randomUUID`. `Math.random` appears nowhere in
  a security path.
- Key rotation is a documented, scripted procedure (`apps/api/src/db/rewrap-credentials.ts`), not an
  aspiration.

## V12 Secure Communication — Met

- TLS 1.2+ at the reverse proxy, HSTS with `preload`, CAA record pinning the issuer.
- Internal service traffic stays on the compose network; the console API binds to loopback and
  refuses to start on `0.0.0.0`.
- Staff reach the console over WireGuard.

## V13 Configuration — Met

- No secret has a default. `infra/.env.example` ships with every value blank and the generation
  command written above it.
- Configuration is parsed and validated at start-up; a missing required value stops the process
  rather than producing a half-configured service.
- Debug endpoints do not exist. Stack traces are never returned to a caller.
- `poweredByHeader: false`; server banners removed at the proxy.
- Dependencies are lockfile-pinned, and `onlyBuiltDependencies` allowlists which packages may run
  install scripts.

## V14 Data Protection — Met

- Credentials are never rendered. The vault has no read-for-display path; `open()` is called in the
  worker, in memory, at run time.
- Logs, tool output, findings and reports pass through a redaction filter with a live secret
  registry; card and identifier numbers are masked at capture with Luhn and Verhoeff checks so that
  masking does not mangle unrelated digits.
- Evidence retention defaults to 90 days and is enforced by a worker, not by intention.
- Closure destroys the engagement's key salt, making its credentials unrecoverable by anyone,
  including us.
- `Cache-Control: no-store` on authenticated responses.

## V15 Secure Coding and Architecture — Met

- TypeScript strict, `noUncheckedIndexedAccess`, no `any` (lint error), no leading-underscore names.
- Exactly one module may import `dockerode`; enforced by an ESLint rule **and** by an architecture
  test, because a control with a single enforcement point is a control that gets moved.
- Denial of service is structurally unavailable: the policy schema cannot express it, rate ceilings
  are clamped, `DENIAL_OF_SERVICE_CAPABILITY = false`, an architecture test greps for DoS-shaped
  symbols, and every adapter's built command is asserted to contain no flood flag.
- Property-based tests (fast-check) on the scope guard's hostname and IP matching.
- 290 unit and property tests, plus integration suites that run only against local targets on a
  network with no route to the internet.

## V16 Security Logging and Error Handling — Partial

- Every security-relevant event is logged with an actor, a subject and a time: authentication,
  tool launch, tool exit, scope refusal, credential access, report generation, report release,
  portal download, risk acceptance.
- Logs are structured JSON and pass through the redaction filter, so a credential in a log is a bug
  with a test rather than a routine occurrence.
- **Gap:** logs are not shipped off-host. An attacker who owns the host can edit the record of
  owning it. This is the single most important item on the platform's own remediation list.
- **Gap:** there is no alerting. A human reads refusals daily. That is a process, not a control, and
  it will not survive a busy week.

## V17 WebRTC — N/A

No WebRTC anywhere in the platform.

---

## Summary

| Chapter | Verdict |
| --- | --- |
| V1 Encoding and Sanitization | Met |
| V2 Validation and Business Logic | Met |
| V3 Web Frontend Security | Met (one accepted gap: inline styles) |
| V4 API and Web Service | Met |
| V5 File Handling | N/A / Partial — revisit if portal upload is ever added |
| V6 Authentication | Met (WebAuthn is the upgrade path) |
| V7 Session Management | Met |
| V8 Authorization | Met |
| V9 Self-contained Tokens | N/A |
| V10 OAuth and OIDC | N/A |
| V11 Cryptography | Met |
| V12 Secure Communication | Met |
| V13 Configuration | Met |
| V14 Data Protection | Met |
| V15 Secure Coding and Architecture | Met |
| V16 Security Logging and Error Handling | **Partial — two real gaps** |
| V17 WebRTC | N/A |

Two genuine gaps, both in V16: **off-host log shipping** and **alerting**. Both are on the platform
roadmap ahead of new features. Everything else is either met or does not apply, and where a chapter
is marked N/A it is because the feature genuinely does not exist rather than because it was not
looked at.

An external test of this platform, by someone who did not build it, is the next step. Until that
has happened, this document is the best available account and not a substitute for one.
