import type { Check } from './types.ts';

export const webChecks: Check[] = [
  /* Configuration and deployment ------------------------------------------------------------- */
  {
    id: 'web-security-headers',
    title: 'HTTP security header configuration',
    category: 'configuration',
    modules: ['web'],
    description:
      'Check Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and the cross-origin isolation headers, and check that the policies actually constrain anything.',
    example:
      'A Content-Security-Policy present but containing `unsafe-inline` and a wildcard script source, which makes it decorative.',
    automation: 'automated',
    tools: ['zap', 'nuclei', 'httpx'],
    standards: {
      // CONF-12 is the Content-Security-Policy test, CONF-07 the HSTS one, and CONF-14 the rest of
      // the header family. This check reads all of them from the same response, so claiming one and
      // leaving the other two as gaps described the code rather than the work.
      wstg: ['WSTG-CONF-12', 'WSTG-CONF-07', 'WSTG-CONF-14'],
      asvs: ['v5.0.0-3.4.1', 'v5.0.0-3.4.3'],
      owaspTop10: ['A02:2025'],
      cwe: [693, 1021],
    },
  },
  {
    id: 'web-cookie-attributes',
    title: 'Cookie attribute review',
    category: 'sessionManagement',
    modules: ['web'],
    description:
      'Check every cookie the application sets for Secure, HttpOnly, SameSite, Path, Domain scope and expiry, and identify which cookies actually carry the session.',
    example:
      'A session cookie without HttpOnly, so any cross-site scripting anywhere on the domain hands over an account.',
    automation: 'automated',
    tools: ['zap', 'playwright'],
    standards: {
      wstg: ['WSTG-SESS-02'],
      asvs: ['v5.0.0-7.1.1', 'v5.0.0-7.1.2'],
      owaspTop10: ['A02:2025'],
      cwe: [614, 1004, 1275],
    },
  },
  {
    id: 'web-cors-configuration',
    title: 'CORS policy review',
    category: 'configuration',
    modules: ['web', 'api'],
    description:
      'Test how the application answers cross-origin requests: origin reflection, null origin, credentialed wildcards, and whether the pre-flight response is consistent with the actual response.',
    example:
      'The API reflecting any Origin header and returning `Access-Control-Allow-Credentials: true`, letting any site read a logged-in user\'s data.',
    automation: 'automated',
    tools: ['zap', 'nuclei'],
    standards: {
      wstg: ['WSTG-CLNT-07'],
      asvs: ['v5.0.0-3.4.4'],
      owaspTop10: ['A01:2025'],
      apiTop10: ['API8:2023'],
      cwe: [942, 346],
    },
  },
  {
    id: 'web-http-methods',
    title: 'HTTP method handling',
    category: 'configuration',
    modules: ['web', 'api'],
    description:
      'Enumerate which methods each endpoint accepts, including TRACE, OPTIONS, PUT and DELETE, and test whether method override headers change authorisation behaviour.',
    example:
      'An endpoint that rejects DELETE but honours `X-HTTP-Method-Override: DELETE` on a POST, bypassing the method-based access rule.',
    automation: 'automated',
    tools: ['requestManipulationProbe', 'zap', 'ffuf'],
    // INPV-03 is the second sentence of the description: whether the answer depends on the method
    // rather than on the identity. The probe sends GET, HEAD and OPTIONS to the same URL and
    // compares, which is that test performed rather than described.
    standards: {
      wstg: ['WSTG-CONF-06', 'WSTG-INPV-03'],
      owaspTop10: ['A01:2025'],
      cwe: [650, 288],
    },
  },
  {
    id: 'web-file-extension-handling',
    title: 'File extension and backup file handling',
    category: 'configuration',
    modules: ['web'],
    description:
      'Test how the server treats alternative extensions, editor backup suffixes and case variations of known paths.',
    example: 'A `config.php.bak` served as plain text, disclosing the database password.',
    automation: 'automated',
    tools: ['ffuf', 'nuclei'],
    standards: { wstg: ['WSTG-CONF-03', 'WSTG-CONF-04'], owaspTop10: ['A02:2025'], cwe: [530] },
  },
  {
    id: 'web-admin-interface-exposure',
    title: 'Administrative interface exposure',
    category: 'configuration',
    modules: ['web'],
    description:
      'Look for administrative panels, monitoring dashboards, framework debug consoles and management endpoints reachable without authentication or from the public internet.',
    example:
      'A framework debug toolbar enabled in production, exposing environment variables and an interactive console.',
    automation: 'automated',
    tools: ['nuclei', 'ffuf', 'httpx'],
    standards: { wstg: ['WSTG-CONF-05'], owaspTop10: ['A02:2025'], cwe: [489, 1188] },
  },
  {
    id: 'web-default-credentials',
    title: 'Default and weak credentials on exposed components',
    category: 'authentication',
    modules: ['web', 'network'],
    description:
      'Test a small, documented set of vendor default credentials against management interfaces found during discovery. Bounded attempts only, never against real user accounts.',
    example: 'A monitoring dashboard still on the vendor default login.',
    automation: 'assisted',
    tools: ['nuclei'],
    // CONF-06 is the HTTP methods test and was never anything this check does; it belongs to
    // `web-http-methods`, which performs it.
    standards: { wstg: ['WSTG-ATHN-02'], owaspTop10: ['A07:2025'], cwe: [1392, 521] },
  },
  {
    id: 'web-subresource-integrity',
    title: 'Third-party script inclusion and subresource integrity',
    category: 'supplyChain',
    modules: ['web'],
    description:
      'Inventory every third-party script the page loads, check whether integrity attributes are present, and identify scripts loaded from hosts the client does not control.',
    example:
      'A payment page loading a marketing tag from a shared CDN with no integrity attribute, giving that vendor script access to the card form.',
    automation: 'automated',
    tools: ['playwright', 'zap'],
    standards: {
      wstg: ['WSTG-CLNT-12'],
      asvs: ['v5.0.0-3.5.1'],
      owaspTop10: ['A03:2025', 'A08:2025'],
      cwe: [829, 494],
    },
  },
  {
    id: 'web-cache-configuration',
    title: 'Caching of authenticated responses',
    category: 'configuration',
    modules: ['web'],
    description:
      'Check cache directives on authenticated pages and API responses, and test for cache deception and cache poisoning where a shared cache sits in front of the application.',
    example:
      'An account page cacheable by a shared CDN, so the next visitor to that path is served the previous user\'s details.',
    automation: 'assisted',
    tools: ['zap', 'nuclei'],
    standards: { wstg: ['WSTG-ATHN-06'], owaspTop10: ['A02:2025'], cwe: [524, 525] },
  },
  {
    id: 'web-host-header-handling',
    title: 'Host header handling',
    category: 'configuration',
    modules: ['web'],
    description:
      'Test whether the application trusts the Host or X-Forwarded-Host header when building links, password reset URLs or cache keys.',
    example:
      'A password reset email whose link uses the attacker-supplied Host header, sending the reset token to a site the attacker controls.',
    automation: 'automated',
    tools: ['requestManipulationProbe'],
    // This is WSTG-INPV-17. It previously claimed CONF-07, which is the HSTS test and is performed
    // by `web-security-headers` — so host header injection read as a gap while a check for it
    // existed. ZAP ships no rule for this at all; the probe sends the header and looks for the name
    // it supplied coming back in a redirect target or in the page.
    standards: { wstg: ['WSTG-INPV-17'], owaspTop10: ['A01:2025'], cwe: [644] },
  },

  /* Identity and registration ---------------------------------------------------------------- */
  {
    id: 'web-user-enumeration',
    title: 'Username and account enumeration',
    category: 'authentication',
    modules: ['web', 'api'],
    description:
      'Compare responses, timings and error text across login, registration, password reset and email-change flows to see whether the application reveals which accounts exist.',
    example:
      'The password reset form saying "no account with that email", allowing an attacker to confirm which customers are registered.',
    automation: 'assisted',
    tools: ['zap', 'ffuf'],
    standards: {
      wstg: ['WSTG-IDNT-04'],
      asvs: ['v5.0.0-6.2.3'],
      owaspTop10: ['A07:2025'],
      cwe: [204, 203],
    },
  },
  {
    id: 'web-registration-process',
    title: 'Registration process review',
    category: 'authentication',
    modules: ['web'],
    description:
      'Check whether registration verifies ownership of the identifier, whether roles or entitlements can be set by the client, and whether duplicate or unverified accounts can be created.',
    example:
      'A registration endpoint accepting a `role` field from the browser, allowing self-service creation of an administrator.',
    automation: 'assisted',
    tools: ['zap', 'playwright'],
    standards: {
      wstg: ['WSTG-IDNT-02'],
      asvs: ['v5.0.0-2.1.1'],
      owaspTop10: ['A01:2025'],
      apiTop10: ['API3:2023'],
      cwe: [915, 269],
    },
  },
  {
    id: 'web-account-provisioning',
    title: 'Account provisioning and de-provisioning',
    category: 'accessControl',
    modules: ['web'],
    description:
      'Check that an administrator cannot provision beyond their own privilege level, and that removing a user actually revokes their sessions, tokens and API keys.',
    example:
      'A removed employee whose API token keeps working because de-provisioning only disabled the login.',
    automation: 'manual',
    tools: [],
    standards: { wstg: ['WSTG-IDNT-03'], owaspTop10: ['A01:2025'], cwe: [613, 285] },
  },

  /* Authentication --------------------------------------------------------------------------- */
  {
    id: 'web-credentials-over-encrypted-channel',
    title: 'Credentials transmitted over an encrypted channel',
    category: 'authentication',
    modules: ['web'],
    description:
      'Confirm that no authentication flow, including redirects and legacy endpoints, accepts credentials over plain HTTP.',
    example:
      'An old mobile login endpoint still answering on HTTP, used by an outdated app version in the wild.',
    automation: 'automated',
    tools: ['zap', 'httpx'],
    standards: {
      wstg: ['WSTG-ATHN-01'],
      asvs: ['v5.0.0-12.1.1'],
      owaspTop10: ['A04:2025'],
      cwe: [319],
    },
  },
  {
    id: 'web-password-policy',
    title: 'Password policy and credential strength',
    category: 'authentication',
    modules: ['web'],
    description:
      'Test minimum and maximum length, whether long passphrases are accepted, whether breached-password checking exists, and whether composition rules are being used in place of length.',
    example:
      'A 16-character maximum that silently truncates, so a password manager\'s output is not what actually gets stored.',
    automation: 'manual',
    tools: [],
    standards: {
      wstg: ['WSTG-ATHN-07'],
      asvs: ['v5.0.0-6.2.1', 'v5.0.0-6.2.2'],
      owaspTop10: ['A07:2025'],
      cwe: [521],
    },
  },
  {
    id: 'web-authentication-bypass',
    title: 'Authentication bypass',
    category: 'authentication',
    modules: ['web', 'api'],
    description:
      'Attempt to reach authenticated functionality by forced browsing, parameter manipulation, request smuggling of authentication state, and by replaying partially completed authentication flows.',
    example:
      'A multi-step login where the second step can be skipped by requesting the post-login landing page directly with the partially authenticated cookie.',
    automation: 'manual',
    tools: ['zap'],
    standards: {
      wstg: ['WSTG-ATHN-04'],
      asvs: ['v5.0.0-6.1.1'],
      owaspTop10: ['A07:2025'],
      cwe: [287, 288],
    },
  },
  {
    id: 'web-brute-force-protection',
    title: 'Brute force and credential stuffing protection',
    category: 'authentication',
    modules: ['web', 'api'],
    description:
      'Measure how many authentication attempts are accepted before throttling, whether throttling is per account or per address, and whether it can be bypassed by varying headers, casing or the request path. Bounded attempts against disposable accounts only.',
    example:
      'Rate limiting applied per IP only, so a credential-stuffing run from a residential proxy pool is unimpeded.',
    automation: 'manual',
    tools: [],
    standards: {
      wstg: ['WSTG-ATHN-03'],
      asvs: ['v5.0.0-6.2.4'],
      owaspTop10: ['A07:2025'],
      apiTop10: ['API4:2023'],
      cwe: [307, 799],
    },
  },
  {
    id: 'web-multi-factor-implementation',
    title: 'Multi-factor authentication implementation',
    category: 'authentication',
    modules: ['web'],
    description:
      'Test whether the second factor can be skipped, replayed, brute forced, or removed without re-authentication, and whether the OTP is bound to the session that requested it.',
    example:
      'An OTP that stays valid for fifteen minutes and is not bound to a session, so it can be used from a different browser.',
    automation: 'manual',
    tools: ['playwright'],
    standards: {
      wstg: ['WSTG-ATHN-11'],
      asvs: ['v5.0.0-6.3.1'],
      owaspTop10: ['A07:2025'],
      cwe: [287, 308],
    },
  },
  {
    id: 'web-password-reset-flow',
    title: 'Password reset and recovery flow',
    category: 'authentication',
    modules: ['web'],
    description:
      'Test token entropy, expiry, single use, binding to the requesting account, whether the reset invalidates existing sessions, and whether the reset link can be redirected to an attacker-controlled host.',
    example:
      'A reset token that remains valid after use, so an old email in a shared inbox still grants access.',
    automation: 'manual',
    tools: ['playwright', 'zap'],
    standards: {
      wstg: ['WSTG-ATHN-09'],
      asvs: ['v5.0.0-6.4.1'],
      owaspTop10: ['A07:2025'],
      cwe: [640, 620],
    },
  },
  {
    id: 'web-remember-me',
    title: 'Remember-me and persistent login',
    category: 'authentication',
    modules: ['web'],
    description:
      'Check what a persistent login token contains, whether it is revocable, whether it survives a password change, and whether it grants sensitive operations without re-authentication.',
    example:
      'A remember-me token that keeps working after the user changes their password following a suspected compromise.',
    automation: 'manual',
    tools: [],
    standards: { wstg: ['WSTG-ATHN-05', 'WSTG-ATHN-06'], owaspTop10: ['A07:2025'], cwe: [539, 613] },
  },
  {
    id: 'web-oauth-oidc-flow',
    title: 'OAuth and OpenID Connect flow review',
    category: 'authentication',
    modules: ['web', 'api'],
    description:
      'Check redirect URI validation, state and nonce handling, PKCE use on public clients, token audience and issuer validation, and whether an authorisation code can be replayed or injected.',
    example:
      'Loose redirect URI matching that accepts an attacker-controlled path on the same host, leaking the authorisation code.',
    automation: 'manual',
    tools: ['zap', 'playwright'],
    standards: {
      wstg: ['WSTG-ATHZ-05'],
      asvs: ['v5.0.0-10.1.1', 'v5.0.0-10.2.1'],
      owaspTop10: ['A07:2025'],
      cwe: [601, 352],
    },
  },
  {
    id: 'web-sso-and-federation',
    title: 'SSO and federated identity handling',
    category: 'authentication',
    modules: ['web'],
    description:
      'For SAML and OIDC single sign-on, check signature validation, assertion replay, audience restriction, and whether an unverified email claim can be used to take over a local account.',
    example:
      'Account linking on an unverified email claim, allowing a self-registered identity provider account to take over an existing user.',
    automation: 'manual',
    tools: ['zap'],
    standards: {
      wstg: ['WSTG-ATHN-04'],
      asvs: ['v5.0.0-10.4.1'],
      owaspTop10: ['A07:2025'],
      cwe: [287, 290],
    },
  },
  {
    id: 'web-jwt-handling',
    title: 'JWT and self-contained token handling',
    category: 'authentication',
    modules: ['web', 'api'],
    description:
      'Test algorithm confusion, `none` algorithm acceptance, weak signing secrets against a bounded wordlist, missing expiry, missing audience and issuer validation, and whether claims are trusted without verification.',
    example:
      'An API accepting a token signed with HS256 using the public RSA key as the secret, letting anyone mint an administrator token.',
    automation: 'assisted',
    tools: ['zap', 'nuclei'],
    standards: {
      wstg: ['WSTG-SESS-10'],
      asvs: ['v5.0.0-9.1.1', 'v5.0.0-9.2.1'],
      owaspTop10: ['A07:2025'],
      apiTop10: ['API2:2023'],
      cwe: [347, 345],
    },
  },
  {
    id: 'web-step-up-authentication',
    title: 'Re-authentication for sensitive operations',
    category: 'authentication',
    modules: ['web'],
    description:
      'Check that changing an email address, changing a password, adding a payment method, or disabling multi-factor authentication requires proof of the current credential.',
    example:
      'An email-change endpoint that needs only a session cookie, turning any session hijack into a permanent account takeover.',
    automation: 'manual',
    tools: [],
    standards: {
      wstg: ['WSTG-ATHN-08'],
      asvs: ['v5.0.0-6.5.1'],
      owaspTop10: ['A07:2025'],
      cwe: [620, 306],
    },
  },

  /* Session management ----------------------------------------------------------------------- */
  {
    id: 'web-session-token-strength',
    title: 'Session token generation and entropy',
    category: 'sessionManagement',
    modules: ['web'],
    description:
      'Collect a sample of issued session identifiers and check for structure, predictability and insufficient entropy.',
    example:
      'A session identifier that is a base64-encoded user id and timestamp, guessable for any known user.',
    automation: 'assisted',
    tools: ['zap'],
    standards: {
      wstg: ['WSTG-SESS-01'],
      asvs: ['v5.0.0-7.1.3'],
      owaspTop10: ['A07:2025'],
      cwe: [330, 340],
    },
  },
  {
    id: 'web-session-fixation',
    title: 'Session fixation',
    category: 'sessionManagement',
    modules: ['web'],
    description:
      'Check that the session identifier is regenerated at login and at any privilege change, so a pre-set identifier cannot be reused after authentication.',
    example:
      'The pre-login session identifier surviving authentication, so a link containing a chosen identifier hands the attacker the authenticated session.',
    automation: 'assisted',
    tools: ['zap', 'playwright'],
    standards: {
      wstg: ['WSTG-SESS-03'],
      asvs: ['v5.0.0-7.2.1'],
      owaspTop10: ['A07:2025'],
      cwe: [384],
    },
  },
  {
    id: 'web-session-timeout',
    title: 'Session timeout and termination',
    category: 'sessionManagement',
    modules: ['web'],
    description:
      'Check idle and absolute timeouts, that logout invalidates the session server-side rather than only clearing the cookie, and that all of a user\'s sessions can be terminated.',
    example:
      'Logout clearing the cookie but leaving the session valid, so a copied cookie keeps working for days.',
    automation: 'manual',
    tools: [],
    standards: {
      wstg: ['WSTG-SESS-06', 'WSTG-SESS-07'],
      asvs: ['v5.0.0-7.3.1'],
      owaspTop10: ['A07:2025'],
      cwe: [613],
    },
  },
  {
    id: 'web-csrf',
    title: 'Cross-site request forgery',
    category: 'sessionManagement',
    modules: ['web'],
    description:
      'Test every state-changing operation for anti-CSRF protection, whether the token is validated and bound to the session, and whether SameSite behaviour is being relied on alone.',
    example:
      'A funds-transfer endpoint that accepts a request with no CSRF token when the content type is changed to `text/plain`.',
    automation: 'assisted',
    tools: ['zap'],
    standards: {
      wstg: ['WSTG-SESS-05'],
      asvs: ['v5.0.0-3.3.1'],
      owaspTop10: ['A01:2025'],
      cwe: [352],
    },
  },
  {
    id: 'web-concurrent-sessions',
    title: 'Concurrent session handling',
    category: 'sessionManagement',
    modules: ['web'],
    description:
      'Check whether concurrent sessions are permitted, visible to the user, and revocable, and whether a password change ends the others.',
    example:
      'No visibility of active sessions and no way to revoke them, so a user who suspects compromise has no remedy.',
    automation: 'manual',
    tools: [],
    // SESS-11 is the concurrent sessions test; SESS-08 is session puzzling, which the check below
    // performs. Both claimed SESS-08, so one of them counted for nothing and SESS-11 read as a gap.
    standards: { wstg: ['WSTG-SESS-11'], owaspTop10: ['A07:2025'], cwe: [613] },
  },
  {
    id: 'web-session-puzzling',
    title: 'Session variable overloading',
    category: 'sessionManagement',
    modules: ['web'],
    description:
      'Test whether the same session variable is used for different purposes in different flows, allowing state from one flow to satisfy a check in another.',
    example:
      'A password-reset flow setting the same session key that the login flow reads as proof of authentication.',
    automation: 'manual',
    tools: [],
    standards: { wstg: ['WSTG-SESS-08'], owaspTop10: ['A07:2025'], cwe: [841] },
  },
  {
    id: 'web-logout-csrf',
    title: 'Logout and session-riding side effects',
    category: 'sessionManagement',
    modules: ['web'],
    description:
      'Check whether logout, login and account-linking can be triggered cross-site, which enables login CSRF and forced de-authentication.',
    example:
      'Login CSRF that signs a victim into the attacker\'s account, so the victim\'s subsequent activity is recorded under it.',
    automation: 'assisted',
    tools: ['zap'],
    standards: { wstg: ['WSTG-SESS-05'], owaspTop10: ['A01:2025'], cwe: [352] },
  },

  /* Access control --------------------------------------------------------------------------- */
  {
    id: 'web-vertical-access-control',
    title: 'Vertical access control across roles',
    category: 'accessControl',
    modules: ['web', 'api'],
    description:
      'Replay every request recorded for a higher-privileged role using each lower-privileged role and an unauthenticated session, and compare the responses structurally rather than for exact equality.',
    example:
      'A support user reaching the administrator-only user-export endpoint because the check is applied in the UI and not on the server.',
    automation: 'assisted',
    tools: ['playwright', 'accessControlMatrix'],
    standards: {
      wstg: ['WSTG-ATHZ-02', 'WSTG-ATHZ-03'],
      asvs: ['v5.0.0-8.1.1'],
      owaspTop10: ['A01:2025'],
      apiTop10: ['API5:2023'],
      cwe: [285, 269],
    },
  },
  {
    id: 'web-horizontal-access-control',
    title: 'Horizontal access control between users',
    category: 'accessControl',
    modules: ['web', 'api'],
    description:
      'Replay each user\'s requests with a second account in the same role, and mutate identifiers to values captured from the other account, to test whether one customer can reach another\'s data.',
    example:
      'Changing an order identifier in a URL to see another customer\'s delivery address and phone number.',
    automation: 'assisted',
    tools: ['playwright', 'accessControlMatrix'],
    standards: {
      wstg: ['WSTG-ATHZ-04'],
      asvs: ['v5.0.0-8.1.2'],
      owaspTop10: ['A01:2025'],
      apiTop10: ['API1:2023'],
      cwe: [639, 566],
    },
  },
  {
    id: 'web-tenant-isolation',
    title: 'Tenant isolation in multi-tenant applications',
    category: 'accessControl',
    modules: ['web', 'api'],
    description:
      'Using accounts in two separate customer organisations, test whether tenant scoping is enforced on every read, write, export, search, webhook and report path.',
    example:
      'A reporting endpoint that filters by tenant in the user interface but accepts a tenant identifier parameter the server does not check.',
    automation: 'assisted',
    tools: ['accessControlMatrix'],
    standards: {
      wstg: ['WSTG-ATHZ-02'],
      asvs: ['v5.0.0-8.1.3'],
      owaspTop10: ['A01:2025'],
      apiTop10: ['API1:2023'],
      cwe: [639, 1230],
    },
  },
  {
    id: 'web-directory-traversal',
    title: 'Path traversal and local file access',
    category: 'accessControl',
    modules: ['web', 'api'],
    description:
      'Test parameters that reference files, templates or paths for traversal, using encoding variants and platform-specific separators.',
    example:
      'A document download endpoint that accepts a relative path and serves any file the application user can read.',
    automation: 'automated',
    tools: ['zap', 'nuclei', 'ffuf'],
    standards: {
      wstg: ['WSTG-ATHZ-01'],
      asvs: ['v5.0.0-5.1.1'],
      owaspTop10: ['A01:2025'],
      cwe: [22, 23],
    },
  },
  {
    id: 'web-forced-browsing',
    title: 'Forced browsing to unlinked functionality',
    category: 'accessControl',
    modules: ['web'],
    description:
      'Request functionality that is hidden in the interface rather than protected on the server, using paths discovered from JavaScript bundles, historical URLs and role comparison.',
    example:
      'An internal refunds screen that is hidden from the menu for support staff but returns data when requested directly.',
    automation: 'assisted',
    tools: ['ffuf', 'katana'],
    standards: { wstg: ['WSTG-ATHZ-02'], owaspTop10: ['A01:2025'], cwe: [425] },
  },
  {
    id: 'web-privilege-escalation-via-parameters',
    title: 'Privilege escalation through request parameters',
    category: 'accessControl',
    modules: ['web', 'api'],
    description:
      'Test whether role, tenant, price, status or entitlement fields submitted by the client are trusted by the server, including fields present in the response but not the form.',
    example:
      'A profile update accepting an `isAdmin` field that the user interface never sends but the server binds.',
    automation: 'assisted',
    tools: ['arjun', 'zap'],
    standards: {
      wstg: ['WSTG-ATHZ-03'],
      asvs: ['v5.0.0-2.2.1'],
      owaspTop10: ['A01:2025'],
      apiTop10: ['API3:2023'],
      cwe: [915, 269],
    },
  },
  {
    id: 'web-ssrf',
    title: 'Server-side request forgery',
    category: 'accessControl',
    modules: ['web', 'api'],
    description:
      'Test any feature that fetches a URL — webhooks, image imports, PDF renderers, link previews, integrations — for the ability to reach internal services and cloud metadata endpoints. Interaction is confirmed out of band without exfiltrating data.',
    example:
      'A webhook test button that will fetch the cloud metadata endpoint and return the instance role credentials in the response body.',
    automation: 'assisted',
    tools: ['zap', 'nuclei'],
    standards: {
      wstg: ['WSTG-INPV-19'],
      asvs: ['v5.0.0-2.4.1'],
      owaspTop10: ['A01:2025'],
      apiTop10: ['API7:2023'],
      cwe: [918],
    },
  },
  {
    id: 'web-file-upload-authorisation',
    title: 'Uploaded file access control',
    category: 'accessControl',
    modules: ['web'],
    description:
      'Check whether uploaded files are served from a predictable path, whether access to them is authorised, and whether the identifier can be enumerated.',
    example:
      'Uploaded identity documents stored under sequential filenames on a path with no authorisation check.',
    automation: 'assisted',
    tools: ['zap', 'ffuf'],
    standards: {
      wstg: ['WSTG-BUSL-09'],
      asvs: ['v5.0.0-5.2.1'],
      owaspTop10: ['A01:2025'],
      cwe: [552, 639],
    },
  },

  /* Input validation ------------------------------------------------------------------------- */
  {
    id: 'web-sql-injection',
    title: 'SQL injection',
    category: 'inputValidation',
    modules: ['web', 'api'],
    description:
      'Test every parameter for SQL injection including blind, time-based and second-order variants. Confirmation is read-only: no destructive statement is ever issued and no bulk data is extracted.',
    example:
      'A sort parameter concatenated into an ORDER BY clause, allowing the whole customer table to be read one boolean at a time.',
    automation: 'assisted',
    tools: ['sqlmap', 'zap', 'nuclei'],
    standards: {
      wstg: ['WSTG-INPV-05'],
      asvs: ['v5.0.0-1.2.1'],
      owaspTop10: ['A05:2025'],
      cwe: [89],
    },
  },
  {
    id: 'web-nosql-injection',
    title: 'NoSQL and ORM injection',
    category: 'inputValidation',
    modules: ['web', 'api'],
    description:
      'Test JSON parameters for operator injection and type confusion against document stores and query builders.',
    example:
      'A login endpoint accepting `{"password": {"$ne": null}}` and authenticating without a password.',
    automation: 'assisted',
    tools: ['zap', 'nuclei'],
    standards: { wstg: ['WSTG-INPV-05'], owaspTop10: ['A05:2025'], cwe: [943] },
  },
  {
    id: 'web-command-injection',
    title: 'OS command injection',
    category: 'inputValidation',
    modules: ['web', 'api'],
    description:
      'Test parameters that reach system utilities — conversion, archiving, network diagnostics, report generation — for command injection, confirmed with a non-destructive out-of-band signal.',
    example:
      'A PDF export feature passing a filename to a shell, allowing arbitrary commands as the application user.',
    automation: 'assisted',
    tools: ['commix', 'zap', 'nuclei'],
    standards: {
      wstg: ['WSTG-INPV-12'],
      asvs: ['v5.0.0-1.2.3'],
      owaspTop10: ['A05:2025'],
      cwe: [78, 77],
    },
  },
  {
    id: 'web-reflected-xss',
    title: 'Reflected cross-site scripting',
    category: 'inputValidation',
    modules: ['web'],
    description:
      'Test reflected parameters across HTML, attribute, JavaScript, URL and CSS contexts, including DOM sinks reached only after client-side routing.',
    example:
      'A search term reflected into an inline script block, executable through a link sent to a logged-in administrator.',
    automation: 'automated',
    tools: ['dalfox', 'zap', 'nuclei'],
    standards: {
      wstg: ['WSTG-INPV-01'],
      asvs: ['v5.0.0-1.3.1'],
      owaspTop10: ['A05:2025'],
      cwe: [79],
    },
  },
  {
    id: 'web-stored-xss',
    title: 'Stored cross-site scripting',
    category: 'inputValidation',
    modules: ['web'],
    description:
      'Submit benign markers through every persistence path — profiles, comments, uploads, filenames, imported data, webhook payloads — and check where they are rendered, including in administrative views.',
    example:
      'A support ticket subject rendered unescaped in the staff console, so a customer can run script in an agent\'s session.',
    automation: 'assisted',
    tools: ['zap', 'playwright'],
    standards: {
      wstg: ['WSTG-INPV-02'],
      asvs: ['v5.0.0-1.3.1'],
      owaspTop10: ['A05:2025'],
      cwe: [79],
    },
  },
  {
    id: 'web-dom-xss',
    title: 'DOM-based cross-site scripting',
    category: 'clientSide',
    modules: ['web'],
    description:
      'Trace client-side sources to sinks in the application\'s own JavaScript, including framework-specific sinks and unsafe use of template rendering.',
    example:
      'A single-page application writing a URL fragment into `innerHTML` to restore scroll position.',
    automation: 'assisted',
    tools: ['dalfox', 'playwright'],
    standards: {
      wstg: ['WSTG-CLNT-01'],
      asvs: ['v5.0.0-3.1.1'],
      owaspTop10: ['A05:2025'],
      cwe: [79],
    },
  },
  {
    id: 'web-template-injection',
    title: 'Server-side template injection',
    category: 'inputValidation',
    modules: ['web'],
    description:
      'Test parameters that reach a template engine — email templates, report headers, custom messages — for expression evaluation.',
    example:
      'A configurable invoice footer evaluated by the template engine, giving code execution on the server.',
    automation: 'assisted',
    tools: ['zap', 'nuclei'],
    standards: { wstg: ['WSTG-INPV-18'], owaspTop10: ['A05:2025'], cwe: [1336, 94] },
  },
  {
    id: 'web-xxe',
    title: 'XML external entity processing',
    category: 'inputValidation',
    modules: ['web', 'api'],
    description:
      'Test XML, SVG, DOCX, XLSX and SAML handling paths for external entity resolution and for entity expansion limits.',
    example:
      'An invoice import that resolves external entities, allowing local files to be read from the application server.',
    automation: 'assisted',
    tools: ['zap', 'nuclei'],
    standards: {
      wstg: ['WSTG-INPV-07'],
      asvs: ['v5.0.0-1.5.1'],
      owaspTop10: ['A05:2025'],
      cwe: [611, 776],
    },
  },
  {
    id: 'web-deserialisation',
    title: 'Insecure deserialisation',
    category: 'inputValidation',
    modules: ['web', 'api'],
    description:
      'Identify serialised objects in cookies, hidden fields, caches and message queues, and test whether they are deserialised without type restriction or integrity checking.',
    example:
      'A signed-but-not-encrypted view state whose signing key is the framework default, allowing arbitrary object graphs to be submitted.',
    // ZAP's release passive rules find serialised Java objects and view state wherever they appear
    // in traffic, which is the discovery half. Whether the endpoint deserialises them without a type
    // restriction is the half a person still has to establish.
    automation: 'assisted',
    tools: ['zap'],
    standards: {
      wstg: ['WSTG-INPV-11'],
      asvs: ['v5.0.0-15.2.1'],
      owaspTop10: ['A08:2025'],
      cwe: [502],
    },
  },
  {
    id: 'web-file-upload-handling',
    title: 'File upload handling',
    category: 'inputValidation',
    modules: ['web'],
    description:
      'Test type validation, content inspection, filename handling, size limits, archive expansion, image processing libraries and whether an uploaded file can be executed or served as active content.',
    example:
      'An avatar upload accepting an SVG that is served inline with the site origin, giving stored cross-site scripting.',
    automation: 'assisted',
    tools: ['zap', 'playwright'],
    standards: {
      wstg: ['WSTG-BUSL-08', 'WSTG-BUSL-09'],
      asvs: ['v5.0.0-5.2.2'],
      owaspTop10: ['A05:2025'],
      cwe: [434, 646],
    },
  },
  {
    id: 'web-open-redirect',
    title: 'Open redirection',
    category: 'inputValidation',
    modules: ['web'],
    description:
      'Test redirect parameters on login, logout, checkout and interstitial pages for redirection to external hosts, including protocol-relative and encoded bypasses.',
    example:
      'A `returnUrl` on the login page that will send an authenticated user to a lookalike domain immediately after sign-in.',
    automation: 'automated',
    tools: ['zap', 'nuclei'],
    standards: { wstg: ['WSTG-CLNT-04'], owaspTop10: ['A01:2025'], cwe: [601] },
  },
  {
    id: 'web-header-injection',
    title: 'HTTP header and response splitting',
    category: 'inputValidation',
    modules: ['web'],
    description:
      'Test whether user input reaches response headers, allowing header injection, cookie setting or response splitting.',
    example:
      'A language parameter written into a Set-Cookie header, permitting an attacker-chosen cookie to be planted.',
    automation: 'automated',
    tools: ['zap', 'nuclei'],
    // Response splitting is the second half of WSTG-INPV-15. It previously claimed INPV-16, which
    // is reviewing the application's own inbound traffic — a monitoring exercise inside the client's
    // infrastructure that this check has never performed and that the register records as such.
    standards: { wstg: ['WSTG-INPV-15'], owaspTop10: ['A05:2025'], cwe: [113, 93] },
  },
  {
    id: 'web-request-smuggling',
    title: 'HTTP request smuggling and desynchronisation',
    category: 'infrastructure',
    modules: ['web'],
    description:
      'Where a proxy or CDN fronts the application, test for differences in how the front end and back end parse request boundaries. Confirmation is timing-based and stops before any request is affected.',
    example:
      'A CDN and origin disagreeing on Transfer-Encoding, allowing a request to be prefixed onto another user\'s connection.',
    automation: 'manual',
    tools: [],
    standards: { wstg: ['WSTG-INPV-15'], owaspTop10: ['A02:2025'], cwe: [444] },
  },
  {
    id: 'web-ldap-injection',
    title: 'LDAP and directory injection',
    category: 'inputValidation',
    modules: ['web'],
    description:
      'Test directory-backed authentication and search functionality for filter injection.',
    example:
      'A staff directory search allowing a wildcard filter that returns every attribute of every user.',
    automation: 'assisted',
    tools: ['zap'],
    standards: { wstg: ['WSTG-INPV-06'], owaspTop10: ['A05:2025'], cwe: [90] },
  },
  {
    id: 'web-mass-assignment',
    title: 'Mass assignment and object property binding',
    category: 'inputValidation',
    modules: ['web', 'api'],
    description:
      'Discover hidden parameters and test whether the server binds fields the client should not control, using response bodies and related endpoints to find candidate field names.',
    example:
      'A signup endpoint binding `emailVerified: true`, skipping the verification the whole flow depends on.',
    automation: 'assisted',
    tools: ['arjun', 'zap'],
    standards: {
      wstg: ['WSTG-INPV-20'],
      asvs: ['v5.0.0-2.2.2'],
      owaspTop10: ['A01:2025'],
      apiTop10: ['API3:2023'],
      cwe: [915],
    },
  },
  {
    id: 'web-formula-injection',
    title: 'CSV and spreadsheet formula injection',
    category: 'inputValidation',
    modules: ['web'],
    description:
      'Check whether user input exported to CSV or spreadsheet formats is neutralised, since a formula in an exported cell executes on the machine of whoever opens it.',
    example:
      'A customer name field containing a formula that runs when the finance team opens the monthly export.',
    automation: 'assisted',
    tools: ['zap'],
    standards: { wstg: ['WSTG-CLNT-13'], owaspTop10: ['A05:2025'], cwe: [1236] },
  },
  {
    id: 'web-prototype-pollution',
    title: 'Prototype pollution',
    category: 'clientSide',
    modules: ['web', 'api'],
    description:
      'Test client and server code paths that merge untrusted objects for prototype pollution, and follow it to a usable gadget where one exists.',
    example:
      'A query-string parser that pollutes the object prototype, turning a benign template into script execution.',
    automation: 'assisted',
    tools: ['dalfox', 'playwright'],
    standards: { wstg: ['WSTG-CLNT-13'], owaspTop10: ['A05:2025'], cwe: [1321] },
  },

  /* Business logic --------------------------------------------------------------------------- */
  {
    id: 'web-workflow-bypass',
    title: 'Workflow and process bypass',
    category: 'businessLogic',
    modules: ['web'],
    description:
      'Complete each multi-step process out of order, skip steps, repeat steps, and resume an abandoned process, to find states the application does not expect.',
    example:
      'Reaching order confirmation without passing payment, because the confirmation step only checks that an order exists.',
    automation: 'manual',
    tools: [],
    standards: {
      wstg: ['WSTG-BUSL-06', 'WSTG-BUSL-07'],
      asvs: ['v5.0.0-2.3.1'],
      owaspTop10: ['A06:2025'],
      cwe: [841, 840],
    },
  },
  {
    id: 'web-price-and-quantity-manipulation',
    title: 'Price, quantity and discount manipulation',
    category: 'businessLogic',
    modules: ['web'],
    description:
      'Test whether prices, quantities, currencies, shipping costs, tax and discounts are recalculated server-side, and what happens with negative, zero, fractional and very large values.',
    example:
      'A negative quantity on a returns line producing a credit larger than the original order.',
    automation: 'manual',
    tools: [],
    standards: {
      wstg: ['WSTG-BUSL-01', 'WSTG-BUSL-02'],
      owaspTop10: ['A06:2025'],
      cwe: [840, 20],
    },
  },
  {
    id: 'web-coupon-and-promotion-abuse',
    title: 'Coupon and promotion abuse',
    category: 'businessLogic',
    modules: ['web'],
    description:
      'Test stacking, reuse, expiry, per-customer limits, and whether a promotion can be applied after the order total is fixed.',
    example:
      'A single-use referral credit that can be applied repeatedly by adding it in separate concurrent requests.',
    automation: 'manual',
    tools: [],
    standards: { wstg: ['WSTG-BUSL-02'], owaspTop10: ['A06:2025'], cwe: [840] },
  },
  {
    id: 'web-race-conditions',
    title: 'Race conditions on limited resources',
    category: 'businessLogic',
    modules: ['web', 'api'],
    description:
      'Issue tightly grouped concurrent requests against operations that consume a limited resource — balance, stock, credits, one-time tokens, invitations — to test whether the limit holds. Concurrency is bounded and never approaches a volumetric level.',
    example:
      'Two simultaneous withdrawal requests both passing the balance check, overdrawing the account.',
    automation: 'manual',
    tools: [],
    standards: {
      wstg: ['WSTG-BUSL-01'],
      asvs: ['v5.0.0-2.3.2'],
      owaspTop10: ['A06:2025'],
      cwe: [362, 367],
    },
  },
  {
    id: 'web-function-limit-testing',
    title: 'Function and transaction limits',
    category: 'businessLogic',
    modules: ['web'],
    description:
      'Test whether limits stated in the interface — maximum transfer, maximum recipients, maximum uploads — are enforced on the server.',
    example:
      'A daily transfer limit enforced only in the browser, so the underlying endpoint accepts any amount.',
    automation: 'manual',
    tools: [],
    standards: { wstg: ['WSTG-BUSL-03'], owaspTop10: ['A06:2025'], cwe: [840] },
  },
  {
    id: 'web-integrity-of-uploaded-data',
    title: 'Integrity checks on submitted data',
    category: 'businessLogic',
    modules: ['web'],
    description:
      'Test whether the application accepts data that is internally inconsistent, such as a date of birth in the future or a total that does not match its line items.',
    example:
      'An expense claim whose stated total is accepted without being recomputed from the attached items.',
    automation: 'manual',
    tools: [],
    standards: { wstg: ['WSTG-BUSL-03'], owaspTop10: ['A06:2025'], cwe: [345] },
  },
  {
    id: 'web-sensitive-business-flow-abuse',
    title: 'Automated abuse of sensitive business flows',
    category: 'businessLogic',
    modules: ['web', 'api'],
    description:
      'Identify flows whose value depends on being used by a human at human speed — ticket purchase, referral credit, appointment booking, review posting — and check what actually prevents scripted use.',
    example:
      'An appointment booking flow with no protection, letting one script hold every available slot.',
    automation: 'manual',
    tools: [],
    standards: {
      wstg: ['WSTG-BUSL-05'],
      owaspTop10: ['A06:2025'],
      apiTop10: ['API6:2023'],
      cwe: [799, 837],
    },
  },
  {
    id: 'web-finding-chaining',
    title: 'Chaining of low-severity findings',
    category: 'businessLogic',
    modules: ['web', 'api'],
    description:
      'Work through what several individually minor findings become in combination, and write the resulting path up as an attack narrative with the real business outcome.',
    example:
      'Account enumeration plus a verbose error plus a weak reset token becoming a reliable account takeover.',
    automation: 'manual',
    tools: [],
    standards: { owaspTop10: ['A06:2025'], cwe: [1120] },
  },

  /* Cryptography and data protection --------------------------------------------------------- */
  {
    id: 'web-sensitive-data-in-transit',
    title: 'Sensitive data exposure in transit',
    category: 'cryptography',
    modules: ['web', 'api'],
    description:
      'Check for sensitive values in URLs, referrer headers, logs and third-party requests, where transport encryption does not protect them from being recorded.',
    example:
      'A password reset token in the query string, which is then sent to an analytics vendor in the referrer header.',
    automation: 'assisted',
    tools: ['zap', 'playwright'],
    standards: {
      wstg: ['WSTG-CRYP-03'],
      asvs: ['v5.0.0-14.1.1'],
      owaspTop10: ['A04:2025'],
      cwe: [598, 200],
    },
  },
  {
    id: 'web-weak-cryptographic-storage',
    title: 'Weak cryptographic storage',
    category: 'cryptography',
    modules: ['web', 'code'],
    description:
      'Where source or configuration is available, check password hashing algorithm and parameters, encryption modes, initialisation vector handling and key storage.',
    example:
      'Passwords stored as unsalted SHA-1, so a database disclosure is an immediate credential disclosure.',
    automation: 'assisted',
    tools: ['semgrep'],
    standards: {
      wstg: ['WSTG-CRYP-04'],
      asvs: ['v5.0.0-11.2.1'],
      owaspTop10: ['A04:2025'],
      cwe: [916, 327],
    },
  },
  {
    id: 'web-padding-oracle',
    title: 'Padding oracle and ciphertext manipulation',
    category: 'cryptography',
    modules: ['web'],
    description:
      'Where the application accepts ciphertext from the client, test whether error behaviour distinguishes padding failures from decryption failures.',
    example:
      'An encrypted-but-unauthenticated identifier in a URL that can be altered a byte at a time to reach another record.',
    // ZAP's release active rules include a generic padding oracle test, and the plan we generate
    // runs the full release policy. Confirming that the oracle is usable against a real identifier
    // is still a person's work, which is what keeps this assisted rather than automated.
    automation: 'assisted',
    tools: ['zap'],
    standards: { wstg: ['WSTG-CRYP-02'], owaspTop10: ['A04:2025'], cwe: [209, 649] },
  },
  {
    id: 'web-randomness',
    title: 'Use of predictable randomness',
    category: 'cryptography',
    modules: ['web', 'code'],
    description:
      'Check that identifiers used for security purposes — tokens, invitation codes, filenames, reset links — come from a cryptographic source.',
    example:
      'Invitation codes generated from a timestamp seed, so codes issued in the same second are guessable.',
    automation: 'assisted',
    tools: ['semgrep'],
    standards: {
      wstg: ['WSTG-CRYP-04'],
      asvs: ['v5.0.0-11.4.1'],
      owaspTop10: ['A04:2025'],
      cwe: [330, 338],
    },
  },

  /* Error handling and logging --------------------------------------------------------------- */
  {
    id: 'web-error-handling',
    title: 'Error handling and information disclosure',
    category: 'errorHandling',
    modules: ['web', 'api'],
    description:
      'Trigger error conditions across the application and check what is disclosed: stack traces, framework versions, internal hostnames, SQL fragments, file paths.',
    example:
      'A stack trace on malformed input revealing the ORM, the schema and the internal service hostname.',
    automation: 'automated',
    tools: ['zap', 'nuclei'],
    standards: {
      wstg: ['WSTG-ERRH-01'],
      asvs: ['v5.0.0-16.2.1'],
      owaspTop10: ['A10:2025'],
      cwe: [209, 200],
    },
  },
  {
    id: 'web-failure-mode-review',
    title: 'Behaviour under failure of a dependency',
    category: 'errorHandling',
    modules: ['web', 'api'],
    description:
      'Check what the application does when an authorisation service, payment provider or feature flag service is unavailable: whether it fails closed or open.',
    example:
      'An entitlement check that grants access when the entitlement service times out.',
    automation: 'manual',
    tools: [],
    standards: {
      wstg: ['WSTG-ERRH-02'],
      asvs: ['v5.0.0-16.1.1'],
      owaspTop10: ['A10:2025'],
      cwe: [636, 703],
    },
  },
  {
    id: 'web-security-logging',
    title: 'Security event logging and alerting',
    category: 'errorHandling',
    modules: ['web'],
    description:
      'Check whether authentication failures, privilege changes, exports and administrative actions are logged with enough context to investigate, and whether logs capture data they should not.',
    example:
      'Successful logins logged but privilege changes not, so an escalation leaves no trace.',
    automation: 'manual',
    tools: [],
    standards: {
      wstg: ['WSTG-ERRH-01'],
      asvs: ['v5.0.0-16.3.1'],
      owaspTop10: ['A09:2025'],
      cwe: [778, 532],
    },
  },

  /* Client-side ------------------------------------------------------------------------------ */
  {
    id: 'web-clickjacking',
    title: 'Clickjacking and UI redress',
    category: 'clientSide',
    modules: ['web'],
    description:
      'Check framing protection on sensitive pages, and whether a framed sensitive action can be triggered by a disguised click.',
    example:
      'A "delete workspace" confirmation that can be framed and covered with a decoy interface.',
    automation: 'automated',
    tools: ['zap', 'nuclei'],
    standards: { wstg: ['WSTG-CLNT-09'], owaspTop10: ['A02:2025'], cwe: [1021] },
  },
  {
    id: 'web-postmessage-handling',
    title: 'Cross-origin messaging',
    category: 'clientSide',
    modules: ['web'],
    description:
      'Check that message listeners validate the origin and the message shape, and that messages containing tokens are not sent to a wildcard target.',
    example:
      'A payment widget posting the session token to `*`, readable by any embedding page.',
    automation: 'manual',
    tools: [],
    standards: { wstg: ['WSTG-CLNT-11'], owaspTop10: ['A01:2025'], cwe: [346, 942] },
  },
  {
    id: 'web-client-side-storage',
    title: 'Client-side storage of sensitive data',
    category: 'clientSide',
    modules: ['web'],
    description:
      'Inspect local storage, session storage, IndexedDB and service worker caches for tokens, personal data and business data that survives logout.',
    example:
      'Access tokens in local storage that remain after logout on a shared machine.',
    automation: 'manual',
    tools: [],
    standards: {
      wstg: ['WSTG-CLNT-12'],
      asvs: ['v5.0.0-3.2.1'],
      owaspTop10: ['A04:2025'],
      cwe: [922, 525],
    },
  },
  {
    id: 'web-websocket-security',
    title: 'WebSocket security',
    category: 'clientSide',
    modules: ['web', 'api'],
    description:
      'Check origin validation on the upgrade request, authentication and authorisation of individual messages, and whether the same access control applies as on the HTTP API.',
    example:
      'A WebSocket that authenticates at connect time and then trusts every message, including messages naming another user.',
    automation: 'assisted',
    tools: ['zap'],
    standards: { wstg: ['WSTG-CLNT-10'], owaspTop10: ['A01:2025'], cwe: [346, 285] },
  },
  {
    id: 'web-browser-storage-of-secrets-in-source-maps',
    title: 'Source maps and build artefacts in production',
    category: 'clientSide',
    modules: ['web'],
    description:
      'Check whether source maps, unminified bundles or development builds are served in production, exposing internal logic and comments.',
    example:
      'Production source maps disclosing an internal admin API and the names of unreleased features.',
    automation: 'automated',
    tools: ['nuclei', 'katana'],
    standards: { wstg: ['WSTG-CONF-04'], owaspTop10: ['A02:2025'], cwe: [540] },
  },
  {
    id: 'web-rate-limit-effectiveness',
    title: 'Rate limiting on sensitive endpoints',
    category: 'configuration',
    modules: ['web', 'api'],
    description:
      'Measure how many requests are accepted before throttling on login, OTP request, password reset, signup and search, and test whether the limit is bypassed by header, method, casing or path variation. Bounded attempts, stopped at the first throttle response.',
    example:
      'An OTP resend endpoint with no limit, allowing an attacker to exhaust the victim\'s SMS quota and to brute force a six-digit code.',
    automation: 'assisted',
    tools: ['rateLimitProbe'],
    standards: {
      wstg: ['WSTG-BUSL-05'],
      asvs: ['v5.0.0-2.3.3'],
      owaspTop10: ['A07:2025'],
      apiTop10: ['API4:2023'],
      cwe: [770, 307],
    },
  },

  /* Tests the platform performs and never used to claim ------------------------------------- *
   *                                                                                            *
   * Each of these was a gap in the WSTG footprint while the tool that performs it was already   *
   * running on every engagement. They are new claims rather than new work: the rule named        *
   * against each one is in ZAP's release set, and the plan the adapter generates runs the full   *
   * release policy with only the denial-of-service rules turned off.                             */
  {
    id: 'web-parameter-pollution',
    title: 'HTTP parameter pollution',
    category: 'inputValidation',
    modules: ['web', 'api'],
    description:
      'Send the same parameter twice and establish which copy the application acts on, because the layers in front of it do not have to agree. A gateway, a WAF and a framework can each read a different one, so the value that is inspected is not always the value that is used.',
    example:
      'A checkout that reads the last `amount` while the fraud rule in front of it reads the first, so a request carrying both passes inspection at one price and is charged at another.',
    automation: 'automated',
    tools: ['requestManipulationProbe'],
    standards: {
      wstg: ['WSTG-INPV-04'],
      owaspTop10: ['A03:2025'],
      cwe: [235],
    },
  },
  {
    id: 'web-server-side-includes',
    title: 'Server-side include injection',
    category: 'inputValidation',
    modules: ['web'],
    description:
      'Test whether input written into a page is processed by the server as a server-side include directive before the page is sent, which turns a reflected value into file disclosure or command execution.',
    example:
      'A search term echoed into an `.shtml` page where an `exec cmd` directive is run by the server rather than displayed.',
    automation: 'automated',
    tools: ['zap'],
    standards: {
      wstg: ['WSTG-INPV-08'],
      owaspTop10: ['A03:2025'],
      cwe: [97],
    },
  },
  {
    id: 'web-xpath-injection',
    title: 'XPath injection',
    category: 'inputValidation',
    modules: ['web', 'api'],
    description:
      'Where a query runs against an XML document rather than a database, test whether input alters the query rather than being compared by it. The authentication bypass shape is identical to SQL injection and the defence is not, because XPath has no prepared statement.',
    example:
      'A login that selects a user node by concatenating the submitted name, so an always-true predicate returns the first account in the document.',
    automation: 'assisted',
    tools: ['zap'],
    standards: {
      wstg: ['WSTG-INPV-09'],
      owaspTop10: ['A03:2025'],
      cwe: [643],
    },
  },
  {
    id: 'web-format-string-injection',
    title: 'Format string injection',
    category: 'inputValidation',
    modules: ['web', 'api'],
    description:
      'Test whether user input reaches a formatting function as the format itself rather than as an argument, which discloses memory or crashes the process depending on the runtime.',
    example:
      'A username passed straight to a logging call as the format string, so a run of conversion specifiers reads adjacent memory into the log.',
    automation: 'assisted',
    tools: ['zap'],
    standards: {
      wstg: ['WSTG-INPV-13'],
      owaspTop10: ['A03:2025'],
      cwe: [134],
    },
  },
  {
    id: 'web-exposed-session-variables',
    title: 'Session identifiers and sensitive values in URLs',
    category: 'sessionManagement',
    modules: ['web', 'api'],
    description:
      'Look for session identifiers, tokens and other sensitive values carried in the query string rather than in a header or a cookie. Anything in a URL reaches the browser history, the Referer header of every outbound link, and every proxy and access log on the path.',
    example:
      'A session id appended to every link, so following an external link hands the session to that site in the Referer header.',
    automation: 'automated',
    tools: ['zap'],
    standards: {
      wstg: ['WSTG-SESS-04'],
      asvs: ['v5.0.0-3.1.1'],
      owaspTop10: ['A02:2025'],
      cwe: [598],
    },
  },
  {
    id: 'web-reverse-tabnabbing',
    title: 'Reverse tabnabbing on outbound links',
    category: 'clientSide',
    modules: ['web'],
    description:
      'Find links and window openers that give the destination a handle back to the page that opened it. The destination can then navigate the original tab to a page of its choosing, which the user returns to believing they never left it.',
    example:
      'A user-submitted profile link opening in a new tab without `rel="noopener"`, letting the linked site replace the original tab with a copy of the login page.',
    automation: 'automated',
    tools: ['zap'],
    standards: {
      wstg: ['WSTG-CLNT-14'],
      owaspTop10: ['A04:2025'],
      cwe: [1022],
    },
  },
  {
    id: 'web-html-injection',
    title: 'HTML injection',
    category: 'clientSide',
    modules: ['web'],
    description:
      'Test whether input is written into the page as markup rather than as text, short of script execution. Content injection alone is enough to forge a login form, deface a page, or rewrite the destination of a form the user already trusts.',
    example:
      'A name field rendered unescaped, allowing an injected form that overlays the real one and posts the password elsewhere.',
    automation: 'assisted',
    tools: ['zap', 'dalfox'],
    standards: {
      wstg: ['WSTG-CLNT-03'],
      owaspTop10: ['A03:2025'],
      cwe: [80],
    },
  },
  {
    id: 'web-client-side-javascript-execution',
    title: 'Client-side JavaScript execution from controllable input',
    category: 'clientSide',
    modules: ['web'],
    description:
      'Find places where input reaches a JavaScript event handler, an inline attribute or a dynamic evaluation, so the page runs code chosen by the requester without a script tag ever appearing in the response.',
    example:
      'A redirect parameter written into an `onclick` attribute, so the value becomes an expression the browser evaluates.',
    automation: 'assisted',
    tools: ['zap'],
    standards: {
      wstg: ['WSTG-CLNT-02'],
      owaspTop10: ['A03:2025'],
      cwe: [95],
    },
  },
  {
    id: 'web-client-side-resource-manipulation',
    title: 'Client-side resource manipulation',
    category: 'clientSide',
    modules: ['web'],
    description:
      'Test whether the requester can choose which resource the page loads or where it sends the user: a script source, a stylesheet, an iframe target, a character set, or a redirect built from a value the client supplied.',
    example:
      'A theme parameter used as the `src` of a script tag, so the page loads code from a host the requester names.',
    automation: 'assisted',
    tools: ['zap'],
    standards: {
      wstg: ['WSTG-CLNT-06'],
      owaspTop10: ['A03:2025'],
      cwe: [601, 829],
    },
  },

  /* Guide tests the platform holds as work a person does ------------------------------------- *
   *                                                                                             *
   * Each is a WSTG test with no tool behind it. They were absent from the catalogue entirely,    *
   * which meant a report simply did not mention them; holding them as manual work is the honest  *
   * arrangement, and `appliesWhen` keeps the ones that need a feature from being counted against  *
   * a target that does not have it.                                                              */
  {
    id: 'web-platform-configuration',
    title: 'Application platform configuration',
    category: 'configuration',
    modules: ['web'],
    description:
      'Check what the platform shipped with and nobody removed: sample applications, documentation trees, installer and setup routes, framework debug modes, directory listing, and the default pages that name the exact build in use.',
    example:
      'A framework profiler route left enabled in production, listing every environment variable including the database password.',
    automation: 'assisted',
    tools: ['nuclei', 'ffuf'],
    standards: { wstg: ['WSTG-CONF-02'], owaspTop10: ['A05:2025'], cwe: [16, 1188] },
  },
  {
    id: 'web-path-confusion',
    title: 'Path confusion and route resolution',
    category: 'configuration',
    modules: ['web', 'api'],
    description:
      'Test whether the proxy, the framework and the file server agree about what a path means. Matrix parameters, encoded separators, trailing suffixes and double slashes are each read differently by different layers, and where they disagree an authorisation rule applied by one is not applied by the other.',
    example:
      'A gateway rule protecting `/admin` that does not match `/admin;x=1`, which the application routes to the same handler.',
    automation: 'manual',
    tools: [],
    standards: { wstg: ['WSTG-CONF-13'], owaspTop10: ['A01:2025'], cwe: [22, 436] },
  },
  {
    id: 'web-file-permissions',
    title: 'File and directory permissions on the host',
    category: 'configuration',
    modules: ['web'],
    description:
      'Where the engagement includes host access, review the ownership and mode of configuration files, key material, log directories and the deployment tree, and establish which of them the application user could modify. Needs access to the host, so it belongs to an internal or configuration-review engagement rather than to a black-box one.',
    example:
      'A world-readable configuration file holding the database password, on a host where several unrelated services run as different users.',
    automation: 'manual',
    tools: [],
    standards: { wstg: ['WSTG-CONF-09'], owaspTop10: ['A05:2025'], cwe: [732] },
  },
  {
    id: 'web-role-definitions',
    title: 'Role definitions and the permission model',
    category: 'accessControl',
    modules: ['web', 'api'],
    description:
      'Establish which roles exist, what each is meant to be able to do, and whether the model is documented anywhere the developers actually read. Without it the access control testing has nothing to compare an observation against, and "this account could reach that record" is an observation rather than a finding.',
    example:
      'A support role documented as read-only that has held write access to customer records since a migration nobody reviewed.',
    automation: 'manual',
    tools: [],
    standards: { wstg: ['WSTG-IDNT-01'], owaspTop10: ['A01:2025'], cwe: [1220] },
  },
  {
    id: 'web-username-policy',
    title: 'Username policy and account identifier handling',
    category: 'authentication',
    modules: ['web'],
    description:
      'Check whether usernames are predictable, whether the application enforces uniqueness in a form the user can see, and whether visually confusable or whitespace-padded identifiers can be registered to impersonate an existing account.',
    example:
      'A registration form that accepts a name differing from an administrator only by a Cyrillic character, which renders identically in the interface.',
    automation: 'manual',
    tools: [],
    appliesWhen: ['registration'],
    standards: { wstg: ['WSTG-IDNT-05'], owaspTop10: ['A07:2025'], cwe: [521, 1007] },
  },
  {
    id: 'web-alternative-channel-authentication',
    title: 'Authentication on alternative channels',
    category: 'authentication',
    modules: ['web', 'api'],
    description:
      'Find the other doors into the same account: a mobile application, a legacy interface, a partner or support console, an interactive voice system, an older API version. Each has to enforce what the main interface enforces, and the weakest one sets the real strength of the authentication.',
    example:
      'A legacy mobile endpoint that still accepts a password with no second factor, months after the web interface began requiring one.',
    automation: 'manual',
    tools: [],
    standards: { wstg: ['WSTG-ATHN-10'], owaspTop10: ['A07:2025'], cwe: [287, 305] },
  },
  {
    id: 'web-session-hijacking',
    title: 'Session hijacking exposure',
    category: 'sessionManagement',
    modules: ['web'],
    description:
      'Take the whole path a session identifier travels and establish where a third party could obtain it: an unencrypted hop, a cookie scoped wider than the application, a value written into a log or a URL, a subdomain able to set cookies for the parent. Then confirm whether a stolen identifier is usable from another address and another browser.',
    example:
      'A session cookie scoped to the registrable domain, so a marketing subdomain run by an agency can read it.',
    automation: 'manual',
    tools: [],
    standards: { wstg: ['WSTG-SESS-09'], owaspTop10: ['A07:2025'], cwe: [384, 614] },
  },
  {
    id: 'web-mail-header-injection',
    title: 'IMAP and SMTP injection through mail features',
    category: 'inputValidation',
    modules: ['web', 'api'],
    description:
      'Where the application sends or reads mail on the user behalf, test whether input reaches the protocol as a command or a header rather than as content, which lets a requester add recipients, forge headers, or reach the mail server directly.',
    example:
      'A contact form that writes the submitted subject into the message headers unfiltered, allowing an extra Bcc line to be added.',
    automation: 'manual',
    tools: [],
    standards: { wstg: ['WSTG-INPV-10'], owaspTop10: ['A03:2025'], cwe: [93, 88] },
  },
  {
    id: 'web-incubated-vulnerabilities',
    title: 'Incubated and delayed-execution vulnerabilities',
    category: 'inputValidation',
    modules: ['web'],
    description:
      'Test the payloads that do nothing when submitted and fire later, somewhere else: content stored now and rendered in an administrative console tomorrow, a filename read by a batch job, a value that reaches a report generator or a mail template. The submission is harmless and the execution happens under somebody else identity.',
    example:
      'A delivery note field rendered unescaped in the warehouse console, so the payload runs with a staff session rather than the submitter one.',
    automation: 'manual',
    tools: [],
    standards: { wstg: ['WSTG-INPV-14'], owaspTop10: ['A03:2025'], cwe: [79, 74] },
  },
  {
    id: 'web-css-injection',
    title: 'CSS injection',
    category: 'clientSide',
    modules: ['web'],
    description:
      'Test whether input reaches a stylesheet or a style attribute. Style alone is enough to read a page a character at a time through attribute selectors and background requests, to overlay a control the user is about to click, and to make a page claim something it does not say.',
    example:
      'A theme colour written straight into a style block, allowing a selector that leaks the value of a hidden anti-forgery token one character per request.',
    automation: 'manual',
    tools: [],
    standards: { wstg: ['WSTG-CLNT-05'], owaspTop10: ['A03:2025'], cwe: [79, 116] },
  },
  {
    id: 'web-process-timing',
    title: 'Process timing and ordering',
    category: 'businessLogic',
    modules: ['web', 'api'],
    description:
      'Measure what the time a response takes reveals, and what happens when the steps of a process arrive in an order the designer did not expect: a step skipped, repeated, or replayed after the window it belonged to.',
    example:
      'A login that answers measurably faster for an account that does not exist, giving an enumeration oracle that the error text carefully avoids.',
    automation: 'manual',
    tools: [],
    standards: { wstg: ['WSTG-BUSL-04'], owaspTop10: ['A04:2025'], cwe: [208, 841] },
  },
  {
    id: 'web-payment-flow',
    title: 'Payment flow integrity',
    category: 'businessLogic',
    modules: ['web', 'api'],
    description:
      'Follow the money through the application: where the amount is decided, whether the client can influence it, whether the confirmation the payment provider sends back is verified rather than trusted, and whether an order can be completed without a settled payment. Tested only against a sandbox or a staging provider, never against live settlement.',
    example:
      'An order marked paid on the browser redirect back from the provider, without checking the signed server-to-server notification that follows it.',
    automation: 'manual',
    tools: [],
    appliesWhen: ['payment'],
    standards: { wstg: ['WSTG-BUSL-10'], owaspTop10: ['A04:2025'], cwe: [602, 840] },
  },
];
