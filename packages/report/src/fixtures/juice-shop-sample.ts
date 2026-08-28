import type { Finding } from '@attestor/findings';

/**
 * The published sample report.
 *
 * It is produced against OWASP Juice Shop, a deliberately vulnerable application, and not against
 * a redacted client. That means no consent problem, no redaction risk, and a reader who wants to
 * can stand the same application up and verify every finding themselves.
 *
 * The same fixture drives the golden-file tests for the report renderer, so if the sample on the
 * website changes shape the tests fail rather than the website quietly drifting.
 */

const ENGAGEMENT_ID = 'sample-engagement';
const start = new Date('2026-07-13T04:00:00Z');
const end = new Date('2026-07-17T13:00:00Z');

function finding(input: Omit<Finding, 'engagementId' | 'firstSeenAt' | 'lastSeenAt'>): Finding {
  return { ...input, engagementId: ENGAGEMENT_ID, firstSeenAt: start, lastSeenAt: end };
}

export const sampleFindings: Finding[] = [
  finding({
    id: 'sample-001',
    reference: 'ATT-2026-000-001',
    source: 'manual',
    checkId: 'web-sql-injection',
    toolName: 'manual',
    title: 'Login form allows authentication as any user through SQL injection',
    description:
      'The email field on the login form is concatenated into a SQL statement without parameterisation. A payload that terminates the string literal and comments out the remainder of the statement authenticates the request as the first row of the users table, which is the administrator. No password is required. The same parameter also supports UNION-based extraction of arbitrary tables, which was confirmed on the schema only and not used to read customer data.',
    severity: 'critical',
    cvssVersion: '4.0',
    cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N',
    cvssScore: 9.3,
    cweId: 89,
    owaspCategory: 'A05:2025',
    wstgId: 'WSTG-INPV-05',
    asvsRequirement: 'v5.0.0-1.2.1',
    affectedAssets: [
      { value: 'juice.attestor-lab.internal', location: '/rest/user/login', parameter: 'email', method: 'POST' },
    ],
    businessImpact:
      'An unauthenticated attacker becomes the administrator in a single request. From that account every customer record, order and payment reference in the application is readable, and product and pricing data is writable. There is no rate limit and no logging that would distinguish this from an ordinary failed login, so the first indication of compromise would be the consequences.',
    likelihood:
      'High. The payload is in every introductory tutorial for this class of issue, the endpoint is public, and no authentication or prior knowledge is required.',
    attackerPrerequisites: 'None. Network access to the login page is sufficient.',
    reproductionSteps: [
      'Open the login page at https://juice.attestor-lab.internal/#/login.',
      "Enter the email address value: ' OR 1=1--",
      'Enter any value in the password field.',
      'Submit the form.',
      'Observe that the response contains a valid authentication token and the session is that of the administrator account.',
    ],
    remediation:
      'Replace the concatenated statement in the login handler with a parameterised query, binding the email address as a parameter rather than interpolating it. In the Sequelize models used by this application that means replacing the raw `sequelize.query` call with a `findOne` using a `where` clause, or passing `replacements` with named bind parameters. Parameterisation is the fix; input filtering is not, because the same data has to be accepted as a legitimate email address. Rotate the administrator credential afterwards, and review the authentication logs for the period the issue was live.',
    references: [
      {
        title: 'OWASP Cheat Sheet: SQL Injection Prevention',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
      },
      { title: 'CWE-89: SQL Injection', url: 'https://cwe.mitre.org/data/definitions/89.html' },
    ],
    status: 'open',
    dedupeKey: 'sample-sqli-login',
  }),

  finding({
    id: 'sample-002',
    reference: 'ATT-2026-000-002',
    source: 'manual',
    checkId: 'web-horizontal-access-control',
    title: 'Basket contents of any customer retrievable by changing the basket identifier',
    description:
      'The basket endpoint authorises on the presence of a valid session rather than on ownership of the basket being requested. Changing the numeric identifier in the path returns another customer\'s basket, including the products, quantities and the coupon applied. Identifiers are sequential, so the whole set is enumerable.',
    severity: 'high',
    cvssVersion: '4.0',
    cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N',
    cvssScore: 8.1,
    cweId: 639,
    owaspCategory: 'A01:2025',
    apiCategory: 'API1:2023',
    wstgId: 'WSTG-ATHZ-04',
    asvsRequirement: 'v5.0.0-8.1.2',
    affectedAssets: [
      { value: 'juice.attestor-lab.internal', location: '/rest/basket/{id}', method: 'GET' },
      { value: 'juice.attestor-lab.internal', location: '/api/BasketItems/{id}', method: 'GET' },
    ],
    businessImpact:
      'Any registered customer can read every other customer\'s basket by counting upwards. The basket reveals purchase intent and the coupon codes in use, and the same authorisation gap on the item endpoint allows items to be added to another customer\'s basket. For a retailer this is both a privacy exposure and a route to manipulating another customer\'s order.',
    likelihood:
      'High. Registration is open, identifiers are sequential, and the request can be made with a browser and no tooling.',
    attackerPrerequisites: 'A registered account, which anyone can create.',
    reproductionSteps: [
      'Register two accounts, A and B, and add a product to each basket.',
      'Sign in as A and note the basket identifier in the response to GET /rest/basket/{id}.',
      'Request the adjacent identifier, GET /rest/basket/{id-1}, with account A\'s session.',
      'Observe that account B\'s basket contents are returned with a 200 response.',
    ],
    remediation:
      'Authorise on ownership, not on session validity: the basket handler must load the basket and compare its owning user against the identity in the session before returning it, rejecting the request with 404 rather than 403 so the identifier space is not confirmed. Apply the same check to the BasketItems handlers, which have the same gap. Adding a non-sequential identifier is worth doing but is not the fix on its own.',
    references: [
      {
        title: 'OWASP Cheat Sheet: Insecure Direct Object Reference Prevention',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html',
      },
      {
        title: 'OWASP API Security Top 10: API1:2023 Broken Object Level Authorization',
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
      },
    ],
    status: 'open',
    dedupeKey: 'sample-idor-basket',
  }),

  finding({
    id: 'sample-003',
    reference: 'ATT-2026-000-003',
    source: 'manual',
    checkId: 'web-jwt-handling',
    title: 'Session tokens accepted with the signature algorithm set to none',
    description:
      'The application issues RS256-signed JSON Web Tokens but the verification path accepts a token whose header declares `alg: none` and which carries no signature. A token can therefore be minted for any account, including the administrator, without possession of any key.',
    severity: 'critical',
    cvssVersion: '4.0',
    cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N',
    cvssScore: 9.3,
    cweId: 347,
    owaspCategory: 'A07:2025',
    apiCategory: 'API2:2023',
    wstgId: 'WSTG-SESS-10',
    asvsRequirement: 'v5.0.0-9.1.1',
    affectedAssets: [
      { value: 'juice.attestor-lab.internal', location: '/rest/*', parameter: 'Authorization' },
    ],
    businessImpact:
      'Authentication is effectively optional. Every control that depends on identity — order history, address book, payment methods, the administration area — can be reached by constructing a token. Because the forged token is structurally valid, nothing in the application logs distinguishes it from a legitimate session.',
    likelihood: 'High. Publicly documented technique, no prerequisites, no rate limiting involved.',
    attackerPrerequisites: 'None beyond network access.',
    reproductionSteps: [
      'Capture a legitimate token from a normal login and decode it.',
      'Change the header to {"alg":"none","typ":"JWT"} and set the payload subject to the administrator account.',
      'Re-encode the header and payload, leaving the signature segment empty, and keep the trailing dot.',
      'Send any authenticated request with that token in the Authorization header.',
      'Observe a 200 response containing administrator-scoped data.',
    ],
    remediation:
      'Pin the accepted algorithm explicitly at verification time rather than reading it from the token header — pass `algorithms: ["RS256"]` to the verifier — and reject any token whose signature segment is empty. Verify the issuer and audience claims at the same point. Rotate the signing key, because tokens already issued cannot be distinguished from forged ones, and invalidate existing sessions.',
    references: [
      {
        title: 'OWASP Cheat Sheet: JSON Web Token for Java',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html',
      },
      { title: 'CWE-347: Improper Verification of Cryptographic Signature', url: 'https://cwe.mitre.org/data/definitions/347.html' },
    ],
    status: 'open',
    dedupeKey: 'sample-jwt-none',
  }),

  finding({
    id: 'sample-004',
    reference: 'ATT-2026-000-004',
    source: 'tool',
    toolName: 'zap',
    checkId: 'web-stored-xss',
    title: 'Product review field stores script that executes in every viewer\'s session',
    description:
      'The review body is stored without encoding and rendered into the product page as markup. A review containing an image tag with an error handler executes for every visitor to that product, including staff using the administration view of the same content.',
    severity: 'high',
    cvssVersion: '4.0',
    cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:N/SC:L/SI:L/SA:N',
    cvssScore: 7.6,
    cweId: 79,
    owaspCategory: 'A05:2025',
    wstgId: 'WSTG-INPV-02',
    asvsRequirement: 'v5.0.0-1.3.1',
    affectedAssets: [
      { value: 'juice.attestor-lab.internal', location: '/rest/products/{id}/reviews', parameter: 'message', method: 'PUT' },
    ],
    businessImpact:
      'One review reaches every customer who opens that product. Because the session token is readable from browser storage rather than being held in an HttpOnly cookie, the payload can take over the accounts of everyone who views the page, staff included.',
    likelihood: 'High. Any registered customer can post a review, and no moderation step exists.',
    attackerPrerequisites: 'A registered account.',
    reproductionSteps: [
      'Sign in as any customer.',
      'Open any product and submit a review whose body is: <img src=x onerror="document.title=document.title+\' XSS\'">',
      'Open the same product page in a second browser signed in as a different customer.',
      'Observe that the injected handler runs, confirmed by the modified document title.',
    ],
    remediation:
      'Encode the review body for the HTML context at render time rather than filtering it at submission, and render it as text unless rich content is a product requirement. If it is, run the submitted markup through an allowlist sanitiser on the server and serve a Content-Security-Policy that does not permit inline event handlers. Moving the session token out of browser storage into a Secure, HttpOnly, SameSite cookie removes the account-takeover consequence even where an injection is later missed.',
    references: [
      {
        title: 'OWASP Cheat Sheet: Cross Site Scripting Prevention',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
      },
    ],
    status: 'open',
    dedupeKey: 'sample-stored-xss-review',
  }),

  finding({
    id: 'sample-005',
    reference: 'ATT-2026-000-005',
    source: 'manual',
    checkId: 'web-directory-traversal',
    title: 'Arbitrary file read through the document download endpoint',
    description:
      'The file download endpoint resolves the requested name relative to a directory without normalising it first. Traversal sequences, including their URL-encoded and double-encoded forms, escape the directory and return any file readable by the application process.',
    severity: 'high',
    cvssVersion: '4.0',
    cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N',
    cvssScore: 8.7,
    cweId: 22,
    owaspCategory: 'A01:2025',
    wstgId: 'WSTG-ATHZ-01',
    asvsRequirement: 'v5.0.0-5.1.1',
    affectedAssets: [
      { value: 'juice.attestor-lab.internal', location: '/ftp', parameter: 'file', method: 'GET' },
    ],
    businessImpact:
      'Application configuration, environment files and the SQLite database file are all readable without authentication. The configuration contains the token signing material, which turns this single issue into a complete authentication bypass without needing the separate token weakness above.',
    likelihood: 'High. Unauthenticated, and the endpoint is linked from the application itself.',
    attackerPrerequisites: 'None.',
    reproductionSteps: [
      'Request GET /ftp/quarantine/%2e%2e%2f%2e%2e%2fpackage.json.',
      'Observe the file contents in the response with a 200 status.',
      'Repeat with the path of the configuration file to confirm the traversal is not limited to one directory.',
    ],
    remediation:
      'Resolve the requested path against the intended base directory and reject it unless the resolved absolute path is still inside that directory — a prefix comparison after `path.resolve`, not a string check on the input. Decode once, and reject rather than repeatedly decoding. Serve downloads by an identifier that maps to a file server-side instead of accepting a filename from the client at all, which removes the class rather than this instance of it.',
    references: [
      {
        title: 'OWASP Cheat Sheet: File Upload and Path Traversal',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html',
      },
    ],
    status: 'open',
    dedupeKey: 'sample-path-traversal-ftp',
  }),

  finding({
    id: 'sample-006',
    reference: 'ATT-2026-000-006',
    source: 'manual',
    checkId: 'web-price-and-quantity-manipulation',
    title: 'Order total accepted from the client, allowing an order to be placed for any amount',
    description:
      'The checkout request carries the basket total as a field and the server records it without recomputing it from the basket contents. Submitting a modified total produces an order for that amount, and the coupon field is applied after the total is fixed rather than before, so a discount can be applied twice.',
    severity: 'high',
    cvssVersion: '4.0',
    cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N',
    cvssScore: 7.1,
    cweId: 840,
    owaspCategory: 'A06:2025',
    wstgId: 'WSTG-BUSL-01',
    affectedAssets: [
      { value: 'juice.attestor-lab.internal', location: '/rest/basket/{id}/checkout', parameter: 'totalPrice', method: 'POST' },
    ],
    businessImpact:
      'Goods can be ordered for any amount the customer chooses, including zero. The loss is direct and per-order, and because the order record itself carries the manipulated total, reconciliation against the payment provider is the only place it would be noticed.',
    likelihood:
      'High for anyone who opens the browser network tab. This class of issue is routinely found by customers, not only by attackers.',
    attackerPrerequisites: 'A registered account and an item in the basket.',
    reproductionSteps: [
      'Add a product priced above 1,000 to the basket.',
      'Intercept the checkout request and change totalPrice to 1.',
      'Submit the request.',
      'Open the order confirmation and observe the order recorded at the submitted total.',
    ],
    remediation:
      'Recompute the total on the server from the basket contents, the current catalogue prices, the applicable tax and the delivery option, and ignore any total supplied by the client. Apply coupons as part of that computation, once, and record the computed total against the payment intent so the payment provider and the order cannot disagree. Add a reconciliation check that rejects an order whose recorded total differs from the authorised payment amount.',
    references: [
      {
        title: 'OWASP WSTG: Testing for Business Logic Data Validation',
        url: 'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation',
      },
    ],
    status: 'open',
    dedupeKey: 'sample-price-manipulation',
  }),

  finding({
    id: 'sample-007',
    reference: 'ATT-2026-000-007',
    source: 'tool',
    toolName: 'zap',
    checkId: 'web-security-headers',
    title: 'Security headers absent across the application',
    description:
      'No Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy or Permissions-Policy header is set on any response. This is one configuration change rather than one issue per endpoint, and it is recorded here once with every affected path listed.',
    severity: 'medium',
    cvssVersion: '4.0',
    cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N',
    cvssScore: 5.1,
    cweId: 693,
    owaspCategory: 'A02:2025',
    wstgId: 'WSTG-CONF-12',
    asvsRequirement: 'v5.0.0-3.4.1',
    affectedAssets: [
      { value: 'juice.attestor-lab.internal', location: '/' },
      { value: 'juice.attestor-lab.internal', location: '/rest/products/search' },
      { value: 'juice.attestor-lab.internal', location: '/rest/user/whoami' },
      { value: 'juice.attestor-lab.internal', location: '/api/Products' },
      { value: 'juice.attestor-lab.internal', location: '/assets/*' },
    ],
    businessImpact:
      'No single header is an exploit on its own. Together their absence removes the layer that would have limited the impact of the stored cross-site scripting above: a policy without inline script would have prevented that payload from running at all.',
    likelihood: 'Not directly exploitable; it increases the impact of other findings.',
    attackerPrerequisites: 'Another finding to amplify.',
    reproductionSteps: [
      'Request any page and inspect the response headers.',
      'Observe that none of the listed headers is present.',
    ],
    remediation:
      "Set the headers at the edge so every response carries them: `Content-Security-Policy` with `default-src 'self'` and no `unsafe-inline`, `Strict-Transport-Security: max-age=31536000; includeSubDomains`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin` and a `Permissions-Policy` that disables the interfaces the application does not use. Deploy the policy in report-only mode first, collect violations for a week, then enforce.",
    references: [
      {
        title: 'OWASP Cheat Sheet: HTTP Security Response Headers',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
      },
    ],
    status: 'open',
    dedupeKey: 'sample-security-headers',
  }),

  finding({
    id: 'sample-008',
    reference: 'ATT-2026-000-008',
    source: 'manual',
    checkId: 'web-user-enumeration',
    title: 'Registered email addresses confirmed by the password reset response',
    description:
      'The password reset endpoint returns a different message and a measurably different response time for a registered address than for an unregistered one, which allows a list of addresses to be sorted into customers and non-customers.',
    severity: 'low',
    cvssVersion: '4.0',
    cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
    cvssScore: 5.3,
    cweId: 204,
    owaspCategory: 'A07:2025',
    wstgId: 'WSTG-IDNT-04',
    asvsRequirement: 'v5.0.0-6.2.3',
    affectedAssets: [
      { value: 'juice.attestor-lab.internal', location: '/rest/user/reset-password', parameter: 'email', method: 'POST' },
    ],
    businessImpact:
      'On its own this is minor. In combination with the absent rate limiting on the login endpoint it turns a generic credential-stuffing list into a targeted one, which is the difference between a low success rate and a high one.',
    likelihood: 'High as an aid to another attack; not damaging alone.',
    attackerPrerequisites: 'A list of candidate email addresses.',
    reproductionSteps: [
      'Submit a reset request for a known registered address and record the response body and timing.',
      'Submit the same request for an address that is not registered.',
      'Compare: the message differs and the registered case is consistently slower.',
    ],
    remediation:
      'Return the same response body, status and approximate timing in both cases — accept the request, say that an email has been sent if the address is registered, and do the work asynchronously so the timing does not vary. Apply the same treatment to registration and to the email-change flow, which have the same tell.',
    references: [
      {
        title: 'OWASP Cheat Sheet: Forgot Password',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html',
      },
    ],
    status: 'open',
    dedupeKey: 'sample-user-enumeration',
  }),

  finding({
    id: 'sample-009',
    reference: 'ATT-2026-000-009',
    source: 'tool',
    toolName: 'trivy',
    checkId: 'code-dependency-vulnerabilities',
    title: 'Three dependencies with published vulnerabilities are reachable from request handling',
    description:
      'The dependency tree carries three components with published vulnerabilities that are reachable from code on the request path, as distinct from the twenty-one further matches that are present only in the build tooling and are recorded in the appendix rather than reported here.',
    severity: 'medium',
    cvssVersion: '4.0',
    cvssVector: 'CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
    cvssScore: 5.1,
    cweId: 1104,
    owaspCategory: 'A03:2025',
    affectedAssets: [
      { value: 'juice.attestor-lab.internal', location: 'package-lock.json' },
    ],
    businessImpact:
      'Two of the three are denial-of-service issues in parsing code, which matters less here than the third, a prototype pollution issue in a utility used by the request body parser and reachable from unauthenticated input.',
    likelihood: 'Medium. Requires a specific request shape but no authentication.',
    attackerPrerequisites: 'Ability to send a request body to the application.',
    reproductionSteps: [
      'Generate a bill of materials for the deployed image.',
      'Correlate the resolved versions against published advisories.',
      'Confirm reachability by tracing the import path from the request handler to the affected function.',
    ],
    remediation:
      'Upgrade the three reachable components to the fixed versions listed in the appendix; the upgrade is a patch-level change in each case with no interface change. Add dependency scanning to the pipeline so this is caught at build time, and pin the lockfile so what is scanned is what deploys.',
    references: [
      {
        title: 'OWASP Top 10 2025: A03 Software Supply Chain Failures',
        url: 'https://owasp.org/Top10/',
      },
    ],
    status: 'open',
    dedupeKey: 'sample-dependencies',
  }),

  finding({
    id: 'sample-010',
    reference: 'ATT-2026-000-010',
    source: 'manual',
    checkId: 'web-rate-limit-effectiveness',
    title: 'No rate limiting on the login endpoint',
    description:
      'The login endpoint accepted 400 attempts against a disposable test account without throttling, lockout or any change in response. Testing was stopped at 400 by our own ceiling rather than by the application. No account lockout was triggered and no alert was generated.',
    severity: 'medium',
    cvssVersion: '4.0',
    cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N',
    cvssScore: 6.9,
    cweId: 307,
    owaspCategory: 'A07:2025',
    apiCategory: 'API4:2023',
    wstgId: 'WSTG-ATHN-03',
    asvsRequirement: 'v5.0.0-6.2.4',
    affectedAssets: [
      { value: 'juice.attestor-lab.internal', location: '/rest/user/login', method: 'POST' },
    ],
    businessImpact:
      'Credential stuffing against this application is unimpeded, and combined with the enumeration finding above the attacker knows which addresses are worth trying. For a retailer holding saved payment methods, a successful stuffing run is a fraud problem rather than only a privacy one.',
    likelihood: 'High. Credential stuffing is automated and continuous across the internet.',
    attackerPrerequisites: 'A credential list, which is freely available.',
    reproductionSteps: [
      'Create a disposable test account.',
      'Submit repeated login attempts with an incorrect password against that account only.',
      'Observe that responses remain consistent and no throttling, delay or lockout occurs.',
      'Testing was stopped at 400 attempts by our own limit.',
    ],
    remediation:
      'Apply rate limiting scoped to both the account and the source address, with an exponential backoff on repeated failure, and prefer a verification challenge over a hard lockout so an attacker cannot lock out real customers. Check submitted passwords against a breached-password list at registration and at change, which addresses the underlying reason stuffing works. Log and alert on failure rates per account rather than only in aggregate.',
    references: [
      {
        title: 'OWASP Cheat Sheet: Credential Stuffing Prevention',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html',
      },
    ],
    status: 'open',
    dedupeKey: 'sample-no-rate-limit',
  }),
];

export const samplePositiveObservations: string[] = [
  'Passwords are stored using a modern password hashing function with per-user salts. Nothing in the storage path required change.',
  'TLS is correctly configured on the public listener: TLS 1.2 and 1.3 only, no weak cipher suites, and a valid certificate chain with 74 days to expiry.',
  'The administration area is not linked from the customer interface and is not indexed, which slowed discovery even though it did not prevent it.',
  'The payment provider integration uses hosted fields, so card numbers never reach the application. This is the correct design and it removed an entire class of finding from this assessment.',
];

export const sampleAttackNarrative = {
  title: 'From an anonymous visitor to every customer record in four steps',
  steps: [
    {
      heading: 'Step 1 — Confirm which addresses are customers',
      body: 'The password reset endpoint distinguishes registered from unregistered addresses (ATT-2026-000-008). A list of 5,000 candidate addresses was reduced to the subset that exists on the platform. On its own this is a low-severity finding and would reasonably be scheduled for a later sprint.',
    },
    {
      heading: 'Step 2 — Read the application configuration',
      body: 'The download endpoint resolves a client-supplied filename without normalising it (ATT-2026-000-005), which returns the configuration file. That file contains the material used to sign session tokens.',
    },
    {
      heading: 'Step 3 — Become any of those customers',
      body: 'With the signing material, and with the verifier accepting the algorithm named in the token header (ATT-2026-000-003), a valid session token can be produced for any of the addresses confirmed in step 1 — including the administrator.',
    },
    {
      heading: 'Step 4 — Take the data',
      body: 'The administrator session reaches every order, address and payment reference. No separate exploitation was required: the ordinary administrative screens do it. During testing this was confirmed on our own test accounts only, and no customer data was read or retained.',
    },
  ],
  conclusion:
    'Each of the first two steps would be triaged as low or high on its own and would sit in a backlog. Together with the token weakness they produce an unauthenticated path to the complete customer database in under an hour. This is why the remediation order in this report is not simply the severity order.',
};

export const sampleEngagement = {
  id: ENGAGEMENT_ID,
  reference: 'ATT-2026-000',
  clientLegalName: 'Sample Retail Private Limited',
  clientDisplayName: 'Sample Retail',
  title: 'Web application and API security assessment',
  testType: 'greyBox' as const,
  startsAt: start,
  endsAt: end,
  reportDate: new Date('2026-07-20T00:00:00Z'),
  reportVersion: '1.0',
  cvssVersion: '4.0' as const,
  timezone: 'Asia/Kolkata',
  scopeIncluded: [
    'juice.attestor-lab.internal — the customer web application and its REST API',
    'The administration interface at the same origin',
    'Three user roles: anonymous visitor, registered customer, administrator',
  ],
  scopeExcluded: [
    'The payment provider, which is a third-party service outside the client’s authorisation',
    'The corporate network, staff email and workstations',
    'Denial-of-service, load and volumetric testing, which are excluded by agreement and are never performed',
    'Social engineering and physical access',
  ],
  environments: ['Staging, running the release candidate for the 2026-07 production deployment'],
  rolesTested: [
    'anonymous — no session',
    'customer — two separate accounts, to test between customers as well as between roles',
    'administrator — one account',
  ],
  constraints: [
    'Testing was permitted between 04:00 and 13:00 UTC on working days, at the client’s request.',
    'Outbound requests were limited to 4 per second per host throughout.',
  ],
  toolsUsed: [
    { name: 'OWASP ZAP', version: '2.16.1', purpose: 'Authenticated crawling and active scanning' },
    { name: 'nuclei', version: '3.4.7', purpose: 'Templated checks for known issues and exposures' },
    { name: 'sqlmap', version: '1.9.4', purpose: 'Injection confirmation, read-only settings' },
    { name: 'ffuf', version: '2.1.0', purpose: 'Content discovery within the agreed rate limit' },
    { name: 'Playwright', version: '1.56.0', purpose: 'Authenticated browsing and evidence capture' },
    { name: 'trivy', version: '0.68.0', purpose: 'Dependency and container analysis' },
    { name: 'testssl.sh', version: '3.2', purpose: 'TLS configuration review' },
  ],
};
