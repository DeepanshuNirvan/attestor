import type { Check } from './types.ts';

export const apiChecks: Check[] = [
  {
    id: 'api-specification-import',
    title: 'API specification import and coverage',
    category: 'apiSpecific',
    modules: ['api'],
    description:
      'Import the OpenAPI document, Postman collection or GraphQL schema and drive testing from it. Where none exists, build a specification from observed traffic so coverage is still measurable.',
    example:
      'A specification listing 61 operations while the deployed service answers on 74, the extra 13 being undocumented and untested.',
    automation: 'automated',
    tools: ['schemathesis', 'mitmproxy'],
    standards: { wstg: ['WSTG-APIT-01'], apiTop10: ['API9:2023'], cwe: [1059] },
  },
  {
    id: 'api-inventory-and-versioning',
    title: 'Endpoint inventory, versioning and deprecated routes',
    category: 'apiSpecific',
    modules: ['api'],
    description:
      'Discover older API versions, debug routes, internal-only routes and endpoints left behind by a migration, and check whether they enforce the same controls as the current version.',
    example:
      'A `/v1/` route still live after the `/v2/` migration, without the object-level authorisation that v2 added.',
    automation: 'automated',
    tools: ['kiterunner', 'ffuf', 'katana'],
    standards: { wstg: ['WSTG-APIT-01'], apiTop10: ['API9:2023'], cwe: [1059, 285] },
  },
  {
    id: 'api-bola',
    title: 'Broken object level authorisation',
    category: 'accessControl',
    modules: ['api'],
    description:
      'For every operation that takes an object identifier, replay it with another account\'s identifier, with identifiers harvested from other responses, and with identifiers of adjacent shape.',
    example:
      'A `GET /invoices/{id}` that returns any invoice in the system to any authenticated user.',
    automation: 'assisted',
    tools: ['accessControlMatrix', 'schemathesis'],
    standards: {
      apiTop10: ['API1:2023'],
      owaspTop10: ['A01:2025'],
      asvs: ['v5.0.0-8.1.2'],
      cwe: [639],
    },
  },
  {
    id: 'api-bfla',
    title: 'Broken function level authorisation',
    category: 'accessControl',
    modules: ['api'],
    description:
      'Call administrative and privileged operations with each lower-privileged role, including operations only the administrative front end normally invokes.',
    example:
      'A `POST /users/{id}/impersonate` reachable by any authenticated user because the guard is on the admin UI route, not the API.',
    automation: 'assisted',
    tools: ['accessControlMatrix'],
    standards: { apiTop10: ['API5:2023'], owaspTop10: ['A01:2025'], cwe: [285] },
  },
  {
    id: 'api-object-property-authorisation',
    title: 'Object property level authorisation',
    category: 'accessControl',
    modules: ['api'],
    description:
      'Check both directions: properties the caller should not be able to read, and properties the caller should not be able to write.',
    example:
      'A profile endpoint returning the internal risk score and the account owner\'s national identifier alongside the display name.',
    automation: 'assisted',
    tools: ['schemathesis', 'arjun'],
    standards: { apiTop10: ['API3:2023'], owaspTop10: ['A01:2025'], cwe: [915, 213] },
  },
  {
    id: 'api-authentication-mechanisms',
    title: 'API authentication mechanisms',
    category: 'authentication',
    modules: ['api'],
    description:
      'Test API key handling, token issuance and refresh, client credential flows, mutual TLS where used, and whether any endpoint answers without authentication.',
    example:
      'A health endpoint that also returns the service configuration, including the internal database host.',
    automation: 'assisted',
    tools: ['schemathesis', 'zap'],
    standards: { apiTop10: ['API2:2023'], owaspTop10: ['A07:2025'], cwe: [306, 287] },
  },
  {
    id: 'api-token-lifecycle',
    title: 'Token lifecycle and revocation',
    category: 'authentication',
    modules: ['api'],
    description:
      'Check expiry, refresh rotation, reuse detection, revocation on logout and on credential change, and whether a revoked token is actually rejected.',
    example:
      'A refresh token that stays valid after the user changes their password, because revocation only clears the session store.',
    automation: 'assisted',
    tools: ['zap'],
    standards: {
      apiTop10: ['API2:2023'],
      asvs: ['v5.0.0-9.2.2'],
      owaspTop10: ['A07:2025'],
      cwe: [613],
    },
  },
  {
    id: 'api-excessive-data-exposure',
    title: 'Excessive data exposure in responses',
    category: 'apiSpecific',
    modules: ['api'],
    description:
      'Compare what each response contains against what the consuming interface displays, since APIs commonly return whole records and filter in the client.',
    example:
      'A public product listing embedding the supplier cost price, which the storefront hides but the response contains.',
    automation: 'assisted',
    tools: ['schemathesis', 'mitmproxy'],
    standards: { apiTop10: ['API3:2023'], owaspTop10: ['A01:2025'], cwe: [213, 200] },
  },
  {
    id: 'api-resource-consumption',
    title: 'Unrestricted resource consumption',
    category: 'apiSpecific',
    modules: ['api'],
    description:
      'Check pagination limits, batch sizes, upload sizes, expensive query parameters and response size caps. Measured with bounded requests only; no volumetric testing is performed at any time.',
    example:
      'A list endpoint accepting `pageSize=100000`, which returns the whole table in one request.',
    automation: 'assisted',
    tools: ['schemathesis'],
    standards: { apiTop10: ['API4:2023'], owaspTop10: ['A06:2025'], cwe: [770] },
  },
  {
    id: 'api-rate-limiting',
    title: 'API rate limiting and quota enforcement',
    category: 'apiSpecific',
    modules: ['api'],
    description:
      'Measure the point at which throttling begins, whether it is scoped per key, per account or per address, and whether it can be bypassed by rotating a header or changing the path casing.',
    example:
      'A per-key quota that resets when the client sends a different `X-Forwarded-For` value.',
    automation: 'assisted',
    tools: ['rateLimitProbe'],
    standards: { apiTop10: ['API4:2023'], owaspTop10: ['A07:2025'], cwe: [770, 799] },
  },
  {
    id: 'api-graphql-introspection',
    title: 'GraphQL introspection and schema exposure',
    category: 'apiSpecific',
    modules: ['api'],
    description:
      'Check whether introspection is enabled in production and whether field suggestions disclose the schema even when it is disabled.',
    example:
      'Introspection disabled but suggestion messages still naming every mutation, including the internal-only ones.',
    automation: 'automated',
    tools: ['nuclei', 'zap'],
    standards: { apiTop10: ['API8:2023', 'API9:2023'], owaspTop10: ['A02:2025'], cwe: [200] },
  },
  {
    id: 'api-graphql-query-abuse',
    title: 'GraphQL query depth, aliasing and batching abuse',
    category: 'apiSpecific',
    modules: ['api'],
    description:
      'Check whether depth limits, complexity limits, alias limits and batch limits exist, and whether aliasing can be used to bypass a per-request rate limit.',
    example:
      'A single request using 500 aliases of the login mutation, defeating a per-request rate limit entirely.',
    automation: 'assisted',
    tools: ['zap'],
    standards: { apiTop10: ['API4:2023'], owaspTop10: ['A06:2025'], cwe: [770, 674] },
  },
  {
    id: 'api-graphql-authorisation',
    title: 'GraphQL field and node authorisation',
    category: 'accessControl',
    modules: ['api'],
    description:
      'Test authorisation at field level and through node interfaces, where an object reachable through one query may be reachable unguarded through another.',
    example:
      'An `orders` field guarded on the customer query but reachable unguarded through the global node interface.',
    automation: 'assisted',
    tools: ['accessControlMatrix'],
    standards: { apiTop10: ['API1:2023', 'API5:2023'], owaspTop10: ['A01:2025'], cwe: [285] },
  },
  {
    id: 'api-injection-through-schema',
    title: 'Schema-driven injection and type confusion',
    category: 'inputValidation',
    modules: ['api'],
    description:
      'Drive every documented parameter with boundary values, wrong types, nulls, oversized values and injection payloads generated from the specification.',
    example:
      'An integer field accepting an array, which reaches the query builder and produces a database error containing the schema.',
    automation: 'automated',
    tools: ['schemathesis'],
    standards: { apiTop10: ['API8:2023'], owaspTop10: ['A05:2025'], cwe: [20, 89] },
  },
  {
    id: 'api-content-type-handling',
    title: 'Content type and parser handling',
    category: 'inputValidation',
    modules: ['api'],
    description:
      'Submit each operation with alternative content types — form, XML, multipart, plain text — and check whether a different parser applies different validation or different authorisation.',
    example:
      'An endpoint that enforces a schema on JSON but accepts form encoding and skips validation entirely.',
    automation: 'assisted',
    tools: ['schemathesis', 'zap'],
    standards: { apiTop10: ['API8:2023'], owaspTop10: ['A05:2025'], cwe: [436, 20] },
  },
  {
    id: 'api-cors-and-preflight',
    title: 'API CORS and pre-flight consistency',
    category: 'configuration',
    modules: ['api'],
    description:
      'Check that the pre-flight response and the actual response agree, and that credentialed cross-origin access is limited to origins the client controls.',
    example:
      'A pre-flight that rejects an origin while the actual request still returns the data with permissive headers.',
    automation: 'automated',
    tools: ['zap', 'nuclei'],
    standards: { apiTop10: ['API8:2023'], owaspTop10: ['A01:2025'], cwe: [942] },
  },
  {
    id: 'api-webhook-security',
    title: 'Webhook delivery and receipt security',
    category: 'apiSpecific',
    modules: ['api'],
    description:
      'For webhooks the client sends, check destination validation and signing. For webhooks the client receives, check signature verification, replay protection and timestamp tolerance.',
    example:
      'An incoming payment webhook whose signature is checked only when a signature header is present.',
    automation: 'assisted',
    tools: ['zap'],
    standards: { apiTop10: ['API7:2023', 'API10:2023'], owaspTop10: ['A08:2025'], cwe: [345, 918] },
  },
  {
    id: 'api-third-party-consumption',
    title: 'Unsafe consumption of third-party APIs',
    category: 'apiSpecific',
    modules: ['api', 'code'],
    description:
      'Check how the application handles responses from upstream services: whether it validates them, whether it follows redirects blindly, and what happens when an upstream returns something unexpected.',
    example:
      'A currency service response written straight into the order total with no bounds check.',
    automation: 'manual',
    tools: ['semgrep'],
    standards: { apiTop10: ['API10:2023'], owaspTop10: ['A08:2025'], cwe: [1104, 20] },
  },
  {
    id: 'api-idempotency-and-replay',
    title: 'Idempotency and request replay',
    category: 'apiSpecific',
    modules: ['api'],
    description:
      'Replay captured requests to check whether operations that should happen once can be repeated, and whether idempotency keys are actually enforced.',
    example:
      'A refund request that can be replayed, issuing the refund again each time.',
    automation: 'assisted',
    tools: ['zap'],
    standards: { apiTop10: ['API6:2023'], owaspTop10: ['A06:2025'], cwe: [294, 837] },
  },
  {
    id: 'api-error-verbosity',
    title: 'API error verbosity',
    category: 'errorHandling',
    modules: ['api'],
    description:
      'Check that error responses do not leak stack traces, internal identifiers, upstream hostnames or validation logic that assists enumeration.',
    example:
      'A validation error naming the internal database column and the constraint it violated.',
    automation: 'automated',
    tools: ['schemathesis', 'zap'],
    standards: { apiTop10: ['API8:2023'], owaspTop10: ['A10:2025'], cwe: [209] },
  },
  {
    id: 'api-grpc-and-binary-protocols',
    title: 'gRPC and binary protocol handling',
    category: 'apiSpecific',
    modules: ['api'],
    description:
      'Where gRPC or another binary protocol is in scope, check reflection exposure, per-method authorisation, message size limits and transport security.',
    example:
      'Server reflection enabled in production, listing every internal service method to any client that can reach the port.',
    automation: 'assisted',
    tools: ['mitmproxy'],
    standards: { apiTop10: ['API9:2023', 'API5:2023'], owaspTop10: ['A02:2025'], cwe: [200, 285] },
  },
  {
    id: 'api-mobile-backend-parity',
    title: 'Mobile backend parity with the web API',
    category: 'apiSpecific',
    modules: ['api', 'mobile'],
    description:
      'Compare the endpoints the mobile application uses against the web API, since mobile-specific endpoints are frequently older and less strictly controlled.',
    example:
      'A mobile-only login endpoint without the rate limiting and device checks the web login has.',
    automation: 'assisted',
    tools: ['mitmproxy', 'kiterunner'],
    standards: { apiTop10: ['API9:2023'], owaspTop10: ['A02:2025'], cwe: [1059] },
  },
];
