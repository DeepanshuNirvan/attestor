# Policy cookbook

Everything configurable about a run lives in one YAML document. This is the full reference plus nine
worked examples you can copy.

Two constraints are enforced by the schema itself, so an unsafe policy fails to load rather than
failing at run time:

1. **Rate limits have hard ceilings.** A policy may go below them and can never go above.
2. **There is no denial-of-service setting to express.** It does not appear in the schema because it
   does not exist in the platform.

---

## 1. How layering works

Four layers, each overriding the one before:

```
global defaults  →  client policy  →  engagement policy  →  single-run override
```

Objects merge key by key; arrays replace wholesale. So an engagement that sets
`rateLimits.globalRequestsPerSecond` keeps the client's `concurrency`, but an engagement that sets
`modules` replaces the client's list entirely.

| Layer | Where it lives | Use it for |
| --- | --- | --- |
| Global | Built-in defaults | The safe baseline |
| Client | `client.policyYaml` | Things true of every engagement for that client — their blackout windows, their masking patterns |
| Engagement | `engagement.policyYaml` | This piece of work |
| Run | The run request | "Just recon, just now, half the rate" |

Set a profile as the engagement's starting point when you create it:

```bash
curl -sS -b jar -X POST :8080/engagements -H 'content-type: application/json' \
  -d '{"clientId":"...","title":"...","type":"webApplication","profileId":"standard-web-app"}'
```

Five profiles ship in `packages/policy/src/profiles/`: `quick-external`, `standard-web-app`,
`deep-web-app`, `cloud-review`, `llm-only`.

---

## 2. The full reference

### 2.1 Top level

```yaml
description: >-
  Free text. Shown in the console's diff view, so a change explains itself to whoever
  reads it in three months.

modules: [recon, web, api, mobile, cloud, code, network, llm]   # required, any subset
intensity: standard        # safe | standard | thorough
readOnlyMode: false        # true suppresses every state-changing request

phases:
  preLogin: true
  postLogin: true
```

`intensity` controls crawl depth, payload sets, fuzz iterations and timeouts. `safe` on anything
that matters to a client's revenue; `thorough` on staging.

### 2.2 Choosing checks

```yaml
checks:
  # When include is non-empty, ONLY these run. Ids, WSTG ids, ASVS requirements
  # or OWASP categories are all accepted.
  include: []
  exclude:
    - web-request-smuggling          # a catalogue check id
    - WSTG-CONF-04                   # a WSTG test id
    - v5.0.0-5.3.1                   # an ASVS requirement
  nucleiTags: [cve, exposure, misconfig]
  nucleiSeverities: [critical, high, medium, low]
```

Excluding a check is not hiding it: the coverage matrix records it as not tested, and the report asks
you for the reason.

### 2.3 Authentication

The part that decides whether an authenticated scan is real or theatre.

```yaml
authProfiles:
  - id: standard-user
    roleName: user
    type: formLogin           # none | formLogin | scriptedLogin | otpAssisted | oauth2
                              # apiKey | bearerJwt | sessionCookie | mtls
    credentialSetId: cs-user-primary        # a vault reference, never a value
    secondaryCredentialSetId: cs-user-second # two accounts per role make horizontal
                                             # access control testable at all
    loginUrl: https://app.example.com/login
    sessionIndicator:
      selector: '[data-testid="account-menu"]'
      loggedOutText: 'Sign in to continue'
    sessionCheckEveryRequests: 25

  - id: admin
    roleName: admin
    type: scriptedLogin
    credentialSetId: cs-admin
    scriptPath: logins/admin.ts     # a Playwright script, for SSO or a multi-step login
    sessionIndicator:
      urlPattern: '/admin/'

  - id: tenant-b-user
    roleName: user
    type: formLogin
    credentialSetId: cs-tenant-b
    tenantId: tenant-b              # multi-tenant isolation testing
```

`sessionIndicator` is required for anything but `type: none`. Without it the scanner cannot tell that
it was logged out an hour ago, and you get a confident report about the login page.

### 2.4 Access control

```yaml
accessControlMatrix:
  enabled: true
  rolePairs: []                # empty = every ordered pair of configured roles
  testUnauthenticated: true
  identifierFields: [id, uuid, userId, accountId, orderId, tenantId, customerId]
  responseSimilarityThreshold: 0.9
  maxReplayRequests: 1500      # ceiling 5000
```

Every request captured as one role is replayed as every other role and as nobody, with identifier
fields mutated. `responseSimilarityThreshold` is how alike two responses must be before they count as
"the same thing came back", which is what distinguishes a real horizontal access-control failure
from a generic error page.

### 2.5 Rate limits

```yaml
rateLimits:
  globalRequestsPerSecond: 10    # ceiling 40
  perTargetRequestsPerSecond: 4  # ceiling 10
  concurrency: 4                 # ceiling 12
  jitterMs: 120                  # random delay, so traffic is not metronomic
  politeMode: false              # true halves every limit above
  adaptive:
    backOffLatencyIncreasePercent: 50
    abortLatencyIncreasePercent: 200
    abortErrorRatePercent: 15
    abortConsecutiveServerErrors: 20
```

A value above a ceiling is **refused when you save the policy**, naming the field and the ceiling —
you find out then, not when the client calls. Nothing is silently reduced, so the number in the
policy is the number the run uses. `politeMode` halves the values you did set, and that halving is
clamped too, so no combination can produce an effective rate above the ceiling. The adaptive block
is what stops a run that is hurting a target: it slows down when latency rises and aborts outright
when it doubles.

### 2.6 Windows and blackouts

```yaml
# Weeknights, 20:00–06:00, in the engagement's timezone
windows:
  - daysOfWeek: [1, 2, 3, 4, 5]
    start: '20:00'
    end: '06:00'

# Never during the Friday release
blackouts:
  - daysOfWeek: [5]
    start: '14:00'
    end: '18:00'
```

`0` is Sunday. Both are evaluated in the engagement's timezone, not the server's. An empty `windows`
list means no restriction.

### 2.7 What never to touch

```yaml
forbiddenActions:
  - '**/checkout/confirm'
  - '**/api/payments/**'
  - '**/users/*/delete'
  - '**/notifications/send'

exclusions:
  paths: ['/admin/billing', '/exports']
  parameters: [callback, redirect_uri, returnUrl]
  hosts: [mail.example.com, status.example.com]
  fileTypes: [pdf, zip, mp4]
```

`forbiddenActions` **extends** the built-in never-touch list and never replaces it. The built-in list
is checked before authorisation, so a signature does not unlock the payment flow.

### 2.8 LLM testing

```yaml
llm:
  targetType: ragApplication      # rawEndpoint | chatUi | ragApplication | agentic | embeddedBot
  endpoint: https://app.example.com/api/chat
  promptPath: 'messages[-1].content'
  answerPath: 'choices[0].message.content'
  systemPrompt: 'You are a support assistant for Northwind Retail.'
  intendedPurpose: 'Answer questions about orders and returns.'
  declaredGuardrails: [profanity-filter, pii-redaction]
  declaredTools: [order-lookup, refund-issue]
  topicsItMustRefuse: [medical advice, legal advice, competitor pricing]
  probePacks: [attestor-core, garak-broad, promptfoo-owasp, deepteam-owasp]
  attemptsPerProbe: 20            # ceiling 200
  budget:
    maxSpendUsd: 25
    maxTokens: 2000000
    estimatedCostPerRequestUsd: 0.002
    clientAcknowledgedCostTesting: true
  teardown:
    enabled: true
    verifyRemoval: true
```

Two rules the schema exists to hold you to. Cost-abuse testing cannot run without a ceiling **and**
the client's written acknowledgement. And `teardown` tracks every artefact injected into a client's
RAG corpus and removes it, then verifies the removal — leaving a poisoned document in production is
the one mistake in LLM testing that a client cannot forgive.

`attemptsPerProbe` matters because a single successful jailbreak is a curiosity; twenty attempts
giving a success rate is a finding with a severity.

### 2.9 AI assistance

```yaml
ai:
  aiAssistEnabled: false        # off by default; the deployment flag must ALSO be on
  agenticEnabled: false         # shipped disabled, refused in code
  model: claude-sonnet-5
  triageModel: claude-haiku-4-5-20251001
  tokenCeiling: 500000
  spendCeilingUsd: 10
  agentic:
    wallClockMinutes: 60
    maxActions: 500
    forbiddenMethods: [DELETE, PUT, PATCH]
```

### 2.10 Evidence

```yaml
evidence:
  capture: [request, response, screenshot, terminal, transcript]
  retentionDays: 90             # ceiling 3650
  legalHold: false              # true suspends deletion, for a dispute
  maxBodyBytes: 262144
  disabledMaskingRuleIds: []    # think hard before adding to this
  extraMaskingPatterns:
    - id: northwind-loyalty-id
      pattern: 'NW-[0-9]{10}'
      replacement: 'NW-**********'
```

Client-specific identifier formats belong in `extraMaskingPatterns`. The built-in rules already cover
cards, Aadhaar, PAN, phone numbers and the common token shapes, with Luhn and Verhoeff checks so that
masking does not mangle unrelated digits.

### 2.11 Report

```yaml
report:
  templateId: attestor-standard-v1
  cvssVersion: '4.0'            # '3.1' when the client's auditor still expects it
  complianceFrameworks: [iso27001, soc2]   # iso27001 | soc2 | pciDss | dpdp | asvs
  includeSections: []
  omitSections: []
  spelling: british
  includeClientLogo: false
```

### 2.12 Notifications

```yaml
notifications:
  testerSeverityThreshold: high
  outOfBandOnCritical: true
  channels: [email]
```

`outOfBandOnCritical` makes a critical finding a phone call today, not a line in a report next week.
The platform queues the message; a person sends it.

---

## 3. Nine worked examples

### 3.1 First look at an unknown external surface

```yaml
description: Passive and light active recon only. Nothing authenticated, nothing intrusive.
modules: [recon]
intensity: safe
readOnlyMode: true
checks:
  nucleiSeverities: [critical, high]
rateLimits:
  globalRequestsPerSecond: 5
  perTargetRequestsPerSecond: 2
  concurrency: 2
  politeMode: true
evidence:
  capture: [request, response, terminal]
  retentionDays: 30
report:
  cvssVersion: '4.0'
  complianceFrameworks: [iso27001]
```

### 3.2 Authenticated web application, three roles

```yaml
description: The standard five-day engagement. Three roles, full access control matrix.
modules: [recon, web, api]
intensity: standard
phases: { preLogin: true, postLogin: true }
authProfiles:
  - id: viewer
    roleName: viewer
    type: formLogin
    credentialSetId: cs-viewer
    secondaryCredentialSetId: cs-viewer-2
    loginUrl: https://app.example.com/login
    sessionIndicator: { loggedOutText: 'Sign in to continue' }
  - id: editor
    roleName: editor
    type: formLogin
    credentialSetId: cs-editor
    secondaryCredentialSetId: cs-editor-2
    loginUrl: https://app.example.com/login
    sessionIndicator: { loggedOutText: 'Sign in to continue' }
  - id: admin
    roleName: admin
    type: formLogin
    credentialSetId: cs-admin
    loginUrl: https://app.example.com/login
    sessionIndicator: { selector: '[data-testid="admin-nav"]' }
accessControlMatrix:
  enabled: true
  testUnauthenticated: true
  identifierFields: [id, orderId, documentId, userId]
  maxReplayRequests: 2000
rateLimits:
  globalRequestsPerSecond: 10
  perTargetRequestsPerSecond: 4
  concurrency: 4
report:
  complianceFrameworks: [iso27001, soc2]
```

### 3.3 Production, during business hours, first pass

The careful one. Read-only, polite, tight windows, payment paths untouchable.

```yaml
description: Production. Read-only, out of hours, with the checkout flow off limits.
modules: [recon, web]
intensity: safe
readOnlyMode: true
rateLimits:
  globalRequestsPerSecond: 3
  perTargetRequestsPerSecond: 1
  concurrency: 2
  jitterMs: 400
  politeMode: true
  adaptive:
    backOffLatencyIncreasePercent: 25
    abortLatencyIncreasePercent: 75
    abortErrorRatePercent: 5
    abortConsecutiveServerErrors: 5
windows:
  - daysOfWeek: [1, 2, 3, 4]
    start: '22:00'
    end: '04:00'
blackouts:
  - daysOfWeek: [5, 6, 0]
    start: '00:00'
    end: '23:59'
forbiddenActions:
  - '**/checkout/**'
  - '**/api/payments/**'
  - '**/api/notifications/**'
exclusions:
  parameters: [redirect_uri, returnUrl]
notifications:
  testerSeverityThreshold: medium
  outOfBandOnCritical: true
```

### 3.4 API from an OpenAPI document

```yaml
description: REST API assessment driven from the client's OpenAPI 3.1 document.
modules: [api]
intensity: thorough
authProfiles:
  - id: service-account
    roleName: service
    type: bearerJwt
    credentialSetId: cs-api-token
    sessionIndicator: { responseHeader: 'x-request-id' }
  - id: tenant-a
    roleName: tenant
    type: bearerJwt
    credentialSetId: cs-tenant-a
    tenantId: tenant-a
  - id: tenant-b
    roleName: tenant
    type: bearerJwt
    credentialSetId: cs-tenant-b
    tenantId: tenant-b
accessControlMatrix:
  enabled: true
  rolePairs: [[tenant-a, tenant-b], [tenant-b, tenant-a]]
  identifierFields: [id, accountId, tenantId, invoiceId]
  maxReplayRequests: 3000
checks:
  exclude: [api-mass-assignment-destructive]
rateLimits:
  globalRequestsPerSecond: 12
  perTargetRequestsPerSecond: 6
  concurrency: 6
```

### 3.5 Cloud configuration review

Read-only by definition — a role, not an attack.

```yaml
description: Read-only AWS review through a dedicated audit role, plus IaC in the repository.
modules: [cloud, code]
intensity: standard
readOnlyMode: true
authProfiles:
  - id: aws-audit
    roleName: auditor
    type: apiKey
    credentialSetId: cs-aws-readonly
checks:
  include: [cloud-*, code-iac-*]
evidence:
  capture: [terminal, file]
  retentionDays: 60
report:
  complianceFrameworks: [iso27001, soc2, pciDss]
```

### 3.6 LLM red teaming, standalone

```yaml
description: A customer support RAG assistant. Prompt injection, tool abuse, data leakage.
modules: [llm]
intensity: thorough
llm:
  targetType: ragApplication
  endpoint: https://app.example.com/api/assistant
  promptPath: 'messages[-1].content'
  answerPath: 'reply'
  intendedPurpose: 'Answer questions about orders, returns and delivery.'
  declaredGuardrails: [system-prompt, output-filter]
  declaredTools: [order-lookup, refund-issue, email-send]
  topicsItMustRefuse: [refund policy exceptions, competitor comparison, medical advice]
  probePacks: [attestor-core, garak-broad, promptfoo-owasp, deepteam-owasp]
  attemptsPerProbe: 30
  budget:
    maxSpendUsd: 40
    maxTokens: 3000000
    estimatedCostPerRequestUsd: 0.003
    clientAcknowledgedCostTesting: true
  teardown:
    enabled: true
    verifyRemoval: true
evidence:
  capture: [transcript, request, response]
  retentionDays: 90
notifications:
  testerSeverityThreshold: medium
```

`declaredTools` is the one to fill in carefully. A model that can issue a refund is a model whose
prompt injection finding is a financial finding, and the severity should say so.

### 3.7 Mobile application plus its API

```yaml
description: Android and iOS, static and runtime, plus the API behind both.
modules: [mobile, api, network]
intensity: standard
authProfiles:
  - id: app-user
    roleName: user
    type: bearerJwt
    credentialSetId: cs-mobile-user
    secondaryCredentialSetId: cs-mobile-user-2
accessControlMatrix:
  enabled: true
  identifierFields: [id, userId, deviceId]
evidence:
  capture: [request, response, screenshot, file, terminal]
  maxBodyBytes: 524288
report:
  complianceFrameworks: [iso27001, asvs]
```

### 3.8 A monthly retainer run

Narrow and repeatable. The point is the delta, not the depth.

```yaml
description: Monthly retainer sweep. Attack surface, known CVEs, TLS, regressions.
modules: [recon, web]
intensity: safe
readOnlyMode: true
checks:
  nucleiSeverities: [critical, high]
  include:
    - recon-*
    - web-tls-*
    - web-security-headers
    - web-known-cve
rateLimits:
  globalRequestsPerSecond: 4
  perTargetRequestsPerSecond: 2
  concurrency: 2
  politeMode: true
windows:
  - daysOfWeek: [6]
    start: '02:00'
    end: '08:00'
evidence:
  retentionDays: 365
notifications:
  testerSeverityThreshold: high
  outOfBandOnCritical: true
```

### 3.9 A client-level policy

Set once on the client, inherited by every engagement for them.

```yaml
description: Northwind Retail. Their windows, their exclusions, their identifier format.
modules: [recon, web]        # engagements override this
blackouts:
  - daysOfWeek: [5]
    start: '12:00'
    end: '20:00'             # Friday release window, every week, forever
exclusions:
  hosts: [mail.northwind.example, status.northwind.example]
evidence:
  extraMaskingPatterns:
    - id: northwind-loyalty-id
      pattern: 'NW-[0-9]{10}'
      replacement: 'NW-**********'
  retentionDays: 60          # they asked for shorter than our default
report:
  complianceFrameworks: [iso27001, soc2, pciDss]
notifications:
  outOfBandOnCritical: true
```

---

## 4. Applying and checking a policy

```bash
curl -sS -b jar -X PUT :8080/engagements/<id>/policy \
  -H 'content-type: application/json' \
  -d "$(jq -Rs '{yaml: .}' < my-policy.yaml)"
```

A rate above a ceiling is an error and the policy is not saved. Everything else that is merely
suspect — a check id that matches nothing, an auth profile with no session indicator — comes back in
`warnings`, which is how you find out before the run instead of during it. Read them.

To see what the four layers actually resolved to:

```bash
curl -sS -b jar :8080/engagements/<id> | jq .policy
```

---

## 5. Things the schema will not let you write

Worth knowing so you do not go looking.

- Any rate above the ceilings. The policy is refused and not saved.
- Any form of flood, stress, volumetric or load test. There is no field, no flag, no escape hatch.
- A destructive payload set. Adapters build commands from a fixed vocabulary.
- Cost-abuse LLM testing without a spend ceiling and the client's acknowledgement.
- Replacing the built-in never-touch list. `forbiddenActions` only extends it.
- A credential value. `credentialSetId` is a reference into the vault; the policy never holds a
  secret, which is why a policy is safe to paste into a ticket.
