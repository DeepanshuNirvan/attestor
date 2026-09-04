import { z } from 'zod';
import { MODULES } from '@attestor/shared';

/**
 * Policy as code.
 *
 * Everything configurable about a run lives here and nowhere else: which modules run, which checks,
 * how hard, against which phases, at what rate, in which windows, with what evidence handling. The
 * console has a form for the common knobs and a raw YAML editor with this schema behind it.
 *
 * Two rules constrain what the schema will accept, and both are enforced here rather than in the
 * runner, so a policy that would be unsafe fails to load rather than failing at run time:
 *
 *  1. Rate limits have a hard ceiling. A policy can lower them and cannot raise them past it.
 *  2. There is no denial-of-service setting to express. It does not appear in the schema because it
 *     does not exist in the platform.
 */

/** Ceilings enforced in code. A policy may go below these; nothing may go above them. */
export const RATE_CEILINGS = {
  globalRequestsPerSecond: 40,
  perTargetRequestsPerSecond: 10,
  concurrency: 12,
  /** Bounded attempts for any check that repeats a request against the same endpoint. */
  maxAttemptsPerCheck: 400,
} as const;

const percent = z.number().min(0).max(100);
const percentIncrease = z.number().min(0).max(10000);

export const rateLimitSchema = z
  .object({
    globalRequestsPerSecond: z
      .number()
      .positive()
      .max(RATE_CEILINGS.globalRequestsPerSecond)
      .default(10),
    perTargetRequestsPerSecond: z
      .number()
      .positive()
      .max(RATE_CEILINGS.perTargetRequestsPerSecond)
      .default(4),
    concurrency: z.number().int().positive().max(RATE_CEILINGS.concurrency).default(4),
    /** Milliseconds of random delay added to each request, to avoid a metronomic pattern. */
    jitterMs: z.number().int().nonnegative().max(2000).default(120),
    /** Halves every limit above. Used on production targets. */
    politeMode: z.boolean().default(false),
    adaptive: z
      .object({
        /** Back off when median latency rises by this percentage over the run's baseline. */
        backOffLatencyIncreasePercent: percentIncrease.default(50),
        /** Abort when it rises by this much, or when the error rate exceeds the threshold. */
        abortLatencyIncreasePercent: percentIncrease.default(200),
        abortErrorRatePercent: percent.default(15),
        /** Consecutive 5xx responses that abort the run outright. */
        abortConsecutiveServerErrors: z.number().int().positive().default(20),
      })
      .prefault({}),
  })
  .prefault({});

export const testWindowSchema = z.object({
  daysOfWeek: z.array(z.number().int().min(0).max(6)).min(1),
  /** 24-hour local time in the engagement timezone. */
  start: z.string().regex(/^\d{2}:\d{2}$/),
  end: z.string().regex(/^\d{2}:\d{2}$/),
});

export const authProfileSchema = z.object({
  id: z.string().min(1),
  roleName: z.string().min(1),
  type: z.enum([
    'none',
    'formLogin',
    'scriptedLogin',
    'otpAssisted',
    'oauth2',
    'apiKey',
    'bearerJwt',
    'sessionCookie',
    'mtls',
  ]),
  /** Reference into the credential vault. Never a value. */
  credentialSetId: z.string().min(1).optional(),
  loginUrl: z.string().optional(),
  /**
   * How to obtain a session by calling the application directly, for tests that replay requests
   * rather than drive a browser — access control comparison, chiefly.
   *
   * Optional, and absent is a normal answer: an API key or a bearer token needs no login at all,
   * and an application whose only way in is a browser form is tested through the browser instead.
   * When it is absent the replay tests simply have no session for that role and say so, rather
   * than guessing at field names and locking the client's account out.
   */
  apiLogin: z
    .object({
      /** Defaults to `loginUrl` when omitted. */
      url: z.string().optional(),
      usernameField: z.string().min(1),
      passwordField: z.string().min(1),
      /**
       * Dotted path to the token in the JSON response, e.g. `authentication.token`. Omit when the
       * application answers with a session cookie, which is used automatically.
       */
      tokenPath: z.string().optional(),
      /** Header the token is presented in. */
      tokenHeader: z.string().default('authorization'),
      /** `{token}` is replaced with the value found at `tokenPath`. */
      tokenTemplate: z.string().default('Bearer {token}'),
    })
    .optional(),
  /** Playwright script path for scriptedLogin, relative to the engagement's script directory. */
  scriptPath: z.string().optional(),
  /** How to tell the session is still alive. At least one is required for anything but `none`. */
  sessionIndicator: z
    .object({
      selector: z.string().optional(),
      urlPattern: z.string().optional(),
      responseHeader: z.string().optional(),
      jsonPath: z.string().optional(),
      /** Text that appears only when logged out, e.g. a login form heading. */
      loggedOutText: z.string().optional(),
    })
    .optional(),
  /** How often to confirm the session is alive, in requests. */
  sessionCheckEveryRequests: z.number().int().positive().default(25),
  /** Two accounts per role is what makes horizontal access control testable. */
  secondaryCredentialSetId: z.string().min(1).optional(),
  tenantId: z.string().optional(),
});

export const accessControlMatrixSchema = z
  .object({
    enabled: z.boolean().default(true),
    /** Role pairs to test. Empty means every ordered pair of configured roles. */
    rolePairs: z.array(z.tuple([z.string(), z.string()])).default([]),
    testUnauthenticated: z.boolean().default(true),
    /** Parameter names treated as object identifiers and mutated during replay. */
    identifierFields: z
      .array(z.string())
      .default(['id', 'uuid', 'userId', 'accountId', 'orderId', 'tenantId', 'customerId']),
    /** Similarity above which two responses are treated as "substantially the same". */
    responseSimilarityThreshold: z.number().min(0).max(1).default(0.9),
    maxReplayRequests: z.number().int().positive().max(5000).default(1500),
  })
  .prefault({});

export const llmPolicySchema = z
  .object({
    targetType: z
      .enum(['rawEndpoint', 'chatUi', 'ragApplication', 'agentic', 'embeddedBot'])
      .default('rawEndpoint'),
    endpoint: z.string().optional(),
    /** JSON path into the request body where the prompt goes, and into the response for the answer. */
    promptPath: z.string().default('messages[-1].content'),
    answerPath: z.string().default('choices[0].message.content'),
    systemPrompt: z.string().optional(),
    declaredGuardrails: z.array(z.string()).default([]),
    declaredTools: z.array(z.string()).default([]),
    intendedPurpose: z.string().default(''),
    topicsItMustRefuse: z.array(z.string()).default([]),
    probePacks: z
      .array(z.string())
      .default(['attestor-core', 'garak-broad', 'promptfoo-owasp', 'deepteam-owasp']),
    attemptsPerProbe: z.number().int().positive().max(200).default(20),
    /** Hard ceiling. Cost-abuse testing cannot run without one, and it stops well before it. */
    budget: z
      .object({
        maxSpendUsd: z.number().nonnegative().default(0),
        maxTokens: z.number().int().nonnegative().default(0),
        estimatedCostPerRequestUsd: z.number().nonnegative().default(0),
        clientAcknowledgedCostTesting: z.boolean().default(false),
      })
      .prefault({}),
    /** Track and remove every artefact injected into a client corpus, then verify removal. */
    teardown: z
      .object({
        enabled: z.boolean().default(true),
        verifyRemoval: z.boolean().default(true),
      })
      .prefault({}),
  })
  .prefault({});

export const aiPolicySchema = z
  .object({
    aiAssistEnabled: z.boolean().default(false),
    agenticEnabled: z.boolean().default(false),
    model: z.string().default('claude-sonnet-5'),
    triageModel: z.string().default('claude-haiku-4-5-20251001'),
    tokenCeiling: z.number().int().nonnegative().default(0),
    spendCeilingUsd: z.number().nonnegative().default(0),
    agentic: z
      .object({
        wallClockMinutes: z.number().int().positive().max(240).default(60),
        maxActions: z.number().int().positive().max(5000).default(500),
        forbiddenMethods: z.array(z.string()).default(['DELETE', 'PUT', 'PATCH']),
      })
      .prefault({}),
  })
  .prefault({});

export const evidencePolicySchema = z
  .object({
    capture: z
      .array(z.enum(['request', 'response', 'screenshot', 'log', 'terminal', 'file', 'transcript']))
      .default(['request', 'response', 'screenshot', 'terminal', 'transcript']),
    /** Masking rule ids to disable, and extra client-specific patterns. */
    disabledMaskingRuleIds: z.array(z.string()).default([]),
    extraMaskingPatterns: z
      .array(z.object({ id: z.string(), pattern: z.string(), replacement: z.string() }))
      .default([]),
    retentionDays: z.number().int().positive().max(3650).default(90),
    legalHold: z.boolean().default(false),
    maxBodyBytes: z.number().int().positive().default(256 * 1024),
  })
  .prefault({});

export const reportPolicySchema = z
  .object({
    templateId: z.string().default('attestor-standard-v1'),
    cvssVersion: z.enum(['3.1', '4.0']).default('4.0'),
    complianceFrameworks: z
      .array(z.enum(['iso27001', 'soc2', 'pciDss', 'dpdp', 'asvs']))
      .default(['iso27001', 'soc2']),
    includeSections: z.array(z.string()).default([]),
    omitSections: z.array(z.string()).default([]),
    spelling: z.enum(['british', 'american']).default('british'),
    includeClientLogo: z.boolean().default(false),
  })
  .prefault({});

export const notificationPolicySchema = z
  .object({
    testerSeverityThreshold: z.enum(['critical', 'high', 'medium', 'low', 'info']).default('high'),
    outOfBandOnCritical: z.boolean().default(true),
    channels: z.array(z.enum(['email', 'slack', 'teams'])).default(['email']),
  })
  .prefault({});

export const policySchema = z.object({
  /** Free text, shown in the console diff so a change explains itself. */
  description: z.string().default(''),
  modules: z.array(z.enum(MODULES)).min(1),
  intensity: z.enum(['safe', 'standard', 'thorough']).default('standard'),
  phases: z
    .object({
      preLogin: z.boolean().default(true),
      postLogin: z.boolean().default(true),
    })
    .prefault({}),
  checks: z
    .object({
      /** When non-empty, only these run. Ids, WSTG ids, ASVS requirements or OWASP categories. */
      include: z.array(z.string()).default([]),
      exclude: z.array(z.string()).default([]),
      /** nuclei template selection. */
      nucleiTags: z.array(z.string()).default([]),
      /**
       * `info` is included, and that is deliberate.
       *
       * Leaving it out looked tidy and quietly removed a whole class of check from every run: the
       * exposure and metafile templates — robots.txt, security.txt, sitemap, exposed panels — are
       * all `info`, so the platform shipped for months unable to perform them however the policy was
       * written. Informational results are candidates like any other and a person decides whether
       * they reach the report, so the cost of including them is triage time and the cost of
       * excluding them was coverage nobody could see was missing.
       */
      nucleiSeverities: z
        .array(z.enum(['critical', 'high', 'medium', 'low', 'info']))
        .default(['critical', 'high', 'medium', 'low', 'info']),
      /**
       * Endpoints to measure throttling on, beyond the login the auth profile already names.
       *
       * Named rather than discovered on purpose. Which endpoint matters is a judgement about the
       * business — an OTP request costs the client money per message, a password reset emails a real
       * person, a search is expensive to run — and a probe that guessed would either miss the one
       * that matters or hammer one that should never have been touched.
       */
      rateLimitEndpoints: z
        .array(
          z.object({
            url: z.string().min(1),
            method: z.enum(['GET', 'POST']).default('GET'),
            /** What this endpoint does, for the finding. `the one-time code request`, say. */
            description: z.string().default(''),
          }),
        )
        .default([]),
      /** Requests sent in the burst. Small enough to stay polite, large enough to see a limit. */
      rateLimitBurst: z.number().int().min(5).max(200).default(30),
      /**
       * Where the target serves its OpenAPI document, as a path on the target itself.
       *
       * A path rather than a URL on purpose: the schema is then fetched from a host that is already
       * inside the engagement's authorisation, and no separate scope decision is needed for it.
       * Empty means the client has not given us one, and schemathesis refuses to run rather than
       * guessing at `/openapi.json` and reporting whatever it finds there.
       */
      openApiSchemaPath: z.string().max(200).default(''),
    })
    .prefault({}),
  authProfiles: z.array(authProfileSchema).default([]),
  accessControlMatrix: accessControlMatrixSchema,
  rateLimits: rateLimitSchema,
  windows: z.array(testWindowSchema).default([]),
  blackouts: z.array(testWindowSchema).default([]),
  /** Suppresses every state-changing request. The first pass on production always uses it. */
  readOnlyMode: z.boolean().default(false),
  /** URL patterns and form actions never to touch. Extends the built-in list, never replaces it. */
  forbiddenActions: z.array(z.string()).default([]),
  exclusions: z
    .object({
      paths: z.array(z.string()).default([]),
      parameters: z.array(z.string()).default([]),
      hosts: z.array(z.string()).default([]),
      fileTypes: z.array(z.string()).default([]),
    })
    .prefault({}),
  llm: llmPolicySchema,
  ai: aiPolicySchema,
  evidence: evidencePolicySchema,
  report: reportPolicySchema,
  notifications: notificationPolicySchema,
});

export type Policy = z.infer<typeof policySchema>;
export type PolicyInput = z.input<typeof policySchema>;
export type AuthProfile = z.infer<typeof authProfileSchema>;
export type RateLimits = z.infer<typeof rateLimitSchema>;
export type LlmPolicy = z.infer<typeof llmPolicySchema>;
export type EvidencePolicy = z.infer<typeof evidencePolicySchema>;

/**
 * Actions never taken during crawling, whatever the policy says. The policy's `forbiddenActions`
 * adds to this list; nothing removes from it.
 */
export const ALWAYS_FORBIDDEN_ACTIONS = [
  '**/logout*',
  '**/signout*',
  '**/sign-out*',
  '**/delete-account*',
  '**/close-account*',
  '**/deactivate*',
  '**/change-password*',
  '**/reset-password*',
  '**/change-email*',
  '**/checkout/confirm*',
  '**/payment/submit*',
  '**/pay*',
  '**/subscribe*',
  '**/cancel-subscription*',
  '**/invite*',
  '**/bulk-delete*',
  '**/purge*',
  '**/wipe*',
  '**/factory-reset*',
  '**/disable-mfa*',
  '**/revoke*',
];
