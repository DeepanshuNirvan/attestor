import type { ModuleName } from '@attestor/shared';

/**
 * The check catalogue is the single source of truth for what Attestor tests. Two things read it:
 * the report's coverage matrix, which records what actually ran against it, and the website's
 * coverage explorer, which publishes the same list to prospective clients. There is no second
 * list to fall out of sync.
 */

export const CHECK_CATEGORIES = [
  'informationGathering',
  'configuration',
  'authentication',
  'sessionManagement',
  'accessControl',
  'inputValidation',
  'businessLogic',
  'cryptography',
  'errorHandling',
  'clientSide',
  'apiSpecific',
  'mobileSpecific',
  'cloudSpecific',
  'llmSpecific',
  'supplyChain',
  'infrastructure',
] as const;

export type CheckCategory = (typeof CHECK_CATEGORIES)[number];

export const CATEGORY_LABELS: Record<CheckCategory, string> = {
  informationGathering: 'Information gathering',
  configuration: 'Configuration and deployment',
  authentication: 'Authentication',
  sessionManagement: 'Session management',
  accessControl: 'Access control',
  inputValidation: 'Input validation',
  businessLogic: 'Business logic',
  cryptography: 'Cryptography',
  errorHandling: 'Error handling',
  clientSide: 'Client-side',
  apiSpecific: 'API',
  mobileSpecific: 'Mobile',
  cloudSpecific: 'Cloud',
  llmSpecific: 'LLM and AI',
  supplyChain: 'Supply chain and code',
  infrastructure: 'Network and infrastructure',
};

/**
 * How much of the check a machine actually does.
 *  - automated: a tool produces the candidate finding without a human in the loop
 *  - assisted: a tool gathers the evidence, a human decides whether it is a finding
 *  - manual: a human does the work; the platform holds the evidence and the notes
 */
export type AutomationLevel = 'automated' | 'assisted' | 'manual';

export const AUTOMATION_LABELS: Record<AutomationLevel, string> = {
  automated: 'Automated',
  assisted: 'Tool-assisted, human-judged',
  manual: 'Manual',
};

/**
 * Things a target either has or does not have.
 *
 * No two clients are built the same. One authenticates with a JWT and another with a server-side
 * session; one exposes GraphQL and another has never heard of it; most have no payment flow at all.
 * A check written for a feature the target does not have must not fail the run, and must not quietly
 * pass either — "we tested your GraphQL authorisation" is a false statement about an application
 * with no GraphQL.
 *
 * Each key is something a run can actually establish by looking, which is the whole constraint on
 * this list: a feature nothing can detect would only ever be `unknown`, and would buy nothing.
 */
export const TARGET_FEATURES = [
  'login',
  'registration',
  'passwordReset',
  'mfa',
  'oauth',
  'saml',
  'jwt',
  'cookieSession',
  'restApi',
  'graphql',
  'soapXml',
  'websocket',
  'fileUpload',
  'payment',
  'adminInterface',
  'multiTenant',
  'cloudStorage',
  'tls',
] as const;

export type TargetFeature = (typeof TARGET_FEATURES)[number];

/**
 * `present` and `absent` are both findings of fact. `unknown` means nothing looked, or what looked
 * could not tell — and it is the default, because absence of evidence is not evidence of absence.
 * Only `absent` may downgrade a check to "not applicable"; `unknown` leaves it as untested, which is
 * the honest answer when nobody checked.
 */
export type TargetFeatureState = 'present' | 'absent' | 'unknown';

export interface CheckStandards {
  wstg?: string[];
  asvs?: string[];
  owaspTop10?: string[];
  apiTop10?: string[];
  masvs?: string[];
  llmTop10?: string[];
  cwe?: number[];
}

export interface Check {
  /** Stable, kebab-case, quoted in the coverage matrix. Never renumber a shipped id. */
  id: string;
  title: string;
  category: CheckCategory;
  modules: ModuleName[];
  /** Plain language, for a reader who is a developer but not a security specialist. */
  description: string;
  /** A concrete thing this check has found or would find. Not a restatement of the title. */
  example: string;
  automation: AutomationLevel;
  /** Tool ids from packages/scanners. Empty for checks that are purely manual. */
  tools: string[];
  standards: CheckStandards;
  /**
   * Features the target must have for this check to mean anything. Omitted means the check applies
   * to every target — most do. When every feature named here was looked for and found absent, the
   * coverage matrix records the check as not applicable, with what was looked for, rather than as a
   * gap in the testing.
   */
  appliesWhen?: TargetFeature[];
}
