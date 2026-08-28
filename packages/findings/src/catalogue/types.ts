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
}
