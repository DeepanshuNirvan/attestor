/**
 * Every published number lives here. The pricing pages, the estimator island and the Service
 * JSON-LD all read from this file, so changing a price is one edit and a redeploy.
 *
 * Figures are the owner's published price sheet, not indicative ranges pulled from a market study.
 * Turnaround days are working days from the start of the test window, and are the number the firm
 * commits to in writing.
 */

export type Currency = 'INR' | 'USD';

export type AssetType = 'web' | 'api' | 'mobile' | 'cloud' | 'llm' | 'external';

export interface PackagePrice {
  id: string;
  name: string;
  assetType: AssetType;
  summary: string;
  /** Headline price in the smallest sensible unit of the currency: whole rupees, whole dollars. */
  price: Record<Currency, number>;
  turnaroundDays: number;
  includes: string[];
  deliverables: string[];
  /** Add-on packages are quoted alongside a base engagement rather than sold alone. */
  addOn?: boolean;
  recurring?: 'month';
}

export const CURRENCY_FORMAT: Record<Currency, { locale: string; code: string }> = {
  INR: { locale: 'en-IN', code: 'INR' },
  USD: { locale: 'en-US', code: 'USD' },
};

export function formatMoney(amount: number, currency: Currency): string {
  const { locale, code } = CURRENCY_FORMAT[currency];
  return new Intl.NumberFormat(locale, {
    style: 'currency',
    currency: code,
    maximumFractionDigits: 0,
  }).format(amount);
}

const DELIVERABLES_STANDARD = [
  'Full assessment report, PDF and in-portal HTML',
  'One-page attestation letter to forward to your buyer or auditor',
  'Findings in the client portal with reproduction steps and evidence',
  'Compliance mapping: ISO 27001 A.8.8, SOC 2, PCI DSS 11.4, DPDP',
  'One free retest within 30 days, then a retest report',
  '30-minute walkthrough call with your developers',
  'Written confirmation when testing evidence is deleted',
];

export const packages: PackagePrice[] = [
  {
    id: 'external-surface-check',
    name: 'External surface check',
    assetType: 'external',
    summary:
      'What an anonymous attacker sees: subdomains, exposed services, TLS and header configuration, leaked secrets in public JavaScript, mail authentication records.',
    price: { INR: 12_000, USD: 600 },
    turnaroundDays: 1,
    includes: [
      'Subdomain and attack-surface enumeration',
      'Port, service and TLS configuration review',
      'HTTP security header and cookie configuration',
      'Secrets exposed in public JavaScript bundles',
      'SPF, DKIM and DMARC review',
    ],
    deliverables: [
      'Short findings report, PDF',
      'Prioritised fix list',
      'No retest included at this price',
    ],
  },
  {
    id: 'cloud-review',
    name: 'Cloud configuration review',
    assetType: 'cloud',
    summary:
      'A read-only role against your AWS, Azure or GCP account. No write call is ever made, so nothing in your environment can change.',
    price: { INR: 45_000, USD: 2_000 },
    turnaroundDays: 2,
    includes: [
      'Read-only role, no write API call made at any point',
      'Benchmark checks across every enabled service',
      'IAM privilege and privilege-escalation path analysis',
      'Public exposure: storage, snapshots, databases, disks',
      'Logging, monitoring, encryption and key rotation gaps',
      'Kubernetes benchmark checks where a cluster is in scope',
    ],
    deliverables: DELIVERABLES_STANDARD,
  },
  {
    id: 'api-assessment',
    name: 'API assessment',
    assetType: 'api',
    summary:
      'REST or GraphQL, driven from your OpenAPI document or from captured traffic where no document exists.',
    price: { INR: 40_000, USD: 2_400 },
    turnaroundDays: 3,
    includes: [
      'Schema-driven testing of every documented endpoint',
      'Object and function level authorisation testing across roles',
      'Mass assignment and excessive data exposure',
      'JWT handling: algorithm confusion, expiry, audience, weak secrets',
      'Rate limiting and resource consumption',
      'GraphQL introspection and query depth abuse',
      'Deprecated and undocumented endpoint discovery',
    ],
    deliverables: DELIVERABLES_STANDARD,
  },
  {
    id: 'web-standard',
    name: 'Web application and API audit',
    assetType: 'web',
    summary:
      'Authenticated, grey-box, per-role. The engagement most companies need when an enterprise buyer asks for a report.',
    price: { INR: 55_000, USD: 3_000 },
    turnaroundDays: 5,
    includes: [
      'Authenticated testing for every user role you supply',
      'Access control: horizontal and vertical, across all roles',
      'Business logic: workflow bypass, price and quantity manipulation, race conditions',
      'Session management, authentication and password reset flows',
      'Injection, file handling, client-side and configuration testing',
      'The API behind the application, in the same engagement',
      'Coverage recorded against OWASP WSTG test identifiers',
    ],
    deliverables: DELIVERABLES_STANDARD,
  },
  {
    id: 'web-complex',
    name: 'Web application audit, complex',
    assetType: 'web',
    summary:
      'Multi-tenant, four or more roles, payment or approval workflows, or an application large enough that the standard window is not honest.',
    price: { INR: 95_000, USD: 5_500 },
    turnaroundDays: 8,
    includes: [
      'Everything in the standard audit',
      'Tenant isolation testing across separate customer accounts',
      'Approval, payment and settlement workflow abuse',
      'Chained exploitation: what several low findings become together',
      'Written attack narrative for the most significant chain',
    ],
    deliverables: DELIVERABLES_STANDARD,
  },
  {
    id: 'mobile',
    name: 'Mobile application assessment',
    assetType: 'mobile',
    summary:
      'Android and iOS, static and runtime, plus the API the app talks to. Includes a data-safety declaration consistency check.',
    price: { INR: 65_000, USD: 3_500 },
    turnaroundDays: 5,
    includes: [
      'Static analysis of the shipped binary, both platforms',
      'Hardcoded secrets, insecure storage, exported components',
      'Certificate pinning presence and bypass assessment',
      'Runtime analysis on an instrumented device',
      'The backing API, tested through intercepted traffic',
      'Play Store and App Store data-safety declaration consistency',
      'Coverage recorded against OWASP MASVS controls',
    ],
    deliverables: DELIVERABLES_STANDARD,
  },
  {
    id: 'llm-addon',
    name: 'LLM and AI red teaming, add-on',
    assetType: 'llm',
    summary: 'Added to a web, API or mobile engagement covering the same product.',
    price: { INR: 40_000, USD: 1_800 },
    turnaroundDays: 2,
    addOn: true,
    includes: [
      'Direct and indirect prompt injection',
      'Jailbreak matrix, single-turn and multi-turn escalation',
      'System prompt extraction and configuration leakage',
      'Insecure output handling where model output reaches HTML, SQL, a shell or a URL fetch',
      'Guardrail bypass against the filters you have declared',
      'Coverage recorded against the OWASP Top 10 for LLM Applications',
    ],
    deliverables: [
      'LLM findings folded into the main report with full conversation transcripts as evidence',
      'OWASP LLM Top 10 coverage matrix',
    ],
  },
  {
    id: 'llm-standalone',
    name: 'LLM and AI red teaming',
    assetType: 'llm',
    summary:
      'A standalone engagement against a chatbot, a RAG application or an agent with tool access. No web assessment required.',
    price: { INR: 120_000, USD: 5_000 },
    turnaroundDays: 6,
    includes: [
      'Everything in the add-on',
      'RAG document poisoning, retrieval manipulation and cross-tenant retrieval leakage',
      'Agent testing: tool abuse, chained tool calls, excessive agency, goal hijacking',
      'Sensitive information disclosure and PII leakage probes',
      'Cost abuse measured and reported in currency, under a hard budget ceiling',
      'Attack success rate over repeated attempts, not a single lucky prompt',
      'Every injected artefact tracked and removed in a verified teardown step',
    ],
    deliverables: DELIVERABLES_STANDARD,
  },
  {
    id: 'retainer',
    name: 'Continuous testing retainer',
    assetType: 'web',
    summary:
      'Scheduled re-testing, attack-surface monitoring and a quarterly deep assessment, on a monthly fee.',
    price: { INR: 40_000, USD: 2_200 },
    turnaroundDays: 0,
    recurring: 'month',
    includes: [
      'Scheduled rescans inside your agreed test windows',
      'New finding, resolved finding and regression tracking between runs',
      'Attack-surface monitoring: new subdomains, new open ports, certificate expiry',
      'Quarterly deep assessment included',
      'Security questionnaire answers maintained for you',
      'Named contact for out-of-band critical findings',
    ],
    deliverables: [
      'Monthly one-page posture summary',
      'Live findings and trend view in the client portal',
      'Quarterly full assessment report and attestation letter',
    ],
  },
  {
    id: 'fractional-lead',
    name: 'Fractional security lead',
    assetType: 'web',
    summary:
      'For companies that need someone answering security questions weekly but cannot justify a hire.',
    price: { INR: 90_000, USD: 4_500 },
    turnaroundDays: 0,
    recurring: 'month',
    includes: [
      'Everything in the retainer',
      'Security questionnaire and buyer due-diligence support',
      'Policy and control design for ISO 27001 or SOC 2',
      'Architecture and design review on new features',
      'Direct line to your engineering team',
    ],
    deliverables: [
      'Monthly posture summary and roadmap review',
      'Questionnaire answers written and kept current',
      'Named security contact your buyers can be told about',
    ],
  },
];

export function packageById(id: string): PackagePrice {
  const found = packages.find((item) => item.id === id);
  if (!found) throw new Error(`unknown package: ${id}`);
  return found;
}

/* ---------------------------------------------------------------------------------------------
 * Estimator model
 *
 * The estimator must return a real band for every valid combination of inputs. It works by taking
 * the base package for the asset type and applying multipliers, then widening into a band. There
 * is no "contact us" branch: if the multipliers push the estimate past the largest published
 * package the answer is still a number, with a note that a scoping call will confirm it.
 * ------------------------------------------------------------------------------------------- */

export interface EstimatorInputs {
  assetType: AssetType;
  /** Endpoints for web and API, screens for mobile, resources for cloud, tools for LLM. */
  scaleUnits: number;
  roleCount: number;
  authComplexity: 'none' | 'simple' | 'multiStep' | 'federated';
  environmentCount: number;
  needsRetest: boolean;
  currency: Currency;
}

export interface Estimate {
  low: number;
  high: number;
  days: number;
  basePackage: PackagePrice;
  includes: string[];
  deliverables: string[];
  notes: string[];
}

const BASE_PACKAGE_FOR_ASSET: Record<AssetType, string> = {
  web: 'web-standard',
  api: 'api-assessment',
  mobile: 'mobile',
  cloud: 'cloud-review',
  llm: 'llm-standalone',
  external: 'external-surface-check',
};

/** Scale is charged in bands, not per endpoint: an endpoint count is an estimate, not a contract. */
const SCALE_BANDS: { upTo: number; multiplier: number; label: string }[] = [
  { upTo: 25, multiplier: 1, label: 'up to 25' },
  { upTo: 60, multiplier: 1.25, label: '26 to 60' },
  { upTo: 120, multiplier: 1.6, label: '61 to 120' },
  { upTo: 250, multiplier: 2.1, label: '121 to 250' },
  { upTo: Number.POSITIVE_INFINITY, multiplier: 2.8, label: 'over 250' },
];

const AUTH_MULTIPLIER: Record<EstimatorInputs['authComplexity'], number> = {
  none: 0.8,
  simple: 1,
  multiStep: 1.2,
  federated: 1.35,
};

const RETEST_MULTIPLIER = 1; // the first retest inside 30 days is included, so it costs nothing

function scaleBandFor(units: number): { multiplier: number; label: string } {
  const band = SCALE_BANDS.find((entry) => units <= entry.upTo);
  return band ?? SCALE_BANDS[SCALE_BANDS.length - 1]!;
}

function roundTo(amount: number, currency: Currency): number {
  const step = currency === 'INR' ? 2_500 : 100;
  return Math.round(amount / step) * step;
}

export function estimate(inputs: EstimatorInputs): Estimate {
  const basePackage = packageById(BASE_PACKAGE_FOR_ASSET[inputs.assetType]);
  const base = basePackage.price[inputs.currency];

  const scale = scaleBandFor(Math.max(1, inputs.scaleUnits));
  // Each role past the first is a separate authenticated pass and a separate cross-role replay set.
  const roleMultiplier = 1 + Math.max(0, inputs.roleCount - 1) * 0.18;
  // Additional environments are re-runs of the same checks, so they are cheaper than the first.
  const environmentMultiplier = 1 + Math.max(0, inputs.environmentCount - 1) * 0.15;
  const authMultiplier =
    inputs.assetType === 'cloud' ? 1 : AUTH_MULTIPLIER[inputs.authComplexity];

  const centre =
    base *
    scale.multiplier *
    roleMultiplier *
    environmentMultiplier *
    authMultiplier *
    RETEST_MULTIPLIER;

  const low = roundTo(centre * 0.9, inputs.currency);
  const high = roundTo(centre * 1.15, inputs.currency);

  const days = Math.max(
    basePackage.turnaroundDays,
    Math.ceil(basePackage.turnaroundDays * scale.multiplier * roleMultiplier * authMultiplier),
  );

  const notes: string[] = [`Scope band: ${scale.label} ${scaleUnitNoun(inputs.assetType)}.`];
  if (inputs.roleCount >= 2) {
    notes.push(
      `Cross-role access control testing needs two accounts per role. That is ${inputs.roleCount * 2} test accounts.`,
    );
  }
  if (inputs.needsRetest) {
    notes.push('One retest within 30 days of report release is included at no extra cost.');
  }
  if (inputs.assetType === 'cloud') {
    notes.push('Read-only access only. No write API call is made against your account.');
  }
  if (inputs.assetType === 'llm') {
    notes.push(
      'Cost-abuse testing runs under a spend ceiling you set, and every injected document is removed in a verified teardown.',
    );
  }
  if (high > basePackage.price[inputs.currency] * 2.5) {
    notes.push(
      'This scope is larger than the published packages. The band is honest, and the scoping call will narrow it.',
    );
  }

  return {
    low,
    high,
    days,
    basePackage,
    includes: basePackage.includes,
    deliverables: basePackage.deliverables,
    notes,
  };
}

export function scaleUnitNoun(assetType: AssetType): string {
  switch (assetType) {
    case 'mobile':
      return 'screens';
    case 'cloud':
      return 'cloud resources';
    case 'llm':
      return 'tools and data sources the model can reach';
    case 'external':
      return 'hosts';
    default:
      return 'endpoints';
  }
}
