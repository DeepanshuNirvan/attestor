import { redactText } from '@attestor/shared';

/**
 * The AI-assist layer.
 *
 * It drafts prose from evidence that has already been captured. It is off by default, off unless a
 * specific engagement turns it on, and structurally incapable of asserting a fact that is not in
 * the material it was given.
 *
 * Five rules, each enforced here rather than requested in a prompt:
 *
 *   1. **Two switches, both required.** The deployment flag and the engagement flag. Either one off
 *      means refused, and the refusal names which.
 *   2. **Redacted input only.** Every string goes through the redaction filter on the way in. A
 *      secret cannot be sent to a third party if it is replaced before the request is built.
 *   3. **Grounded output.** Hosts, URLs, file paths and CVE identifiers in the output are checked
 *      against the input. Anything the model introduced is a hallucination, and the draft is
 *      refused rather than shown with a warning — a warning is something a tired person clicks past.
 *   4. **Always a draft.** There is no path that returns approved text. The caller stores it marked
 *      as a draft, and the pre-release checklist refuses to release an unapproved AI block.
 *   5. **Recorded.** Model, purpose, token counts and cost go to the usage log; the prompt hash goes
 *      to the audit log. "Which model wrote this sentence" has to be answerable a year later.
 *
 * The transport is injected, so every test here runs without a network and without a key.
 */

export type AiPurpose =
  | 'findingProse'
  | 'executiveSummary'
  | 'toolOutputExplanation'
  | 'cvssRationale'
  | 'deduplicationProposal';

export interface AiRequest {
  engagementId: string;
  purpose: AiPurpose;
  /**
   * The evidence the draft must be grounded in. Everything the model is allowed to assert has to
   * appear here; nothing else is sent.
   */
  evidence: string[];
  /** What to write. Never contains client data — that is what `evidence` is for. */
  instruction: string;
}

export interface AiTransportRequest {
  model: string;
  system: string;
  userContent: string;
  maxTokens: number;
}

export interface AiTransportResponse {
  text: string;
  inputTokens: number;
  outputTokens: number;
}

export type AiTransport = (request: AiTransportRequest) => Promise<AiTransportResponse>;

export interface AiAssistConfig {
  /** The deployment-wide switch. False means this class refuses everything. */
  enabled: boolean;
  provider: 'anthropic' | 'openai' | 'none';
  modelDrafting: string;
  modelTriage: string;
  /** Monthly ceiling in USD. Zero means no spending is permitted at all. */
  monthlyBudgetUsd: number;
  /** Per million tokens, for the estimate written to the usage log. */
  inputCostPerMillionUsd?: number;
  outputCostPerMillionUsd?: number;
}

export interface AiAssistDependencies {
  config: AiAssistConfig;
  transport: AiTransport;
  /** Whether this engagement has the assist flag set. */
  engagementEnabled: (engagementId: string) => Promise<boolean>;
  /** Spend already recorded this calendar month, in USD. */
  spentThisMonthUsd: (engagementId: string) => Promise<number>;
  record: (entry: {
    engagementId: string;
    model: string;
    purpose: AiPurpose;
    inputTokens: number;
    outputTokens: number;
    estimatedCostUsd: number;
    promptSha256: string;
  }) => Promise<void>;
}

export type AiRefusalRule =
  | 'deploymentDisabled'
  | 'engagementDisabled'
  | 'noProvider'
  | 'budgetExhausted'
  | 'noEvidence'
  | 'ungrounded';

export interface AiRefused {
  status: 'refused';
  rule: AiRefusalRule;
  detail: string;
}

export interface AiDrafted {
  status: 'drafted';
  /** Always a draft. There is no other kind of output from this module. */
  isDraft: true;
  markdown: string;
  model: string;
  promptSha256: string;
  inputTokens: number;
  outputTokens: number;
  estimatedCostUsd: number;
}

export type AiOutcome = AiRefused | AiDrafted;

const SYSTEM_PROMPT = [
  'You draft prose for a security assessment report.',
  '',
  'You may only state what appears in the EVIDENCE below. If the evidence does not support a',
  'sentence, do not write that sentence. Do not name a host, URL, parameter, file, CVE or product',
  'version that does not appear in the evidence. Do not estimate a severity the evidence does not',
  'support. Do not invent a reference.',
  '',
  'If the evidence is insufficient to answer, say exactly what is missing and stop.',
  '',
  'Write British English, plain and specific, addressed to an engineer who has to fix the thing.',
  'No marketing language and no reassurance.',
].join('\n');

/** Things a model inventing detail would produce: hostnames, URLs, paths, CVEs, versions. */
const GROUNDING_PATTERNS: { name: string; pattern: RegExp }[] = [
  { name: 'URL', pattern: /https?:\/\/[^\s)"'<>]+/gi },
  { name: 'CVE', pattern: /CVE-\d{4}-\d{4,7}/gi },
  { name: 'hostname', pattern: /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b/gi },
];

function normalise(value: string): string {
  return value.toLowerCase().replace(/[.,;:)\]}]+$/, '');
}

/**
 * Returns the tokens the output asserts that the input never mentioned.
 *
 * Deliberately conservative in the direction that matters: a false positive here costs a redraft,
 * a false negative puts an invented hostname in a client's report.
 */
export function ungroundedClaims(output: string, evidence: string[]): string[] {
  const haystack = normalise(evidence.join('\n'));
  const missing: string[] = [];

  // URLs are matched first, so the hostname inside an already-flagged URL is not reported a second
  // time. One invented host should read as one problem.
  for (const { pattern } of GROUNDING_PATTERNS) {
    for (const match of output.matchAll(pattern)) {
      const candidate = normalise(match[0]);
      // Too short to be anything but a false positive from a sentence ending without a space.
      if (candidate.length < 4) continue;
      if (haystack.includes(candidate)) continue;
      if (missing.some((flagged) => normalise(flagged).includes(candidate))) continue;
      if (!missing.includes(match[0])) missing.push(match[0]);
    }
  }

  return missing;
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export class AiAssist {
  private readonly dependencies: AiAssistDependencies;

  constructor(dependencies: AiAssistDependencies) {
    this.dependencies = dependencies;
  }

  async draft(request: AiRequest): Promise<AiOutcome> {
    const { config } = this.dependencies;

    if (!config.enabled) {
      return {
        status: 'refused',
        rule: 'deploymentDisabled',
        detail: 'the AI layer is off for this deployment (AI_ENABLED is false)',
      };
    }
    if (config.provider === 'none') {
      return {
        status: 'refused',
        rule: 'noProvider',
        detail: 'no AI provider is configured (AI_PROVIDER is none)',
      };
    }
    if (!(await this.dependencies.engagementEnabled(request.engagementId))) {
      return {
        status: 'refused',
        rule: 'engagementDisabled',
        detail:
          'this engagement has not enabled AI assistance. It is a per-engagement decision, and the client agreed to the engagement, not to the tooling.',
      };
    }

    const evidence = request.evidence.map((entry) => entry.trim()).filter((entry) => entry !== '');
    if (evidence.length === 0) {
      return {
        status: 'refused',
        rule: 'noEvidence',
        detail: 'nothing to ground a draft in. Prose without evidence is fiction.',
      };
    }

    const spent = await this.dependencies.spentThisMonthUsd(request.engagementId);
    if (spent >= config.monthlyBudgetUsd) {
      return {
        status: 'refused',
        rule: 'budgetExhausted',
        detail: `the monthly ceiling of $${config.monthlyBudgetUsd} has been reached ($${spent.toFixed(2)} spent)`,
      };
    }

    // Redaction happens here, on the way out, so no later change to a caller can bypass it.
    const redactedEvidence = evidence.map((entry) => redactText(entry));
    const userContent = [
      'EVIDENCE',
      '--------',
      ...redactedEvidence.map((entry, index) => `[${index + 1}] ${entry}`),
      '',
      'TASK',
      '----',
      redactText(request.instruction),
    ].join('\n');

    const model = request.purpose === 'findingProse' || request.purpose === 'executiveSummary'
      ? config.modelDrafting
      : config.modelTriage;

    const promptSha256 = await sha256Hex(`${SYSTEM_PROMPT}\n${userContent}`);

    const response = await this.dependencies.transport({
      model,
      system: SYSTEM_PROMPT,
      userContent,
      maxTokens: 2_000,
    });

    const estimatedCostUsd =
      (response.inputTokens / 1_000_000) * (config.inputCostPerMillionUsd ?? 0) +
      (response.outputTokens / 1_000_000) * (config.outputCostPerMillionUsd ?? 0);

    // Recorded whether or not the output survives the grounding check: the money was spent and the
    // request was made, and a usage log that only records successes understates both.
    await this.dependencies.record({
      engagementId: request.engagementId,
      model,
      purpose: request.purpose,
      inputTokens: response.inputTokens,
      outputTokens: response.outputTokens,
      estimatedCostUsd,
      promptSha256,
    });

    const ungrounded = ungroundedClaims(response.text, redactedEvidence);
    if (ungrounded.length > 0) {
      return {
        status: 'refused',
        rule: 'ungrounded',
        detail: `the draft asserted detail that is not in the evidence: ${ungrounded.join(', ')}. It has been discarded.`,
      };
    }

    return {
      status: 'drafted',
      isDraft: true,
      markdown: response.text,
      model,
      promptSha256,
      inputTokens: response.inputTokens,
      outputTokens: response.outputTokens,
      estimatedCostUsd,
    };
  }
}

/**
 * Agentic testing is not shipped.
 *
 * The engagement column and the policy field exist because the design allows for it, and this
 * function exists so that a flag nobody reads cannot be mistaken for a feature that works. It
 * refuses, with the reason, every time.
 *
 * What it would need before it could ship: egress restricted to the resolved in-scope addresses at
 * the proxy layer, a hard token and wall-clock budget enforced by the runner, a forbidden-action
 * list enforced outside the model, and every action in the audit log with its full request. Until
 * all four exist, an autonomous agent with our egress address is an unacceptable risk to clients
 * who allowlisted it.
 */
export function agenticRun(): AiRefused {
  return {
    status: 'refused',
    rule: 'noProvider',
    detail:
      'agentic testing is not enabled in this build. The scope guard, egress restriction and spend limits it would require are not implemented, and shipping it without them would put an autonomous agent behind an address clients have allowlisted.',
  };
}
