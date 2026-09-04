import type { Check } from './types.ts';

/**
 * The LLM module is the one Attestor sells as a differentiator, so the catalogue is deliberately
 * deeper than the tool suites it orchestrates. Every check records attack success rate over
 * repeated attempts rather than a single lucky prompt, and keeps the full transcript as evidence.
 */
export const llmChecks: Check[] = [
  {
    id: 'llm-direct-prompt-injection',
    title: 'Direct prompt injection',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Attempt to override the system instruction from user input using instruction overrides, role reassignment, delimiter attacks, and payloads split or encoded to survive input filtering.',
    example:
      'A support assistant instructed to discuss only orders, persuaded to write an unrelated legal opinion in the company\'s name.',
    automation: 'automated',
    tools: ['garak', 'promptfoo', 'attestorProbes'],
    standards: { llmTop10: ['LLM01:2025'], cwe: [77, 1427] },
  },
  {
    id: 'llm-indirect-prompt-injection',
    title: 'Indirect prompt injection through ingested content',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Plant instructions in content the model ingests rather than in the user message: uploaded documents, retrieved pages, email bodies, file names, image alt text and API responses. This is the highest-impact class for retrieval and agent systems.',
    example:
      'A CV uploaded to a screening assistant containing hidden text that instructs the model to recommend the candidate regardless of the role.',
    automation: 'assisted',
    tools: ['pyrit', 'promptfoo', 'attestorProbes'],
    standards: { llmTop10: ['LLM01:2025', 'LLM04:2025'], cwe: [1427, 20] },
  },
  {
    id: 'llm-multi-turn-jailbreak',
    title: 'Multi-turn jailbreak escalation',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Escalate gradually across a conversation, each turn slightly beyond the last, and adapt the approach from the model\'s own refusals. Single-turn filters routinely miss this.',
    example:
      'A refusal reached in one turn, and the same content produced after six turns of incremental reframing.',
    automation: 'manual',
    tools: [],
    standards: { llmTop10: ['LLM01:2025'], cwe: [1427] },
  },
  {
    id: 'llm-single-turn-jailbreak-matrix',
    title: 'Single-turn jailbreak matrix',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Run a matrix of persona framing, hypothetical framing, translation, encoding, token smuggling and formatting tricks against each restricted topic, and report success rate per technique.',
    example:
      'Base64-encoded instructions producing restricted output that the same request in plain text refuses.',
    automation: 'automated',
    tools: ['garak', 'promptfoo', 'attestorProbes'],
    standards: { llmTop10: ['LLM01:2025'], cwe: [1427] },
  },
  {
    id: 'llm-system-prompt-extraction',
    title: 'System prompt and configuration extraction',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Attempt to recover the system prompt, tool definitions, guardrail wording and model configuration through direct requests, indirect summarisation and partial-completion tricks.',
    example:
      'The assistant reproducing its own instructions when asked to translate "the text above" into another language.',
    automation: 'automated',
    tools: ['garak', 'promptfoo', 'attestorProbes'],
    standards: { llmTop10: ['LLM07:2025'], cwe: [200] },
  },
  {
    id: 'llm-sensitive-information-disclosure',
    title: 'Sensitive information disclosure',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Probe for disclosure of personal data, internal documents, other users\' content, credentials embedded in context, and material memorised from training or fine-tuning data.',
    example:
      'A support assistant quoting another customer\'s ticket, retrieved because the query matched semantically.',
    automation: 'assisted',
    tools: ['garak', 'deepteam', 'attestorProbes'],
    standards: { llmTop10: ['LLM02:2025'], cwe: [200, 359] },
  },
  {
    id: 'llm-cross-tenant-retrieval',
    title: 'Cross-tenant retrieval leakage',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'With accounts in two separate customer organisations, test whether retrieval filters by tenant on every path, including summarisation, citation and follow-up questions.',
    example:
      'A summary that cites a document belonging to a different customer because the filter is applied after retrieval rather than during it.',
    automation: 'manual',
    tools: [],
    standards: { llmTop10: ['LLM02:2025', 'LLM08:2025'], owaspTop10: ['A01:2025'], cwe: [1230, 639] },
  },
  {
    id: 'llm-rag-document-poisoning',
    title: 'Retrieval corpus poisoning',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Where the client can supply documents to the corpus, insert a marked document containing instructions and measure whether it influences answers to unrelated questions. Every injected artefact is tracked and removed in a verified teardown step.',
    example:
      'A single planted policy document that causes the assistant to quote an incorrect refund window to every customer who asks.',
    automation: 'manual',
    tools: [],
    standards: { llmTop10: ['LLM04:2025', 'LLM08:2025'], cwe: [1427] },
  },
  {
    id: 'llm-retrieval-manipulation',
    title: 'Retrieval manipulation and citation fabrication',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Test whether a crafted query can force retrieval of a chosen document, and whether the system fabricates citations or attributes claims to documents that do not contain them.',
    example:
      'An answer citing a policy document by name for a statement that document never makes.',
    automation: 'assisted',
    tools: ['promptfoo', 'attestorProbes'],
    standards: { llmTop10: ['LLM08:2025', 'LLM09:2025'], cwe: [345] },
  },
  {
    id: 'llm-insecure-output-html',
    title: 'Model output rendered as HTML',
    category: 'llmSpecific',
    modules: ['llm', 'web'],
    description:
      'Test whether model output reaches the page without sanitisation, including through markdown rendering, and whether an injected instruction can make the model produce active content.',
    example:
      'A markdown image reference in the model\'s answer that sends the conversation to an external host when it renders.',
    automation: 'manual',
    tools: [],
    standards: { llmTop10: ['LLM05:2025'], owaspTop10: ['A05:2025'], cwe: [79] },
  },
  {
    id: 'llm-insecure-output-code-paths',
    title: 'Model output reaching a query, a shell or a file path',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Where model output is used to build a database query, a command, a file path or a URL to fetch, test whether it is treated as data or as instruction.',
    example:
      'A natural-language reporting feature whose generated SQL is executed with the application\'s full database rights.',
    automation: 'manual',
    tools: [],
    standards: { llmTop10: ['LLM05:2025'], owaspTop10: ['A05:2025'], cwe: [89, 78, 918] },
  },
  {
    id: 'llm-excessive-agency-tool-invocation',
    title: 'Excessive agency in tool invocation',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Test whether the model can call a tool it should not, with arguments it should not, or without the confirmation the design requires.',
    example:
      'A scheduling assistant persuaded to call the refund tool because the user framed the request as a calendar correction.',
    automation: 'manual',
    tools: [],
    standards: { llmTop10: ['LLM06:2025'], owaspTop10: ['A01:2025'], cwe: [269, 285] },
  },
  {
    id: 'llm-chained-tool-abuse',
    title: 'Chained tool abuse and privilege composition',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Test what becomes reachable by composing individually safe tools, which is where agent systems usually fail.',
    example:
      'A read-only file tool plus an email tool together producing exfiltration that neither tool permits alone.',
    automation: 'manual',
    tools: ['attestorProbes'],
    standards: { llmTop10: ['LLM06:2025'], owaspTop10: ['A01:2025'], cwe: [269] },
  },
  {
    id: 'llm-agent-goal-hijacking',
    title: 'Agent goal hijacking',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Attempt to replace the agent\'s objective mid-task through content it encounters, and observe whether it abandons the user\'s goal.',
    example:
      'A web page the agent reads while researching, instructing it to summarise and send the conversation elsewhere.',
    automation: 'manual',
    tools: [],
    standards: { llmTop10: ['LLM01:2025', 'LLM06:2025'], cwe: [1427] },
  },
  {
    id: 'llm-memory-poisoning',
    title: 'Persistent memory poisoning',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Where the system keeps memory across sessions, test whether a single conversation can plant an instruction that persists and affects later sessions or other users.',
    example:
      'A stored user preference containing an instruction that alters the assistant\'s behaviour on every future conversation.',
    automation: 'manual',
    tools: [],
    standards: { llmTop10: ['LLM04:2025'], cwe: [1427] },
  },
  {
    id: 'llm-inter-agent-trust',
    title: 'Inter-agent trust abuse',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'In multi-agent systems, test whether one agent trusts another\'s output as instruction, and whether a compromised agent can direct the others.',
    example:
      'A research agent\'s output taken as a command by the execution agent, with no validation between them.',
    automation: 'manual',
    tools: ['attestorProbes'],
    standards: { llmTop10: ['LLM06:2025'], cwe: [345, 269] },
  },
  {
    id: 'llm-guardrail-bypass',
    title: 'Guardrail and content filter bypass',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Test the declared guardrails specifically: input classifiers, output classifiers, topic restrictions and refusal policies, and measure what fraction of attempts get through.',
    example:
      'An output filter that catches the restricted content in English and misses it in transliterated Hindi.',
    automation: 'automated',
    tools: ['garak', 'deepteam', 'promptfoo'],
    standards: { llmTop10: ['LLM01:2025'], cwe: [693] },
  },
  {
    id: 'llm-multilingual-and-obfuscated-payloads',
    title: 'Multilingual and obfuscated payloads',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Run the payload set through translation, transliteration, homoglyphs, zero-width characters, leetspeak and encodings, since guardrails are usually tuned on English.',
    example:
      'A restricted request refused in English and answered when written in transliterated Marathi.',
    automation: 'automated',
    tools: ['garak', 'attestorProbes'],
    standards: { llmTop10: ['LLM01:2025'], cwe: [176, 1427] },
  },
  {
    id: 'llm-training-data-extraction',
    title: 'Training and fine-tuning data extraction',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Probe for verbatim reproduction of fine-tuning data, particularly where the client fine-tuned on internal documents or customer conversations.',
    example:
      'A model fine-tuned on support transcripts reproducing a customer\'s full name and order history from a partial prompt.',
    automation: 'automated',
    tools: ['garak', 'deepteam'],
    standards: { llmTop10: ['LLM02:2025'], cwe: [200, 359] },
  },
  {
    id: 'llm-unbounded-consumption',
    title: 'Unbounded consumption and cost abuse',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Test for unbounded output length, recursive prompting, expensive tool loops and unauthenticated access to a billed endpoint. Measured under a hard spend ceiling set before the run and acknowledged by the client, and stopped well before any real cost impact.',
    example:
      'An unauthenticated chat widget that will produce maximum-length output on request, at the client\'s expense.',
    automation: 'manual',
    tools: [],
    standards: { llmTop10: ['LLM10:2025'], owaspTop10: ['A06:2025'], cwe: [770, 400] },
  },
  {
    id: 'llm-denial-of-service-resistance-observation',
    title: 'Resource limit observation',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Record what limits exist — per-user quotas, output caps, tool call caps, concurrency limits — as an observation. No load is generated at any point.',
    example:
      'No per-user cap on tool calls, so one conversation can invoke a paid search tool without limit.',
    automation: 'manual',
    tools: [],
    standards: { llmTop10: ['LLM10:2025'], cwe: [770] },
  },
  {
    id: 'llm-model-supply-chain',
    title: 'Model and plugin supply chain',
    category: 'supplyChain',
    modules: ['llm'],
    description:
      'Check model provenance, whether model versions are pinned, where weights come from, and what trust is extended to plugins, extensions and community-supplied tools.',
    example:
      'A production system pointing at a floating model alias, so behaviour changes without a release.',
    automation: 'manual',
    tools: [],
    standards: { llmTop10: ['LLM03:2025'], owaspTop10: ['A03:2025'], cwe: [1104, 494] },
  },
  {
    id: 'llm-embedding-inversion',
    title: 'Embedding and vector store weaknesses',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Check access control on the vector store, whether embeddings of sensitive text are retrievable, and whether metadata filters can be bypassed.',
    example:
      'A vector store reachable without authentication, from which document content can be approximately recovered.',
    automation: 'manual',
    tools: [],
    standards: { llmTop10: ['LLM08:2025'], owaspTop10: ['A01:2025'], cwe: [200, 285] },
  },
  {
    id: 'llm-misinformation-in-decision-path',
    title: 'Misinformation in a business-critical path',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Where an answer is used for a decision — pricing, eligibility, medical, legal, compliance — measure how often the system produces a confident wrong answer, and whether it says when it does not know.',
    example:
      'An eligibility assistant confidently stating an incorrect income threshold in eleven of forty attempts.',
    automation: 'assisted',
    tools: ['promptfoo', 'deepteam'],
    standards: { llmTop10: ['LLM09:2025'], cwe: [1039] },
  },
  {
    id: 'llm-bias-and-toxicity',
    title: 'Bias and harmful output where relevant to the client risk',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Where the application makes or influences decisions about people, test for differential treatment across protected characteristics and for harmful output reaching customers.',
    example:
      'A screening assistant producing systematically shorter summaries for one group of candidates.',
    automation: 'automated',
    tools: ['garak', 'deepteam'],
    standards: { llmTop10: ['LLM09:2025'], cwe: [1039] },
  },
  {
    id: 'llm-authentication-and-authorisation-of-the-endpoint',
    title: 'Authentication and authorisation of the model endpoint',
    category: 'accessControl',
    modules: ['llm', 'api'],
    description:
      'Test the endpoint as an API: whether it requires authentication, whether the key is exposed in the front end, whether users can select a different model or system prompt, and whether per-user limits are enforced.',
    example:
      'A provider API key readable in the browser bundle, usable directly against the provider at the client\'s expense.',
    automation: 'automated',
    tools: ['zap', 'attestorProbes'],
    standards: {
      llmTop10: ['LLM10:2025'],
      owaspTop10: ['A01:2025'],
      apiTop10: ['API2:2023'],
      cwe: [306, 798],
    },
  },
  {
    id: 'llm-conversation-isolation',
    title: 'Conversation and context isolation',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Test whether one conversation can read another\'s history through identifier manipulation, shared context or caching.',
    example:
      'A conversation identifier in a URL that returns another user\'s transcript.',
    automation: 'assisted',
    tools: ['accessControlMatrix', 'attestorProbes'],
    standards: { llmTop10: ['LLM02:2025'], owaspTop10: ['A01:2025'], cwe: [639] },
  },
  {
    id: 'llm-logging-and-transcript-handling',
    title: 'Transcript logging and retention',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Check what is logged from conversations, where it goes, how long it is kept, and whether customers\' personal data ends up with a model provider without a basis.',
    example:
      'Full transcripts including uploaded identity documents retained indefinitely in a third-party observability tool.',
    automation: 'manual',
    tools: [],
    standards: { llmTop10: ['LLM02:2025'], owaspTop10: ['A09:2025'], cwe: [532, 359] },
  },
  {
    id: 'llm-refusal-consistency',
    title: 'Refusal consistency across repeated attempts',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Repeat each successful bypass to establish an attack success rate, because a bypass that works once in fifty is a different finding from one that works every time.',
    example:
      'A jailbreak succeeding in 34 of 50 attempts, reported as a reliable bypass rather than an anomaly.',
    automation: 'automated',
    tools: ['promptfoo', 'attestorProbes'],
    standards: { llmTop10: ['LLM01:2025'], cwe: [693] },
  },
  {
    id: 'llm-teardown-verification',
    title: 'Injected artefact teardown and verification',
    category: 'llmSpecific',
    modules: ['llm'],
    description:
      'Track every document, memory entry and record created during testing, remove them at the end of the engagement, and verify removal by querying for them again.',
    example:
      'Three planted documents removed and confirmed absent from retrieval before the engagement closes.',
    automation: 'manual',
    tools: [],
    standards: {},
  },
];
