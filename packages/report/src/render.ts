import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import type { CoverageEntry, Finding } from '@attestor/findings';
import {
  CATEGORY_LABELS,
  COMPLIANCE_CONTROLS,
  FRAMEWORK_LABELS,
  OWASP_RISK_FACTORS,
  countBySeverity,
  owaspRiskRating,
} from '@attestor/findings';
import { fillPlaceholders, legalBlock, mandatoryBlocksFor } from './legal/blocks.ts';

/**
 * The report renderer.
 *
 * Output is deterministic: the same input produces byte-identical HTML, which is what makes the
 * golden-file test worth having. Nothing is read from the clock here — every date arrives in the
 * input.
 *
 * Everything that came from a target is escaped. Evidence bodies are attacker-controlled by
 * definition, and a report that runs script when opened would be an attack delivered by the
 * security vendor.
 */

export interface ReportBranding {
  wordmark: string;
  legalEntityName: string;
  brandName: string;
  contactEmail: string;
  country: string;
  jurisdiction: string;
  /** Data URI. Optional, and only used when the client has asked for their logo on the cover. */
  clientLogoDataUri?: string;
}

export interface ReportTool {
  name: string;
  version: string;
  purpose: string;
}

export interface ReportEvidence {
  kind: string;
  caption: string;
  /** Text evidence, already masked and redacted by the capture layer. */
  text?: string;
  /** Data URI for a screenshot. */
  imageDataUri?: string;
}

export interface ReportFinding extends Finding {
  evidence: ReportEvidence[];
  /** Retest outcome, present on a retest report. */
  retestOutcome?: 'verifiedFixed' | 'stillOpen' | 'regressed' | 'riskAccepted' | 'notRetested';
}

export interface AttackNarrative {
  title: string;
  steps: { heading: string; body: string }[];
  conclusion: string;
  /** Monospace step diagram. Plain text so it prints and needs no image pipeline. */
  diagram?: string;
}

export interface ReportData {
  kind: 'assessment' | 'retest';
  templateId: string;
  branding: ReportBranding;

  clientLegalName: string;
  clientDisplayName: string;
  engagementTitle: string;
  reportReference: string;
  reportVersion: string;
  reportDate: string;
  testStartDate: string;
  testEndDate: string;
  retestDate?: string;
  originalReportVersion?: string;
  statusDate?: string;

  testType: 'blackBox' | 'greyBox' | 'whiteBox';
  cvssVersion: '3.1' | '4.0';
  methodology: string[];
  timezone: string;

  scopeIncluded: string[];
  scopeExcluded: string[];
  environments: string[];
  rolesTested: string[];
  constraints: string[];
  toolsUsed: ReportTool[];

  documentControl: {
    author: string;
    reviewer: string;
    distribution: string[];
    versionHistory: { version: string; date: string; note: string }[];
  };

  /** Prose blocks, written or edited by a human in the console. Markdown-lite: paragraphs only. */
  executiveSummary: string[];
  headlineActions: string[];
  positiveObservations: string[];
  roadmap: { horizon: string; items: string[] }[];

  attackNarrative?: AttackNarrative;
  findings: ReportFinding[];
  coverage: CoverageEntry[];
  complianceFrameworks: (keyof typeof FRAMEWORK_LABELS)[];

  appendices: {
    assetInventory: string[];
    portsAndServices: { host: string; port: number; service: string; version: string }[];
    outOfScopeNotes: string[];
    glossary: { term: string; definition: string }[];
  };
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
const SEVERITY_LABEL = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Informational',
} as const;

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Paragraph splitting only. There is no markdown engine here and no HTML passes through. */
function paragraphs(blocks: string[]): string {
  return blocks
    .flatMap((block) => block.split(/\n{2,}/))
    .map((block) => block.trim())
    .filter((block) => block !== '')
    .map((block) => `<p>${escapeHtml(block)}</p>`)
    .join('\n');
}

function list(items: string[], ordered = false): string {
  if (items.length === 0) return '<p class="none">None.</p>';
  const tag = ordered ? 'ol' : 'ul';
  return `<${tag}>\n${items.map((item) => `<li>${escapeHtml(item)}</li>`).join('\n')}\n</${tag}>`;
}

function placeholderValues(data: ReportData): Record<string, string> {
  const counts = countBySeverity(data.findings);
  return {
    'LEGAL ENTITY NAME': data.branding.legalEntityName,
    'BRAND NAME': data.branding.brandName,
    'CLIENT LEGAL NAME': data.clientLegalName,
    'CONTACT EMAIL': data.branding.contactEmail,
    COUNTRY: data.branding.country,
    JURISDICTION: data.branding.jurisdiction,
    'REPORT REFERENCE': data.reportReference,
    'REPORT VERSION': data.reportVersion,
    'REPORT DATE': data.reportDate,
    'TEST START DATE': data.testStartDate,
    'TEST END DATE': data.testEndDate,
    'RETEST DATE': data.retestDate ?? '',
    'ORIGINAL REPORT VERSION': data.originalReportVersion ?? '',
    'ENGAGEMENT TITLE': data.engagementTitle,
    'METHODOLOGY LIST': data.methodology.join(', '),
    'SCOPE SUMMARY': data.scopeIncluded.join('; '),
    'CVSS VERSION': data.cvssVersion,
    'ASSESSMENT TYPE': testTypeLabel(data.testType),
    'CRITICAL COUNT': String(counts.critical),
    'HIGH COUNT': String(counts.high),
    'MEDIUM COUNT': String(counts.medium),
    'LOW COUNT': String(counts.low),
    'INFO COUNT': String(counts.info),
    'STATUS DATE': data.statusDate ?? data.reportDate,
  };
}

function testTypeLabel(testType: ReportData['testType']): string {
  return { blackBox: 'Black box', greyBox: 'Grey box', whiteBox: 'White box' }[testType];
}

/**
 * Section numbering.
 *
 * Two sections are conditional — the attack narrative and the compliance mapping — so numbers
 * cannot be written into the headings. They are derived once, in document order, from the sections
 * this particular report actually contains, and the contents list and every cross-reference read
 * from the same map. A report whose contents page disagrees with its headings, or which refers to
 * a section that is not in it, is one an auditor stops trusting.
 */
const SECTION_TITLES = {
  executiveSummary: 'Executive summary',
  riskOverview: 'Risk overview',
  scope: 'Scope',
  methodology: 'Methodology',
  coverage: 'Coverage matrix',
  attackNarrative: 'Attack narrative',
  findings: 'Detailed findings',
  positiveObservations: 'Positive observations',
  recommendations: 'Strategic recommendations',
  compliance: 'Compliance mapping',
  appendices: 'Appendices',
  limitations: 'Limitations and disclaimer',
} as const;

type SectionKey = keyof typeof SECTION_TITLES;

export type SectionNumbers = ReadonlyMap<SectionKey, number>;

function numberSections(data: ReportData): SectionNumbers {
  const present = (Object.keys(SECTION_TITLES) as SectionKey[]).filter((key) => {
    if (key === 'attackNarrative') return data.attackNarrative !== undefined;
    if (key === 'compliance') return data.complianceFrameworks.length > 0;
    return true;
  });
  return new Map(present.map((key, index) => [key, index + 1]));
}

function heading(numbers: SectionNumbers, key: SectionKey): string {
  return escapeHtml(`${numbers.get(key)}. ${SECTION_TITLES[key]}`);
}

function coverHtml(data: ReportData): string {
  const classification = legalBlock('report-cover-classification');
  const filled = fillPlaceholders(classification.text, placeholderValues(data));

  return `<div class="cover">
  <div>
    <p class="cover-wordmark">${escapeHtml(data.branding.wordmark)}</p>
    <p class="cover-classification">Confidential — contains unresolved security findings</p>
  </div>

  <div class="cover-title">
    <h1>${escapeHtml(data.engagementTitle)}</h1>
    <p class="cover-client">Prepared for <span class="client-name-source">${escapeHtml(data.clientLegalName)}</span></p>
    <dl class="cover-meta">
      <div><span class="label">Report reference</span><span class="value report-reference-source">${escapeHtml(data.reportReference)}</span></div>
      <div><span class="label">Version</span><span class="value report-version-source">${escapeHtml(data.reportVersion)}</span></div>
      <div><span class="label">Issued</span><span class="value">${escapeHtml(data.reportDate)}</span></div>
      <div><span class="label">Assessment period</span><span class="value">${escapeHtml(data.testStartDate)} to ${escapeHtml(data.testEndDate)}</span></div>
      <div><span class="label">Assessment type</span><span class="value">${escapeHtml(testTypeLabel(data.testType))}</span></div>
      <div><span class="label">Severity model</span><span class="value">CVSS ${escapeHtml(data.cvssVersion)}</span></div>
    </dl>
  </div>

  <p class="cover-handling">${escapeHtml(filled.text)}</p>
</div>`;
}

function documentControlHtml(data: ReportData): string {
  const rows = data.documentControl.versionHistory
    .map(
      (entry) =>
        `<tr><td>${escapeHtml(entry.version)}</td><td>${escapeHtml(entry.date)}</td><td>${escapeHtml(entry.note)}</td></tr>`,
    )
    .join('\n');

  return `<section id="document-control">
  <h2>Document control</h2>
  <table>
    <thead><tr><th>Version</th><th>Date</th><th>Change</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <h3>Responsibility</h3>
  <table>
    <tbody>
      <tr><td>Author</td><td>${escapeHtml(data.documentControl.author)}</td></tr>
      <tr><td>Reviewer</td><td>${escapeHtml(data.documentControl.reviewer)}</td></tr>
      <tr><td>Distribution</td><td>${escapeHtml(data.documentControl.distribution.join(', '))}</td></tr>
    </tbody>
  </table>
  <h3>Handling</h3>
  <p>This document contains information about unresolved security weaknesses in systems belonging to ${escapeHtml(data.clientLegalName)}. Store it in access-controlled storage, distribute it on a need-to-know basis, and do not publish or quote from it without written consent.</p>
</section>`;
}

function executiveSummaryHtml(data: ReportData, numbers: SectionNumbers): string {
  return `<section id="executive-summary">
  <h2>${heading(numbers, 'executiveSummary')}</h2>
  ${paragraphs(data.executiveSummary)}
  <h3>The first things to do</h3>
  ${list(data.headlineActions, true)}
</section>`;
}

function riskOverviewHtml(data: ReportData, numbers: SectionNumbers): string {
  const counts = countBySeverity(data.findings);
  const total = data.findings.length || 1;
  const severityRows = (['critical', 'high', 'medium', 'low', 'info'] as const)
    .map((severity) => {
      const share = Math.round((counts[severity] / total) * 100);
      return `<tr>
      <td><span class="severity severity-${severity}">${SEVERITY_LABEL[severity]}</span></td>
      <td class="numeric">${counts[severity]}</td>
      <td><span class="bar severity-${severity}" style="width:${share}%"></span></td>
    </tr>`;
    })
    .join('\n');

  const byCategory = new Map<string, number>();
  for (const finding of data.findings) {
    const key = finding.owaspCategory ?? finding.llmCategory ?? finding.apiCategory ?? 'Unmapped';
    byCategory.set(key, (byCategory.get(key) ?? 0) + 1);
  }
  const categoryRows = [...byCategory.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([category, count]) => `<tr><td>${escapeHtml(category)}</td><td class="numeric">${count}</td></tr>`)
    .join('\n');

  const byAsset = new Map<string, number>();
  for (const finding of data.findings) {
    for (const asset of finding.affectedAssets) {
      byAsset.set(asset.value, (byAsset.get(asset.value) ?? 0) + 1);
    }
  }
  const assetRows = [...byAsset.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15)
    .map(([asset, count]) => `<tr><td>${escapeHtml(asset)}</td><td class="numeric">${count}</td></tr>`)
    .join('\n');

  return `<section id="risk-overview">
  <h2>${heading(numbers, 'riskOverview')}</h2>
  <h3>Findings by severity</h3>
  <table><tbody>${severityRows}</tbody></table>
  <h3>Findings by category</h3>
  <table><thead><tr><th>Category</th><th class="numeric">Findings</th></tr></thead><tbody>${categoryRows}</tbody></table>
  <h3>Findings by asset</h3>
  <table><thead><tr><th>Asset</th><th class="numeric">Findings</th></tr></thead><tbody>${assetRows}</tbody></table>
  <p class="callout">Remediation order in section ${numbers.get('recommendations')} is not the same as severity order. Several findings that are individually minor are steps in the chain described in section ${numbers.get('findings')}, and fixing them is cheap.</p>
</section>`;
}

function scopeHtml(data: ReportData, numbers: SectionNumbers): string {
  return `<section id="scope">
  <h2>${heading(numbers, 'scope')}</h2>
  <h3>Assets in scope</h3>
  ${list(data.scopeIncluded)}
  <h3>Explicitly out of scope</h3>
  ${list(data.scopeExcluded)}
  <h3>Environments</h3>
  ${list(data.environments)}
  <h3>Roles and accounts used</h3>
  ${list(data.rolesTested)}
  <h3>Test dates</h3>
  <p>${escapeHtml(data.testStartDate)} to ${escapeHtml(data.testEndDate)}, ${escapeHtml(data.timezone)}. Assessment type: ${escapeHtml(testTypeLabel(data.testType))}.</p>
  <h3>Constraints imposed by the client</h3>
  ${list(data.constraints)}
</section>`;
}

function methodologyHtml(data: ReportData, numbers: SectionNumbers): string {
  const toolRows = data.toolsUsed
    .map(
      (tool) =>
        `<tr><td>${escapeHtml(tool.name)}</td><td>${escapeHtml(tool.version)}</td><td>${escapeHtml(tool.purpose)}</td></tr>`,
    )
    .join('\n');

  return `<section id="methodology">
  <h2>${heading(numbers, 'methodology')}</h2>
  <p>Testing followed ${escapeHtml(data.methodology.join(', '))}.</p>
  <p>The engagement ran in four phases: unauthenticated discovery and enumeration; automated scanning under agreed rate limits; human validation of every candidate finding; and human-led testing of access control, business logic and multi-step flows. Automated tooling was used to obtain coverage. Every finding in this report was reproduced by a tester before it was included, and findings that came only from a tool and could not be reproduced are not present.</p>
  <h3>Tools used</h3>
  <table>
    <thead><tr><th>Tool</th><th>Version</th><th>Used for</th></tr></thead>
    <tbody>${toolRows}</tbody>
  </table>
  <h3>Severity model</h3>
  <p>Severities are derived from CVSS ${escapeHtml(data.cvssVersion)}. The vector string is printed with every finding so the score can be recomputed. Where a tester has overridden a computed severity because the business context changes the impact, the finding records the reason.</p>
  <h3>Excluded techniques</h3>
  <p>Denial-of-service, distributed denial-of-service, stress, load and volumetric testing were not performed and are not offered. Destructive actions, mass extraction of production personal data, social engineering of personnel and physical intrusion were not performed.</p>
</section>`;
}

function coverageHtml(data: ReportData, numbers: SectionNumbers): string {
  const byCategory = new Map<string, CoverageEntry[]>();
  for (const entry of data.coverage) {
    const list = byCategory.get(entry.check.category);
    if (list) list.push(entry);
    else byCategory.set(entry.check.category, [entry]);
  }

  const stateLabel = {
    tested: 'Tested',
    partiallyTested: 'Partially tested',
    notTested: 'Not tested',
    notApplicable: 'Not present',
  } as const;

  const sections = [...byCategory.entries()]
    .map(([, entries]) => {
      const rows = entries
        .map(
          (entry) => `<tr>
        <td>${escapeHtml(entry.check.title)}</td>
        <td><span class="coverage-state state-${entry.state}">${stateLabel[entry.state]}</span></td>
        <td>${escapeHtml(entry.reason ?? '')}</td>
        <td class="numeric">${entry.findingCount}</td>
      </tr>`,
        )
        .join('\n');
      return `<h3>${escapeHtml(CATEGORY_LABELS[entries[0]!.check.category])}</h3>
    <table>
      <thead><tr><th>Check</th><th>State</th><th>Reason where not fully tested</th><th class="numeric">Findings</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
    })
    .join('\n');

  const tested = data.coverage.filter((entry) => entry.state === 'tested').length;
  const partial = data.coverage.filter((entry) => entry.state === 'partiallyTested').length;
  const notPresent = data.coverage.filter((entry) => entry.state === 'notApplicable').length;
  const notTested = data.coverage.length - tested - partial - notPresent;

  return `<section id="coverage">
  <h2>${heading(numbers, 'coverage')}</h2>
  <p>This matrix is generated from what actually executed during the engagement. It is not a statement of intent: a check appears as tested only where a completed run or a recorded manual test covered it, and anything less carries the reason.</p>
  <p><strong>Not present</strong> means the check has no subject in this application — there was no GraphQL endpoint, no file upload, no payment flow — and is counted separately from a gap in the testing, because they are different facts about your system.</p>
  <table>
    <thead><tr><th>State</th><th class="numeric">Checks</th></tr></thead>
    <tbody>
      <tr><td>Tested</td><td class="numeric">${tested}</td></tr>
      <tr><td>Partially tested</td><td class="numeric">${partial}</td></tr>
      <tr><td>Not present in this application</td><td class="numeric">${notPresent}</td></tr>
      <tr><td>Not tested</td><td class="numeric">${notTested}</td></tr>
    </tbody>
  </table>
  ${sections}
</section>`;
}

function narrativeHtml(data: ReportData, numbers: SectionNumbers): string {
  if (!data.attackNarrative) return '';
  const steps = data.attackNarrative.steps
    .map(
      (step) =>
        `<div class="narrative-step"><h4>${escapeHtml(step.heading)}</h4><p>${escapeHtml(step.body)}</p></div>`,
    )
    .join('\n');
  const diagram = data.attackNarrative.diagram
    ? `<div class="narrative-diagram">${escapeHtml(data.attackNarrative.diagram)}</div>`
    : '';

  return `<section id="attack-narrative">
  <h2>${heading(numbers, 'attackNarrative')}</h2>
  <h3>${escapeHtml(data.attackNarrative.title)}</h3>
  ${diagram}
  ${steps}
  <p class="callout">${escapeHtml(data.attackNarrative.conclusion)}</p>
</section>`;
}

function evidenceHtml(evidence: ReportEvidence[]): string {
  if (evidence.length === 0) return '';
  return evidence
    .map((item) => {
      const body = item.imageDataUri
        ? `<img src="${escapeHtml(item.imageDataUri)}" alt="${escapeHtml(item.caption)}" />`
        : `<pre>${escapeHtml(item.text ?? '')}</pre>`;
      return `<figure class="evidence"><figcaption>${escapeHtml(item.caption)}</figcaption>${body}</figure>`;
    })
    .join('\n');
}

const OWASP_SEVERITY_LABEL: Record<string, string> = {
  note: 'Note',
  low: 'Low',
  moderate: 'Moderate',
  high: 'High',
  critical: 'Critical',
};

const RISK_FACTOR_LABEL = new Map(OWASP_RISK_FACTORS.map((factor) => [factor.id, factor.label]));

/**
 * The OWASP Risk Rating, printed beside CVSS rather than instead of it.
 *
 * The two disagree usefully. CVSS scores the class of flaw; this scores what it means for this
 * client, and the sixteen answers are printed with it so the reader can argue with the reasoning
 * rather than with the number. A finding nobody has rated this way simply omits the section — an
 * unanswered form must never be shown as a low risk.
 */
function owaspRiskHtml(scores: Record<string, number> | undefined): string {
  if (scores === undefined || Object.keys(scores).length === 0) return '';

  const rating = owaspRiskRating(scores);
  const rows = Object.entries(scores)
    .map(
      ([id, score]) =>
        `<tr><td>${escapeHtml(RISK_FACTOR_LABEL.get(id) ?? id)}</td><td class="numeric">${score}</td></tr>`,
    )
    .join('\n');

  return `<h5>OWASP risk rating</h5>
  <p>Likelihood ${rating.likelihood.toFixed(2)} (${rating.likelihoodLevel}), impact ${rating.impact.toFixed(2)} (${rating.impactLevel}), giving an overall rating of <strong>${OWASP_SEVERITY_LABEL[rating.severity] ?? rating.severity}</strong>. Scored against the OWASP Risk Rating Methodology; each factor below is a published option of that method.</p>
  <table>
    <thead><tr><th>Factor</th><th class="numeric">Score</th></tr></thead>
    <tbody>
${rows}
    </tbody>
  </table>`;
}

function findingHtml(finding: ReportFinding, index: number): string {
  const badges = [
    finding.cvssScore !== undefined ? `<span class="tag">${finding.cvssScore.toFixed(1)}</span>` : '',
    finding.cvssVector ? `<span class="tag">${escapeHtml(finding.cvssVector)}</span>` : '',
    finding.owaspRiskScores && Object.keys(finding.owaspRiskScores).length > 0
      ? `<span class="tag">OWASP ${OWASP_SEVERITY_LABEL[owaspRiskRating(finding.owaspRiskScores).severity]}</span>`
      : '',
    finding.cweId ? `<span class="tag">CWE-${finding.cweId}</span>` : '',
    finding.owaspCategory ? `<span class="tag">${escapeHtml(finding.owaspCategory)}</span>` : '',
    finding.apiCategory ? `<span class="tag">${escapeHtml(finding.apiCategory)}</span>` : '',
    finding.wstgId ? `<span class="tag">${escapeHtml(finding.wstgId)}</span>` : '',
    finding.asvsRequirement
      ? `<span class="tag">ASVS ${escapeHtml(finding.asvsRequirement.replace('v5.0.0-', ''))}</span>`
      : '',
    finding.masvsControl ? `<span class="tag">${escapeHtml(finding.masvsControl)}</span>` : '',
    finding.llmCategory ? `<span class="tag">${escapeHtml(finding.llmCategory)}</span>` : '',
  ]
    .filter(Boolean)
    .join('\n      ');

  const assets = finding.affectedAssets
    .map((asset) => {
      const parts = [
        asset.method ? `${asset.method} ` : '',
        asset.value,
        asset.location ?? '',
        asset.parameter ? ` (${asset.parameter})` : '',
      ].join('');
      return `<li><code>${escapeHtml(parts)}</code></li>`;
    })
    .join('\n');

  const references = finding.references
    .map(
      (reference) =>
        `<li><a href="${escapeHtml(reference.url)}">${escapeHtml(reference.title)}</a></li>`,
    )
    .join('\n');

  const successRate =
    finding.attackSuccessRate !== undefined && finding.attemptCount
      ? `<h5>Attack success rate</h5><p>${Math.round(finding.attackSuccessRate * 100)}% over ${finding.attemptCount} attempts.</p>`
      : '';

  const override = finding.severityOverrideReason
    ? `<h5>Severity justification</h5><p>${escapeHtml(finding.severityOverrideReason)}</p>`
    : '';

  const retest = finding.retestOutcome
    ? `<h5>Retest result</h5><p>${escapeHtml(retestLabel(finding.retestOutcome))}</p>`
    : '';

  return `<article class="finding" id="${escapeHtml(finding.reference ?? `finding-${index}`)}">
  <header class="finding-header">
    <p class="finding-reference">${escapeHtml(finding.reference ?? '')}</p>
    <h3 class="finding-title">${escapeHtml(finding.title)}</h3>
    <p class="finding-badges">
      <span class="severity severity-${finding.severity}">${SEVERITY_LABEL[finding.severity]}</span>
      ${badges}
    </p>
  </header>

  <h5>Affected</h5>
  <ul>${assets}</ul>

  <h5>Business impact</h5>
  <p>${escapeHtml(finding.businessImpact)}</p>

  <h5>Likelihood</h5>
  <p>${escapeHtml(finding.likelihood)}</p>

  <h5>Attacker prerequisites</h5>
  <p>${escapeHtml(finding.attackerPrerequisites)}</p>

  <h5>Technical description</h5>
  <p>${escapeHtml(finding.description)}</p>

  <h5>Reproduction</h5>
  ${list(finding.reproductionSteps, true)}

  <h5>Evidence</h5>
  ${evidenceHtml(finding.evidence) || '<p class="none">No evidence attached.</p>'}

  <h5>Remediation</h5>
  <p>${escapeHtml(finding.remediation)}</p>

  <h5>References</h5>
  ${references ? `<ul>${references}</ul>` : '<p class="none">None.</p>'}

  ${owaspRiskHtml(finding.owaspRiskScores)}

  ${successRate}
  ${override}
  ${retest}
</article>`;
}

function retestLabel(outcome: NonNullable<ReportFinding['retestOutcome']>): string {
  return {
    verifiedFixed: 'Verified fixed. The original reproduction steps no longer produce the issue.',
    stillOpen: 'Still open. The issue was reproduced again at retest.',
    regressed: 'Regressed. This finding was previously fixed and has reappeared.',
    riskAccepted: 'Risk accepted by the client. Not re-verified.',
    notRetested: 'Not retested. Outside the scope of this retest.',
  }[outcome];
}

function findingsHtml(data: ReportData, numbers: SectionNumbers): string {
  const ordered = [...data.findings].sort((a, b) => {
    const bySeverity = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (bySeverity !== 0) return bySeverity;
    return (a.reference ?? '').localeCompare(b.reference ?? '');
  });

  return `<section id="findings">
  <h2>${heading(numbers, 'findings')}</h2>
  <p>Ordered by severity, then by reference. Every finding here was reproduced by a tester.</p>
</section>
${ordered.map((finding, index) => findingHtml(finding, index)).join('\n')}`;
}

function positivesHtml(data: ReportData, numbers: SectionNumbers): string {
  return `<section id="positive-observations">
  <h2>${heading(numbers, 'positiveObservations')}</h2>
  <p>Controls found to be working. These are recorded because a report that lists only failures gives a distorted picture of the system and of the team that built it.</p>
  ${list(data.positiveObservations)}
</section>`;
}

function roadmapHtml(data: ReportData, numbers: SectionNumbers): string {
  const blocks = data.roadmap
    .map((horizon) => `<h3>${escapeHtml(horizon.horizon)}</h3>${list(horizon.items)}`)
    .join('\n');
  return `<section id="recommendations">
  <h2>${heading(numbers, 'recommendations')}</h2>
  <p>Grouped by root cause rather than by finding, because several findings frequently share one fix.</p>
  ${blocks}
</section>`;
}

function complianceHtml(data: ReportData, numbers: SectionNumbers): string {
  if (data.complianceFrameworks.length === 0) return '';

  const sections = data.complianceFrameworks
    .map((framework) => {
      const controls = COMPLIANCE_CONTROLS.filter((control) => control.framework === framework);
      const rows = controls
        .map((control) => {
          const related = data.findings.filter((finding) =>
            controlTouchesFinding(control.id, framework, finding),
          );
          return `<tr>
        <td>${escapeHtml(control.id)}</td>
        <td>${escapeHtml(control.title)}</td>
        <td>${escapeHtml(control.evidenceExpectation)}</td>
        <td class="numeric">${related.length}</td>
      </tr>`;
        })
        .join('\n');

      return `<h3>${escapeHtml(FRAMEWORK_LABELS[framework])}</h3>
    <table>
      <thead><tr><th>Control</th><th>Title</th><th>What the auditor expects</th><th class="numeric">Related findings</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
    })
    .join('\n');

  return `<section id="compliance">
  <h2>${heading(numbers, 'compliance')}</h2>
  <p class="callout callout-warning">This mapping is provided for convenience in evidencing your own programme. It is not a compliance opinion, not an audit opinion and not a certification. ${escapeHtml(data.branding.legalEntityName)} is not empanelled by CERT-In.</p>
  ${sections}
</section>`;
}

/**
 * A control relates to a finding when the finding's category is one the control is about. The
 * mapping is intentionally coarse: a fine-grained one would imply a precision this exercise does
 * not have, and an auditor asked for evidence, not for arithmetic.
 */
function controlTouchesFinding(
  controlId: string,
  framework: string,
  finding: Finding,
): boolean {
  if (framework === 'iso27001' && controlId === 'A.8.8') return true;
  if (framework === 'soc2' && controlId === 'CC7.1') return true;
  if (framework === 'pciDss' && controlId === '11.4.3') return true;
  if (framework === 'dpdp' && controlId === 's8(5)') return true;

  const access = finding.owaspCategory === 'A01:2025' || finding.apiCategory?.startsWith('API1');
  if (framework === 'soc2' && controlId === 'CC6.1') return Boolean(access);
  if (framework === 'iso27001' && controlId === 'A.8.9') {
    return finding.owaspCategory === 'A02:2025';
  }
  if (framework === 'iso27001' && controlId === 'A.8.28') {
    return finding.owaspCategory === 'A05:2025';
  }
  if (framework === 'pciDss' && controlId === '6.2') {
    return finding.owaspCategory === 'A05:2025';
  }
  return false;
}

function appendicesHtml(data: ReportData, numbers: SectionNumbers): string {
  const portRows = data.appendices.portsAndServices
    .map(
      (row) =>
        `<tr><td>${escapeHtml(row.host)}</td><td class="numeric">${row.port}</td><td>${escapeHtml(row.service)}</td><td>${escapeHtml(row.version)}</td></tr>`,
    )
    .join('\n');

  const glossaryRows = data.appendices.glossary
    .map((entry) => `<tr><td>${escapeHtml(entry.term)}</td><td>${escapeHtml(entry.definition)}</td></tr>`)
    .join('\n');

  return `<section id="appendices">
  <h2>${heading(numbers, 'appendices')}</h2>
  <h3>Asset inventory</h3>
  ${list(data.appendices.assetInventory)}
  <h3>Ports and services</h3>
  ${
    portRows
      ? `<table><thead><tr><th>Host</th><th class="numeric">Port</th><th>Service</th><th>Version</th></tr></thead><tbody>${portRows}</tbody></table>`
      : '<p class="none">No port scanning was performed in this engagement.</p>'
  }
  <h3>Out-of-scope notes</h3>
  ${list(data.appendices.outOfScopeNotes)}
  <h3>Glossary</h3>
  ${glossaryRows ? `<table><tbody>${glossaryRows}</tbody></table>` : '<p class="none">None.</p>'}
</section>`;
}

function legalHtml(data: ReportData, numbers: SectionNumbers): string {
  const document = data.kind === 'retest' ? 'retestReport' : 'assessmentReport';
  const values = placeholderValues(data);

  const blocks = mandatoryBlocksFor(document)
    .filter((block) => block.id !== 'report-cover-classification')
    .map((block) => {
      const filled = fillPlaceholders(block.text, values);
      const banner =
        block.lawyerReviewedAt === null
          ? '<p class="draft-banner">This wording is in draft and has not yet been reviewed by a qualified lawyer.</p>'
          : '';
      return `${banner}<div class="legal">${escapeHtml(filled.text)}</div>`;
    })
    .join('\n');

  return `<section id="limitations">
  <h2>${heading(numbers, 'limitations')}</h2>
  ${blocks}
</section>`;
}

function tableOfContentsHtml(numbers: SectionNumbers): string {
  const entries = [
    escapeHtml('Document control'),
    ...[...numbers.keys()].map((key) => heading(numbers, key)),
  ];

  return `<section id="contents" class="toc continues">
  <h2>Contents</h2>
  <ol>${entries.map((entry) => `<li><span>${entry}</span></li>`).join('\n')}</ol>
</section>`;
}

function retestBasisHtml(data: ReportData): string {
  if (data.kind !== 'retest') return '';
  const block = legalBlock('retest-basis');
  const filled = fillPlaceholders(block.text, placeholderValues(data));
  return `<section id="retest-basis" class="continues">
  <h2>Basis of this retest</h2>
  <div class="legal">${escapeHtml(filled.text)}</div>
</section>`;
}

/**
 * Fonts are embedded as data URIs rather than linked. A report is opened offline, forwarded by
 * email and printed in an audit pack; a document whose typography depends on the reader's machine
 * is a document that looks different to every reader, and one that fetches a font is a document
 * that phones home.
 */
async function embeddedFontCss(templateId: string): Promise<string> {
  const faces = [
    { family: 'Source Serif 4', file: 'source-serif-4-variable.woff2', weight: '200 900', variations: true },
    { family: 'Public Sans', file: 'public-sans-variable.woff2', weight: '100 900', variations: true },
    { family: 'IBM Plex Mono', file: 'ibm-plex-mono-400-normal.woff2', weight: '400', variations: false },
  ];

  const blocks = await Promise.all(
    faces.map(async (face) => {
      const path = fileURLToPath(
        new URL(`./templates/${templateId}/fonts/${face.file}`, import.meta.url),
      );
      const base64 = (await readFile(path)).toString('base64');
      const format = face.variations ? 'woff2-variations' : 'woff2';
      return `@font-face {
  font-family: '${face.family}';
  src: url(data:font/woff2;base64,${base64}) format('${format}');
  font-weight: ${face.weight};
  font-style: normal;
  font-display: block;
}`;
    }),
  );

  return blocks.join('\n');
}

async function templateCss(templateId: string): Promise<string> {
  const path = fileURLToPath(new URL(`./templates/${templateId}/report.css`, import.meta.url));
  return readFile(path, 'utf8');
}

export async function renderReportHtml(data: ReportData): Promise<string> {
  const numbers = numberSections(data);
  const [fonts, css] = await Promise.all([
    embeddedFontCss(data.templateId),
    templateCss(data.templateId),
  ]);

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>${escapeHtml(`${data.reportReference} — ${data.engagementTitle}`)}</title>
<style>
${fonts}
${css}
</style>
</head>
<body>
${coverHtml(data)}
${tableOfContentsHtml(numbers)}
${documentControlHtml(data)}
${retestBasisHtml(data)}
${executiveSummaryHtml(data, numbers)}
${riskOverviewHtml(data, numbers)}
${scopeHtml(data, numbers)}
${methodologyHtml(data, numbers)}
${coverageHtml(data, numbers)}
${narrativeHtml(data, numbers)}
${findingsHtml(data, numbers)}
${positivesHtml(data, numbers)}
${roadmapHtml(data, numbers)}
${complianceHtml(data, numbers)}
${appendicesHtml(data, numbers)}
${legalHtml(data, numbers)}
</body>
</html>
`;
}

/** Every placeholder left unfilled anywhere in the document. The checklist blocks release on this. */
export function unfilledPlaceholders(data: ReportData): string[] {
  const values = placeholderValues(data);
  const document = data.kind === 'retest' ? 'retestReport' : 'assessmentReport';
  const missing = new Set<string>();

  for (const block of mandatoryBlocksFor(document)) {
    for (const key of fillPlaceholders(block.text, values).missing) missing.add(key);
  }
  return [...missing].sort();
}
