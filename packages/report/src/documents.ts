import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { countBySeverity, type Finding } from '@attestor/findings';
import { fillPlaceholders, legalBlock } from './legal/blocks.ts';
import { escapeHtml, type ReportBranding } from './render.ts';

/**
 * The one-page documents: the attestation letter, the evidence deletion confirmation and the
 * executive one-pager.
 *
 * The attestation letter is the artefact clients value most, because it is the thing they can
 * forward to a buyer without forwarding a list of their unfixed vulnerabilities. It therefore
 * contains no finding detail at all — only counts, scope, methodology and remediation status.
 */

export interface AttestationInput {
  branding: ReportBranding;
  clientLegalName: string;
  engagementTitle: string;
  reportReference: string;
  reportVersion: string;
  reportDate: string;
  statusDate: string;
  testStartDate: string;
  testEndDate: string;
  testType: 'blackBox' | 'greyBox' | 'whiteBox';
  cvssVersion: '3.1' | '4.0';
  methodology: string[];
  scopeSummary: string[];
  findings: Finding[];
  testerName: string;
  testerTitle: string;
  registeredAddress: string;
}

function remediationStatement(findings: Finding[], statusDate: string): string {
  const serious = findings.filter(
    (finding) => finding.severity === 'critical' || finding.severity === 'high',
  );
  if (serious.length === 0) {
    return 'No critical or high severity findings were identified.';
  }
  const remediated = serious.filter(
    (finding) => finding.status === 'fixed' && finding.retestedAt !== undefined,
  );
  if (remediated.length === serious.length) {
    return 'All critical and high severity findings have been remediated and independently re-verified.';
  }
  const outstanding = serious.length - remediated.length;
  return `${remediated.length} of ${serious.length} critical and high severity findings have been remediated and independently re-verified as at ${statusDate}. ${outstanding} remain open.`;
}

async function letterCss(): Promise<string> {
  const path = fileURLToPath(new URL('./templates/attestor-standard-v1/letter.css', import.meta.url));
  return readFile(path, 'utf8');
}

export async function renderAttestationLetterHtml(input: AttestationInput): Promise<string> {
  const counts = countBySeverity(input.findings);
  const block = legalBlock('attestation-letter');
  const filled = fillPlaceholders(block.text, {
    'LEGAL ENTITY NAME': input.branding.legalEntityName,
    'BRAND NAME': input.branding.brandName,
    'CLIENT LEGAL NAME': input.clientLegalName,
    'ENGAGEMENT TITLE': input.engagementTitle,
    'TEST START DATE': input.testStartDate,
    'TEST END DATE': input.testEndDate,
    'SCOPE SUMMARY': input.scopeSummary.join('; '),
    'ASSESSMENT TYPE': { blackBox: 'Black box', greyBox: 'Grey box', whiteBox: 'White box' }[
      input.testType
    ],
    'METHODOLOGY LIST': input.methodology.join(', '),
    'CVSS VERSION': input.cvssVersion,
    'REPORT REFERENCE': input.reportReference,
    'REPORT VERSION': input.reportVersion,
    'CRITICAL COUNT': String(counts.critical),
    'HIGH COUNT': String(counts.high),
    'MEDIUM COUNT': String(counts.medium),
    'LOW COUNT': String(counts.low),
    'INFO COUNT': String(counts.info),
    'STATUS DATE': input.statusDate,
    'REMEDIATION STATEMENT': remediationStatement(input.findings, input.statusDate),
    'CONTACT EMAIL': input.branding.contactEmail,
    'TESTER NAME': input.testerName,
    'TESTER TITLE': input.testerTitle,
  });

  const css = await letterCss();

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>${escapeHtml(`Letter of attestation — ${input.reportReference}`)}</title>
<style>${css}</style>
</head>
<body>
<header class="letterhead">
  <p class="wordmark">${escapeHtml(input.branding.wordmark)}</p>
  <p class="address">${escapeHtml(input.registeredAddress)} · ${escapeHtml(input.branding.contactEmail)}</p>
</header>
<p class="date">${escapeHtml(input.reportDate)}</p>
<div class="letter">${escapeHtml(filled.text)}</div>
${
  filled.missing.length > 0
    ? `<p class="draft-banner">Unfilled: ${escapeHtml(filled.missing.join(', '))}</p>`
    : ''
}
</body>
</html>
`;
}

export interface DeletionConfirmationInput {
  branding: ReportBranding;
  clientLegalName: string;
  engagementTitle: string;
  reportReference: string;
  testStartDate: string;
  testEndDate: string;
  retentionDays: number;
  deletionDate: string;
  reportDate: string;
  testerName: string;
  testerTitle: string;
  /** What was actually destroyed, counted. An unquantified promise is not a confirmation. */
  destroyed: { evidenceObjects: number; credentialSets: number };
}

export async function renderDeletionConfirmationHtml(
  input: DeletionConfirmationInput,
): Promise<string> {
  const block = legalBlock('evidence-deletion-confirmation');
  const filled = fillPlaceholders(block.text, {
    'REPORT DATE': input.reportDate,
    'CLIENT LEGAL NAME': input.clientLegalName,
    'ENGAGEMENT TITLE': input.engagementTitle,
    'REPORT REFERENCE': input.reportReference,
    'TEST START DATE': input.testStartDate,
    'TEST END DATE': input.testEndDate,
    'RETENTION DAYS': String(input.retentionDays),
    'DELETION DATE': input.deletionDate,
    'LEGAL ENTITY NAME': input.branding.legalEntityName,
    'TESTER NAME': input.testerName,
    'TESTER TITLE': input.testerTitle,
  });

  const css = await letterCss();

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>${escapeHtml(`Confirmation of data deletion — ${input.reportReference}`)}</title>
<style>${css}</style>
</head>
<body>
<header class="letterhead">
  <p class="wordmark">${escapeHtml(input.branding.wordmark)}</p>
  <p class="address">${escapeHtml(input.branding.contactEmail)}</p>
</header>
<div class="letter">${escapeHtml(filled.text)}</div>
<table class="destroyed">
  <thead><tr><th>Destroyed</th><th class="numeric">Count</th></tr></thead>
  <tbody>
    <tr><td>Evidence objects</td><td class="numeric">${input.destroyed.evidenceObjects}</td></tr>
    <tr><td>Credential sets, cryptographically shredded</td><td class="numeric">${input.destroyed.credentialSets}</td></tr>
  </tbody>
</table>
</body>
</html>
`;
}

export interface ExecutiveOnePagerInput {
  branding: ReportBranding;
  clientDisplayName: string;
  engagementTitle: string;
  reportReference: string;
  reportDate: string;
  findings: Finding[];
  headline: string;
  threeThings: string[];
  postureStatement: string;
}

export async function renderExecutiveOnePagerHtml(
  input: ExecutiveOnePagerInput,
): Promise<string> {
  const counts = countBySeverity(input.findings);
  const css = await letterCss();

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>${escapeHtml(`${input.reportReference} — board summary`)}</title>
<style>${css}</style>
</head>
<body>
<header class="letterhead">
  <p class="wordmark">${escapeHtml(input.branding.wordmark)}</p>
  <p class="address">${escapeHtml(input.reportReference)} · ${escapeHtml(input.reportDate)}</p>
</header>
<h1>${escapeHtml(input.engagementTitle)}</h1>
<p class="lede">${escapeHtml(input.headline)}</p>
<table class="counts">
  <thead><tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Informational</th></tr></thead>
  <tbody><tr>
    <td class="numeric">${counts.critical}</td>
    <td class="numeric">${counts.high}</td>
    <td class="numeric">${counts.medium}</td>
    <td class="numeric">${counts.low}</td>
    <td class="numeric">${counts.info}</td>
  </tr></tbody>
</table>
<h2>Posture</h2>
<p>${escapeHtml(input.postureStatement)}</p>
<h2>The three things to do first</h2>
<ol>${input.threeThings.map((item) => `<li>${escapeHtml(item)}</li>`).join('\n')}</ol>
<p class="footnote">This summary omits technical detail deliberately. The full report, including reproduction steps and evidence, is available to ${escapeHtml(input.clientDisplayName)} in the client portal.</p>
</body>
</html>
`;
}
