#!/usr/bin/env node
/**
 * Renders the published sample report to PDF and writes it into the website's public directory.
 *
 * Run from the repository root: `pnpm --filter @attestor/report generate:sample`
 *
 * The website renders the same fixture inline as HTML, so this produces the download rather than a
 * second, separately maintained document.
 */

import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { buildSampleReportData } from '../src/fixtures/sample-report-data.ts';
import { renderReportHtml } from '../src/render.ts';
import { renderAttestationLetterHtml } from '../src/documents.ts';
import { closePdfBrowser, renderPdf } from '../src/pdf.ts';

const websitePublic = fileURLToPath(new URL('../../../apps/website/public/', import.meta.url));

const data = buildSampleReportData();

await mkdir(websitePublic, { recursive: true });

const reportHtml = await renderReportHtml(data);
const reportPdf = await renderPdf(reportHtml, { format: 'A4' });
await writeFile(`${websitePublic}sample-report.pdf`, reportPdf);

const letterHtml = await renderAttestationLetterHtml({
  branding: data.branding,
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
  testerName: 'Attestor Security',
  testerTitle: 'Principal consultant',
  registeredAddress: 'Registered address to be published on incorporation',
});
const letterPdf = await renderPdf(letterHtml, { format: 'A4' });
await writeFile(`${websitePublic}sample-attestation-letter.pdf`, letterPdf);

await closePdfBrowser();

console.error(
  `wrote sample-report.pdf (${Math.round(reportPdf.byteLength / 1024)} KB) and sample-attestation-letter.pdf (${Math.round(letterPdf.byteLength / 1024)} KB)`,
);
