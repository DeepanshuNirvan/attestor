import { chromium } from 'playwright';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Browser } from 'playwright';
import { buildSampleReportData } from './fixtures/sample-report-data.ts';
import { renderReportHtml, type ReportData } from './render.ts';

/**
 * The evidence in a report is attacker-controlled by definition.
 *
 * A finding's title, its affected URL, its reproduction steps and above all its evidence bodies are
 * whatever the tested application returned — which, in a web assessment, is frequently whatever an
 * attacker put there. If any of it executes when a client opens the report, the security vendor has
 * delivered the vulnerability rather than reported it.
 *
 * This fires a payload corpus through every string field of a real report, renders it, and opens
 * the result in a real browser. The assertion is not "the output looks escaped" — it is that
 * nothing ran.
 */

const PAYLOADS = [
  `<script>window.__attestorXss = 'script-tag';</script>`,
  `<img src=x onerror="window.__attestorXss='img-onerror'">`,
  `<svg/onload="window.__attestorXss='svg-onload'">`,
  `<body onload="window.__attestorXss='body-onload'">`,
  `"><script>window.__attestorXss='attribute-break'</script>`,
  `'><img src=x onerror=window.__attestorXss='quote-break'>`,
  `<iframe src="javascript:window.parent.__attestorXss='iframe-js'"></iframe>`,
  `<a href="javascript:window.__attestorXss='href-js'">click</a>`,
  `<details open ontoggle="window.__attestorXss='ontoggle'">`,
  `<style>@import 'http://127.0.0.1:1/x.css';</style>`,
  `<link rel=stylesheet href="http://127.0.0.1:1/x.css">`,
  `<meta http-equiv="refresh" content="0;url=http://127.0.0.1:1/">`,
  `<base href="http://127.0.0.1:1/">`,
  `<object data="http://127.0.0.1:1/x.swf"></object>`,
  `<form action="http://127.0.0.1:1/"><input name=x></form>`,
  `<math><mtext><table><mglyph><style><img src=x onerror="window.__attestorXss='mglyph'">`,
  `<noscript><p title="</noscript><img src=x onerror=window.__attestorXss='noscript'>">`,
  `<template><script>window.__attestorXss='template'</script></template>`,
  `javascript:window.__attestorXss='bare-scheme'`,
  `data:text/html;base64,PHNjcmlwdD53aW5kb3cuX19hdHRlc3Rvclhzcz0nZGF0YS11cmknPC9zY3JpcHQ+`,
  // Mixed encodings, because a filter that only looks for "<script" misses these.
  `&lt;script&gt;window.__attestorXss='entity'&lt;/script&gt;`,
  `\u003cscript\u003ewindow.__attestorXss='unicode-escape'\u003c/script\u003e`,
  `<scr<script>ipt>window.__attestorXss='nested'</scr</script>ipt>`,
  `<SCRIPT>window.__attestorXss='uppercase'</SCRIPT>`,
  `<img src="x" onerror=	window.__attestorXss='tab-separated'>`,
];

/** Puts a payload into every string a report renders, including the ones nobody thinks about. */
function poison(data: ReportData, payload: string): ReportData {
  return {
    ...data,
    clientLegalName: payload,
    clientDisplayName: payload,
    engagementTitle: payload,
    reportReference: payload,
    reportVersion: payload,
    methodology: [payload],
    scopeIncluded: [payload],
    scopeExcluded: [payload],
    environments: [payload],
    rolesTested: [payload],
    constraints: [payload],
    toolsUsed: data.toolsUsed.map((tool) => ({ ...tool, name: payload, version: payload, purpose: payload })),
    documentControl: {
      ...data.documentControl,
      author: payload,
      reviewer: payload,
      distribution: [payload],
      versionHistory: [{ version: payload, date: payload, note: payload }],
    },
    executiveSummary: [payload],
    headlineActions: [payload],
    positiveObservations: [payload],
    roadmap: [{ horizon: payload, items: [payload] }],
    findings: data.findings.map((finding) => ({
      ...finding,
      title: payload,
      description: payload,
      businessImpact: payload,
      likelihood: payload,
      attackerPrerequisites: payload,
      remediation: payload,
      reproductionSteps: [payload],
      references: [{ title: payload, url: payload }],
      affectedAssets: finding.affectedAssets.map((asset) => ({
        ...asset,
        value: payload,
        location: payload,
        parameter: payload,
      })),
      evidence: [
        { kind: 'httpResponse', caption: payload, text: payload },
        { kind: 'toolOutput', caption: payload, text: payload },
      ],
    })),
    attackNarrative: {
      title: payload,
      steps: [{ heading: payload, body: payload }],
      conclusion: payload,
      diagram: payload,
    },
    appendices: {
      ...data.appendices,
      assetInventory: [payload],
      portsAndServices: [{ host: payload, port: 8080, service: payload, version: payload }],
      outOfScopeNotes: [payload],
      glossary: [{ term: payload, definition: payload }],
    },
  };
}

describe('report rendering against an XSS payload corpus', () => {
  let browser: Browser;

  beforeAll(async () => {
    browser = await chromium.launch({ args: ['--disable-dev-shm-usage'] });
  }, 120_000);

  afterAll(async () => {
    await browser.close();
  });

  it.each(PAYLOADS)('renders %j inertly', async (payload) => {
    const html = await renderReportHtml(poison(buildSampleReportData(), payload));
    const page = await browser.newPage();

    const consoleErrors: string[] = [];
    const requests: string[] = [];
    page.on('request', (request) => requests.push(request.url()));
    page.on('pageerror', (error) => consoleErrors.push(error.message));
    // A dialog would mean an inline handler ran. Fail loudly rather than hanging.
    page.on('dialog', (dialog) => {
      consoleErrors.push(`dialog opened: ${dialog.message()}`);
      void dialog.dismiss();
    });

    await page.setContent(html, { waitUntil: 'load' });
    await page.waitForTimeout(250);

    const executed = await page.evaluate<string | null>(
      'window.__attestorXss ?? null',
    );
    const scriptCount = await page.evaluate<number>('document.scripts.length');
    const externalRequests = requests.filter((url) => !url.startsWith('data:') && url !== 'about:blank');

    expect(executed).toBeNull();
    expect(scriptCount).toBe(0);
    expect(consoleErrors).toEqual([]);
    // A report that fetches anything at open time is a report that tells a third party when and
    // where it was read.
    expect(externalRequests).toEqual([]);

    await page.close();
  }, 120_000);

  it('keeps the payload visible as text, so evidence is not silently swallowed', async () => {
    const payload = `<script>window.__attestorXss='visible'</script>`;
    const html = await renderReportHtml(poison(buildSampleReportData(), payload));
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'load' });

    const text = await page.evaluate<string>('document.body.innerText');
    expect(text).toContain("<script>window.__attestorXss='visible'</script>");

    await page.close();
  }, 120_000);
});
