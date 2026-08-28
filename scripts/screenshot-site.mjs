#!/usr/bin/env node
/**
 * Screenshots the running site for a quick visual check. Not part of the build; run it against a
 * dev server when reviewing a design change.
 *
 * Usage: node scripts/screenshot-site.mjs <outputDirectory> [baseUrl]
 */

import { mkdir } from 'node:fs/promises';
import { chromium } from 'playwright';

const outputDirectory = process.argv[2];
const baseUrl = process.argv[3] ?? 'http://localhost:4321';

if (!outputDirectory) {
  console.error('usage: node scripts/screenshot-site.mjs <outputDirectory> [baseUrl]');
  process.exit(1);
}

const pages = [
  ['/', 'home'],
  ['/services', 'services'],
  ['/services/web-application-and-api', 'service-detail'],
  ['/pricing', 'pricing'],
  ['/pricing/usd', 'pricing-usd'],
  ['/what-we-test', 'coverage'],
  ['/sample-report', 'sample-report'],
  ['/how-we-work', 'how-we-work'],
  ['/about', 'about'],
  ['/contact', 'contact'],
  ['/insights', 'insights'],
];

await mkdir(outputDirectory, { recursive: true });
const browser = await chromium.launch();

for (const [width, height, suffix] of [
  [1440, 1100, 'desktop'],
  [390, 900, 'mobile'],
]) {
  const page = await browser.newPage({ viewport: { width, height } });
  for (const [path, name] of pages) {
    await page.goto(baseUrl + path, { waitUntil: 'networkidle' });
    await page.screenshot({ path: `${outputDirectory}/${name}-${suffix}.png` });
  }
  await page.close();
}

await browser.close();
console.error(`screenshots written to ${outputDirectory}`);
