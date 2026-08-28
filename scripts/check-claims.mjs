#!/usr/bin/env node
/**
 * Fails the build if the repository contains a claim the firm cannot make.
 *
 * This is a hard rule rather than a review habit because the cost of getting it wrong is not a bug,
 * it is fraud: CERT-In empanelment is checkable in thirty seconds and a false claim ends the firm in
 * a small market. The same applies to guarantees of security, which are indefensible in a report.
 *
 * Run: node scripts/check-claims.mjs
 */

import { readdir, readFile } from 'node:fs/promises';
import { extname, join, relative } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');

const SKIP_DIRECTORIES = new Set([
  'node_modules',
  'dist',
  '.git',
  '.astro',
  '.next',
  'coverage',
  '_pagefind',
  'scripts',
]);

/** Research inputs, not shipped content. They quote the banned phrases in order to forbid them. */
const SKIP_FILES = new Set(['ATTESTOR-BUILD-PROMPT.txt', 'security-audit-agency-2026.html']);

const SCANNED_EXTENSIONS = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.mjs',
  '.astro',
  '.md',
  '.mdx',
  '.html',
  '.json',
  '.yaml',
  '.yml',
  '.txt',
]);

/**
 * Each rule is a pattern plus why it is banned. Patterns are deliberately loose: a false positive
 * costs somebody ten seconds, a false negative costs the firm its licence to trade on trust.
 */
const RULES = [
  {
    // Only fires when the subject is us. Statements about what a regulated client needs, or about
    // other firms that are empanelled, are true and must not be blocked.
    id: 'cert-in-empanelment',
    pattern:
      /\b(?:we|attestor(?: security)?|the firm|our (?:firm|practice))\b[^.\n]{0,60}\bempanel(?:led|ment)\b/i,
    reason: 'Attestor is not CERT-In empanelled. Any first-person phrasing that reads as a claim is banned.',
    allowIfLineMatches: /\b(not|never|no)\b/i,
  },
  {
    id: 'crest-accreditation',
    pattern:
      /\b(?:we|attestor(?: security)?)\b[^.\n]{0,60}\b(crest[- ]accredited|crest[- ]certified|crest member)\b/i,
    reason: 'Attestor holds no CREST accreditation.',
    allowIfLineMatches: /\b(not|never|no)\b/i,
  },
  {
    id: 'iso-certified-self',
    pattern: /\bwe are iso[ /]?(?:\/?iec )?27001[- ]certified\b/i,
    reason: 'Attestor is not itself ISO 27001 certified. Client certification is a different claim.',
  },
  {
    id: 'security-guarantee',
    pattern: /\b(guarantee(?:d|s)? (?:your |their )?security|unhackable|100% secure|fully compliant|completely secure|bulletproof security)\b/i,
    reason: 'No assessment can guarantee security. This wording is indefensible in a report.',
  },
  {
    id: 'zero-vulnerabilities',
    pattern: /\b(?:certif(?:y|ied|ies)) (?:as |the system as )?(?:secure|vulnerability[- ]free)\b/i,
    reason: 'Attestor is not an accreditation body and certifies nothing.',
  },
  {
    id: 'fabricated-social-proof',
    pattern: /\btrusted by (?:\d{2,}|hundreds|thousands) of\b/i,
    reason: 'No client count or logo strip may appear until the owner supplies it in writing.',
  },
];

async function walk(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (entry.name.startsWith('.') && entry.name !== '.well-known') continue;
    const full = join(directory, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRECTORIES.has(entry.name)) continue;
      files.push(...(await walk(full)));
    } else if (SCANNED_EXTENSIONS.has(extname(entry.name)) && !SKIP_FILES.has(entry.name)) {
      files.push(full);
    }
  }
  return files;
}

const files = await walk(ROOT);
const violations = [];

for (const file of files) {
  const text = await readFile(file, 'utf8');
  const lines = text.split('\n');
  for (const rule of RULES) {
    for (const [index, line] of lines.entries()) {
      if (!rule.pattern.test(line)) continue;
      if (rule.allowIfLineMatches?.test(line)) continue;
      violations.push({
        file: relative(ROOT, file),
        line: index + 1,
        rule: rule.id,
        reason: rule.reason,
        text: line.trim().slice(0, 140),
      });
    }
  }
}

if (violations.length === 0) {
  console.log(`check-claims: ${files.length} files scanned, no banned claims found.`);
  process.exit(0);
}

console.error(`check-claims: ${violations.length} banned claim(s) found.\n`);
for (const violation of violations) {
  console.error(`  ${violation.file}:${violation.line}  [${violation.rule}]`);
  console.error(`    ${violation.text}`);
  console.error(`    ${violation.reason}\n`);
}
process.exit(1);
