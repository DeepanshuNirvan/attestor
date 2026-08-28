#!/usr/bin/env node
/**
 * Pins every security tool image by digest.
 *
 * Pulls each tag once, records the digest the daemon resolved, and writes
 * `infra/tool-images.lock.json`. The runner refuses to start a tool that has no digest here.
 *
 * Why this matters beyond reproducibility: a report states the tool version it used. If the tag
 * moved between the assessment and the retest, "verified fixed" was verified with different code,
 * and there is no way to show which.
 *
 * Run: node scripts/pin-tool-images.mjs [--pull]
 */

import { execFile } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { promisify } from 'node:util';

const run = promisify(execFile);

const toolImagesPath = new URL('../packages/core/src/runner/tool-images.ts', import.meta.url);
const lockPath = new URL('../infra/tool-images.lock.json', import.meta.url);

const shouldPull = process.argv.includes('--pull');

const source = await readFile(toolImagesPath, 'utf8');
const entries = [...source.matchAll(/id: '([^']+)',[^}]*?image: '([^']+)', tag: '([^']+)'/g)].map(
  ([, id, image, tag]) => ({ id, image, tag }),
);

if (entries.length === 0) {
  console.error('no tool images found; has the shape of tool-images.ts changed?');
  process.exit(1);
}

const images = {};
let failures = 0;

for (const entry of entries) {
  const reference = `${entry.image}:${entry.tag}`;

  if (entry.tag === 'local') {
    console.error(`skip  ${entry.id}: built locally, pin it from the build output instead`);
    continue;
  }

  try {
    if (shouldPull) {
      await run('docker', ['pull', '--quiet', reference], { timeout: 900_000 });
    }
    const { stdout } = await run('docker', [
      'image',
      'inspect',
      '--format',
      '{{index .RepoDigests 0}}',
      reference,
    ]);
    const digest = stdout.trim().split('@')[1];
    if (!digest?.startsWith('sha256:')) throw new Error('no digest reported');

    images[entry.id] = { image: entry.image, tag: entry.tag, digest, pinnedAt: new Date().toISOString() };
    console.error(`pin   ${entry.id.padEnd(14)} ${digest}`);
  } catch (error) {
    failures += 1;
    console.error(
      `FAIL  ${entry.id.padEnd(14)} ${reference}: ${error instanceof Error ? error.message.split('\n')[0] : 'unknown error'}`,
    );
  }
}

await writeFile(
  lockPath,
  `${JSON.stringify({ generatedAt: new Date().toISOString(), images }, null, 2)}\n`,
  'utf8',
);

console.error(
  `\nwrote ${Object.keys(images).length} pinned image(s)${failures > 0 ? `, ${failures} failed` : ''}`,
);
if (failures > 0) {
  console.error('Run with --pull to fetch the missing images first.');
  process.exit(1);
}
