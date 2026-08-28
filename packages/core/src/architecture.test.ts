import { readdir, readFile } from 'node:fs/promises';
import { extname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * Architectural rules, enforced as tests.
 *
 * The ESLint `no-restricted-imports` rule covers the same ground, but a lint rule can be disabled
 * with a comment and this cannot. The scope guard is only a guarantee if there is exactly one path
 * to starting a container, so that property is asserted here rather than assumed.
 */

const repositoryRoot = fileURLToPath(new URL('../../../', import.meta.url));

const SKIP = new Set(['node_modules', 'dist', '.git', '.astro', '.next', 'coverage', '_pagefind']);
const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.astro', '.mjs', '.js']);

async function sourceFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    if (entry.name.startsWith('.') || SKIP.has(entry.name)) continue;
    const full = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await sourceFiles(full)));
    else if (SOURCE_EXTENSIONS.has(extname(entry.name))) files.push(full);
  }
  return files;
}

const CONTAINER_CHOKE_POINT = 'packages/core/src/runner/container-runner.ts';

describe('architecture', () => {
  it('only the container runner may talk to Docker', async () => {
    const files = await sourceFiles(repositoryRoot);
    const offenders: string[] = [];

    for (const file of files) {
      const relativePath = relative(repositoryRoot, file).split('\\').join('/');
      if (relativePath === CONTAINER_CHOKE_POINT) continue;
      if (relativePath.endsWith('architecture.test.ts')) continue;

      const text = await readFile(file, 'utf8');
      if (/from ['"]dockerode['"]/.test(text) || /require\(['"]dockerode['"]\)/.test(text)) {
        offenders.push(relativePath);
      }
    }

    expect(
      offenders,
      `dockerode may only be imported by ${CONTAINER_CHOKE_POINT}. Container execution has one entry point so the scope guard cannot be bypassed.`,
    ).toEqual([]);
  });

  it('the container runner is reached only through the choke point', async () => {
    const files = await sourceFiles(join(repositoryRoot, 'packages'));
    const allowed = new Set([
      'packages/core/src/runner/run-tool-for-engagement.ts',
      'packages/core/src/runner/container-runner.ts',
      'packages/core/src/index.ts',
    ]);
    const offenders: string[] = [];

    for (const file of files) {
      const relativePath = relative(repositoryRoot, file).split('\\').join('/');
      if (allowed.has(relativePath) || relativePath.includes('.test.')) continue;
      const text = await readFile(file, 'utf8');
      if (/new ContainerRunner\(/.test(text)) offenders.push(relativePath);
    }

    expect(offenders).toEqual([]);
  });

  it('no source file contains a denial-of-service capability', async () => {
    const files = await sourceFiles(join(repositoryRoot, 'packages'));
    const banned = /\b(floodTarget|startFlood|ddos|denialOfServiceTest|stressTest|loadTest)\s*[(=:]/i;
    const offenders: string[] = [];

    for (const file of files) {
      const relativePath = relative(repositoryRoot, file).split('\\').join('/');
      if (relativePath.includes('.test.')) continue;
      const text = await readFile(file, 'utf8');
      if (banned.test(text)) offenders.push(relativePath);
    }

    expect(offenders).toEqual([]);
  });

  it('no source file carries a hardcoded secret-looking literal', async () => {
    const files = await sourceFiles(join(repositoryRoot, 'packages'));
    const patterns = [
      /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
      /\bsk-ant-[A-Za-z0-9_-]{20,}/,
      /\bgh[pousr]_[A-Za-z0-9]{30,}/,
      /-----BEGIN[ A-Z]*PRIVATE KEY-----/,
    ];
    const offenders: string[] = [];

    for (const file of files) {
      const relativePath = relative(repositoryRoot, file).split('\\').join('/');
      if (relativePath.includes('.test.') || relativePath.includes('redaction.ts')) continue;
      const text = await readFile(file, 'utf8');
      if (patterns.some((pattern) => pattern.test(text))) offenders.push(relativePath);
    }

    expect(offenders).toEqual([]);
  });
});
