import { execFileSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

/**
 * Scoring, under the runtime that actually serves requests.
 *
 * `ae-cvss-calculator` is CommonJS, and the two runtimes disagree about where its exports land:
 * Vite's module runner hoists them onto the namespace, Node puts them on `default`. Every other
 * test in this package runs under Vite, so a form that works there and fails under Node passes the
 * whole suite and then throws `Cvss3P1 is not a constructor` on the first finding anybody saves.
 *
 * This is the only test that runs the module the way the API runs it, which is the only way that
 * class of bug is visible before production.
 */

// A file: URL, because a bare Windows path is not a scheme `import()` accepts.
const cvssModule = new URL('./cvss.ts', import.meta.url).href;

function scoreUnderNode(vector: string): { score: number; severity: string } {
  const script = `
    const mod = await import(${JSON.stringify(cvssModule)});
    const result = mod.scoreCvss(${JSON.stringify(vector)});
    process.stdout.write(JSON.stringify(result));
  `;
  const output = execFileSync(
    process.execPath,
    ['--experimental-strip-types', '--input-type=module', '--eval', script],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  return JSON.parse(output) as { score: number; severity: string };
}

describe('cvss scoring under plain node', () => {
  it('scores a 3.1 vector', () => {
    const result = scoreUnderNode('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N');
    expect(result.score).toBe(6.1);
    expect(result.severity).toBe('medium');
  });

  it('scores a 4.0 vector', () => {
    const result = scoreUnderNode(
      'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N',
    );
    expect(typeof result.score).toBe('number');
    expect(result.score).toBeGreaterThan(0);
  });
});
