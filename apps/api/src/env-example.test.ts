import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * Does `infra/.env.example` still describe every variable the platform needs?
 *
 * The failure this exists to prevent was real and quiet. Six required variables — `DATABASE_URL`,
 * `PORTAL_DATABASE_URL`, `REDIS_URL` and the three `S3_*` credentials — appeared nowhere in the
 * example file, because compose builds them from the passwords and injects them into the
 * containers. Under compose everything worked. Anyone following `docs/COMMANDS.md` §1 and running
 * an API on the host got a config validation error naming a variable that no document mentioned.
 *
 * A commented line counts. The point is that somebody reading the file finds out the variable
 * exists and what shape it takes, not that it has a value they must fill in.
 */

const envExample = readFileSync(
  fileURLToPath(new URL('../../../infra/.env.example', import.meta.url)),
  'utf8',
);

const configSource = readFileSync(
  fileURLToPath(new URL('../../../packages/shared/src/config.ts', import.meta.url)),
  'utf8',
);

/** Every `NAME:` key in the config schema, which is the set the process refuses to start without. */
function requiredVariables(source: string): string[] {
  return [...new Set(source.match(/^\s{2}([A-Z][A-Z0-9_]+):/gm)?.map((line) => line.trim().replace(':', '')) ?? [])];
}

/** Both `NAME=` and `# NAME=` count as documented. */
function documentedVariables(example: string): Set<string> {
  return new Set(
    example
      .split('\n')
      .map((line) => line.replace(/^#\s*/, '').trim())
      .map((line) => /^([A-Z][A-Z0-9_]+)=/.exec(line)?.[1])
      .filter((name): name is string => name !== undefined),
  );
}

describe('infra/.env.example', () => {
  it('documents every variable the config schema requires', () => {
    const documented = documentedVariables(envExample);
    const undocumented = requiredVariables(configSource).filter((name) => !documented.has(name));

    expect(undocumented, `not in infra/.env.example: ${undocumented.join(', ')}`).toEqual([]);
  });

  it('reads the schema it claims to read', () => {
    // Guards the test itself: a rename that made the regex match nothing would turn the assertion
    // above into a test that passes because it checks an empty list.
    expect(requiredVariables(configSource).length).toBeGreaterThan(20);
    expect(requiredVariables(configSource)).toContain('DATABASE_URL');
  });
});
