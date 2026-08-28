import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { resolvePolicy, type ResolvedPolicy } from './resolve.ts';

/**
 * The five ready-made profiles. Picking one and changing two lines should be enough to run a
 * complete engagement, which is the point of the profiles existing at all.
 *
 * They are YAML files rather than TypeScript because the owner edits them, and because a profile
 * that cannot be read as plain YAML is a profile nobody will adjust under time pressure.
 */

export const PROFILE_IDS = [
  'quick-external',
  'standard-web-app',
  'deep-web-app',
  'cloud-review',
  'llm-only',
] as const;

export type ProfileId = (typeof PROFILE_IDS)[number];

const profileDirectory = fileURLToPath(new URL('./profiles/', import.meta.url));

export async function loadProfileYaml(id: ProfileId): Promise<string> {
  return readFile(join(profileDirectory, `${id}.yaml`), 'utf8');
}

export async function loadProfile(id: ProfileId): Promise<ResolvedPolicy> {
  const yamlSource = await loadProfileYaml(id);
  return resolvePolicy([{ name: 'global', yamlSource }]);
}

/** Used by the console's profile picker and by the test that keeps this list honest. */
export async function listProfileFiles(): Promise<string[]> {
  const entries = await readdir(profileDirectory);
  return entries.filter((entry) => entry.endsWith('.yaml')).sort();
}
