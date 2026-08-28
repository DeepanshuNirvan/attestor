import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

/**
 * Pinned tool image digests.
 *
 * `infra/tool-images.lock.json` is written by `scripts/pin-tool-images.mjs`, which resolves each
 * tag once against the local Docker daemon. The runner refuses to start a tool with no digest here,
 * because a report that says "nuclei 3.4.7" must mean the same bytes at the retest as it did at the
 * assessment.
 */

const lockPath = fileURLToPath(new URL('../../../../infra/tool-images.lock.json', import.meta.url));

let cache: Record<string, string> | null = null;

export async function loadToolDigests(): Promise<Record<string, string>> {
  if (cache) return cache;
  try {
    const contents = await readFile(lockPath, 'utf8');
    const parsed = JSON.parse(contents) as { images?: Record<string, { digest?: string }> };
    const resolved: Record<string, string> = {};
    for (const [id, entry] of Object.entries(parsed.images ?? {})) {
      if (entry.digest) resolved[id] = entry.digest;
    }
    cache = resolved;
    return resolved;
  } catch {
    // An empty map is correct here rather than a throw: the runner's own check produces a message
    // naming the tool and the script to run, which is more useful than a file-not-found.
    cache = {};
    return {};
  }
}

export function resetToolDigestCache(): void {
  cache = null;
}
