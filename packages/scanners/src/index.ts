import type { ModuleName } from '@attestor/shared';
import type { ScannerAdapter } from './adapter.ts';
import { nucleiAdapter } from './adapters/nuclei.ts';
import { httpxAdapter, naabuAdapter, subfinderAdapter, tlsxAdapter } from './adapters/recon.ts';
import { dalfoxAdapter, zapAdapter } from './adapters/web.ts';
import {
  gitleaksAdapter,
  semgrepAdapter,
  trivyAdapter,
  truffleHogAdapter,
} from './adapters/code-supply-chain.ts';
import { kubescapeAdapter, prowlerAdapter } from './adapters/cloud.ts';
import { garakAdapter, promptfooAdapter } from './adapters/llm.ts';
import {
  mobsfAdapter,
  nmapAdapter,
  schemathesisAdapter,
} from './adapters/mobile-api-network.ts';

export * from './adapter.ts';
export { parseNmapXml } from './adapters/mobile-api-network.ts';
export { severityFromSuccessRate } from './adapters/llm.ts';

/**
 * The adapter registry.
 *
 * Adding a tool is: write one adapter file, import it here, add it to this array. Nothing else in
 * the platform changes — the runner, the scope guard, the findings pipeline and the coverage matrix
 * all work off the `ScannerAdapter` shape.
 */
export const ADAPTERS: ScannerAdapter[] = [
  subfinderAdapter,
  httpxAdapter,
  naabuAdapter,
  tlsxAdapter,
  nucleiAdapter,
  zapAdapter,
  dalfoxAdapter,
  semgrepAdapter,
  gitleaksAdapter,
  truffleHogAdapter,
  trivyAdapter,
  prowlerAdapter,
  kubescapeAdapter,
  garakAdapter,
  promptfooAdapter,
  mobsfAdapter,
  schemathesisAdapter,
  nmapAdapter,
];

const byId = new Map(ADAPTERS.map((adapter) => [adapter.id, adapter]));

export function adapterFor(toolId: string): ScannerAdapter {
  const adapter = byId.get(toolId);
  if (!adapter) throw new Error(`no adapter registered for tool "${toolId}"`);
  return adapter;
}

export function hasAdapter(toolId: string): boolean {
  return byId.has(toolId);
}

export function adaptersForModule(module: ModuleName): ScannerAdapter[] {
  return ADAPTERS.filter((adapter) => adapter.modules.includes(module));
}

/** Every catalogue check id any adapter claims to cover, for the coverage matrix. */
export function checkIdsCoveredByModule(module: ModuleName): string[] {
  const ids = new Set<string>();
  for (const adapter of adaptersForModule(module)) {
    for (const id of adapter.coversCheckIds) ids.add(id);
  }
  return [...ids].sort();
}
