import type { ModuleName } from '@attestor/shared';
import { reconChecks } from './recon.ts';
import { webChecks } from './web.ts';
import { apiChecks } from './api.ts';
import { cloudChecks } from './cloud.ts';
import { mobileChecks } from './mobile.ts';
import { llmChecks } from './llm.ts';
import { codeChecks, networkChecks } from './code-and-network.ts';
import type { Check, CheckCategory } from './types.ts';

export * from './types.ts';

export const checkCatalogue: Check[] = [
  ...reconChecks,
  ...webChecks,
  ...apiChecks,
  ...cloudChecks,
  ...mobileChecks,
  ...llmChecks,
  ...codeChecks,
  ...networkChecks,
];

const byId = new Map(checkCatalogue.map((check) => [check.id, check]));

export function checkById(id: string): Check | undefined {
  return byId.get(id);
}

export function checksForModule(module: ModuleName): Check[] {
  return checkCatalogue.filter((check) => check.modules.includes(module));
}

export function checksForCategory(category: CheckCategory): Check[] {
  return checkCatalogue.filter((check) => check.category === category);
}

export function checksForStandard(standardId: string): Check[] {
  return checkCatalogue.filter((check) =>
    Object.values(check.standards).some(
      (values) => Array.isArray(values) && values.some((value) => String(value) === standardId),
    ),
  );
}

/** Every WSTG id the catalogue claims to cover. The report's coverage matrix is built from this. */
export function coveredWstgIds(): string[] {
  const ids = new Set<string>();
  for (const check of checkCatalogue) {
    for (const id of check.standards.wstg ?? []) ids.add(id);
  }
  return [...ids].sort();
}

export function catalogueSummary(): {
  total: number;
  byModule: Record<string, number>;
  byAutomation: Record<string, number>;
} {
  const byModule: Record<string, number> = {};
  const byAutomation: Record<string, number> = {};
  for (const check of checkCatalogue) {
    for (const module of check.modules) byModule[module] = (byModule[module] ?? 0) + 1;
    byAutomation[check.automation] = (byAutomation[check.automation] ?? 0) + 1;
  }
  return { total: checkCatalogue.length, byModule, byAutomation };
}
