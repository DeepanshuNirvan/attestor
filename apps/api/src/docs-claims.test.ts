import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { catalogueSummary, checkCatalogue } from '@attestor/findings';

/**
 * Do the numbers written into the documentation still match the catalogue?
 *
 * The website imports the catalogue at build time, so `/what-we-test` is always right. The operator
 * handbook quotes the same figures as prose typed by hand, and it had drifted: it said 85 automated,
 * 99 assisted and 26 manual while the catalogue said 91, 75 and 69, and its per-module table added
 * up to 258 checks out of 235. Those numbers are quoted on sales calls, so a stale one is a claim
 * about the product rather than a typo.
 */

const handbook = readFileSync(
  fileURLToPath(new URL('../../../docs/OPERATOR-HANDBOOK.md', import.meta.url)),
  'utf8',
);

describe('documentation quoting the catalogue', () => {
  it('states the automation split the catalogue actually has', () => {
    const summary = catalogueSummary();
    const expected = `**${summary.byAutomation.automated} automated, ${summary.byAutomation.assisted} tool-assisted with human judgement, ${summary.byAutomation.manual} purely manual.**`;

    expect(handbook, `OPERATOR-HANDBOOK.md should contain: ${expected}`).toContain(expected);
  });

  it('states the total the catalogue actually has', () => {
    expect(handbook).toContain(`**${checkCatalogue.length} checks.**`);
  });

  it('gives each module the count the catalogue gives it', () => {
    const perModule = new Map<string, number>();
    for (const check of checkCatalogue) {
      for (const module of check.modules) {
        perModule.set(module, (perModule.get(module) ?? 0) + 1);
      }
    }

    // The row label in the handbook is prose ("Code and supply chain"), so match on the count cell
    // in a table row rather than trying to reproduce the labels here.
    const rowCounts = [...handbook.matchAll(/^\| [A-Za-z][A-Za-z\s]*\| (\d+) \| /gm)].map((match) =>
      Number(match[1]),
    );

    for (const [module, count] of perModule) {
      expect(rowCounts, `no handbook row with the count for module ${module}`).toContain(count);
    }
  });
});
