import { describe, expect, it } from 'vitest';
import { checkCatalogue, coveredWstgIds, wstgCoverage, WSTG_TESTS } from '@attestor/findings';
import { IN_PROCESS_TOOLS, TOOL_IMAGES } from '@attestor/core';
import { ADAPTERS } from '@attestor/scanners';

/**
 * Does the platform actually do what its catalogue says it does?
 *
 * This test lives here rather than in a package because it is the only place that can see all three
 * halves at once: the catalogue of checks we publish, the container adapters that exist, and the
 * in-process probes that exist. Each package can be internally consistent while the three of them
 * together describe a product that does not exist.
 *
 * The failure it exists to prevent is specific and was real. Forty-four checks were marked
 * `automated` or `assisted` and named tools with no implementation behind them at all — a browser
 * driver, a replay engine, a rate-limit probe, mobile instrumentation. Nothing could ever run them,
 * so the coverage matrix would have shown them untested for the life of the firm while the website
 * offered them to prospective clients. That is not a bug in a run; it is a claim.
 */

const adapterIds = new Set(ADAPTERS.map((adapter) => adapter.id));
const implementedProbeIds = new Set(
  IN_PROCESS_TOOLS.filter((tool) => tool.implemented).map((tool) => tool.id),
);
const runnableToolIds = new Set([...adapterIds, ...implementedProbeIds]);

describe('what the catalogue claims can actually be done', () => {
  it('gives every automated and tool-assisted check a tool that exists', () => {
    const broken = checkCatalogue
      .filter((check) => check.automation !== 'manual')
      .filter((check) => !check.tools.some((tool) => runnableToolIds.has(tool)))
      .map((check) => `${check.id} (${check.automation}) -> ${check.tools.join(', ') || 'no tools'}`);

    expect(
      broken,
      'these checks claim a machine does the work, and name only tools with no implementation. ' +
        'Either build the tool or mark the check manual — a check nothing can run must not be sold ' +
        'as one that runs.',
    ).toEqual([]);
  });

  it('lets a manual check name a tool without promising it runs by itself', () => {
    // A manual check may still list a tool a tester drives by hand. What it must not do is claim
    // the platform performs it.
    for (const check of checkCatalogue) {
      if (check.automation !== 'manual') continue;
      expect(Array.isArray(check.tools), check.id).toBe(true);
    }
  });

  it('names only tools the platform knows about at all', () => {
    const known = new Set([
      ...TOOL_IMAGES.map((tool) => tool.id),
      ...IN_PROCESS_TOOLS.map((tool) => tool.id),
    ]);
    const unknown = new Set<string>();
    for (const check of checkCatalogue) {
      for (const tool of check.tools) if (!known.has(tool)) unknown.add(`${check.id} -> ${tool}`);
    }
    expect([...unknown]).toEqual([]);
  });

  it('claims coverage only for check ids that exist', () => {
    const checkIds = new Set(checkCatalogue.map((check) => check.id));
    for (const adapter of ADAPTERS) {
      for (const id of adapter.coversCheckIds) {
        expect(checkIds.has(id), `${adapter.id} claims to cover "${id}", which is not a check`).toBe(
          true,
        );
      }
    }
    for (const tool of IN_PROCESS_TOOLS) {
      for (const id of tool.coversCheckIds) {
        expect(checkIds.has(id), `${tool.id} claims to cover "${id}", which is not a check`).toBe(
          true,
        );
      }
    }
  });

  it('does not let an unimplemented probe claim to cover anything', () => {
    for (const tool of IN_PROCESS_TOOLS) {
      if (tool.implemented) continue;
      expect(tool.coversCheckIds, `${tool.id} is not built and must not claim coverage`).toEqual([]);
    }
  });
});

describe('the WSTG footprint we publish', () => {
  it('references only real WSTG tests', () => {
    const real = new Set(WSTG_TESTS.map((test) => test.id));
    const invented: string[] = [];
    for (const check of checkCatalogue) {
      for (const id of check.standards.wstg ?? []) {
        if (!real.has(id)) invented.push(`${check.id} -> ${id}`);
      }
    }
    expect(invented).toEqual([]);
  });

  it('accounts for every test in the guide, as covered or as an explained decision', () => {
    // The gap is allowed to be non-zero — no firm covers all 109 with automation. What is not
    // allowed is for it to be unknown. Every uncovered test is either in the not-applicable table
    // with a reason a client can read, or it is counted here as a gap we admit to.
    const coverage = wstgCoverage(coveredWstgIds());
    expect(coverage.covered.length + coverage.notApplicable.length + coverage.gaps.length).toBe(
      coverage.total,
    );
    expect(coverage.total).toBe(109);
  });

  it('holds the WSTG gap at or below the level it has been reduced to', () => {
    // A ratchet, not a target. It exists so a future change cannot quietly drop coverage: reduce
    // the number when you close a gap, and never raise it without saying why in the commit.
    const coverage = wstgCoverage(coveredWstgIds());
    expect(coverage.gaps.map((test) => test.id).sort()).toMatchSnapshot();
  });
});
