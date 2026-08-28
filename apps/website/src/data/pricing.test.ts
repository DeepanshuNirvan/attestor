import { describe, expect, it } from 'vitest';
import {
  estimate,
  formatMoney,
  packageById,
  packages,
  type AssetType,
  type Currency,
  type EstimatorInputs,
} from './pricing.ts';

const assetTypes: AssetType[] = ['web', 'api', 'mobile', 'cloud', 'llm', 'external'];
const currencies: Currency[] = ['INR', 'USD'];
const authComplexities: EstimatorInputs['authComplexity'][] = [
  'none',
  'simple',
  'multiStep',
  'federated',
];

describe('price sheet', () => {
  it('has unique ids and a price in both currencies', () => {
    const ids = packages.map((item) => item.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const item of packages) {
      expect(item.price.INR).toBeGreaterThan(0);
      expect(item.price.USD).toBeGreaterThan(0);
      expect(item.includes.length).toBeGreaterThan(0);
      expect(item.deliverables.length).toBeGreaterThan(0);
    }
  });

  it('throws loudly on an unknown package rather than rendering an empty card', () => {
    expect(() => packageById('does-not-exist')).toThrow(/unknown package/);
  });
});

describe('estimate', () => {
  it('returns a usable band for every valid combination of inputs', () => {
    for (const assetType of assetTypes) {
      for (const currency of currencies) {
        for (const authComplexity of authComplexities) {
          for (const scaleUnits of [1, 25, 26, 120, 251, 5000]) {
            for (const roleCount of [0, 1, 4, 20]) {
              for (const environmentCount of [1, 3, 6]) {
                const result = estimate({
                  assetType,
                  scaleUnits,
                  roleCount,
                  authComplexity,
                  environmentCount,
                  needsRetest: true,
                  currency,
                });
                const label = `${assetType}/${currency}/${authComplexity}/${scaleUnits}/${roleCount}/${environmentCount}`;
                expect(Number.isFinite(result.low), label).toBe(true);
                expect(result.low, label).toBeGreaterThan(0);
                expect(result.high, label).toBeGreaterThanOrEqual(result.low);
                expect(result.days, label).toBeGreaterThanOrEqual(1);
                expect(result.includes.length, label).toBeGreaterThan(0);
                expect(result.notes.length, label).toBeGreaterThan(0);
              }
            }
          }
        }
      }
    }
  });

  it('never falls below the base package price for the smallest possible scope', () => {
    const smallest = estimate({
      assetType: 'web',
      scaleUnits: 1,
      roleCount: 0,
      authComplexity: 'none',
      environmentCount: 1,
      needsRetest: false,
      currency: 'INR',
    });
    // The floor is the base times the lowest multipliers, not zero, and it is a round number.
    expect(smallest.low).toBeGreaterThan(30_000);
    expect(smallest.low % 2_500).toBe(0);
  });

  it('charges more for more roles, and more for harder authentication', () => {
    const base: EstimatorInputs = {
      assetType: 'web',
      scaleUnits: 40,
      roleCount: 1,
      authComplexity: 'simple',
      environmentCount: 1,
      needsRetest: true,
      currency: 'INR',
    };
    expect(estimate({ ...base, roleCount: 4 }).low).toBeGreaterThan(estimate(base).low);
    expect(estimate({ ...base, authComplexity: 'federated' }).low).toBeGreaterThan(
      estimate(base).low,
    );
    expect(estimate({ ...base, scaleUnits: 300 }).days).toBeGreaterThan(estimate(base).days);
  });

  it('tells the client how many test accounts they need once there are two roles', () => {
    const result = estimate({
      assetType: 'web',
      scaleUnits: 40,
      roleCount: 3,
      authComplexity: 'simple',
      environmentCount: 1,
      needsRetest: true,
      currency: 'INR',
    });
    expect(result.notes.join(' ')).toContain('6 test accounts');
  });

  it('says the cloud review is read-only, because that is what unblocks the approval', () => {
    const result = estimate({
      assetType: 'cloud',
      scaleUnits: 200,
      roleCount: 1,
      authComplexity: 'none',
      environmentCount: 1,
      needsRetest: false,
      currency: 'USD',
    });
    expect(result.notes.join(' ')).toContain('Read-only');
  });
});

describe('formatMoney', () => {
  it('formats in the right currency with no decimal noise', () => {
    expect(formatMoney(55_000, 'INR')).toContain('55,000');
    expect(formatMoney(3_000, 'USD')).toContain('3,000');
    expect(formatMoney(3_000, 'USD')).not.toContain('.00');
  });
});
