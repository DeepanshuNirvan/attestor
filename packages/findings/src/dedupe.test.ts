import { describe, expect, it } from 'vitest';
import type { Finding } from './model.ts';
import { correlateFindings, dedupeFindings, dedupeKey } from './dedupe.ts';
import { buildRetestLines, countBySeverity, diffFindings } from './diff.ts';

function makeFinding(overrides: Partial<Finding> & { dedupeKey: string }): Finding {
  return {
    id: overrides.id ?? `f-${overrides.dedupeKey}`,
    engagementId: 'eng-1',
    source: 'tool',
    title: 'Missing Content-Security-Policy header',
    description: 'short',
    severity: 'low',
    affectedAssets: [{ value: 'shop.example.com', location: '/' }],
    businessImpact: '',
    likelihood: '',
    attackerPrerequisites: '',
    reproductionSteps: [],
    remediation: '',
    references: [],
    status: 'candidate',
    firstSeenAt: new Date('2026-08-01T00:00:00Z'),
    lastSeenAt: new Date('2026-08-01T00:00:00Z'),
    ...overrides,
  };
}

describe('dedupeKey', () => {
  it('treats identifiers in a path as instance data, not identity', () => {
    const first = dedupeKey({
      ruleId: 'web-horizontal-access-control',
      asset: { value: 'shop.example.com', location: '/orders/1042' },
    });
    const second = dedupeKey({
      ruleId: 'web-horizontal-access-control',
      asset: { value: 'shop.example.com', location: '/orders/9981' },
    });
    expect(first).toBe(second);
  });

  it('separates different parameters on the same path', () => {
    const base = { value: 'shop.example.com', location: '/search' };
    expect(
      dedupeKey({ ruleId: 'web-reflected-xss', asset: base, parameter: 'q' }),
    ).not.toBe(dedupeKey({ ruleId: 'web-reflected-xss', asset: base, parameter: 'sort' }));
  });

  it('ignores scheme, trailing slash and query string', () => {
    const a = dedupeKey({ ruleId: 'r', asset: { value: 'https://a.example.com', location: '/x/' } });
    const b = dedupeKey({ ruleId: 'r', asset: { value: 'a.example.com', location: '/x?page=2' } });
    expect(a).toBe(b);
  });

  it('separates different rules on the same asset', () => {
    const asset = { value: 'a.example.com', location: '/x' };
    expect(dedupeKey({ ruleId: 'one', asset })).not.toBe(dedupeKey({ ruleId: 'two', asset }));
  });
});

describe('dedupeFindings', () => {
  it('keeps the highest severity and the richest text when merging', () => {
    const merged = dedupeFindings([
      makeFinding({ dedupeKey: 'k1', severity: 'low', description: 'short' }),
      makeFinding({
        dedupeKey: 'k1',
        severity: 'high',
        description: 'a much longer description from the second tool',
        remediation: 'set the header at the edge',
      }),
    ]);
    expect(merged.merged).toHaveLength(1);
    expect(merged.merged[0]!.severity).toBe('high');
    expect(merged.merged[0]!.description).toContain('longer description');
    expect(merged.merged[0]!.remediation).toContain('set the header');
    expect(merged.collapsed.get('k1')).toBe(2);
  });

  it('unions affected assets and widens the seen window', () => {
    const merged = dedupeFindings([
      makeFinding({
        dedupeKey: 'k1',
        affectedAssets: [{ value: 'a.example.com', location: '/one' }],
        firstSeenAt: new Date('2026-07-01T00:00:00Z'),
      }),
      makeFinding({
        dedupeKey: 'k1',
        affectedAssets: [{ value: 'a.example.com', location: '/two' }],
        lastSeenAt: new Date('2026-08-20T00:00:00Z'),
      }),
    ]);
    expect(merged.merged[0]!.affectedAssets).toHaveLength(2);
    expect(merged.merged[0]!.firstSeenAt.toISOString()).toContain('2026-07-01');
    expect(merged.merged[0]!.lastSeenAt.toISOString()).toContain('2026-08-20');
  });

  it('lets a manual finding win authorship over a tool finding', () => {
    const merged = dedupeFindings([
      makeFinding({ dedupeKey: 'k1', source: 'tool', severity: 'high' }),
      makeFinding({ dedupeKey: 'k1', source: 'manual', severity: 'low' }),
    ]);
    expect(merged.merged[0]!.source).toBe('manual');
    expect(merged.merged[0]!.severity).toBe('high');
  });
});

describe('correlateFindings', () => {
  it('folds one root cause across many assets into a single reportable finding', () => {
    const findings = ['/a', '/b', '/c', '/d'].map((path, index) =>
      makeFinding({
        dedupeKey: `k${index}`,
        checkId: 'web-security-headers',
        affectedAssets: [{ value: 'shop.example.com', location: path }],
      }),
    );
    const { correlated, groups } = correlateFindings(findings);
    expect(correlated).toHaveLength(1);
    expect(correlated[0]!.affectedAssets).toHaveLength(4);
    expect(groups[0]!.members).toHaveLength(4);
  });

  it('keeps access-control findings separate, because each is its own fix', () => {
    const findings = ['/orders', '/invoices'].map((path, index) =>
      makeFinding({
        dedupeKey: `k${index}`,
        checkId: 'web-horizontal-access-control',
        affectedAssets: [{ value: 'shop.example.com', location: path }],
      }),
    );
    expect(correlateFindings(findings).correlated).toHaveLength(2);
  });
});

describe('diffFindings', () => {
  const previous = [
    makeFinding({ dedupeKey: 'stays', status: 'open' }),
    makeFinding({ dedupeKey: 'gone', status: 'open' }),
    makeFinding({ dedupeKey: 'came-back', status: 'fixed' }),
  ];
  const current = [
    makeFinding({ dedupeKey: 'stays' }),
    makeFinding({ dedupeKey: 'brand-new' }),
    makeFinding({ dedupeKey: 'came-back' }),
  ];

  it('separates new findings, regressions, still-open and resolved', () => {
    const diff = diffFindings(previous, current);
    expect(diff.newFindings.map((f) => f.dedupeKey)).toEqual(['brand-new']);
    expect(diff.regressions.map((f) => f.dedupeKey)).toEqual(['came-back']);
    expect(diff.stillOpen.map((f) => f.dedupeKey)).toEqual(['stays']);
    expect(diff.resolved.map((f) => f.dedupeKey)).toEqual(['gone']);
  });
});

describe('buildRetestLines', () => {
  it('never assumes a finding is fixed just because it was not retested', () => {
    const original = [
      makeFinding({ dedupeKey: 'a', status: 'open' }),
      makeFinding({ dedupeKey: 'b', status: 'open' }),
      makeFinding({ dedupeKey: 'c', status: 'riskAccepted' }),
    ];
    const lines = buildRetestLines(original, [], new Set(['a']));
    expect(lines.find((l) => l.finding.dedupeKey === 'a')!.outcome).toBe('verifiedFixed');
    expect(lines.find((l) => l.finding.dedupeKey === 'b')!.outcome).toBe('notRetested');
    expect(lines.find((l) => l.finding.dedupeKey === 'c')!.outcome).toBe('riskAccepted');
  });
});

describe('countBySeverity', () => {
  it('counts every band', () => {
    const counts = countBySeverity([
      makeFinding({ dedupeKey: '1', severity: 'critical' }),
      makeFinding({ dedupeKey: '2', severity: 'critical' }),
      makeFinding({ dedupeKey: '3', severity: 'info' }),
    ]);
    expect(counts).toEqual({ critical: 2, high: 0, medium: 0, low: 0, info: 1 });
  });
});
