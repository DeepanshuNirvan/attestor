import { describe, expect, it } from 'vitest';
import { runChecklist } from './checklist.ts';
import { buildSampleReportData } from './fixtures/sample-report-data.ts';

/**
 * The release gate.
 *
 * The sample report is written to pass every automated item, so a failure here means either the
 * sample has drifted or a check has become stricter — both of which are worth being told about.
 */

const data = buildSampleReportData();

const ALL_MANUAL = {
  'critical-notified': true,
  'evidence-masked': true,
  'read-every-line': true,
};

describe('the automated items', () => {
  it('all pass against a report written to a releasable standard', () => {
    const outcome = runChecklist(data, ALL_MANUAL);

    expect(outcome.blocking.map((item) => `${item.id}: ${item.reason ?? ''}`)).toEqual([]);
  });

  it('blocks a report with a finding that has no evidence', () => {
    const stripped = {
      ...data,
      findings: data.findings.map((finding, index) =>
        index === 0 ? { ...finding, evidence: [] } : finding,
      ),
    };

    const outcome = runChecklist(stripped, ALL_MANUAL);

    expect(outcome.releasable).toBe(false);
    expect(outcome.blocking.map((item) => item.id)).toContain('findings-have-evidence');
  });
});

describe('the manual items', () => {
  it('hold release until a person confirms each one', () => {
    const outcome = runChecklist(data, {});

    expect(outcome.releasable).toBe(false);
    expect(outcome.awaitingHuman.map((item) => item.id)).toEqual([
      'critical-notified',
      'evidence-masked',
      'read-every-line',
    ]);
  });

  it('cannot be satisfied by anything other than an explicit true', () => {
    // A checklist that accepts a truthy value accepts a string, and a string is what arrives from a
    // form that was never filled in.
    const outcome = runChecklist(data, {
      'critical-notified': true,
      'evidence-masked': true,
      'read-every-line': false,
    });

    expect(outcome.awaitingHuman.map((item) => item.id)).toEqual(['read-every-line']);
  });
});

describe('AI drafts', () => {
  it('block release while a section is still an unapproved draft', () => {
    const outcome = runChecklist(data, ALL_MANUAL, {
      unapprovedAiDrafts: ['executiveSummary'],
    });

    expect(outcome.releasable).toBe(false);
    const item = outcome.blocking.find((entry) => entry.id === 'ai-drafts-approved');
    expect(item?.reason).toContain('executiveSummary');
  });

  it('pass when no section is an unapproved draft', () => {
    const outcome = runChecklist(data, ALL_MANUAL, { unapprovedAiDrafts: [] });

    expect(outcome.releasable).toBe(true);
  });

  it('default to passing, so a caller that knows nothing about AI is not blocked by it', () => {
    expect(runChecklist(data, ALL_MANUAL).releasable).toBe(true);
  });
});
