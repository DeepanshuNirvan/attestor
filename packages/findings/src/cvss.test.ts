import { describe, expect, it } from 'vitest';
import {
  CvssVectorError,
  derivedVectorForSeverity,
  isValidCvssVector,
  parseCvssVector,
  scoreCvss,
} from './cvss.ts';

describe('parseCvssVector', () => {
  it('accepts a complete 3.1 base vector', () => {
    const parsed = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(parsed.version).toBe('3.1');
    expect(parsed.metrics.get('AV')).toBe('N');
  });

  it('accepts a complete 4.0 base vector including the new AT metric', () => {
    const parsed = parseCvssVector(
      'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    );
    expect(parsed.version).toBe('4.0');
    expect(parsed.metrics.get('AT')).toBe('N');
  });

  it('rejects an incomplete base vector rather than scoring it as zero', () => {
    expect(() => parseCvssVector('CVSS:4.0/AV:N/AC:L')).toThrow(CvssVectorError);
    expect(() => parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H')).toThrow(/A/);
  });

  it('rejects 3.1 metrics inside a 4.0 vector', () => {
    // S: exists in both but means different things; C/I/A do not exist in 4.0 at all.
    expect(() => parseCvssVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/C:H/I:H/A:H')).toThrow(
      /not part of CVSS 4.0/,
    );
  });

  it('rejects unknown values and duplicate metrics', () => {
    expect(() => parseCvssVector('CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toThrow(/AV/);
    expect(() =>
      parseCvssVector('CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    ).toThrow(/more than once/);
  });

  it('rejects unsupported versions outright', () => {
    expect(() => parseCvssVector('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toThrow(
      /CVSS:3.1 or CVSS:4.0/,
    );
  });
});

describe('scoreCvss', () => {
  it('matches the published 3.1 reference scores', () => {
    expect(scoreCvss('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').score).toBe(9.8);
    expect(scoreCvss('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H').score).toBe(10);
    expect(scoreCvss('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H').score).toBe(7.5);
    expect(scoreCvss('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N').score).toBe(5.5);
    expect(scoreCvss('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N').score).toBe(4.3);
  });

  it('scores 4.0 vectors and maps them to a severity band', () => {
    const worst = scoreCvss('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
    expect(worst.score).toBeGreaterThanOrEqual(9);
    expect(worst.severity).toBe('critical');

    const none = scoreCvss('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N');
    expect(none.score).toBe(0);
    expect(none.severity).toBe('info');
  });

  it('keeps the vector string it was given', () => {
    const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    expect(scoreCvss(vector).vector).toBe(vector);
  });
});

describe('derivedVectorForSeverity', () => {
  it('produces a vector that parses and lands in the intended band, both versions', () => {
    for (const version of ['3.1', '4.0'] as const) {
      for (const severity of ['critical', 'high', 'medium', 'low', 'info'] as const) {
        const vector = derivedVectorForSeverity(severity, version);
        expect(isValidCvssVector(vector), `${version} ${severity}`).toBe(true);
        const scored = scoreCvss(vector);
        if (severity === 'info') expect(scored.score).toBe(0);
        else expect(scored.score).toBeGreaterThan(0);
      }
    }
  });
});
