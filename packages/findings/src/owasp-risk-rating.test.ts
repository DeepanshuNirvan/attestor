import { describe, expect, it } from 'vitest';
import {
  isValidRiskScore,
  owaspRiskRating,
  OWASP_RISK_FACTORS,
  riskLevel,
  severityFromOwaspRating,
} from './owasp-risk-rating.ts';

/**
 * The worked example the supplied workbook ships with, on the "Risk Assessment Calculator" sheet.
 * If our arithmetic and the client's copy of the sheet ever disagree, the client is right.
 */
const WORKBOOK_EXAMPLE = {
  skillLevel: 3,
  motive: 4,
  opportunity: 4,
  populationSize: 5,
  easeOfDiscovery: 9,
  easeOfExploit: 9,
  awareness: 4,
  intrusionDetection: 8,
  lossOfConfidentiality: 6,
  lossOfIntegrity: 1,
  lossOfAvailability: 1,
  lossOfAccountability: 1,
  financialDamage: 3,
  reputationDamage: 4,
  nonCompliance: 0,
  privacyViolation: 3,
};

describe('the OWASP risk rating', () => {
  it('reproduces the worked example in the supplied workbook exactly', () => {
    const rating = owaspRiskRating(WORKBOOK_EXAMPLE);
    expect(rating.likelihood).toBe(5.75);
    expect(rating.impact).toBe(2.375);
    expect(rating.likelihoodLevel).toBe('medium');
    expect(rating.impactLevel).toBe('low');
    expect(rating.severity).toBe('low');
  });

  it('puts the band boundaries where the methodology puts them', () => {
    // A 6.0 is high, not medium. Off by one here and every rating near the boundary is wrong.
    expect(riskLevel(0)).toBe('low');
    expect(riskLevel(2.99)).toBe('low');
    expect(riskLevel(3)).toBe('medium');
    expect(riskLevel(5.99)).toBe('medium');
    expect(riskLevel(6)).toBe('high');
    expect(riskLevel(9)).toBe('high');
  });

  it('walks the whole severity matrix', () => {
    const at = (likelihood: number, impact: number) => {
      const scores: Record<string, number> = {};
      for (const entry of OWASP_RISK_FACTORS) {
        const isLikelihood = entry.group === 'threatAgent' || entry.group === 'vulnerability';
        scores[entry.id] = isLikelihood ? likelihood : impact;
      }
      return owaspRiskRating(scores).severity;
    };

    expect(at(1, 1)).toBe('note');
    expect(at(1, 4)).toBe('low');
    expect(at(1, 7)).toBe('moderate');
    expect(at(4, 1)).toBe('low');
    expect(at(4, 4)).toBe('moderate');
    expect(at(4, 7)).toBe('high');
    expect(at(7, 1)).toBe('moderate');
    expect(at(7, 4)).toBe('high');
    expect(at(7, 7)).toBe('critical');
  });

  it('leaves an unanswered factor out of the average instead of scoring it zero', () => {
    // Scoring a blank as zero argues the risk is lower than anyone has established, which is the
    // one direction a half-filled form must never move the number.
    const partial = { skillLevel: 9, motive: 9, opportunity: 9, populationSize: 9 };
    const rating = owaspRiskRating(partial);
    expect(rating.likelihood).toBe(9);
    expect(rating.unanswered).toHaveLength(12);
    expect(rating.unanswered).toContain('easeOfExploit');
  });

  it('reports a rating with nothing answered rather than throwing', () => {
    const rating = owaspRiskRating({});
    expect(rating.likelihood).toBe(0);
    expect(rating.impact).toBe(0);
    expect(rating.severity).toBe('note');
    expect(rating.unanswered).toHaveLength(16);
  });

  it('accepts only scores that are published options', () => {
    expect(isValidRiskScore('motive', 4)).toBe(true);
    // 5 is not on the motive scale — it is 1, 4 or 9. A number a client cannot find in the
    // methodology is a number we cannot defend in front of their engineers.
    expect(isValidRiskScore('motive', 5)).toBe(false);
    expect(isValidRiskScore('notAFactor', 4)).toBe(false);
  });

  it('asks all sixteen questions, eight a side', () => {
    const groups = OWASP_RISK_FACTORS.reduce<Record<string, number>>((counts, entry) => {
      counts[entry.group] = (counts[entry.group] ?? 0) + 1;
      return counts;
    }, {});
    expect(groups).toEqual({
      threatAgent: 4,
      vulnerability: 4,
      technicalImpact: 4,
      businessImpact: 4,
    });
  });

  it('keeps every option inside the published range', () => {
    for (const entry of OWASP_RISK_FACTORS) {
      for (const option of entry.options) {
        expect(option.score, `${entry.id}: ${option.label}`).toBeGreaterThanOrEqual(0);
        expect(option.score, `${entry.id}: ${option.label}`).toBeLessThanOrEqual(9);
      }
    }
  });

  it('translates into the severity words the rest of the platform uses', () => {
    expect(severityFromOwaspRating('note')).toBe('info');
    expect(severityFromOwaspRating('moderate')).toBe('medium');
    expect(severityFromOwaspRating('critical')).toBe('critical');
  });
});
