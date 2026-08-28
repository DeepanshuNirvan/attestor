import { describe, expect, it } from 'vitest';
import { maskText, passesLuhn, passesVerhoeff } from './masking.ts';

describe('maskText', () => {
  it('masks an email but keeps the shape a developer needs to recognise the record', () => {
    const { text, applied } = maskText('order placed by priya.sharma@example.co.in');
    expect(text).not.toContain('priya.sharma');
    expect(text).toContain('.in');
    expect(applied).toContain('email');
  });

  it('masks Indian mobile numbers with and without country code', () => {
    expect(maskText('call 9876543210').text).not.toContain('9876543210');
    expect(maskText('call +91 9876543210').text).not.toContain('9876543210');
  });

  it('masks a PAN', () => {
    expect(maskText('PAN ABCDE1234F on file').text).not.toContain('ABCDE1234F');
  });

  it('only masks a card number that passes Luhn', () => {
    // 4111 1111 1111 1111 is the canonical Luhn-valid test card.
    const card = maskText('card 4111111111111111').text;
    expect(card).toContain('411111');
    expect(card).toContain('1111');
    expect(card).not.toBe('card 4111111111111111');

    // A 16-digit order id that fails Luhn must survive untouched.
    const orderId = maskText('order 4111111111111112').text;
    expect(orderId).toBe('order 4111111111111112');
  });

  it('only masks an Aadhaar-shaped number that passes Verhoeff', () => {
    // 2345 6789 0124 satisfies the Verhoeff check digit; 2345 6789 0123 does not.
    expect(passesVerhoeff('234567890124')).toBe(true);
    expect(passesVerhoeff('234567890123')).toBe(false);

    const masked = maskText('aadhaar 2345 6789 0124').text;
    expect(masked).toContain('XXXX XXXX 0124');
    expect(masked).not.toContain('2345 6789 0124');

    // A reference number of the same shape that fails the check digit survives untouched.
    expect(maskText('reference 2345 6789 0123').text).toContain('2345 6789 0123');
  });

  it('honours disabled rules from the engagement policy', () => {
    const { text } = maskText('contact a@b.com', { disabledRuleIds: ['email'] });
    expect(text).toContain('a@b.com');
  });

  it('applies an extra client-supplied rule', () => {
    const { text, applied } = maskText('member MBR-99881', {
      extraRules: [
        {
          id: 'memberId',
          description: 'client member ids',
          pattern: /\bMBR-\d{5}\b/g,
          replace: () => 'MBR-*****',
        },
      ],
    });
    expect(text).toContain('MBR-*****');
    expect(applied).toContain('memberId');
  });
});

describe('check digits', () => {
  it('luhn accepts a valid card and rejects a mutated one', () => {
    expect(passesLuhn('4111111111111111')).toBe(true);
    expect(passesLuhn('4111111111111112')).toBe(false);
  });
});
