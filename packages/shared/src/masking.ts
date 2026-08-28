/**
 * Masking of personal data. Applied at capture time, before an evidence object is written, so raw
 * client personal data never reaches disk. This is a DPDP obligation, not a report preference.
 *
 * Masking is lossy and deliberately so. It keeps enough shape for a developer to recognise the
 * record ("the order belonged to a different user") without keeping the person's data.
 */

export interface MaskingRule {
  id: string;
  description: string;
  pattern: RegExp;
  replace: (match: string) => string;
}

function keepEdges(value: string, lead: number, trail: number): string {
  if (value.length <= lead + trail) return '*'.repeat(value.length);
  return `${value.slice(0, lead)}${'*'.repeat(value.length - lead - trail)}${value.slice(value.length - trail)}`;
}

/** Luhn check, so a 16-digit order id is not mistaken for a card number. */
export function passesLuhn(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    const char = digits[index];
    if (char === undefined) return false;
    let value = char.charCodeAt(0) - 48;
    if (value < 0 || value > 9) return false;
    if (double) {
      value *= 2;
      if (value > 9) value -= 9;
    }
    sum += value;
    double = !double;
  }
  return sum % 10 === 0;
}

/** Verhoeff check digit, which is what an Aadhaar number actually validates against. */
const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

export function passesVerhoeff(digits: string): boolean {
  let checksum = 0;
  const reversed = digits.split('').reverse();
  for (let index = 0; index < reversed.length; index += 1) {
    const digit = Number(reversed[index]);
    if (!Number.isInteger(digit)) return false;
    const permuted = VERHOEFF_P[index % 8]?.[digit];
    const next = VERHOEFF_D[checksum]?.[permuted ?? 0];
    checksum = next ?? 0;
  }
  return checksum === 0;
}

export const DEFAULT_MASKING_RULES: MaskingRule[] = [
  {
    id: 'email',
    description: 'Email addresses, keeping the first character and the top-level domain.',
    pattern: /\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+)\.([A-Za-z]{2,24})\b/g,
    replace: (match) => {
      const [local = '', rest = ''] = match.split('@');
      const dot = rest.lastIndexOf('.');
      const domain = rest.slice(0, dot);
      const tld = rest.slice(dot + 1);
      return `${keepEdges(local, 1, 0)}@${keepEdges(domain, 1, 0)}.${tld}`;
    },
  },
  {
    id: 'indianMobile',
    description: 'Indian mobile numbers with or without a country code.',
    pattern: /\b(?:\+?91[-\s]?)?[6-9]\d{9}\b/g,
    replace: (match) => keepEdges(match, 2, 2),
  },
  {
    id: 'internationalPhone',
    description: 'E.164-shaped international numbers.',
    pattern: /\+\d{1,3}[-\s]?\d{6,12}\b/g,
    replace: (match) => keepEdges(match, 3, 2),
  },
  {
    id: 'pan',
    description: 'Indian permanent account number.',
    pattern: /\b[A-Z]{5}\d{4}[A-Z]\b/g,
    replace: (match) => keepEdges(match, 2, 1),
  },
  {
    id: 'aadhaar',
    description: 'Aadhaar number, checked against the Verhoeff digit before masking.',
    pattern: /\b[2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4}\b/g,
    replace: (match) => {
      const digits = match.replace(/\D/g, '');
      return passesVerhoeff(digits) ? `XXXX XXXX ${digits.slice(-4)}` : match;
    },
  },
  {
    id: 'paymentCard',
    description: 'Payment card numbers, checked against Luhn before masking.',
    pattern: /\b(?:\d[ -]?){12,18}\d\b/g,
    replace: (match) => {
      const digits = match.replace(/\D/g, '');
      if (digits.length < 13 || digits.length > 19 || !passesLuhn(digits)) return match;
      return `${digits.slice(0, 6)}${'*'.repeat(digits.length - 10)}${digits.slice(-4)}`;
    },
  },
  {
    id: 'ifsc',
    description: 'Indian bank IFSC codes, which identify a branch and often accompany an account.',
    pattern: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g,
    replace: (match) => keepEdges(match, 4, 0),
  },
];

export interface MaskingOptions {
  /** Extra client-specified patterns from the engagement policy. */
  extraRules?: MaskingRule[];
  /** Rule ids to skip, for the rare case where a client asks for a field to stay readable. */
  disabledRuleIds?: string[];
}

export interface MaskingOutcome {
  text: string;
  /** Rule ids that actually fired, recorded on the evidence object for defensibility. */
  applied: string[];
}

export function maskText(input: string, options: MaskingOptions = {}): MaskingOutcome {
  const disabled = new Set(options.disabledRuleIds ?? []);
  const rules = [...DEFAULT_MASKING_RULES, ...(options.extraRules ?? [])].filter(
    (rule) => !disabled.has(rule.id),
  );

  const applied: string[] = [];
  let text = input;
  for (const rule of rules) {
    let fired = false;
    text = text.replace(rule.pattern, (match) => {
      const replaced = rule.replace(match);
      if (replaced !== match) fired = true;
      return replaced;
    });
    if (fired) applied.push(rule.id);
  }
  return { text, applied };
}
