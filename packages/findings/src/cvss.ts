// Namespace import: the package is CommonJS, and a named import breaks under Vite's dev module
// runner even though the bundler resolves it.
import * as cvssCalculator from 'ae-cvss-calculator';
import { severityFromCvssScore, type CvssVersion, type Severity } from '@attestor/shared';

const { Cvss3P1, Cvss4P0 } = cvssCalculator;

/**
 * CVSS 3.1 and 4.0, both supported, chosen per engagement.
 *
 * Scoring is delegated to `ae-cvss-calculator` because CVSS 4.0 is a 270-entry MacroVector lookup
 * and a hand-rolled version would be a correctness liability. The grammar below is ours, because
 * the library treats an incomplete base vector as scoring zero rather than as an error, and a
 * finding that silently scores zero is worse than one that fails to save.
 */

const BASE_METRICS_3_1 = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'] as const;
const BASE_METRICS_4_0 = [
  'AV',
  'AC',
  'AT',
  'PR',
  'UI',
  'VC',
  'VI',
  'VA',
  'SC',
  'SI',
  'SA',
] as const;

const ALLOWED_VALUES_3_1: Record<string, string[]> = {
  AV: ['N', 'A', 'L', 'P'],
  AC: ['L', 'H'],
  PR: ['N', 'L', 'H'],
  UI: ['N', 'R'],
  S: ['U', 'C'],
  C: ['H', 'L', 'N'],
  I: ['H', 'L', 'N'],
  A: ['H', 'L', 'N'],
  E: ['X', 'U', 'P', 'F', 'H'],
  RL: ['X', 'O', 'T', 'W', 'U'],
  RC: ['X', 'U', 'R', 'C'],
  CR: ['X', 'L', 'M', 'H'],
  IR: ['X', 'L', 'M', 'H'],
  AR: ['X', 'L', 'M', 'H'],
  MAV: ['X', 'N', 'A', 'L', 'P'],
  MAC: ['X', 'L', 'H'],
  MPR: ['X', 'N', 'L', 'H'],
  MUI: ['X', 'N', 'R'],
  MS: ['X', 'U', 'C'],
  MC: ['X', 'H', 'L', 'N'],
  MI: ['X', 'H', 'L', 'N'],
  MA: ['X', 'H', 'L', 'N'],
};

const ALLOWED_VALUES_4_0: Record<string, string[]> = {
  AV: ['N', 'A', 'L', 'P'],
  AC: ['L', 'H'],
  AT: ['N', 'P'],
  PR: ['N', 'L', 'H'],
  UI: ['N', 'P', 'A'],
  VC: ['H', 'L', 'N'],
  VI: ['H', 'L', 'N'],
  VA: ['H', 'L', 'N'],
  SC: ['H', 'L', 'N'],
  SI: ['H', 'L', 'N'],
  SA: ['H', 'L', 'N'],
  E: ['X', 'A', 'P', 'U'],
  CR: ['X', 'H', 'M', 'L'],
  IR: ['X', 'H', 'M', 'L'],
  AR: ['X', 'H', 'M', 'L'],
  MAV: ['X', 'N', 'A', 'L', 'P'],
  MAC: ['X', 'L', 'H'],
  MAT: ['X', 'N', 'P'],
  MPR: ['X', 'N', 'L', 'H'],
  MUI: ['X', 'N', 'P', 'A'],
  MVC: ['X', 'H', 'L', 'N'],
  MVI: ['X', 'H', 'L', 'N'],
  MVA: ['X', 'H', 'L', 'N'],
  MSC: ['X', 'H', 'L', 'N'],
  MSI: ['X', 'S', 'H', 'L', 'N'],
  MSA: ['X', 'S', 'H', 'L', 'N'],
  S: ['X', 'N', 'P'],
  AU: ['X', 'N', 'Y'],
  R: ['X', 'A', 'U', 'I'],
  V: ['X', 'D', 'C'],
  RE: ['X', 'L', 'M', 'H'],
  U: ['X', 'Clear', 'Green', 'Amber', 'Red'],
};

export class CvssVectorError extends Error {
  readonly vector: string;

  constructor(message: string, vector: string) {
    super(message);
    this.name = 'CvssVectorError';
    this.vector = vector;
  }
}

export interface ParsedCvss {
  version: CvssVersion;
  vector: string;
  metrics: Map<string, string>;
}

/** Parse and validate. Throws rather than returning a partial result. */
export function parseCvssVector(vector: string): ParsedCvss {
  const trimmed = vector.trim();
  const parts = trimmed.split('/');
  const prefix = parts.shift();

  if (prefix !== 'CVSS:3.1' && prefix !== 'CVSS:4.0') {
    throw new CvssVectorError(
      'vector must begin with CVSS:3.1 or CVSS:4.0; other versions are not supported',
      vector,
    );
  }
  const version: CvssVersion = prefix === 'CVSS:3.1' ? '3.1' : '4.0';
  const allowed = version === '3.1' ? ALLOWED_VALUES_3_1 : ALLOWED_VALUES_4_0;
  const required = version === '3.1' ? BASE_METRICS_3_1 : BASE_METRICS_4_0;

  const metrics = new Map<string, string>();
  for (const part of parts) {
    const [metric, value, ...rest] = part.split(':');
    if (!metric || !value || rest.length > 0) {
      throw new CvssVectorError(`malformed metric "${part}"`, vector);
    }
    if (metrics.has(metric)) {
      throw new CvssVectorError(`metric ${metric} appears more than once`, vector);
    }
    const permitted = allowed[metric];
    if (!permitted) {
      throw new CvssVectorError(`metric ${metric} is not part of CVSS ${version}`, vector);
    }
    if (!permitted.includes(value)) {
      throw new CvssVectorError(`value ${value} is not valid for metric ${metric}`, vector);
    }
    metrics.set(metric, value);
  }

  const missing = required.filter((metric) => !metrics.has(metric));
  if (missing.length > 0) {
    throw new CvssVectorError(`base metrics missing: ${missing.join(', ')}`, vector);
  }

  return { version, vector: trimmed, metrics };
}

export interface CvssResult {
  version: CvssVersion;
  vector: string;
  score: number;
  severity: Severity;
}

export function scoreCvss(vector: string): CvssResult {
  const parsed = parseCvssVector(vector);
  const score =
    parsed.version === '3.1'
      ? new Cvss3P1(parsed.vector).calculateScores().overall
      : new Cvss4P0(parsed.vector).calculateOverallScore();

  if (typeof score !== 'number' || Number.isNaN(score)) {
    throw new CvssVectorError('scoring produced no result', vector);
  }

  return {
    version: parsed.version,
    vector: parsed.vector,
    score,
    severity: severityFromCvssScore(score),
  };
}

/** True when the vector parses. Used at the edge, where a refusal is more useful than a throw. */
export function isValidCvssVector(vector: string): boolean {
  try {
    parseCvssVector(vector);
    return true;
  } catch {
    return false;
  }
}

/**
 * A conservative vector for a tool finding that has no CVSS of its own, derived from the severity
 * the tool reported. It is marked as derived so a human replaces it before the report goes out.
 */
export function derivedVectorForSeverity(severity: Severity, version: CvssVersion): string {
  if (version === '4.0') {
    const impact: Record<Severity, string> = {
      critical: 'VC:H/VI:H/VA:H/SC:L/SI:L/SA:N',
      high: 'VC:H/VI:L/VA:N/SC:N/SI:N/SA:N',
      medium: 'VC:L/VI:L/VA:N/SC:N/SI:N/SA:N',
      low: 'VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
      info: 'VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',
    };
    return `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/${impact[severity]}`;
  }
  const impact: Record<Severity, string> = {
    critical: 'C:H/I:H/A:H',
    high: 'C:H/I:L/A:N',
    medium: 'C:L/I:L/A:N',
    low: 'C:L/I:N/A:N',
    info: 'C:N/I:N/A:N',
  };
  return `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/${impact[severity]}`;
}
