/**
 * The OWASP Risk Rating Methodology, as data and as a pure function.
 *
 * CVSS answers "how bad is this class of flaw in the abstract". It has no opinion about who the
 * client is, what the data is worth, or whether anyone would be fined for losing it — and a report
 * that offers only CVSS invites the reader to argue with a number that was never about their
 * business. The OWASP method asks sixteen questions that are specifically about *this* client, and
 * the answers are what the remediation conversation is actually about.
 *
 * Both are published for every finding, because they disagree usefully. A stored cross-site
 * scripting flaw in an internal tool used by four people is a 6.1 either way in CVSS and a very
 * different risk to the business; so is an information disclosure that happens to expose the one
 * table covered by a regulator.
 *
 * The scales, the wording and the severity matrix are taken from the OWASP Risk Rating Methodology
 * and match the calculator sheet in `OWASP_WSTG_Checklist.xlsx`, which the firm's clients recognise.
 * Nothing here is invented: a score that cannot be traced to a published option is not defensible in
 * front of a client's engineers, which is the only place these numbers matter.
 */

export type RiskLevel = 'low' | 'medium' | 'high';
export type OwaspSeverity = 'note' | 'low' | 'moderate' | 'high' | 'critical';

export interface RiskFactorOption {
  label: string;
  score: number;
}

export interface RiskFactor {
  id: string;
  label: string;
  group: 'threatAgent' | 'vulnerability' | 'technicalImpact' | 'businessImpact';
  options: RiskFactorOption[];
}

function factor(
  id: string,
  label: string,
  group: RiskFactor['group'],
  options: [string, number][],
): RiskFactor {
  return { id, label, group, options: options.map(([l, score]) => ({ label: l, score })) };
}

/**
 * The sixteen questions, in the order the OWASP sheet asks them.
 *
 * Exported as data so the console renders the same list the methodology defines rather than a
 * hand-copied one, and so a factor cannot be added in one place and missed in the other.
 */
export const OWASP_RISK_FACTORS: RiskFactor[] = [
  factor('skillLevel', 'Skills required', 'threatAgent', [
    ['No technical skills', 1],
    ['Some technical skills', 3],
    ['Advanced computer user', 5],
    ['Network and programming skills', 6],
    ['Security penetration skills', 9],
  ]),
  factor('motive', 'Motive', 'threatAgent', [
    ['Low or no reward', 1],
    ['Possible reward', 4],
    ['High reward', 9],
  ]),
  factor('opportunity', 'Opportunity', 'threatAgent', [
    ['Full access or expensive resources required', 0],
    ['Special access or resources required', 4],
    ['Some access or resources required', 7],
    ['No access or resources required', 9],
  ]),
  factor('populationSize', 'Population size', 'threatAgent', [
    ['Developers or system administrators', 2],
    ['Intranet users', 4],
    ['Partners', 5],
    ['Authenticated users', 6],
    ['Anonymous internet users', 9],
  ]),

  factor('easeOfDiscovery', 'Ease of discovery', 'vulnerability', [
    ['Practically impossible', 1],
    ['Difficult', 3],
    ['Easy', 7],
    ['Automated tools available', 9],
  ]),
  factor('easeOfExploit', 'Ease of exploit', 'vulnerability', [
    ['Theoretical', 1],
    ['Difficult', 3],
    ['Easy', 5],
    ['Automated tools available', 9],
  ]),
  factor('awareness', 'Awareness', 'vulnerability', [
    ['Unknown', 1],
    ['Hidden', 4],
    ['Obvious', 6],
    ['Public knowledge', 9],
  ]),
  factor('intrusionDetection', 'Intrusion detection', 'vulnerability', [
    ['Active detection in application', 1],
    ['Logged and reviewed', 3],
    ['Logged without review', 8],
    ['Not logged', 9],
  ]),

  factor('lossOfConfidentiality', 'Loss of confidentiality', 'technicalImpact', [
    ['Minimal non-sensitive data disclosed', 2],
    ['Minimal critical data disclosed', 6],
    ['Extensive non-sensitive data disclosed', 6],
    ['Extensive critical data disclosed', 7],
    ['All data disclosed', 9],
  ]),
  factor('lossOfIntegrity', 'Loss of integrity', 'technicalImpact', [
    ['Minimal slightly corrupt data', 1],
    ['Minimal seriously corrupt data', 3],
    ['Extensive slightly corrupt data', 5],
    ['Extensive seriously corrupt data', 7],
    ['All data totally corrupt', 9],
  ]),
  factor('lossOfAvailability', 'Loss of availability', 'technicalImpact', [
    ['Minimal secondary services interrupted', 1],
    ['Minimal primary services interrupted', 5],
    ['Extensive secondary services interrupted', 5],
    ['Extensive primary services interrupted', 7],
    ['All services completely lost', 9],
  ]),
  factor('lossOfAccountability', 'Loss of accountability', 'technicalImpact', [
    ['Attack fully traceable to an individual', 1],
    ['Possibly traceable', 7],
    ['Completely anonymous', 9],
  ]),

  factor('financialDamage', 'Financial damage', 'businessImpact', [
    ['Less than the cost to fix the vulnerability', 1],
    ['Minor effect on annual profit', 3],
    ['Significant effect on annual profit', 7],
    ['Bankruptcy', 9],
  ]),
  factor('reputationDamage', 'Reputation damage', 'businessImpact', [
    ['Minimal damage', 1],
    ['Loss of major accounts', 4],
    ['Loss of goodwill', 5],
    ['Brand damage', 9],
  ]),
  factor('nonCompliance', 'Non-compliance', 'businessImpact', [
    ['Not applicable', 0],
    ['Minor violation', 2],
    ['Clear violation', 5],
    ['High profile violation', 7],
  ]),
  factor('privacyViolation', 'Privacy violation', 'businessImpact', [
    ['Not applicable', 0],
    ['One individual', 3],
    ['Hundreds of people', 5],
    ['Thousands of people', 7],
    ['Millions of people', 9],
  ]),
];

const FACTOR_BY_ID = new Map(OWASP_RISK_FACTORS.map((entry) => [entry.id, entry]));

export type OwaspRiskScores = Record<string, number>;

export interface OwaspRiskRating {
  likelihood: number;
  impact: number;
  likelihoodLevel: RiskLevel;
  impactLevel: RiskLevel;
  severity: OwaspSeverity;
  /** Factors the caller did not answer. An unanswered factor is left out of its average. */
  unanswered: string[];
}

/**
 * The published bands: below 3 is low, 3 to below 6 is medium, 6 and above is high.
 *
 * The boundary matters and is easy to get wrong by one: a 6.0 is high, not medium. Exactly the
 * arithmetic the workbook does, so a client comparing our number against their own copy of the
 * sheet gets the same answer.
 */
export function riskLevel(score: number): RiskLevel {
  if (score < 3) return 'low';
  if (score < 6) return 'medium';
  return 'high';
}

/** Likelihood down the side, impact across the top, exactly as the methodology prints it. */
const SEVERITY_MATRIX: Record<RiskLevel, Record<RiskLevel, OwaspSeverity>> = {
  low: { low: 'note', medium: 'low', high: 'moderate' },
  medium: { low: 'low', medium: 'moderate', high: 'high' },
  high: { low: 'moderate', medium: 'high', high: 'critical' },
};

function averageOf(groups: RiskFactor['group'][], scores: OwaspRiskScores): [number, string[]] {
  const wanted = OWASP_RISK_FACTORS.filter((entry) => groups.includes(entry.group));
  const answered: number[] = [];
  const unanswered: string[] = [];

  for (const entry of wanted) {
    const value = scores[entry.id];
    if (value === undefined) unanswered.push(entry.id);
    else answered.push(value);
  }

  // Averaging over what was answered rather than treating a blank as zero. A blank is "we have not
  // asked the client yet", and scoring it zero quietly argues the risk is lower than it is.
  const total = answered.reduce((sum, value) => sum + value, 0);
  return [answered.length === 0 ? 0 : total / answered.length, unanswered];
}

/** Every score must be a published option for its factor. A number nobody can trace is not evidence. */
export function isValidRiskScore(factorId: string, score: number): boolean {
  const entry = FACTOR_BY_ID.get(factorId);
  if (!entry) return false;
  return entry.options.some((option) => option.score === score);
}

export function owaspRiskRating(scores: OwaspRiskScores): OwaspRiskRating {
  const [likelihood, likelihoodMissing] = averageOf(['threatAgent', 'vulnerability'], scores);
  const [impact, impactMissing] = averageOf(['technicalImpact', 'businessImpact'], scores);
  const likelihoodLevel = riskLevel(likelihood);
  const impactLevel = riskLevel(impact);

  return {
    likelihood,
    impact,
    likelihoodLevel,
    impactLevel,
    severity: SEVERITY_MATRIX[likelihoodLevel][impactLevel],
    unanswered: [...likelihoodMissing, ...impactMissing],
  };
}

/**
 * The OWASP severity mapped onto the five words the rest of the platform uses for a finding.
 *
 * `note` becomes `info` and `moderate` becomes `medium`; the other three already agree. This exists
 * so the two scoring systems can be compared in the report without the reader translating, and it
 * is deliberately one-way: the OWASP rating informs the severity a tester sets, it does not
 * overwrite it. A person decides what a finding is worth to a client.
 */
export function severityFromOwaspRating(
  severity: OwaspSeverity,
): 'info' | 'low' | 'medium' | 'high' | 'critical' {
  switch (severity) {
    case 'note':
      return 'info';
    case 'moderate':
      return 'medium';
    default:
      return severity;
  }
}
