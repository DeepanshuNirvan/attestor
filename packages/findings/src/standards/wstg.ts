/**
 * The OWASP Web Security Testing Guide, as data.
 *
 * Every test in the current stable checklist, by id and name. It exists so three questions have an
 * answer that is computed rather than claimed:
 *
 *   1. Is this a real test id? A regex over the shape accepts `WSTG-INPV-99`, which is not a test.
 *      A typo in a check's `standards.wstg` would print a broken reference into a client's report.
 *   2. Which of the 109 do we cover, and which do we not? A firm that sells OWASP-aligned testing
 *      has to be able to say, and to say it from the catalogue rather than from a slide.
 *   3. For the ones we do not cover, is that a gap or a decision? `WSTG_NOT_APPLICABLE` records the
 *      decision and the reason, so an uncovered test is either explained or is honestly a gap.
 *
 * Source: https://github.com/OWASP/wstg/blob/master/checklists/checklist.md, read 2026-08-28. The
 * v4.2 edition had 105 tests; the current list adds CONF-14, SESS-11, APIT-01 and APIT-02, and
 * numbers GraphQL as APIT-99. `docs/RESEARCH-NOTES.md` carries the dated source.
 */

export interface WstgTest {
  id: string;
  name: string;
  /** The category prefix, e.g. `INPV`. */
  category: string;
}

function tests(category: string, names: Record<string, string>): WstgTest[] {
  return Object.entries(names).map(([number, name]) => ({
    id: `WSTG-${category}-${number}`,
    name,
    category,
  }));
}

export const WSTG_TESTS: WstgTest[] = [
  ...tests('INFO', {
    '01': 'Conduct Search Engine Discovery and Reconnaissance for Information Leakage',
    '02': 'Fingerprint Web Server',
    '03': 'Review Webserver Metafiles for Information Leakage',
    '04': 'Enumerate Applications on Webserver',
    '05': 'Review Webpage Content for Information Leakage',
    '06': 'Identify Application Entry Points',
    '07': 'Map Execution Paths Through Application',
    '08': 'Fingerprint Web Application Framework',
    '09': 'Fingerprint Web Application',
    '10': 'Map Application Architecture',
  }),
  ...tests('CONF', {
    '01': 'Test Network Infrastructure Configuration',
    '02': 'Test Application Platform Configuration',
    '03': 'Test File Extensions Handling for Sensitive Information',
    '04': 'Review Old Backup and Unreferenced Files for Sensitive Information',
    '05': 'Enumerate Infrastructure and Application Admin Interfaces',
    '06': 'Test HTTP Methods',
    '07': 'Test HTTP Strict Transport Security',
    '08': 'Test RIA Cross Domain Policy',
    '09': 'Test File Permission',
    '10': 'Test for Subdomain Takeover',
    '11': 'Test Cloud Storage',
    '12': 'Testing for Content Security Policy',
    '13': 'Test Path Confusion',
    '14': 'Test Other HTTP Security Header Misconfigurations',
  }),
  ...tests('IDNT', {
    '01': 'Test Role Definitions',
    '02': 'Test User Registration Process',
    '03': 'Test Account Provisioning Process',
    '04': 'Testing for Account Enumeration and Guessable User Account',
    '05': 'Testing for Weak or Unenforced Username Policy',
  }),
  ...tests('ATHN', {
    '01': 'Testing for Credentials Transported over an Encrypted Channel',
    '02': 'Testing for Default Credentials',
    '03': 'Testing for Weak Lock Out Mechanism',
    '04': 'Testing for Bypassing Authentication Schema',
    '05': 'Testing for Vulnerable Remember Password',
    '06': 'Testing for Browser Cache Weakness',
    '07': 'Testing for Weak Password Policy',
    '08': 'Testing for Weak Security Question Answer',
    '09': 'Testing for Weak Password Change or Reset Functionalities',
    '10': 'Testing for Weaker Authentication in Alternative Channel',
    '11': 'Testing Multi-Factor Authentication (MFA)',
  }),
  ...tests('ATHZ', {
    '01': 'Testing Directory Traversal File Include',
    '02': 'Testing for Bypassing Authorization Schema',
    '03': 'Testing for Privilege Escalation',
    '04': 'Testing for Insecure Direct Object References',
    '05': 'Testing for OAuth Weaknesses',
  }),
  ...tests('SESS', {
    '01': 'Testing for Session Management Schema',
    '02': 'Testing for Cookies Attributes',
    '03': 'Testing for Session Fixation',
    '04': 'Testing for Exposed Session Variables',
    '05': 'Testing for Cross Site Request Forgery',
    '06': 'Testing for Logout Functionality',
    '07': 'Testing Session Timeout',
    '08': 'Testing for Session Puzzling',
    '09': 'Testing for Session Hijacking',
    '10': 'Testing JSON Web Tokens',
    '11': 'Testing for Concurrent Sessions',
  }),
  ...tests('INPV', {
    '01': 'Testing for Reflected Cross Site Scripting',
    '02': 'Testing for Stored Cross Site Scripting',
    '03': 'Testing for HTTP Verb Tampering',
    '04': 'Testing for HTTP Parameter Pollution',
    '05': 'Testing for SQL Injection',
    '06': 'Testing for LDAP Injection',
    '07': 'Testing for XML Injection',
    '08': 'Testing for SSI Injection',
    '09': 'Testing for XPath Injection',
    '10': 'Testing for IMAP SMTP Injection',
    '11': 'Testing for Code Injection',
    '12': 'Testing for Command Injection',
    '13': 'Testing for Format String Injection',
    '14': 'Testing for Incubated Vulnerabilities',
    '15': 'Testing for HTTP Splitting Smuggling',
    '16': 'Testing for HTTP Incoming Requests',
    '17': 'Testing for Host Header Injection',
    '18': 'Testing for Server-Side Template Injection',
    '19': 'Testing for Server-Side Request Forgery',
    '20': 'Testing for Mass Assignment',
  }),
  ...tests('ERRH', {
    '01': 'Testing for Improper Error Handling',
    '02': 'Testing for Stack Traces',
  }),
  ...tests('CRYP', {
    '01': 'Testing for Weak Transport Layer Security',
    '02': 'Testing for Padding Oracle',
    '03': 'Testing for Sensitive Information Sent Via Unencrypted Channels',
    '04': 'Testing for Weak Cryptographic Primitives',
  }),
  ...tests('BUSL', {
    '01': 'Test Business Logic Data Validation',
    '02': 'Test Ability to Forge Requests',
    '03': 'Test Integrity Checks',
    '04': 'Test for Process Timing',
    '05': 'Test Number of Times a Function Can Be Used Limits',
    '06': 'Testing for the Circumvention of Work Flows',
    '07': 'Test Defenses Against Application Misuse',
    '08': 'Test Upload of Unexpected File Types',
    '09': 'Test Upload of Malicious Files',
    '10': 'Test Payment Functionality',
  }),
  ...tests('CLNT', {
    '01': 'Testing for DOM Based Cross Site Scripting',
    '02': 'Testing for JavaScript Execution',
    '03': 'Testing for HTML Injection',
    '04': 'Testing for Client-Side URL Redirect',
    '05': 'Testing for CSS Injection',
    '06': 'Testing for Client-Side Resource Manipulation',
    '07': 'Test Cross Origin Resource Sharing',
    '08': 'Testing for Cross Site Flashing',
    '09': 'Testing for Clickjacking',
    '10': 'Testing WebSockets',
    '11': 'Test Web Messaging',
    '12': 'Test Browser Storage',
    '13': 'Testing for Cross Site Script Inclusion',
    '14': 'Testing for Reverse Tabnabbing',
  }),
  ...tests('APIT', {
    '01': 'API Reconnaissance',
    '02': 'API Broken Object Level Authorization',
    '99': 'Testing GraphQL',
  }),
];

const BY_ID = new Map(WSTG_TESTS.map((test) => [test.id, test]));

export function wstgTest(id: string): WstgTest | undefined {
  return BY_ID.get(id);
}

/**
 * Tests this platform deliberately does not perform, and why.
 *
 * A gap and a decision look identical in a coverage percentage, which is how a firm ends up
 * defending a number it cannot explain. Everything here is a decision somebody made on purpose;
 * anything uncovered and absent from this table is a real gap and is reported as one.
 */
export const WSTG_NOT_APPLICABLE: Record<string, string> = {
  // INFO-09 used to sit here as well as being claimed by the technology inventory check, which is a
  // contradiction: a test cannot be both performed and deliberately skipped. OWASP merged it into
  // INFO-08 and we do the work, so it is covered and no longer listed.

  'WSTG-CONF-08':
    'Cross-domain policy files are a Flash and Silverlight mechanism, and both plugins were removed from every current browser — a permissive crossdomain.xml no longer grants a browser anything. The file is still reported when found, as information disclosure, but the original attack cannot be performed against a modern client.',
  'WSTG-CLNT-08':
    'Cross-site flashing requires Flash Player, which reached end of life in December 2020 and ships in no current browser. There is no way to demonstrate the finding and no user on whom it is exploitable.',
  'WSTG-INPV-16':
    'Testing for HTTP incoming requests means intercepting and reviewing the application own inbound traffic. That is a monitoring exercise inside the client infrastructure rather than something testable from outside it, and it belongs to a review engagement rather than to a scan.',
};

/** How much of the guide the catalogue claims, computed rather than asserted. */
export interface WstgCoverage {
  total: number;
  covered: WstgTest[];
  /** Uncovered on purpose, with the reason. */
  notApplicable: (WstgTest & { reason: string })[];
  /** Uncovered and not explained. This number is the honest gap. */
  gaps: WstgTest[];
}

export function wstgCoverage(coveredIds: readonly string[]): WstgCoverage {
  const covered = new Set(coveredIds);
  const result: WstgCoverage = {
    total: WSTG_TESTS.length,
    covered: [],
    notApplicable: [],
    gaps: [],
  };

  for (const test of WSTG_TESTS) {
    const reason = WSTG_NOT_APPLICABLE[test.id];
    if (covered.has(test.id)) result.covered.push(test);
    else if (reason !== undefined) result.notApplicable.push({ ...test, reason });
    else result.gaps.push(test);
  }

  return result;
}
