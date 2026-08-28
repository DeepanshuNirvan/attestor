/**
 * Legal and boilerplate text, versioned.
 *
 * Rules that hold for everything in this file:
 *
 *   - Three blocks are mandatory on every assessment and retest report: the limitations and
 *     disclaimer, the confidentiality statement and the reliance statement. There is no console
 *     control that removes them. They can be replaced by a newer approved version, never deleted.
 *   - Placeholders are `[SQUARE BRACKETS]` and are filled from engagement data at render time. A
 *     document containing an unfilled placeholder fails the pre-release checklist.
 *   - `lawyerReviewedAt` is null until a qualified lawyer has reviewed the text. Until then the
 *     console shows a banner and the website carries a draft notice. Nothing here is legal advice.
 *   - The version used is recorded on each issued document, so an old report can be re-rendered
 *     exactly as it was sent.
 */

export interface LegalBlock {
  id: string;
  title: string;
  version: string;
  /** Set by the owner once a lawyer has signed the text off. */
  lawyerReviewedAt: string | null;
  mandatory: boolean;
  /** Where this block appears. Used by the renderer and by the checklist. */
  appearsIn: (
    | 'assessmentReport'
    | 'retestReport'
    | 'attestationLetter'
    | 'deletionConfirmation'
    | 'authorisationForm'
    | 'website'
    | 'portal'
    | 'email'
  )[];
  text: string;
}

const PLACEHOLDER = /\[[A-Z][A-Z0-9 ./_-]*\]/g;

export const LEGAL_BLOCKS: LegalBlock[] = [
  {
    id: 'report-limitations-and-disclaimer',
    title: 'Limitations and disclaimer',
    version: '1.0.0-draft',
    lawyerReviewedAt: null,
    mandatory: true,
    appearsIn: ['assessmentReport', 'retestReport'],
    text: `LIMITATIONS AND DISCLAIMER

Nature of this assessment. This report presents the results of a point-in-time security assessment carried out by [LEGAL ENTITY NAME], trading as [BRAND NAME], for [CLIENT LEGAL NAME] between [TEST START DATE] and [TEST END DATE], against the scope recorded in the Scope section of this report. The findings describe the state of the tested assets as observed during that period only. Systems change; a result that was accurate during the test window may cease to be accurate immediately afterwards as a consequence of code changes, configuration changes, dependency updates, infrastructure changes or newly disclosed vulnerabilities.

Scope limitation. Only the assets, environments, interfaces and user roles listed in the Scope section were assessed. Assets that were excluded from scope, that were unavailable during the test window, or for which access or credentials were not provided, were not assessed and no statement is made about them. The Coverage Matrix in this report records what was tested, what was partially tested and what was not tested, together with the reason in each case.

No warranty of completeness. Security assessment is a sampling exercise performed under time and scope constraints. No assessment, however thorough, can identify every vulnerability in a system, and the absence of a finding in this report must not be interpreted as evidence that a vulnerability does not exist. [LEGAL ENTITY NAME] does not warrant that the tested assets are free from vulnerabilities, secure against all attacks, or fit for any particular purpose.

Not a certification. This report is not a certificate, accreditation, attestation of compliance, or guarantee of compliance with any law, standard, framework or contractual obligation. Where findings are mapped to a standard such as ISO/IEC 27001, SOC 2, PCI DSS or India's Digital Personal Data Protection Act, that mapping is provided for the client's convenience in evidencing its own programme and does not constitute a compliance opinion, an audit opinion, or certification of any kind. [LEGAL ENTITY NAME] is not empanelled by CERT-In and this report is not a CERT-In audit report.

Methodology. The assessment followed [METHODOLOGY LIST]. Automated tooling was used to obtain coverage and all reported findings were reviewed and validated by a human tester before inclusion. Findings arising solely from automated output and not validated by a tester are not included in this report.

Client responsibilities. [CLIENT LEGAL NAME] confirmed, prior to testing, that it owns or is otherwise entitled to authorise testing of the assets in scope, that any necessary permissions from third parties including hosting, cloud and service providers had been obtained, and that current backups existed. The accuracy of information supplied by [CLIENT LEGAL NAME], including asset inventories, architecture descriptions and credentials, has been relied upon and has not been independently verified except where stated.

Remediation. Remediation guidance in this report is provided in good faith and should be reviewed, adapted to the client's environment and tested by [CLIENT LEGAL NAME] before deployment. [LEGAL ENTITY NAME] is not responsible for the implementation of remediation, nor for any effect of implementing it. Findings recorded as resolved were re-verified only where a retest was performed and only to the extent recorded in the retest results.

Reliance and distribution. This report is prepared solely for [CLIENT LEGAL NAME] and for the internal purposes described in the engagement documents. It may be shared with the client's auditors, insurers, regulators and prospective customers where necessary for assurance purposes, on the basis that no duty of care is owed by [LEGAL ENTITY NAME] to any such recipient and no such recipient may rely on this report. It must not be published, quoted in part, or used in marketing without the prior written consent of [LEGAL ENTITY NAME] and [CLIENT LEGAL NAME].

Confidentiality. This report contains information about unresolved security weaknesses. Disclosure to unauthorised parties may materially increase the risk to [CLIENT LEGAL NAME]. It must be handled as confidential and distributed on a need-to-know basis.

Liability. Except in respect of liability which cannot lawfully be limited, the total aggregate liability of [LEGAL ENTITY NAME] arising out of or in connection with this engagement, whether in contract, tort including negligence, or otherwise, is limited to the fees actually paid by [CLIENT LEGAL NAME] for this engagement. [LEGAL ENTITY NAME] is not liable for indirect, special or consequential loss, nor for loss of profit, revenue, goodwill, data or anticipated savings. Nothing in this report varies the terms of the executed engagement documents, which prevail in the event of conflict.

Governing law. This report and the engagement to which it relates are governed by the laws of [COUNTRY] and subject to the exclusive jurisdiction of [JURISDICTION], unless the executed engagement documents provide otherwise.`,
  },

  {
    id: 'report-cover-classification',
    title: 'Cover classification and handling statement',
    version: '1.0.0-draft',
    lawyerReviewedAt: null,
    mandatory: true,
    appearsIn: ['assessmentReport', 'retestReport'],
    text: `CONFIDENTIAL — CONTAINS UNRESOLVED SECURITY FINDINGS

Prepared for [CLIENT LEGAL NAME] by [LEGAL ENTITY NAME] trading as [BRAND NAME]. Report reference [REPORT REFERENCE], version [REPORT VERSION], issued [REPORT DATE].

Distribute on a need-to-know basis only. Do not forward, publish or store this document in an unrestricted location. If you have received this document in error, please notify [CONTACT EMAIL] and delete all copies.`,
  },

  {
    id: 'attestation-letter',
    title: 'Letter of attestation',
    version: '1.0.0-draft',
    lawyerReviewedAt: null,
    mandatory: false,
    appearsIn: ['attestationLetter'],
    text: `LETTER OF ATTESTATION — INDEPENDENT SECURITY ASSESSMENT

To whom it may concern,

[LEGAL ENTITY NAME], trading as [BRAND NAME], was engaged by [CLIENT LEGAL NAME] to perform an independent security assessment of [ENGAGEMENT TITLE].

Assessment period:      [TEST START DATE] to [TEST END DATE]
Scope:                  [SCOPE SUMMARY]
Assessment type:        [ASSESSMENT TYPE]
Methodology:            [METHODOLOGY LIST]
Severity model:         CVSS [CVSS VERSION]
Report reference:       [REPORT REFERENCE], version [REPORT VERSION]

Findings identified:    [CRITICAL COUNT] critical, [HIGH COUNT] high, [MEDIUM COUNT] medium, [LOW COUNT] low, [INFO COUNT] informational

Remediation status as at [STATUS DATE]: [REMEDIATION STATEMENT]

Independence: [LEGAL ENTITY NAME] did not design, develop, operate or maintain any of the systems assessed, and has no financial or operational interest in [CLIENT LEGAL NAME] beyond the fees for this engagement.

Basis and limitations: this letter summarises a point-in-time assessment limited to the scope stated above and is subject in full to the limitations and disclaimer set out in the accompanying report. It is not a certification of compliance with any standard or law, and it does not warrant that the assessed systems are free from vulnerabilities. [LEGAL ENTITY NAME] is not empanelled by CERT-In. No duty of care is owed to any recipient of this letter other than [CLIENT LEGAL NAME], and no such recipient may rely upon it. The detailed report is available from [CLIENT LEGAL NAME] under their own confidentiality arrangements.

Verification: the authenticity of this letter may be confirmed by writing to [CONTACT EMAIL] quoting reference [REPORT REFERENCE].

Yours faithfully,

[TESTER NAME]
[TESTER TITLE], [LEGAL ENTITY NAME]`,
  },

  {
    id: 'retest-basis',
    title: 'Basis of this retest',
    version: '1.0.0-draft',
    lawyerReviewedAt: null,
    mandatory: true,
    appearsIn: ['retestReport'],
    text: `BASIS OF THIS RETEST

This retest was performed on [RETEST DATE] and was limited to re-verifying the findings listed in report [REPORT REFERENCE] version [ORIGINAL REPORT VERSION]. No new assessment of the application, infrastructure or environment was performed and no search for new vulnerabilities was undertaken.

A finding recorded as "verified fixed" means that the specific issue described in the original finding could no longer be reproduced using the original reproduction steps at the time of retest. It does not mean that the underlying class of weakness has been eliminated, that the fix is complete in all code paths, or that no related issue exists elsewhere in the system.

Changes made to the environment after [RETEST DATE] are outside the scope of this retest. The limitations and disclaimer in the original report apply to this document in full.`,
  },

  {
    id: 'evidence-deletion-confirmation',
    title: 'Confirmation of data deletion',
    version: '1.0.0-draft',
    lawyerReviewedAt: null,
    mandatory: false,
    appearsIn: ['deletionConfirmation'],
    text: `CONFIRMATION OF DATA DELETION

[REPORT DATE]

[CLIENT LEGAL NAME]

Engagement:            [ENGAGEMENT TITLE]
Report reference:      [REPORT REFERENCE]
Assessment period:     [TEST START DATE] to [TEST END DATE]
Retention period:      [RETENTION DAYS] days from report release

This confirms that as at [DELETION DATE], [LEGAL ENTITY NAME] has deleted from its systems all testing evidence collected during the above engagement, including captured requests and responses, screenshots, logs, transcripts and raw tool output, together with all credentials supplied by [CLIENT LEGAL NAME] for the purpose of the engagement.

Retained for record and defence purposes only: the issued report and attestation letter, the executed engagement documents and authorisation, and the immutable activity log recording what was executed and when. These are held in encrypted storage with access restricted to authorised personnel.

We recommend that any test accounts created for this engagement are disabled and that credentials shared with us are rotated, if this has not already been done.

[TESTER NAME]
[TESTER TITLE], [LEGAL ENTITY NAME]`,
  },

  {
    id: 'authorisation-to-test',
    title: 'Authorisation for security testing',
    version: '1.0.0-draft',
    lawyerReviewedAt: null,
    mandatory: false,
    appearsIn: ['authorisationForm'],
    text: `AUTHORISATION FOR SECURITY TESTING

Client:              [CLIENT LEGAL NAME], [CLIENT ADDRESS]
Service provider:    [LEGAL ENTITY NAME] trading as [BRAND NAME]
Engagement:          [ENGAGEMENT TITLE]
Engagement document: [SOW REFERENCE] dated [SOW DATE]

1. Authorised assets. [CLIENT LEGAL NAME] authorises [LEGAL ENTITY NAME] to perform security testing against, and only against, the following assets:

[ASSET LIST]

   Explicitly excluded from this authorisation:

[EXCLUSION LIST]

2. Testing window. Testing is authorised from [TEST START DATE AND TIME] to [TEST END DATE AND TIME] ([TIMEZONE]), during the following hours: [PERMITTED HOURS]. No testing is authorised outside this window.

3. Source addresses. Testing will originate from the following addresses: [SOURCE IP LIST]. [CLIENT LEGAL NAME] will allow these addresses where necessary and will inform its hosting, cloud, WAF and managed security providers as required.

4. Authority and ownership. The signatory confirms that they are authorised to bind [CLIENT LEGAL NAME]; that [CLIENT LEGAL NAME] owns or otherwise controls the assets listed in clause 1; and that where any asset is hosted, operated or provided by a third party, all permissions required from that third party have been obtained. [CLIENT LEGAL NAME] will provide evidence of such third-party permission on request.

5. Permitted activity. Authorised techniques comprise reconnaissance, enumeration, vulnerability identification, and controlled exploitation to the minimum extent necessary to demonstrate impact, in accordance with the agreed Rules of Engagement.

6. Excluded activity. The following are not authorised and will not be performed: denial-of-service, distributed denial-of-service, stress, load or volumetric testing of any kind; destructive actions including deletion or modification of data, accounts or configuration; extraction of production personal data beyond the minimum masked sample required to evidence a finding; social engineering or phishing of personnel; physical intrusion; and testing of any asset not listed in clause 1.

7. Preparation. [CLIENT LEGAL NAME] confirms that current, tested backups of the assets in scope exist prior to the testing window, and has nominated the following contact, available throughout the window, with authority to halt testing immediately: [EMERGENCY CONTACT]

8. Halting. Either party may halt testing at any time by contacting the other at the nominated contact details. [LEGAL ENTITY NAME] will cease all activity promptly upon such a request.

9. Critical findings. Findings assessed as critical will be notified to [CLIENT LEGAL NAME] as soon as practicable and in any event within [CRITICAL NOTIFICATION HOURS] hours of validation, ahead of the report.

10. Data handling. Testing evidence will be stored encrypted, access-restricted and masked where it would otherwise contain personal data, and will be deleted [RETENTION DAYS] days after report release, with written confirmation. Credentials supplied will be held in encrypted storage and destroyed on closure. The parties' respective obligations as data fiduciary and data processor are set out in the Data Processing Agreement dated [DPA DATE].

11. Legal effect. This authorisation is given for the purposes of, among others, the Information Technology Act, 2000 and any equivalent law applicable to the assets in scope, and constitutes the consent of [CLIENT LEGAL NAME] to the access described. It does not authorise access to any system not listed in clause 1.

12. Revocation. This authorisation may be revoked in writing at any time and expires automatically at the end of the testing window in clause 2.

Signed for and on behalf of [CLIENT LEGAL NAME]

Name: ____________________  Role: ____________________
Email: ___________________  Date: ____________________
Signature: _______________________________________`,
  },

  {
    id: 'portal-terms-of-access',
    title: 'Portal terms of access',
    version: '1.0.0-draft',
    lawyerReviewedAt: null,
    mandatory: true,
    appearsIn: ['portal'],
    text: `PORTAL TERMS OF ACCESS

This portal contains confidential information about unresolved security weaknesses in your organisation's systems. By accessing it you agree that:

1. Your account is personal to you. You will not share your credentials or your multi-factor authentication device with anyone.
2. You will access only information relating to your own organisation, and will report any access you believe you should not have to [CONTACT EMAIL] immediately.
3. Reports and findings downloaded from this portal are confidential, are watermarked with your identity, and must be distributed only on a need-to-know basis within your organisation and to your auditors, insurers, regulators and prospective customers where necessary for assurance purposes.
4. You will not publish, or use in marketing, any material obtained from this portal without our prior written consent.
5. Marking a finding as remediated or risk accepted is your organisation's decision and record. A finding is treated as verified only after we have re-tested it and recorded the result.
6. Your activity in this portal, including views and downloads, is logged for security and audit purposes.
7. Access may be suspended or withdrawn where these terms are breached or where your engagement with us ends.

Reports remain subject in full to the limitations and disclaimer set out within them.`,
  },

  {
    id: 'email-confidentiality-footer',
    title: 'Email confidentiality footer',
    version: '1.0.0-draft',
    lawyerReviewedAt: null,
    mandatory: true,
    appearsIn: ['email'],
    text: `This message and any attachment are confidential and intended solely for the named recipient. If you are not the intended recipient, please notify [CONTACT EMAIL] and delete this message. [LEGAL ENTITY NAME] does not send security findings by email; findings are made available through our client portal.`,
  },
];

const byId = new Map(LEGAL_BLOCKS.map((block) => [block.id, block]));

export function legalBlock(id: string): LegalBlock {
  const found = byId.get(id);
  if (!found) throw new Error(`unknown legal block "${id}"`);
  return found;
}

export function mandatoryBlocksFor(document: LegalBlock['appearsIn'][number]): LegalBlock[] {
  return LEGAL_BLOCKS.filter((block) => block.mandatory && block.appearsIn.includes(document));
}

/**
 * Fill placeholders. Anything left unfilled is returned in `missing`, and the pre-release checklist
 * refuses to release a document with a non-empty `missing` list.
 */
export function fillPlaceholders(
  text: string,
  values: Record<string, string>,
): { text: string; missing: string[] } {
  const missing = new Set<string>();
  const filled = text.replace(PLACEHOLDER, (match) => {
    const key = match.slice(1, -1);
    const value = values[key];
    if (value === undefined || value === '') {
      missing.add(key);
      return match;
    }
    return value;
  });
  return { text: filled, missing: [...missing].sort() };
}

/** True when every mandatory block for a document type has been reviewed by a lawyer. */
export function legalReviewComplete(document: LegalBlock['appearsIn'][number]): boolean {
  return mandatoryBlocksFor(document).every((block) => block.lawyerReviewedAt !== null);
}

/** The points a lawyer is specifically being asked to rule on, surfaced with the review request. */
export const LAWYER_REVIEW_POINTS = [
  'Whether the liability cap at fees paid is enforceable as drafted, and whether a higher cap is needed to satisfy the professional indemnity insurer or larger clients.',
  'The exclusion of third-party reliance in the report and attestation letter, which is the clause that matters most when a client forwards the report to an enterprise buyer.',
  'Whether the Data Processing Agreement wording meets the DPDP Act, 2023 and its rules, including breach notification timelines, purpose limitation, deletion obligations and processor duties.',
  'Whether the CERT-In incident reporting directions impose obligations on the firm as a service provider, including reporting timelines and log retention, and how that interacts with the deletion promise in the deletion confirmation.',
  'Whether a separate governing-law and dispute-resolution clause is required for non-Indian clients, and whether an arbitration clause is preferable.',
  'Whether the authorisation letter is sufficient as consent for the purposes of the Information Technology Act, 2000, and whether additional wording is advisable for assets located outside India.',
  "Whether the responsible disclosure policy's assurance against legal action is worded safely.",
  'The indemnity position where a client authorises testing of an asset it turns out not to own — the current draft relies on the client warranty in clause 4 of the authorisation.',
];
