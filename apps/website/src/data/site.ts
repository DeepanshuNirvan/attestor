/**
 * Everything the owner edits about the firm itself. One file, no CMS.
 *
 * Fields marked `awaitingOwner` render a visible draft notice on the site until they are filled.
 * Nothing here may claim a certification, empanelment, client or metric the firm does not hold —
 * `pnpm check:claims` fails the build if a banned claim string appears anywhere in the repo.
 */

export const site = {
  brandName: 'Attestor Security',
  wordmark: 'Attestor',
  origin: 'https://attestorsecurity.com',
  portalOrigin: 'https://portal.attestorsecurity.com',
  tagline: 'Independent security assessment. Fixed price, fixed dates, evidence you can forward.',
  description:
    'Attestor Security runs web, API, cloud, mobile and LLM security assessments for companies that have to prove their security to a buyer, an auditor or an insurer.',

  contactEmail: 'hello@attestorsecurity.com',
  securityContactEmail: 'security@attestorsecurity.com',
  bookingUrl: 'https://cal.com/attestor/scoping-call',
  formEndpoint: '/api/enquiry',

  /** Overlap advertised to international buyers. Stated as hours, never as a location. */
  overlapHours: {
    usEastern: '07:30–11:30 ET, Monday to Friday',
    unitedKingdom: '12:30–18:00 UK, Monday to Friday',
  },

  /** Set once the policy is bought. Until then the About page says cover is being arranged. */
  professionalIndemnity: {
    awaitingOwner: true,
    coverAmount: '',
    insurer: '',
  },

  /** Set once the company is registered. Until then legal pages carry a draft notice. */
  legalEntity: {
    awaitingOwner: true,
    name: '',
    jurisdiction: '',
    registeredAddress: '',
    country: 'India',
  },

  founder: {
    awaitingOwner: true,
    name: '',
    credentials: [] as string[],
    publications: [] as { title: string; url: string }[],
  },

  evidenceRetentionDays: 90,
  freeRetestWindowDays: 30,

  methodology: [
    { id: 'wstg', name: 'OWASP Web Security Testing Guide', version: '4.2' },
    { id: 'asvs', name: 'OWASP Application Security Verification Standard', version: '5.0' },
    { id: 'top10', name: 'OWASP Top 10', version: '2025' },
    { id: 'api-top10', name: 'OWASP API Security Top 10', version: '2023' },
    { id: 'masvs', name: 'OWASP MASVS', version: '2.1' },
    { id: 'llm-top10', name: 'OWASP Top 10 for LLM Applications', version: '2025' },
    { id: 'sp800-115', name: 'NIST SP 800-115', version: '' },
    { id: 'ptes', name: 'PTES', version: '' },
  ],
} as const;

export type Site = typeof site;
