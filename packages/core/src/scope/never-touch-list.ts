/**
 * The global never-touch list.
 *
 * Nothing on this list can be targeted, regardless of what an authorisation says, because a signed
 * authorisation from a client does not make it lawful to test somebody else's infrastructure. If a
 * client genuinely owns something on this list, the entry is removed here by the owner in a commit
 * with a reason — deliberately a code change and a review, not a console setting.
 */

export interface NeverTouchEntry {
  pattern: string;
  reason: string;
}

export const NEVER_TOUCH_HOSTS: NeverTouchEntry[] = [
  // Indian government and regulators
  { pattern: '*.gov.in', reason: 'Indian government. Testing requires CERT-In empanelment and a government engagement.' },
  { pattern: '*.nic.in', reason: 'National Informatics Centre infrastructure.' },
  { pattern: '*.rbi.org.in', reason: 'Reserve Bank of India.' },
  { pattern: '*.sebi.gov.in', reason: 'Securities and Exchange Board of India.' },
  { pattern: '*.irdai.gov.in', reason: 'Insurance Regulatory and Development Authority.' },
  { pattern: '*.uidai.gov.in', reason: 'UIDAI. Aadhaar-linked systems are out of bounds.' },
  { pattern: '*.npci.org.in', reason: 'National Payments Corporation of India.' },
  { pattern: '*.cert-in.org.in', reason: 'CERT-In.' },
  { pattern: '*.mygov.in', reason: 'Indian government platform.' },
  { pattern: '*.nseindia.com', reason: 'National Stock Exchange.' },
  { pattern: '*.bseindia.com', reason: 'Bombay Stock Exchange.' },

  // Foreign government
  { pattern: '*.gov', reason: 'United States government.' },
  { pattern: '*.mil', reason: 'United States military.' },
  { pattern: '*.gov.uk', reason: 'United Kingdom government.' },
  { pattern: '*.europa.eu', reason: 'European Union institutions.' },
  { pattern: '*.gov.au', reason: 'Australian government.' },
  { pattern: '*.gc.ca', reason: 'Government of Canada.' },
  { pattern: '*.gov.sg', reason: 'Government of Singapore.' },
  { pattern: '*.gov.ae', reason: 'Government of the United Arab Emirates.' },

  // Cloud and platform control planes. A client owns their account, not the provider's API.
  { pattern: '*.amazonaws.com', reason: "AWS service endpoints belong to AWS. Test the client's resources by their own names." },
  { pattern: '*.azure.com', reason: 'Azure control plane.' },
  { pattern: '*.windows.net', reason: 'Azure service endpoints.' },
  { pattern: '*.googleapis.com', reason: 'Google Cloud control plane.' },
  { pattern: '*.cloudflare.com', reason: 'Cloudflare control plane.' },
  { pattern: '*.akamai.net', reason: 'Akamai edge infrastructure.' },
  { pattern: '*.fastly.net', reason: 'Fastly edge infrastructure.' },

  // Identity, payment and communication providers. Shared infrastructure, never in a client's gift.
  { pattern: '*.okta.com', reason: 'Okta tenant infrastructure is shared and not the client to authorise.' },
  { pattern: '*.auth0.com', reason: 'Auth0 shared infrastructure.' },
  { pattern: '*.stripe.com', reason: 'Stripe. Card infrastructure, never in scope.' },
  { pattern: '*.razorpay.com', reason: 'Razorpay. Payment infrastructure.' },
  { pattern: '*.payu.in', reason: 'PayU. Payment infrastructure.' },
  { pattern: '*.paypal.com', reason: 'PayPal. Payment infrastructure.' },
  { pattern: '*.twilio.com', reason: 'Twilio shared infrastructure.' },
  { pattern: '*.sendgrid.net', reason: 'SendGrid shared infrastructure.' },

  // Our own infrastructure. Testing it during a client engagement would put client data at risk and
  // would not be covered by that client's authorisation.
  { pattern: 'attestorsecurity.com', reason: "Attestor's own infrastructure." },
  { pattern: '*.attestorsecurity.com', reason: "Attestor's own infrastructure." },
];

/**
 * IP ranges that are never targets, on top of the reserved ranges in `ip.ts`. The owner adds any
 * range they are told to avoid here, with the reason.
 */
export const NEVER_TOUCH_CIDRS: NeverTouchEntry[] = [
  // Populated by the owner as engagements reveal ranges to avoid. Kept as a list rather than an
  // empty array so the shape and the reason requirement are obvious at the first addition.
];
