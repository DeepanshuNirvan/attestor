/**
 * The kinds of login a client can hand over, and the fields each one needs.
 *
 * Every real application has authentication, so an assessment that cannot log in is an assessment
 * of a login page. This catalogue is what makes the intake form specific: the tester picks the kind
 * when they create the link, and the client sees only the two or three boxes that kind actually
 * needs rather than a general-purpose form they have to interpret.
 *
 * It lives in core because three places must agree on it — the console that requests a credential,
 * the page the client fills in, and the API that stores it. A fourth agreement, with the policy's
 * `authProfiles.type`, is recorded on each kind so a stored credential lines up with the profile
 * that will use it.
 */

import type { AuthProfile } from '@attestor/policy';

export interface CredentialField {
  name: string;
  label: string;
  /** `password` masks the input; `tel` and `email` get the right keyboard on a phone. */
  input: 'text' | 'password' | 'email' | 'tel' | 'textarea';
  /** Shown under the box. Say what you want and where they find it. */
  help: string;
  optional?: boolean;
  /**
   * Whether the value is a secret. Decides three things at once: the box is masked, the value is
   * registered with the redaction filter for the life of a run so it cannot reach a log or a piece
   * of evidence, and it reaches a tool through the container's environment rather than its command
   * line. Stated rather than guessed from the field name — a rule that reads names is a rule that
   * silently stops covering a field somebody renames.
   */
  secret?: boolean;
}

export interface CredentialKind {
  id: string;
  label: string;
  /** One line, shown to the tester when choosing, and to the client at the top of the form. */
  description: string;
  /** The policy `authProfiles.type` a credential of this kind satisfies. */
  authProfileType: AuthProfile['type'];
  fields: CredentialField[];
}

const PASSWORD_HELP =
  'Use a password set for this test account, not one anybody uses elsewhere. Change it back when the test is over.';

export const CREDENTIAL_KINDS: readonly CredentialKind[] = [
  {
    id: 'emailPassword',
    label: 'Email and password',
    description: 'The ordinary sign-in form, where the username is an email address.',
    authProfileType: 'formLogin',
    fields: [
      {
        name: 'email',
        label: 'Email address',
        input: 'email',
        help: 'The test account. Not a real customer, and not your own admin account.',
      },
      { name: 'password', label: 'Password', input: 'password', secret: true, help: PASSWORD_HELP },
    ],
  },
  {
    id: 'usernamePassword',
    label: 'Username and password',
    description: 'A sign-in form where the username is not an email address.',
    authProfileType: 'formLogin',
    fields: [
      { name: 'username', label: 'Username', input: 'text', help: 'The test account.' },
      { name: 'password', label: 'Password', input: 'password', secret: true, help: PASSWORD_HELP },
    ],
  },
  {
    id: 'mobileOtp',
    label: 'Mobile number, with a code',
    description: 'Sign-in by mobile number and a one-time code.',
    authProfileType: 'otpAssisted',
    fields: [
      {
        name: 'mobile',
        label: 'Mobile number',
        input: 'tel',
        help: 'With the country code, for example +91 90000 00000.',
      },
      {
        name: 'password',
        label: 'Password or PIN',
        input: 'password',
        secret: true,
        optional: true,
        help: 'Only if the account has one as well as the code.',
      },
      {
        name: 'totpSecret',
        label: 'Authenticator secret',
        input: 'password',
        secret: true,
        optional: true,
        help: 'If the code comes from an authenticator app, paste the setup key here — it is the long code shown beside the QR image, and it lets us generate codes ourselves. Leave it empty if the code arrives by SMS.',
      },
      {
        name: 'otpDelivery',
        label: 'How does the code reach you?',
        input: 'text',
        optional: true,
        help: 'For example "SMS to the number above" or "our operations phone". If it comes by SMS we will call you during the test to read it out, because nobody can automate your phone.',
      },
    ],
  },
  {
    id: 'oauth2',
    label: 'Sign in with Google, Microsoft or similar',
    description: 'Single sign-on through an external identity provider.',
    authProfileType: 'oauth2',
    fields: [
      {
        name: 'provider',
        label: 'Which provider',
        input: 'text',
        help: 'For example Google, Microsoft Entra, Okta, or your own.',
      },
      {
        name: 'username',
        label: 'Test account at that provider',
        input: 'text',
        help: 'The account we sign in as.',
      },
      { name: 'password', label: 'Its password', input: 'password', secret: true, help: PASSWORD_HELP },
      {
        name: 'totpSecret',
        label: 'Authenticator secret for that account',
        input: 'password',
        secret: true,
        optional: true,
        help: 'If the provider asks for a second factor, paste the setup key so we can generate codes.',
      },
      {
        name: 'notes',
        label: 'Anything else we need',
        input: 'textarea',
        optional: true,
        help: 'For example a tenant name, a domain to pick, or an extra prompt the login shows.',
      },
    ],
  },
  {
    id: 'apiKey',
    label: 'API key',
    description: 'A key sent in a header, for an API rather than a browser.',
    authProfileType: 'apiKey',
    fields: [
      {
        name: 'headerName',
        label: 'Header name',
        input: 'text',
        help: 'For example X-API-Key. If you are not sure, your API documentation will say.',
      },
      { name: 'value', label: 'The key', input: 'password', secret: true, help: 'A key issued for this test.' },
    ],
  },
  {
    id: 'bearerToken',
    label: 'Bearer token',
    description: 'A token sent as `Authorization: Bearer …`.',
    authProfileType: 'bearerJwt',
    fields: [
      { name: 'token', label: 'The token', input: 'textarea', secret: true, help: 'Paste the whole token.' },
      {
        name: 'refreshNotes',
        label: 'How long does it last?',
        input: 'text',
        optional: true,
        help: 'If it expires during the test we will need a way to get a new one.',
      },
    ],
  },
  {
    id: 'sessionCookie',
    label: 'Session cookie',
    description: 'A cookie captured from a signed-in browser. The last resort, because it expires.',
    authProfileType: 'sessionCookie',
    fields: [
      { name: 'cookieName', label: 'Cookie name', input: 'text', help: 'For example session_id.' },
      { name: 'value', label: 'Cookie value', input: 'password', secret: true, help: 'The value, without the name.' },
      {
        name: 'expiresNotes',
        label: 'When does it expire?',
        input: 'text',
        optional: true,
        help: 'So we know how long we have.',
      },
    ],
  },
];

const BY_ID = new Map(CREDENTIAL_KINDS.map((kind) => [kind.id, kind]));

export const CREDENTIAL_KIND_IDS = CREDENTIAL_KINDS.map((kind) => kind.id);

export function credentialKind(id: string): CredentialKind | undefined {
  return BY_ID.get(id);
}

/**
 * Check a submitted set of values against the kind that was asked for.
 *
 * Returns the problems, one per field, in the client's language. An empty array means it is good.
 * Unknown fields are refused rather than dropped: a form that silently ignores what somebody typed
 * is a form that loses a credential and gives no sign of it.
 */
export function validateCredentialValues(
  kindId: string,
  values: Record<string, string>,
): string[] {
  const kind = BY_ID.get(kindId);
  if (!kind) return [`"${kindId}" is not a kind of login this form knows about.`];

  const problems: string[] = [];
  const known = new Set(kind.fields.map((field) => field.name));

  for (const field of kind.fields) {
    const value = values[field.name]?.trim() ?? '';
    if (value === '' && !field.optional) problems.push(`${field.label} is needed.`);
  }

  for (const name of Object.keys(values)) {
    if (!known.has(name)) problems.push(`"${name}" is not a field on this form.`);
  }

  return problems;
}
