import { describe, expect, it } from 'vitest';
import {
  CREDENTIAL_KINDS,
  credentialKind,
  validateCredentialValues,
} from './credential-kinds.ts';

/**
 * The catalogue is what a client sees, so its shape is worth pinning: every kind must be usable
 * from a form, and every kind must name an auth profile type the policy actually has.
 */

describe('the credential catalogue', () => {
  it('covers the ways real applications are signed into', () => {
    const ids = CREDENTIAL_KINDS.map((kind) => kind.id);
    for (const expected of [
      'emailPassword',
      'usernamePassword',
      'mobileOtp',
      'oauth2',
      'apiKey',
      'bearerToken',
      'sessionCookie',
    ]) {
      expect(ids, `no way to hand over a ${expected} login`).toContain(expected);
    }
  });

  it('gives every kind a unique id and at least one required field', () => {
    const ids = CREDENTIAL_KINDS.map((kind) => kind.id);
    expect(new Set(ids).size).toBe(ids.length);

    for (const kind of CREDENTIAL_KINDS) {
      expect(kind.fields.length, kind.id).toBeGreaterThan(0);
      expect(
        kind.fields.some((field) => !field.optional),
        `${kind.id} has nothing the client must fill in`,
      ).toBe(true);
    }
  });

  it('writes help for every field, because this is the page a client gives up on', () => {
    for (const kind of CREDENTIAL_KINDS) {
      expect(kind.description.length, kind.id).toBeGreaterThan(10);
      for (const field of kind.fields) {
        expect(field.help.length, `${kind.id}.${field.name}`).toBeGreaterThan(10);
      }
    }
  });

  it('never renders a secret as plain visible text', () => {
    // `password` for anything short. A bearer token is a secret too, but it is hundreds of
    // characters and a client pasting one into a masked single-line box cannot tell whether the
    // paste worked — so a textarea is allowed for those, and plain `text` is allowed for neither.
    for (const kind of CREDENTIAL_KINDS) {
      for (const field of kind.fields) {
        if (!field.secret) continue;
        expect(
          ['password', 'textarea'],
          `${kind.id}.${field.name} is a secret rendered as ${field.input}`,
        ).toContain(field.input);
      }
    }
  });

  it('marks as secret everything that reads like one', () => {
    // The flag is what the runner acts on: an unmarked secret reaches a tool on its command line
    // and lands in the audit log, because that is where an unmarked field is put. The name check
    // is not the rule — it is a net under the rule, so a new kind cannot forget to set it.
    for (const kind of CREDENTIAL_KINDS) {
      for (const field of kind.fields) {
        if (!/password|secret|^value$|^token$/i.test(field.name)) continue;
        expect(field.secret, `${kind.id}.${field.name} is not marked secret`).toBe(true);
      }
    }
  });
});

describe('validating what a client submitted', () => {
  it('accepts a complete submission', () => {
    expect(
      validateCredentialValues('emailPassword', {
        email: 'test.user@acme.example',
        password: 'a-password-for-this-test',
      }),
    ).toEqual([]);
  });

  it('names the missing box in the client’s words, not a field name', () => {
    const problems = validateCredentialValues('emailPassword', { email: 'test@acme.example' });
    expect(problems).toEqual(['Password is needed.']);
  });

  it('lets an optional field be left out', () => {
    expect(validateCredentialValues('mobileOtp', { mobile: '+91 90000 00000' })).toEqual([]);
  });

  it('refuses a field the form never offered rather than dropping it silently', () => {
    const problems = validateCredentialValues('emailPassword', {
      email: 'test@acme.example',
      password: 'a-password-for-this-test',
      recoveryAnswer: 'smuggled',
    });
    expect(problems).toEqual(['"recoveryAnswer" is not a field on this form.']);
  });

  it('refuses a kind it does not know', () => {
    expect(validateCredentialValues('carrierPigeon', {})).toHaveLength(1);
  });

  it('treats whitespace as empty, so a stray space is not a password', () => {
    expect(validateCredentialValues('emailPassword', { email: 'a@b.example', password: '   ' })).toEqual(
      ['Password is needed.'],
    );
  });
});

describe('lookup', () => {
  it('finds a kind by id and returns nothing for one that does not exist', () => {
    expect(credentialKind('emailPassword')?.label).toBe('Email and password');
    expect(credentialKind('nope')).toBeUndefined();
  });
});
