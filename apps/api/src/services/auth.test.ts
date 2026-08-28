import { describe, expect, it } from 'vitest';
import { Secret, TOTP } from 'otpauth';
import {
  beginTotpEnrolment,
  constantTimeEquals,
  hashPassword,
  hashToken,
  LoginThrottle,
  newSessionToken,
  verifyPassword,
  verifyTotp,
} from './auth.ts';

describe('passwords', () => {
  it('hashes and verifies with argon2id', async () => {
    const hash = await hashPassword('a-long-enough-password');
    expect(hash.startsWith('$argon2id$')).toBe(true);
    expect(await verifyPassword(hash, 'a-long-enough-password')).toBe(true);
    expect(await verifyPassword(hash, 'a-long-enough-passwore')).toBe(false);
  });

  it('refuses a password too short to be worth hashing', async () => {
    await expect(hashPassword('short')).rejects.toThrow(/at least 12/);
  });

  it('returns false rather than throwing on a malformed hash', async () => {
    expect(await verifyPassword('not-a-hash', 'anything')).toBe(false);
  });
});

describe('session tokens', () => {
  it('are unpredictable and stored only as a hash', () => {
    const tokens = new Set(Array.from({ length: 500 }, () => newSessionToken()));
    expect(tokens.size).toBe(500);

    const token = newSessionToken();
    const hash = hashToken(token);
    expect(hash).toHaveLength(64);
    expect(hash).not.toContain(token);
    expect(hashToken(token)).toBe(hash);
  });
});

describe('constantTimeEquals', () => {
  it('compares equal and unequal values without throwing on length mismatch', () => {
    expect(constantTimeEquals('abc123', 'abc123')).toBe(true);
    expect(constantTimeEquals('abc123', 'abc124')).toBe(false);
    expect(constantTimeEquals('abc', 'abcdef')).toBe(false);
  });
});

describe('TOTP', () => {
  it('enrols and verifies a code', () => {
    const enrolment = beginTotpEnrolment('tester@attestorsecurity.com');
    expect(enrolment.otpauthUrl).toContain('otpauth://totp/');
    expect(enrolment.secretBase32.length).toBeGreaterThan(20);

    // Derive the current code the same way an authenticator app would.
    const totp = new TOTP({ secret: Secret.fromBase32(enrolment.secretBase32) });
    expect(verifyTotp(enrolment.secretBase32, totp.generate())).toBe(true);
    expect(verifyTotp(enrolment.secretBase32, '000000')).toBe(false);
  });

  it('tolerates spaces in a pasted code', () => {
    const enrolment = beginTotpEnrolment('tester@attestorsecurity.com');
    const totp = new TOTP({ secret: Secret.fromBase32(enrolment.secretBase32) });
    const code = totp.generate();
    expect(verifyTotp(enrolment.secretBase32, `${code.slice(0, 3)} ${code.slice(3)}`)).toBe(true);
  });
});

describe('LoginThrottle', () => {
  it('allows attempts up to the limit and then delays', () => {
    const throttle = new LoginThrottle(3, 60_000);
    const now = 1_000_000;

    expect(throttle.check('a@b.com', now)).toBe(0);
    throttle.recordFailure('a@b.com', now);
    throttle.recordFailure('a@b.com', now);
    expect(throttle.check('a@b.com', now)).toBe(0);
    throttle.recordFailure('a@b.com', now);
    expect(throttle.check('a@b.com', now)).toBeGreaterThan(0);
  });

  it('clears on success', () => {
    const throttle = new LoginThrottle(2, 60_000);
    const now = 1_000_000;
    throttle.recordFailure('a@b.com', now);
    throttle.recordFailure('a@b.com', now);
    expect(throttle.check('a@b.com', now)).toBeGreaterThan(0);
    throttle.recordSuccess('a@b.com');
    expect(throttle.check('a@b.com', now)).toBe(0);
  });

  it('forgets after the window, so nobody is locked out permanently', () => {
    const throttle = new LoginThrottle(1, 60_000);
    const now = 1_000_000;
    throttle.recordFailure('a@b.com', now);
    expect(throttle.check('a@b.com', now)).toBeGreaterThan(0);
    expect(throttle.check('a@b.com', now + 300_000)).toBe(0);
  });

  it('tracks keys independently, so one address cannot lock out another', () => {
    const throttle = new LoginThrottle(1, 60_000);
    const now = 1_000_000;
    throttle.recordFailure('attacker-key', now);
    expect(throttle.check('victim-key', now)).toBe(0);
  });
});
