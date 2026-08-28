import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { hash as argon2Hash, verify as argon2Verify } from '@node-rs/argon2';
import { TOTP, Secret } from 'otpauth';
import { and, eq, gt, isNull } from 'drizzle-orm';
import type { Database } from '../db/client.ts';
import { clientUser, session, staffUser } from '../db/schema.ts';

/**
 * Authentication.
 *
 * Multi-factor authentication is mandatory for both staff and client users. It is not a preference
 * and there is no bypass: a client account can see unfixed vulnerabilities in that client's
 * production systems, which makes it a more valuable target than most of the systems it describes.
 *
 * Session tokens are random, stored only as a hash, and rotated whenever the privilege attached to
 * the session changes.
 */

const SESSION_BYTES = 32;
const STAFF_SESSION_HOURS = 8;
const CLIENT_SESSION_HOURS = 12;

/**
 * `Algorithm.Argon2id` from @node-rs/argon2. It ships as an ambient const enum, which cannot be
 * imported under verbatimModuleSyntax, so the published value is named here instead.
 */
const ARGON2_ID = 2;

/** Argon2id parameters. Deliberately above the library defaults for a system holding this data. */

const ARGON2_OPTIONS = {
  algorithm: ARGON2_ID,
  memoryCost: 64 * 1024,
  timeCost: 3,
  parallelism: 4,
};

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function newSessionToken(): string {
  return randomBytes(SESSION_BYTES).toString('base64url');
}

export async function hashPassword(password: string): Promise<string> {
  if (password.length < 12) {
    throw new Error('passwords must be at least 12 characters');
  }
  return argon2Hash(password, ARGON2_OPTIONS);
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await argon2Verify(hash, password);
  } catch {
    return false;
  }
}

/**
 * Constant-time comparison for anything that is a secret but not a password: invitation tokens,
 * intake links, one-time codes.
 */
export function constantTimeEquals(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export interface TotpEnrolment {
  secretBase32: string;
  otpauthUrl: string;
}

export function beginTotpEnrolment(accountLabel: string, issuer = 'Attestor Security'): TotpEnrolment {
  const secret = new Secret({ size: 20 });
  const totp = new TOTP({ issuer, label: accountLabel, algorithm: 'SHA1', digits: 6, period: 30, secret });
  return { secretBase32: secret.base32, otpauthUrl: totp.toString() };
}

/**
 * Verify a TOTP code. A window of one step either side covers ordinary clock drift; anything wider
 * meaningfully extends how long a shoulder-surfed code stays usable.
 */
export function verifyTotp(secretBase32: string, code: string): boolean {
  const totp = new TOTP({
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(secretBase32),
  });
  return totp.validate({ token: code.replace(/\s/g, ''), window: 1 }) !== null;
}

export type SessionSubject =
  | { kind: 'staff'; staffUserId: string; role: string }
  | { kind: 'client'; clientUserId: string; clientId: string; role: string };

export interface CreatedSession {
  token: string;
  expiresAt: Date;
}

export async function createSession(
  database: Database,
  subject: SessionSubject,
  context: { ipAddress?: string; userAgent?: string; mfaSatisfied: boolean },
): Promise<CreatedSession> {
  const token = newSessionToken();
  const hours = subject.kind === 'staff' ? STAFF_SESSION_HOURS : CLIENT_SESSION_HOURS;
  const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000);

  await database.insert(session).values({
    staffUserId: subject.kind === 'staff' ? subject.staffUserId : null,
    clientUserId: subject.kind === 'client' ? subject.clientUserId : null,
    tokenHash: hashToken(token),
    ipAddress: context.ipAddress ?? null,
    userAgent: context.userAgent ?? null,
    mfaSatisfiedAt: context.mfaSatisfied ? new Date() : null,
    expiresAt,
  });

  return { token, expiresAt };
}

export interface ResolvedSession {
  sessionId: string;
  subject: SessionSubject;
  mfaSatisfied: boolean;
}

export async function resolveSession(
  database: Database,
  token: string,
): Promise<ResolvedSession | null> {
  const rows = await database
    .select()
    .from(session)
    .where(
      and(
        eq(session.tokenHash, hashToken(token)),
        isNull(session.revokedAt),
        gt(session.expiresAt, new Date()),
      ),
    )
    .limit(1);

  const row = rows[0];
  if (!row) return null;

  if (row.staffUserId) {
    const staff = await database
      .select()
      .from(staffUser)
      .where(and(eq(staffUser.id, row.staffUserId), eq(staffUser.active, true)))
      .limit(1);
    const user = staff[0];
    if (!user) return null;
    return {
      sessionId: row.id,
      mfaSatisfied: row.mfaSatisfiedAt !== null,
      subject: { kind: 'staff', staffUserId: user.id, role: user.role },
    };
  }

  if (row.clientUserId) {
    const clients = await database
      .select()
      .from(clientUser)
      .where(and(eq(clientUser.id, row.clientUserId), isNull(clientUser.deactivatedAt)))
      .limit(1);
    const user = clients[0];
    if (!user) return null;
    return {
      sessionId: row.id,
      mfaSatisfied: row.mfaSatisfiedAt !== null,
      subject: {
        kind: 'client',
        clientUserId: user.id,
        clientId: user.clientId,
        role: user.role,
      },
    };
  }

  return null;
}

export async function revokeSession(database: Database, sessionId: string): Promise<void> {
  await database.update(session).set({ revokedAt: new Date() }).where(eq(session.id, sessionId));
}

/**
 * Revoke every session for a user. Called on password change, on privilege change, and on
 * deactivation — in the same transaction as the change itself, so there is no window where the old
 * session still works.
 */
export async function revokeAllSessionsFor(
  database: Database,
  subject: { staffUserId?: string; clientUserId?: string },
): Promise<number> {
  const condition = subject.staffUserId
    ? eq(session.staffUserId, subject.staffUserId)
    : eq(session.clientUserId, subject.clientUserId ?? '');

  const revoked = await database
    .update(session)
    .set({ revokedAt: new Date() })
    .where(and(condition, isNull(session.revokedAt)))
    .returning({ id: session.id });

  return revoked.length;
}

/**
 * Login throttling that does not reveal whether an account exists.
 *
 * Failures are counted per address and per submitted identifier, and the response and its timing
 * are the same either way. The counter lives in Redis in production; this in-memory version is what
 * a single-process development setup uses.
 */
export class LoginThrottle {
  private readonly attempts = new Map<string, { count: number; firstAt: number }>();

  private readonly maxAttempts: number;
  private readonly windowMs: number;

  constructor(maxAttempts = 8, windowMs = 15 * 60 * 1000) {
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
  }

  /** Milliseconds the caller must wait, or zero when an attempt is allowed. */
  check(key: string, now = Date.now()): number {
    const entry = this.attempts.get(key);
    if (!entry) return 0;
    if (now - entry.firstAt > this.windowMs) {
      this.attempts.delete(key);
      return 0;
    }
    if (entry.count < this.maxAttempts) return 0;
    // Exponential backoff past the limit, capped so an account is never locked out permanently.
    const over = entry.count - this.maxAttempts;
    const delay = Math.min(15 * 60 * 1000, 1000 * 2 ** Math.min(over, 10));
    return Math.max(0, entry.firstAt + this.windowMs + delay - now);
  }

  recordFailure(key: string, now = Date.now()): void {
    const entry = this.attempts.get(key);
    if (!entry || now - entry.firstAt > this.windowMs) {
      this.attempts.set(key, { count: 1, firstAt: now });
      return;
    }
    entry.count += 1;
  }

  recordSuccess(key: string): void {
    this.attempts.delete(key);
  }
}
