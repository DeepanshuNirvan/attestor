import { and, eq, isNotNull, isNull, sql } from 'drizzle-orm';
import { credentialKind, validateCredentialValues } from '@attestor/core';
import type { Database } from '../db/client.ts';
import {
  client as clientTable,
  credentialIntakeLink,
  credentialSet,
  engagement as engagementTable,
} from '../db/schema.ts';
import type { CredentialVault } from './credential-vault.ts';
import { hashToken } from './auth.ts';

/**
 * Taking a credential from a client.
 *
 * The client opens a one-time link, sees the two or three boxes the login actually needs, and
 * submits. The value is sealed here and stored; there is no column that holds it in the clear and no
 * route anywhere returns it.
 *
 * Sealing lives in this service rather than in the route because a route that can open the vault is
 * a route that can put a client's password on somebody's screen — a rule the console's structural
 * test enforces by refusing any `vault.open`/`vault.seal` in a route file.
 *
 * The page is served by the portal, which is the only surface a client can reach, but the
 * submission goes to the console API. That is deliberate: the console holds the vault key, and the
 * portal is the service exposed to the internet. The portal never touches the credential tables.
 */

export interface RequestedCredential {
  /** Stable id for this account within the link. A resubmission replaces it rather than adding. */
  slot: string;
  label: string;
  roleName: string;
  /** A `CREDENTIAL_KINDS` id. Decides which boxes the client is shown. */
  kind: string;
  isSecondary: boolean;
}

export interface IntakeLink {
  id: string;
  engagementId: string;
  requested: RequestedCredential[];
  expiresAt: Date;
  usedAt: Date | null;
}

export type IntakeRefusal =
  | { ok: false; reason: 'notFound' }
  | { ok: false; reason: 'expired' };

/**
 * Resolve a token to its link.
 *
 * A missing token and an expired one are told apart, because "this link has expired, ask for
 * another" is something a client can act on, while "not found" for an expired link sends them back
 * to their inbox looking for a typo. Neither reveals anything to somebody guessing tokens: a wrong
 * token is `notFound` whatever the reason.
 */
export async function resolveIntakeLink(
  database: Database,
  token: string,
  now = new Date(),
): Promise<{ ok: true; link: IntakeLink } | IntakeRefusal> {
  const rows = await database
    .select()
    .from(credentialIntakeLink)
    .where(eq(credentialIntakeLink.tokenHash, hashToken(token)))
    .limit(1);

  const row = rows[0];
  if (!row) return { ok: false, reason: 'notFound' };
  if (row.expiresAt <= now) return { ok: false, reason: 'expired' };

  return {
    ok: true,
    link: {
      id: row.id,
      engagementId: row.engagementId,
      requested: row.requested as RequestedCredential[],
      expiresAt: row.expiresAt,
      usedAt: row.usedAt,
    },
  };
}

export interface IntakeContext {
  engagementReference: string;
  engagementTitle: string;
  clientName: string;
  /** Slots already filled, so the form can say so rather than asking twice. */
  filledSlots: string[];
}

/** What the client's page needs to render. Carries no credential and no engagement internals. */
export async function intakeContextFor(
  database: Database,
  link: IntakeLink,
): Promise<IntakeContext | null> {
  const rows = await database
    .select({
      reference: engagementTable.reference,
      title: engagementTable.title,
      clientName: clientTable.name,
    })
    .from(engagementTable)
    .innerJoin(clientTable, eq(clientTable.id, engagementTable.clientId))
    .where(eq(engagementTable.id, link.engagementId))
    .limit(1);

  const row = rows[0];
  if (!row) return null;

  const filled = await database
    .select({ slot: credentialSet.intakeSlot })
    .from(credentialSet)
    .where(
      and(eq(credentialSet.engagementId, link.engagementId), isNull(credentialSet.revokedAt)),
    );

  return {
    engagementReference: row.reference,
    engagementTitle: row.title,
    clientName: row.clientName,
    filledSlots: filled
      .map((entry) => entry.slot)
      .filter((slot): slot is string => slot !== null),
  };
}

export interface SubmitInput {
  link: IntakeLink;
  slot: string;
  /** Field name to value, as the kind defines them. */
  values: Record<string, string>;
  vault: CredentialVault;
  now?: Date;
}

export type SubmitOutcome =
  | { ok: true; credentialSetId: string; label: string }
  | { ok: false; problems: string[] };

/**
 * Store one submitted credential.
 *
 * The whole set of values is sealed as one JSON document rather than a column per field, because
 * the fields differ per kind and a schema that grows a column every time a new login type appears
 * is a schema that eventually holds a plaintext one by accident.
 */
export async function submitCredential(
  database: Database,
  input: SubmitInput,
): Promise<SubmitOutcome> {
  const now = input.now ?? new Date();
  const requested = input.link.requested.find((entry) => entry.slot === input.slot);
  if (!requested) {
    return { ok: false, problems: ['That form is not one this link is asking for.'] };
  }

  const kind = credentialKind(requested.kind);
  if (!kind) {
    return { ok: false, problems: ['This link asks for a kind of login the system no longer has.'] };
  }

  const problems = validateCredentialValues(requested.kind, input.values);
  if (problems.length > 0) return { ok: false, problems };

  const sealed = await input.vault.seal(
    input.link.engagementId,
    JSON.stringify({ kind: requested.kind, values: input.values }),
  );

  // Credentials outlive the link but not the engagement. Ninety days matches the default evidence
  // retention; closing the engagement destroys the key salt before then and makes this unreadable
  // whatever the date says.
  const expiresAt = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);

  const [stored] = await database
    .insert(credentialSet)
    .values({
      engagementId: input.link.engagementId,
      label: requested.label,
      roleName: requested.roleName,
      authType: kind.authProfileType,
      sealedValue: sealed.sealedValue,
      keySalt: sealed.keySalt,
      nonce: sealed.nonce,
      isSecondary: requested.isSecondary,
      intakeSlot: requested.slot,
      expiresAt,
    })
    .onConflictDoUpdate({
      target: [credentialSet.engagementId, credentialSet.intakeSlot],
      // The index is partial, so the inference has to repeat its predicate. Without this Postgres
      // matches no index and refuses the whole statement rather than falling back to an insert.
      targetWhere: isNotNull(credentialSet.intakeSlot),
      set: {
        label: requested.label,
        roleName: requested.roleName,
        authType: kind.authProfileType,
        sealedValue: sealed.sealedValue,
        keySalt: sealed.keySalt,
        nonce: sealed.nonce,
        isSecondary: requested.isSecondary,
        expiresAt,
        // A replacement has not been checked either, so it goes back to unverified.
        lastVerifiedAt: null,
        verificationError: null,
        revokedAt: null,
      },
    })
    .returning({ id: credentialSet.id });

  await database
    .update(credentialIntakeLink)
    .set({ usedAt: sql`coalesce(${credentialIntakeLink.usedAt}, ${now})` })
    .where(eq(credentialIntakeLink.id, input.link.id));

  return { ok: true, credentialSetId: stored?.id ?? '', label: requested.label };
}
