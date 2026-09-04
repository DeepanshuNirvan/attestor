import { and, desc, eq, gt, isNull } from 'drizzle-orm';
import { credentialKind } from '@attestor/core';
import type { Policy } from '@attestor/policy';
import type { AccessIdentity } from '@attestor/core';
import type { RunCredential } from '@attestor/scanners';
import type { Database } from '../db/client.ts';
import { credentialSet } from '../db/schema.ts';
import type { CredentialVault } from './credential-vault.ts';

/**
 * Turning stored credentials into something a tool can use.
 *
 * This is the only place a client credential is opened, and it is called from the worker rather
 * than from a request handler — the console API can seal a credential and never unseal one, so
 * there is no route anywhere that can put a client's password on a screen.
 *
 * What comes out is deliberately two things rather than one:
 *
 *   - `credentials`, which an adapter sees. Secret fields on it are `${ENV_NAME}` references, so an
 *     adapter and everything it produces — a plan file, a command line, an audit record — can be
 *     stored and read without exposing anything.
 *   - `secrets`, which only the runner sees. It puts them in the container's environment and
 *     registers each value with the redaction filter for the life of the run, so a secret that
 *     comes back in tool output is scrubbed before it reaches evidence.
 *
 * The join to the policy is by role rather than by id where it can be. A tester who has just been
 * handed three accounts should not have to paste three uuids into a YAML file to use them, and an
 * explicit `credentialSetId` still wins when one is set.
 */

export interface RunCredentials {
  credentials: RunCredential[];
  /** Environment variable name to secret value. Never logged, never persisted. */
  secrets: Record<string, string>;
  /** Roles the policy wants to test authenticated and has no usable credential for. */
  warnings: string[];
}


/** `ATTESTOR_CRED_1_PASSWORD`. Uppercase, and anything else becomes an underscore. */
function environmentName(index: number, field: string): string {
  return `ATTESTOR_CRED_${index}_${field.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`;
}

interface StoredCredential {
  id: string;
  roleName: string;
  isSecondary: boolean;
  sealedValue: string;
  keySalt: string;
  nonce: string;
}

export async function openRunCredentials(
  database: Database,
  vault: CredentialVault,
  engagementId: string,
  policy: Policy,
  now = new Date(),
): Promise<RunCredentials> {
  const profiles = policy.authProfiles.filter((profile) => profile.type !== 'none');

  // Revoked, shredded and expired rows are excluded here rather than filtered later: a credential
  // the client has withdrawn must not reach a tool, and a shredded one cannot be opened at all.
  const rows: StoredCredential[] = await database
    .select({
      id: credentialSet.id,
      roleName: credentialSet.roleName,
      isSecondary: credentialSet.isSecondary,
      sealedValue: credentialSet.sealedValue,
      keySalt: credentialSet.keySalt,
      nonce: credentialSet.nonce,
    })
    .from(credentialSet)
    .where(
      and(
        eq(credentialSet.engagementId, engagementId),
        isNull(credentialSet.revokedAt),
        isNull(credentialSet.shreddedAt),
        gt(credentialSet.expiresAt, now),
      ),
    )
    // Newest first. A second intake link for the same role creates a second row rather than
    // replacing the first, so ordering the other way meant a client who was asked again — because
    // the first account was wrong, or expired, or the wrong environment — would go on being tested
    // with the account they had already replaced, and the run would report a login failure for a
    // password nobody was using any more.
    .orderBy(desc(credentialSet.createdAt));

  const credentials: RunCredential[] = [];
  const secrets: Record<string, string> = {};
  const warnings: string[] = [];
  const used = new Set<string>();

  // The silent failure this whole function exists to prevent. A client who has handed over test
  // accounts has been asked to do real work and reasonably expects them to be used; a policy with
  // no auth profile means every one of those accounts sits in the vault while the scan browses as
  // a stranger, and the report then describes a login page. Saying so is the difference between a
  // configuration mistake and a worthless engagement nobody noticed.
  if (profiles.length === 0) {
    if (rows.length > 0) {
      warnings.push(
        `This engagement holds ${rows.length} credential(s) and the policy has no authentication ` +
          'profile, so none of them will be used. Add an authProfiles entry whose roleName matches ' +
          'the role the account was submitted for.',
      );
    }
    return { credentials, secrets, warnings };
  }

  const pick = (id: string | undefined, roleName: string, secondary: boolean) => {
    if (id !== undefined) return rows.find((row) => row.id === id);
    return rows.find(
      (row) => row.roleName === roleName && row.isSecondary === secondary && !used.has(row.id),
    );
  };

  for (const profile of profiles) {
    for (const [wanted, secondary] of [
      [profile.credentialSetId, false],
      [profile.secondaryCredentialSetId, true],
    ] as const) {
      // Only look for a second account when the policy asks to test access control with one.
      if (secondary && !policy.accessControlMatrix.enabled && wanted === undefined) continue;

      const row = pick(wanted, profile.roleName, secondary);
      if (!row) {
        if (!secondary) {
          warnings.push(
            `Auth profile "${profile.id}" (role ${profile.roleName}) has no usable credential. ` +
              'Its checks will run unauthenticated.',
          );
        }
        continue;
      }
      used.add(row.id);

      const opened = JSON.parse(
        await vault.open(engagementId, {
          sealedValue: row.sealedValue,
          keySalt: row.keySalt,
          nonce: row.nonce,
        }),
      ) as { kind: string; values: Record<string, string> };

      const kind = credentialKind(opened.kind);
      if (!kind) {
        warnings.push(
          `Credential "${row.id}" was submitted as a kind of login this build no longer has ` +
            `("${opened.kind}"). It cannot be used.`,
        );
        continue;
      }

      // The profile says how the application authenticates; the kind says what the client actually
      // handed over. When they disagree the run is not what anybody thinks it is — a policy that
      // says `formLogin` against an account whose only secret is an authenticator seed produces a
      // scan that quietly never signs in.
      if (kind.authProfileType !== profile.type) {
        warnings.push(
          `Auth profile "${profile.id}" is ${profile.type}, but the credential submitted for role ` +
            `${profile.roleName} is a ${kind.label.toLowerCase()} (${kind.authProfileType}). ` +
            'Change one of them so they agree.',
        );
      }

      const index = credentials.length + 1;
      const fields: Record<string, string> = {};
      const secretRefs: Record<string, string> = {};

      for (const field of kind.fields) {
        const value = opened.values[field.name];
        if (value === undefined || value === '') continue;
        if (field.secret) {
          const name = environmentName(index, field.name);
          secrets[name] = value;
          secretRefs[field.name] = `\${${name}}`;
        } else {
          fields[field.name] = value;
        }
      }

      credentials.push({
        credentialSetId: row.id,
        profileId: profile.id,
        roleName: profile.roleName,
        // The credential's own kind, not the profile's declaration. A tool decides whether to
        // perform a login or present a token from what it actually has.
        authType: kind.authProfileType,
        isSecondary: secondary,
        loginUrl: profile.loginUrl,
        sessionIndicator: profile.sessionIndicator,
        sessionCheckEveryRequests: profile.sessionCheckEveryRequests,
        fields,
        secretRefs,
      });
    }
  }

  return { credentials, secrets, warnings };
}

/**
 * Turn resolved credentials into identities the access control matrix can replay as.
 *
 * The point of this function is that it does not care how the application authenticates. An API key
 * goes in whatever header the client named; a bearer token goes in `Authorization`; a session
 * cookie goes in `Cookie`; a username and password is exchanged for a session first. All four come
 * out the same shape — a set of headers — which is why the replay engine needs no knowledge of the
 * scheme and works on a JWT API and a server-rendered application without being told which it is.
 *
 * A credential with no way to become a session is left out **with a reason**, never guessed at. The
 * reason reaches the run's stats, so "we compared two accounts" and "we could only sign one of them
 * in" are different sentences in front of the tester.
 */
export function accessIdentitiesFrom(
  resolved: RunCredentials,
  policy: Policy,
): { identities: AccessIdentity[]; withoutSession: { name: string; reason: string }[] } {
  const identities: AccessIdentity[] = [];
  const withoutSession: { name: string; reason: string }[] = [];

  /** `${ATTESTOR_CRED_1_PASSWORD}` back to the value the client submitted. */
  const secretFor = (reference: string | undefined): string | undefined => {
    if (reference === undefined) return undefined;
    const name = /^\$\{(.+)\}$/.exec(reference)?.[1];
    return name === undefined ? undefined : resolved.secrets[name];
  };

  for (const credential of resolved.credentials) {
    const name = `${credential.roleName}${credential.isSecondary ? ' (second account)' : ''}`;
    const profile = policy.authProfiles.find((entry) => entry.id === credential.profileId);

    switch (credential.authType) {
      case 'apiKey': {
        const value = secretFor(credential.secretRefs.value);
        const header = credential.fields.headerName ?? 'X-API-Key';
        if (value === undefined) break;
        identities.push({
          name,
          roleName: credential.roleName,
          isSecondary: credential.isSecondary,
          headers: { [header.toLowerCase()]: value },
        });
        continue;
      }
      case 'bearerJwt': {
        const token = secretFor(credential.secretRefs.token);
        if (token === undefined) break;
        identities.push({
          name,
          roleName: credential.roleName,
          isSecondary: credential.isSecondary,
          headers: { authorization: `Bearer ${token}` },
        });
        continue;
      }
      case 'sessionCookie': {
        const value = secretFor(credential.secretRefs.value);
        const cookieName = credential.fields.cookieName;
        if (value === undefined || cookieName === undefined) break;
        identities.push({
          name,
          roleName: credential.roleName,
          isSecondary: credential.isSecondary,
          headers: { cookie: `${cookieName}=${value}` },
        });
        continue;
      }
      default: {
        // A login to perform. Only where the policy says how — the fields a login form expects
        // differ per application, and guessing at them is how a test locks out a client's account.
        const apiLogin = profile?.apiLogin;
        const password = secretFor(credential.secretRefs.password);
        const username =
          credential.fields.email ?? credential.fields.username ?? credential.fields.mobile;

        if (apiLogin === undefined) {
          withoutSession.push({
            name,
            reason: `Auth profile "${credential.profileId}" has no apiLogin block, so there is no way to exchange this password for a session without a browser. Add one, or expect access control comparison to skip this role.`,
          });
          continue;
        }
        if (password === undefined || username === undefined) {
          withoutSession.push({
            name,
            reason: 'The submitted credential carries no username and password to sign in with.',
          });
          continue;
        }
        const url = apiLogin.url ?? profile?.loginUrl;
        if (url === undefined) {
          withoutSession.push({
            name,
            reason: `Auth profile "${credential.profileId}" names neither an apiLogin url nor a loginUrl.`,
          });
          continue;
        }

        identities.push({
          name,
          roleName: credential.roleName,
          isSecondary: credential.isSecondary,
          headers: {},
          login: {
            url,
            usernameField: apiLogin.usernameField,
            passwordField: apiLogin.passwordField,
            username,
            password,
            tokenPath: apiLogin.tokenPath,
            tokenHeader: apiLogin.tokenHeader,
            tokenTemplate: apiLogin.tokenTemplate,
          },
        });
        continue;
      }
    }

    withoutSession.push({
      name,
      reason: 'The submitted credential is missing the value this kind of login needs.',
    });
  }

  return { identities, withoutSession };
}
