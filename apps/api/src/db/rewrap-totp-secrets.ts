import { eq, isNotNull } from 'drizzle-orm';
import { CredentialVault } from '../services/credential-vault.ts';
import { consoleDatabase } from './client.ts';
import { clientUser } from './schema.ts';

/**
 * Re-wraps every client authenticator secret under a new `PORTAL_TOTP_KEY`.
 *
 * Run this and only this during a rotation of that key, with both keys present:
 *
 *   PORTAL_TOTP_KEY_PREVIOUS=<old> PORTAL_TOTP_KEY=<new> \
 *     node --experimental-strip-types apps/api/src/db/rewrap-totp-secrets.ts
 *
 * Rotating the key without running this locks every client out of the portal: their password still
 * works and their second factor never will, which looks exactly like an attack to them.
 *
 * It connects as the console role rather than the portal role on purpose. The portal is granted
 * only what it needs to verify a code at sign-in; rewriting the column is administration, and
 * administration does not belong to the internet-facing service.
 */

const previousKey = process.env.PORTAL_TOTP_KEY_PREVIOUS;
const nextKey = process.env.PORTAL_TOTP_KEY;
const databaseUrl = process.env.DATABASE_URL;

if (!previousKey || !nextKey) {
  console.error(
    'set both PORTAL_TOTP_KEY_PREVIOUS (the current key) and PORTAL_TOTP_KEY (the new one)',
  );
  process.exit(1);
}
if (previousKey === nextKey) {
  console.error('the two keys are identical; there is nothing to rotate');
  process.exit(1);
}
if (!databaseUrl) {
  console.error('DATABASE_URL is not set');
  process.exit(1);
}

/** Must match the context the portal seals with, or nothing opens. */
const TOTP_CONTEXT = 'portal-totp';

const database = consoleDatabase(databaseUrl);
const from = new CredentialVault(previousKey);
const to = new CredentialVault(nextKey);

const rows = await database
  .select({
    id: clientUser.id,
    email: clientUser.email,
    totpSecretSealed: clientUser.totpSecretSealed,
  })
  .from(clientUser)
  .where(isNotNull(clientUser.totpSecretSealed));

console.error(`${rows.length} authenticator secret(s) to re-wrap`);

let rewrapped = 0;

for (const row of rows) {
  if (!row.totpSecretSealed) continue;

  let secret: string;
  try {
    secret = await from.open(
      TOTP_CONTEXT,
      JSON.parse(row.totpSecretSealed) as { sealedValue: string; keySalt: string; nonce: string },
    );
  } catch {
    // The address is named because an operator needs to know whose account is affected. The secret
    // is not, here or anywhere else.
    console.error(
      `STOPPED at ${row.email}: it did not open with PORTAL_TOTP_KEY_PREVIOUS. Nothing further has ` +
        'been changed. Restore from backup and check which key sealed this row.',
    );
    process.exit(2);
  }

  const sealed = await to.seal(TOTP_CONTEXT, secret);
  secret = '';

  await database
    .update(clientUser)
    .set({ totpSecretSealed: JSON.stringify(sealed) })
    .where(eq(clientUser.id, row.id));

  rewrapped += 1;
}

console.error(`re-wrapped ${rewrapped}`);
console.error(
  'Now remove PORTAL_TOTP_KEY_PREVIOUS, restart the portal API, and store the new key offline. ' +
    'Confirm one client can sign in before you walk away.',
);
process.exit(0);
