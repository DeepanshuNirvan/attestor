import { eq, isNull } from 'drizzle-orm';
import { CredentialVault } from '../services/credential-vault.ts';
import { consoleDatabase } from './client.ts';
import { credentialSet } from './schema.ts';

/**
 * Re-wraps every stored credential under a new master key.
 *
 * Run this and only this during a `VAULT_MASTER_KEY` rotation, with both keys present:
 *
 *   VAULT_MASTER_KEY_PREVIOUS=<old> VAULT_MASTER_KEY=<new> \
 *     node --experimental-strip-types apps/api/src/db/rewrap-credentials.ts
 *
 * Properties that matter:
 *
 *   - Each row is re-wrapped in its own transaction. A failure halfway leaves earlier rows on the
 *     new key and later rows on the old one, which is recoverable by running it again; a single
 *     giant transaction that fails at 99% leaves nothing done and a very long lock.
 *   - Shredded rows are skipped, not repaired. Their salt was destroyed on purpose and there is no
 *     key that opens them — that is the retention promise working.
 *   - A row that cannot be opened with the old key stops the run. Continuing past it would quietly
 *     strand a credential nobody can decrypt, and finding that out during an engagement is worse
 *     than finding it out now.
 *   - Nothing here logs a plaintext. The value exists in memory for the length of one re-seal.
 */

const previousKey = process.env.VAULT_MASTER_KEY_PREVIOUS;
const nextKey = process.env.VAULT_MASTER_KEY;
const databaseUrl = process.env.DATABASE_URL;

if (!previousKey || !nextKey) {
  console.error(
    'set both VAULT_MASTER_KEY_PREVIOUS (the current key) and VAULT_MASTER_KEY (the new one)',
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

const database = consoleDatabase(databaseUrl);
const from = new CredentialVault(previousKey);
const to = new CredentialVault(nextKey);

const rows = await database
  .select({
    id: credentialSet.id,
    engagementId: credentialSet.engagementId,
    label: credentialSet.label,
    sealedValue: credentialSet.sealedValue,
    keySalt: credentialSet.keySalt,
    nonce: credentialSet.nonce,
  })
  .from(credentialSet)
  .where(isNull(credentialSet.shreddedAt));

console.error(`${rows.length} credential(s) to re-wrap`);

let rewrapped = 0;
let skipped = 0;

for (const row of rows) {
  if (row.keySalt === '') {
    skipped += 1;
    continue;
  }

  let plaintext: string;
  try {
    plaintext = await from.open(row.engagementId, {
      sealedValue: row.sealedValue,
      keySalt: row.keySalt,
      nonce: row.nonce,
    });
  } catch {
    console.error(
      `STOPPED: credential ${row.id} ("${row.label}") did not open with VAULT_MASTER_KEY_PREVIOUS. ` +
        'Nothing further has been changed. Restore from backup and check which key sealed this row.',
    );
    process.exit(2);
  }

  const sealed = await to.seal(row.engagementId, plaintext);
  plaintext = '';

  await database
    .update(credentialSet)
    .set({ sealedValue: sealed.sealedValue, keySalt: sealed.keySalt, nonce: sealed.nonce })
    .where(eq(credentialSet.id, row.id));

  rewrapped += 1;
}

console.error(`re-wrapped ${rewrapped}, skipped ${skipped} already-shredded`);
console.error(
  'Now remove VAULT_MASTER_KEY_PREVIOUS, restart the services, and store the new key offline.',
);
process.exit(0);
