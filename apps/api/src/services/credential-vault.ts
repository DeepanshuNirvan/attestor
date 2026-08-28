import sodium from 'libsodium-wrappers-sumo';

/**
 * The credential vault.
 *
 * Client credentials are the single largest liability this firm carries, so the design is shaped
 * around one property: closing an engagement must destroy that engagement's credentials and nothing
 * else, with no ability to recover them afterwards.
 *
 * That is done with a per-engagement subkey derived from the master key and a random salt stored
 * beside the ciphertext. Deleting the salt makes the subkey underivable, which makes the ciphertext
 * undecryptable — cryptographic shredding, rather than a DELETE that leaves rows in a backup.
 *
 * The master key lives in the environment or a KMS. It is never in the database and never in the
 * repository.
 */

const SALT_BYTES = 16;
const CONTEXT = 'attestcr'; // crypto_kdf contexts are exactly 8 bytes

export interface SealedSecret {
  sealedValue: string;
  keySalt: string;
  nonce: string;
}

let ready: Promise<void> | null = null;

async function ensureReady(): Promise<void> {
  ready ??= sodium.ready;
  await ready;
}

function masterKeyBytes(masterKeyBase64: string): Uint8Array {
  const key = sodium.from_base64(masterKeyBase64, sodium.base64_variants.ORIGINAL);
  if (key.length !== sodium.crypto_secretbox_KEYBYTES) {
    throw new Error(
      `VAULT_MASTER_KEY must decode to ${sodium.crypto_secretbox_KEYBYTES} bytes; got ${key.length}`,
    );
  }
  return key;
}

/**
 * Derive the engagement subkey. Blake2b keyed with the master key over the salt and the engagement
 * id: binding the id in means a salt copied between engagements does not unlock the other's data.
 */
function deriveSubkey(
  masterKey: Uint8Array,
  salt: Uint8Array,
  engagementId: string,
): Uint8Array {
  const material = new Uint8Array([
    ...salt,
    ...sodium.from_string(`${CONTEXT}:${engagementId}`),
  ]);
  return sodium.crypto_generichash(sodium.crypto_secretbox_KEYBYTES, material, masterKey);
}

export class CredentialVault {
  private readonly masterKeyBase64: string;

  constructor(masterKeyBase64: string) {
    this.masterKeyBase64 = masterKeyBase64;
  }

  async seal(engagementId: string, plaintext: string): Promise<SealedSecret> {
    await ensureReady();
    const masterKey = masterKeyBytes(this.masterKeyBase64);
    const salt = sodium.randombytes_buf(SALT_BYTES);
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const subkey = deriveSubkey(masterKey, salt, engagementId);

    const sealed = sodium.crypto_secretbox_easy(sodium.from_string(plaintext), nonce, subkey);

    sodium.memzero(subkey);
    sodium.memzero(masterKey);

    return {
      sealedValue: sodium.to_base64(sealed, sodium.base64_variants.ORIGINAL),
      keySalt: sodium.to_base64(salt, sodium.base64_variants.ORIGINAL),
      nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
    };
  }

  /**
   * Open a sealed secret. Called only inside a worker, in memory, at run time — never in a request
   * handler and never to display a value in the console.
   */
  async open(engagementId: string, secret: SealedSecret): Promise<string> {
    await ensureReady();
    if (secret.keySalt === '') {
      throw new Error(
        'this credential has been shredded: the engagement key salt was destroyed on closure',
      );
    }

    const masterKey = masterKeyBytes(this.masterKeyBase64);
    const salt = sodium.from_base64(secret.keySalt, sodium.base64_variants.ORIGINAL);
    const nonce = sodium.from_base64(secret.nonce, sodium.base64_variants.ORIGINAL);
    const sealed = sodium.from_base64(secret.sealedValue, sodium.base64_variants.ORIGINAL);
    const subkey = deriveSubkey(masterKey, salt, engagementId);

    try {
      const opened = sodium.crypto_secretbox_open_easy(sealed, nonce, subkey);
      return sodium.to_string(opened);
    } catch {
      // Deliberately vague: a decryption failure should not distinguish "wrong key" from "tampered".
      throw new Error('credential could not be opened');
    } finally {
      sodium.memzero(subkey);
      sodium.memzero(masterKey);
    }
  }

  /**
   * Shred by clearing the salt. The row stays so the audit trail still shows a credential existed,
   * which account it was for and when it was destroyed; the value becomes unrecoverable.
   */
  shredPatch(): { sealedValue: string; keySalt: string; nonce: string; shreddedAt: Date } {
    return { sealedValue: '', keySalt: '', nonce: '', shreddedAt: new Date() };
  }

  static async generateMasterKey(): Promise<string> {
    await ensureReady();
    return sodium.to_base64(
      sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES),
      sodium.base64_variants.ORIGINAL,
    );
  }
}
