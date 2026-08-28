import { describe, expect, it } from 'vitest';
import { CredentialVault } from './credential-vault.ts';

const masterKey = await CredentialVault.generateMasterKey();
const vault = new CredentialVault(masterKey);

describe('CredentialVault', () => {
  it('seals and opens a value for the engagement it belongs to', async () => {
    const sealed = await vault.seal('eng-1', 'P@ssw0rd-for-the-test-account');
    expect(sealed.sealedValue).not.toContain('P@ssw0rd');
    expect(await vault.open('eng-1', sealed)).toBe('P@ssw0rd-for-the-test-account');
  });

  it('will not open a secret under a different engagement id', async () => {
    const sealed = await vault.seal('eng-1', 'secret-value');
    await expect(vault.open('eng-2', sealed)).rejects.toThrow(/could not be opened/);
  });

  it('produces a different ciphertext every time, so repeats are not recognisable', async () => {
    const first = await vault.seal('eng-1', 'same-value');
    const second = await vault.seal('eng-1', 'same-value');
    expect(first.sealedValue).not.toBe(second.sealedValue);
    expect(first.keySalt).not.toBe(second.keySalt);
  });

  it('detects tampering rather than returning altered plaintext', async () => {
    const sealed = await vault.seal('eng-1', 'do-not-change-me');
    const bytes = Buffer.from(sealed.sealedValue, 'base64');
    bytes[5] = (bytes[5] ?? 0) ^ 0xff;
    await expect(
      vault.open('eng-1', { ...sealed, sealedValue: bytes.toString('base64') }),
    ).rejects.toThrow(/could not be opened/);
  });

  it('cannot open anything once the salt is shredded', async () => {
    const sealed = await vault.seal('eng-1', 'about-to-be-destroyed');
    const shredded = { ...sealed, ...vault.shredPatch() };
    await expect(vault.open('eng-1', shredded)).rejects.toThrow(/shredded/);
  });

  it('will not start with a master key of the wrong length', async () => {
    const wrong = new CredentialVault(Buffer.from('too short').toString('base64'));
    await expect(wrong.seal('eng-1', 'anything')).rejects.toThrow(/VAULT_MASTER_KEY/);
  });

  it('does not let one engagement key open another engagement\'s data', async () => {
    const first = await vault.seal('eng-1', 'first-secret');
    const second = await vault.seal('eng-2', 'second-secret');
    // Same salt, different engagement: still refuses, because the id is bound into the subkey.
    await expect(
      vault.open('eng-2', { ...first, keySalt: second.keySalt }),
    ).rejects.toThrow(/could not be opened/);
  });
});
