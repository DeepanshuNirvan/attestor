import { describe, expect, it } from 'vitest';
import { SecretRegistry, redactText, redactValue, isSecretKey } from './redaction.ts';

describe('redactText', () => {
  it('strips whole header values, not just the obvious ones', () => {
    const raw = [
      'GET /orders HTTP/1.1',
      'Host: shop.example.com',
      'Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345',
      'Cookie: session=9f8a7b6c5d4e3f2a1b; theme=dark',
      'X-Api-Key: live_key_9182736455',
      'Accept: application/json',
    ].join('\n');
    const out = redactText(raw);
    expect(out).not.toContain('abcdefghijklmnopqrstuvwxyz012345');
    expect(out).not.toContain('9f8a7b6c5d4e3f2a1b');
    expect(out).not.toContain('live_key_9182736455');
    expect(out).toContain('Host: shop.example.com');
    expect(out).toContain('Accept: application/json');
  });

  it('strips secret values out of JSON bodies by key name', () => {
    const out = redactText('{"email":"a@b.com","password":"hunter2000","note":"keep"}');
    expect(out).not.toContain('hunter2000');
    expect(out).toContain('"note":"keep"');
  });

  it('strips secrets out of query strings and form bodies', () => {
    expect(redactText('GET /reset?token=abc123def456&page=2')).not.toContain('abc123def456');
    expect(redactText('GET /reset?token=abc123def456&page=2')).toContain('page=2');
    expect(redactText('username=alice&password=s3cr3tvalue&next=/home')).not.toContain('s3cr3tvalue');
  });

  it('strips shaped secrets that carry no key name', () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r0W1';
    expect(redactText(`token was ${jwt} in the log`)).not.toContain(jwt);
    expect(redactText('key AKIAIOSFODNN7EXAMPLE leaked')).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(redactText('sk-ant-api03-abcdefghijklmnopqrstuvwx')).not.toContain('abcdefghijklmnopqrst');
  });

  it('strips a registered credential wherever it appears, including url-encoded', () => {
    const registry = new SecretRegistry();
    registry.add('P@ssw0rd!long');
    const encoded = encodeURIComponent('P@ssw0rd!long');
    const out = redactText(`login with P@ssw0rd!long or ${encoded}`, registry);
    expect(out).not.toContain('P@ssw0rd!long');
    expect(out).not.toContain(encoded);
  });

  it('ignores registered values too short to be distinguishable', () => {
    const registry = new SecretRegistry();
    registry.add('abc');
    expect(registry.size).toBe(0);
  });
});

describe('redactValue', () => {
  it('redacts by key name at any depth', () => {
    const out = redactValue({
      engagement: 'ATT-2026-014',
      credentials: { username: 'alice', password: 'longenoughsecret' },
      headers: { Authorization: 'Bearer aaaaaaaaaaaaaaaaaaaa' },
    }) as Record<string, unknown>;
    expect(JSON.stringify(out)).not.toContain('longenoughsecret');
    expect(JSON.stringify(out)).not.toContain('aaaaaaaaaaaaaaaaaaaa');
    expect(out.engagement).toBe('ATT-2026-014');
  });

  it('cuts runaway depth instead of throwing on the logging path', () => {
    const deep: Record<string, unknown> = {};
    let cursor = deep;
    for (let index = 0; index < 40; index += 1) {
      const next: Record<string, unknown> = {};
      cursor.next = next;
      cursor = next;
    }
    expect(() => redactValue(deep)).not.toThrow();
    expect(JSON.stringify(redactValue(deep))).toContain('[TRUNCATED]');
  });

  it('redacts message and stack of an Error without losing the name', () => {
    const error = new Error('failed with token eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.c2lnbmF0dXJlaGVyZQ');
    const out = redactValue(error) as { name: string; message: string };
    expect(out.name).toBe('Error');
    expect(out.message).not.toContain('eyJhbGciOiJIUzI1NiJ9');
  });
});

describe('isSecretKey', () => {
  it('matches across separator styles', () => {
    for (const key of ['apiKey', 'api_key', 'API-KEY', 'Authorization', 'refresh_token']) {
      expect(isSecretKey(key)).toBe(true);
    }
    expect(isSecretKey('endpoint')).toBe(false);
  });
});
