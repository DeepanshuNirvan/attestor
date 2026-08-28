import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { cidrContains, forbiddenIpReason, parseCidr, parseIp } from './ip.ts';

describe('parseIp', () => {
  it('parses both families', () => {
    expect(parseIp('192.0.2.1')?.version).toBe(4);
    expect(parseIp('2001:db8::1')?.version).toBe(6);
    expect(parseIp('::1')?.value).toBe(1n);
    expect(parseIp('0.0.0.0')?.value).toBe(0n);
    expect(parseIp('255.255.255.255')?.value).toBe(4294967295n);
  });

  it('parses an IPv4-mapped IPv6 address to the same numeric tail', () => {
    const mapped = parseIp('::ffff:127.0.0.1');
    expect(mapped?.version).toBe(6);
    expect(mapped && mapped.value & 0xffffffffn).toBe(parseIp('127.0.0.1')?.value);
  });

  it('returns null rather than guessing', () => {
    for (const bad of ['', 'example.com', '256.1.1.1', '1.2.3', 'not an ip', '::gg']) {
      expect(parseIp(bad), bad).toBeNull();
    }
  });
});

describe('parseCidr and cidrContains', () => {
  it('handles the boundaries of a range', () => {
    const cidr = parseCidr('10.0.0.0/8');
    expect(cidr).not.toBeNull();
    expect(cidrContains(cidr!, parseIp('10.0.0.0')!)).toBe(true);
    expect(cidrContains(cidr!, parseIp('10.255.255.255')!)).toBe(true);
    expect(cidrContains(cidr!, parseIp('9.255.255.255')!)).toBe(false);
    expect(cidrContains(cidr!, parseIp('11.0.0.0')!)).toBe(false);
  });

  it('handles /32 and /0', () => {
    const single = parseCidr('192.0.2.7/32')!;
    expect(cidrContains(single, parseIp('192.0.2.7')!)).toBe(true);
    expect(cidrContains(single, parseIp('192.0.2.8')!)).toBe(false);

    const everything = parseCidr('0.0.0.0/0')!;
    expect(cidrContains(everything, parseIp('203.0.113.9')!)).toBe(true);
  });

  it('never matches across address families', () => {
    const v4 = parseCidr('10.0.0.0/8')!;
    expect(cidrContains(v4, parseIp('::1')!)).toBe(false);
    const v6 = parseCidr('fc00::/7')!;
    expect(cidrContains(v6, parseIp('10.1.1.1')!)).toBe(false);
  });

  it('rejects malformed ranges', () => {
    for (const bad of ['10.0.0.0/33', '10.0.0.0/-1', '10.0.0.0/abc', 'not/8', '/8']) {
      expect(parseCidr(bad), bad).toBeNull();
    }
  });

  it('treats a bare address as a host route', () => {
    const cidr = parseCidr('203.0.113.5')!;
    expect(cidr.prefix).toBe(32);
    expect(cidrContains(cidr, parseIp('203.0.113.5')!)).toBe(true);
  });
});

describe('forbiddenIpReason', () => {
  it('blocks loopback, private, link-local and reserved ranges', () => {
    for (const address of [
      '127.0.0.1',
      '10.1.2.3',
      '172.16.0.1',
      '192.168.1.1',
      '169.254.1.1',
      '100.64.0.1',
      '0.0.0.0',
      '224.0.0.1',
      '255.255.255.255',
      '::1',
      'fe80::1',
      'fc00::1',
      'ff02::1',
    ]) {
      expect(forbiddenIpReason(address), address).not.toBeNull();
    }
  });

  it('names the metadata endpoint specifically, not just "link-local"', () => {
    expect(forbiddenIpReason('169.254.169.254')?.reason).toBe('cloudMetadataEndpoint');
    expect(forbiddenIpReason('169.254.170.2')?.reason).toBe('cloudMetadataEndpoint');
    expect(forbiddenIpReason('fd00:ec2::254')?.reason).toBe('cloudMetadataEndpoint');
  });

  it('sees through an IPv4-mapped IPv6 address', () => {
    // ::ffff:127.0.0.1 is loopback wearing a v6 costume, and a v4-only rule set would miss it.
    const reason = forbiddenIpReason('::ffff:127.0.0.1');
    expect(reason).not.toBeNull();
    expect(reason?.detail).toContain('127.0.0.1');

    expect(forbiddenIpReason('::ffff:169.254.169.254')?.reason).toBe('cloudMetadataEndpoint');
  });

  it('permits a private range the client has explicitly authorised', () => {
    const owned = [parseCidr('10.20.0.0/16')!];
    expect(forbiddenIpReason('10.20.5.5', owned)).toBeNull();
    // Neighbouring private space is still refused: authorisation is per range, not per family.
    expect(forbiddenIpReason('10.21.5.5', owned)).not.toBeNull();
    // The metadata endpoint stays refused even inside an authorised range.
    expect(forbiddenIpReason('169.254.169.254', [parseCidr('169.254.0.0/16')!])?.reason).toBe(
      'cloudMetadataEndpoint',
    );
  });

  it('refuses anything it cannot parse', () => {
    expect(forbiddenIpReason('not-an-ip')?.reason).toBe('unparseableAddress');
    expect(forbiddenIpReason('')?.reason).toBe('unparseableAddress');
  });

  it('allows ordinary public addresses', () => {
    for (const address of ['8.8.8.8', '1.1.1.1', '2606:4700::1111', '13.107.42.14']) {
      expect(forbiddenIpReason(address), address).toBeNull();
    }
  });

  it('never throws and never returns a partially-formed reason', () => {
    fc.assert(
      fc.property(fc.string(), (input) => {
        const result = forbiddenIpReason(input);
        if (result !== null) {
          expect(typeof result.reason).toBe('string');
          expect(result.detail.length).toBeGreaterThan(0);
        }
      }),
      { numRuns: 1000 },
    );
  });

  it('refuses every address inside every reserved v4 range, exhaustively sampled', () => {
    const reserved = [
      ['10.0.0.0', '10.255.255.255'],
      ['127.0.0.0', '127.255.255.255'],
      ['169.254.0.0', '169.254.255.255'],
      ['172.16.0.0', '172.31.255.255'],
      ['192.168.0.0', '192.168.255.255'],
    ] as const;

    const toNumber = (address: string) => Number(parseIp(address)!.value);
    const toDotted = (value: number) =>
      [24, 16, 8, 0].map((shift) => (value >>> shift) & 0xff).join('.');

    fc.assert(
      fc.property(fc.nat(reserved.length - 1), fc.nat(), (rangeIndex, offset) => {
        const [low, high] = reserved[rangeIndex]!;
        const start = toNumber(low);
        const end = toNumber(high);
        const address = toDotted(start + (offset % (end - start + 1)));
        expect(forbiddenIpReason(address), address).not.toBeNull();
      }),
      { numRuns: 2000 },
    );
  });
});
