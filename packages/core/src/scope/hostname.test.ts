import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  hostnameMatches,
  isValidHostnamePattern,
  normaliseHostname,
  parseTargetUrl,
} from './hostname.ts';

describe('normaliseHostname', () => {
  it('lowercases, strips a trailing dot and converts internationalised names', () => {
    expect(normaliseHostname('Example.COM')).toBe('example.com');
    expect(normaliseHostname('example.com.')).toBe('example.com');
    expect(normaliseHostname('bücher.example')).toBe('xn--bcher-kva.example');
  });

  it('rejects anything that is not a hostname', () => {
    for (const bad of [
      '',
      '   ',
      'exam ple.com',
      'example.com/path',
      'user@example.com',
      'example.com:8080',
      'http://example.com',
      '..example.com',
      'example..com',
      '-example.com',
      'example-.com',
      'exa\tmple.com',
      `${'a'.repeat(64)}.example.com`,
      `${'a.'.repeat(200)}com`,
    ]) {
      expect(normaliseHostname(bad), JSON.stringify(bad)).toBeNull();
    }
  });

  it('never invents a hostname by dropping characters', () => {
    // domainToASCII on its own would turn this into "example.com", which is the bug this guards.
    expect(normaliseHostname('exam­ple.com')).toBeNull();
  });

  it('canonicalises numeric and obfuscated IPv4 forms to dotted quads', () => {
    // This is the behaviour that stops "0x7f.1" being treated as an ordinary hostname and slipping
    // past the loopback rule. The canonical form is what the address checks then see.
    expect(normaliseHostname('0x7f.1')).toBe('127.0.0.1');
    expect(normaliseHostname('2130706433')).toBe('127.0.0.1');
    expect(normaliseHostname('0177.0.0.1')).toBe('127.0.0.1');
    expect(normaliseHostname('0.0')).toBe('0.0.0.0');
  });
});

describe('hostnameMatches — exact patterns', () => {
  it('matches only the same host', () => {
    expect(hostnameMatches('example.com', 'example.com')).toBe(true);
    expect(hostnameMatches('example.com', 'EXAMPLE.COM')).toBe(true);
    expect(hostnameMatches('example.com', 'example.com.')).toBe(true);
    expect(hostnameMatches('example.com', 'www.example.com')).toBe(false);
    expect(hostnameMatches('example.com', 'notexample.com')).toBe(false);
    expect(hostnameMatches('example.com', 'example.com.attacker.net')).toBe(false);
  });
});

describe('hostnameMatches — wildcard patterns', () => {
  it('matches subdomains at any depth but never the apex', () => {
    expect(hostnameMatches('*.example.com', 'www.example.com')).toBe(true);
    expect(hostnameMatches('*.example.com', 'a.b.c.example.com')).toBe(true);
    expect(hostnameMatches('*.example.com', 'example.com')).toBe(false);
  });

  it('is not a string suffix comparison', () => {
    for (const evil of [
      'notexample.com',
      'xexample.com',
      'example.com.attacker.net',
      'wwwexample.com',
      'example.como',
      'aexample.com',
      'example-com.attacker.net',
    ]) {
      expect(hostnameMatches('*.example.com', evil), evil).toBe(false);
    }
  });

  it('rejects wildcard forms other than a leading label', () => {
    expect(hostnameMatches('*example.com', 'www.example.com')).toBe(false);
    expect(hostnameMatches('ex*.com', 'example.com')).toBe(false);
    expect(hostnameMatches('*', 'example.com')).toBe(false);
    expect(hostnameMatches('*.', 'example.com')).toBe(false);
    expect(hostnameMatches('**.example.com', 'www.example.com')).toBe(false);
  });

  it('handles internationalised bases and candidates consistently', () => {
    expect(hostnameMatches('*.bücher.example', 'shop.bücher.example')).toBe(true);
    expect(hostnameMatches('*.xn--bcher-kva.example', 'shop.bücher.example')).toBe(true);
    expect(hostnameMatches('*.bücher.example', 'shop.bucher.example')).toBe(false);
  });
});

describe('hostnameMatches — properties', () => {
  // Labels always start with a letter. An all-numeric name is an IPv4 literal to the URL parser,
  // not a hostname, and is handled by the address rules rather than by label matching.
  const label = fc
    .stringMatching(/^[a-z]([a-z0-9-]{0,20}[a-z0-9])?$/)
    .filter((value) => value.length > 0 && value.length <= 22);

  const hostname = fc
    .array(label, { minLength: 2, maxLength: 4 })
    .map((labels) => labels.join('.'))
    .filter((value) => value.length <= 200 && normaliseHostname(value) === value);

  it('a wildcard never matches its own apex', () => {
    fc.assert(
      fc.property(hostname, (base) => {
        expect(hostnameMatches(`*.${base}`, base)).toBe(false);
      }),
      { numRuns: 400 },
    );
  });

  it('a wildcard matches exactly the hosts that end in its labels', () => {
    fc.assert(
      fc.property(hostname, label, (base, prefix) => {
        const candidate = `${prefix}.${base}`;
        if (normaliseHostname(candidate) === null) return;
        expect(hostnameMatches(`*.${base}`, candidate)).toBe(true);
      }),
      { numRuns: 400 },
    );
  });

  it('concatenating without a separator never matches', () => {
    fc.assert(
      fc.property(hostname, label, (base, prefix) => {
        const glued = `${prefix}${base}`;
        if (normaliseHostname(glued) === null) return;
        expect(hostnameMatches(`*.${base}`, glued)).toBe(false);
        expect(hostnameMatches(base, glued)).toBe(false);
      }),
      { numRuns: 400 },
    );
  });

  it('appending a suffix domain never matches', () => {
    fc.assert(
      fc.property(hostname, hostname, (base, suffix) => {
        const candidate = `${base}.${suffix}`;
        if (normaliseHostname(candidate) === null) return;
        if (candidate.endsWith(`.${base}`)) return; // genuinely a subdomain, tested elsewhere
        expect(hostnameMatches(`*.${base}`, candidate)).toBe(false);
      }),
      { numRuns: 400 },
    );
  });

  it('matching is case and trailing-dot insensitive', () => {
    fc.assert(
      fc.property(hostname, (base) => {
        expect(hostnameMatches(base, base.toUpperCase())).toBe(true);
        expect(hostnameMatches(base, `${base}.`)).toBe(true);
        expect(hostnameMatches(base.toUpperCase(), base)).toBe(true);
      }),
      { numRuns: 300 },
    );
  });

  it('never throws, whatever it is given', () => {
    fc.assert(
      fc.property(fc.string(), fc.string(), (pattern, candidate) => {
        expect(() => hostnameMatches(pattern, candidate)).not.toThrow();
      }),
      { numRuns: 1000 },
    );
  });
});

describe('isValidHostnamePattern', () => {
  it('accepts exact and leading-wildcard patterns only', () => {
    expect(isValidHostnamePattern('example.com')).toBe(true);
    expect(isValidHostnamePattern('*.example.com')).toBe(true);
    expect(isValidHostnamePattern('*example.com')).toBe(false);
    expect(isValidHostnamePattern('ex*mple.com')).toBe(false);
    expect(isValidHostnamePattern('*')).toBe(false);
    expect(isValidHostnamePattern('')).toBe(false);
  });
});

describe('parseTargetUrl', () => {
  it('accepts bare hosts and full urls', () => {
    expect(parseTargetUrl('example.com')?.hostname).toBe('example.com');
    expect(parseTargetUrl('https://example.com/path?x=1')?.hostname).toBe('example.com');
    expect(parseTargetUrl('https://example.com:8443/')?.port).toBe(8443);
    expect(parseTargetUrl('wss://example.com/socket')?.scheme).toBe('wss:');
  });

  it('rejects schemes the platform does not speak', () => {
    for (const bad of ['file:///etc/passwd', 'gopher://example.com', 'ftp://example.com', 'javascript:alert(1)']) {
      expect(parseTargetUrl(bad), bad).toBeNull();
    }
  });

  it('rejects embedded credentials, which are how a target gets redirected', () => {
    expect(parseTargetUrl('https://example.com@attacker.net/')).toBeNull();
    expect(parseTargetUrl('https://user:pass@example.com/')).toBeNull();
  });

  it('unwraps a bracketed IPv6 literal', () => {
    expect(parseTargetUrl('https://[2001:db8::1]:8080/')?.hostname).toBe('2001:db8::1');
  });
});
