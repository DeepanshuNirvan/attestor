import { describe, expect, it } from 'vitest';
import { endpointsWithinTargets } from './run-service.ts';

/**
 * Found by running it. A probe read the endpoints an earlier run had crawled, one of which pointed
 * at a container that had since been replaced, and the scope guard refused the whole probe —
 * correctly, but the result was a run that tested nothing while the real target sat there.
 */
describe('narrowing crawled endpoints to what this run may touch', () => {
  const crawled = [
    'http://172.18.0.12:3000/rest/basket/1',
    'http://192.168.65.254:3013/users/v1',
    'https://192.168.65.254:3013/books/v1',
  ];

  it('keeps the endpoints whose host is a target of this run', () => {
    expect(endpointsWithinTargets(crawled, ['http://192.168.65.254:3013'])).toEqual([
      'http://192.168.65.254:3013/users/v1',
      'https://192.168.65.254:3013/books/v1',
    ]);
  });

  it('drops an endpoint left over from an earlier run against another host', () => {
    expect(endpointsWithinTargets(crawled, ['http://192.168.65.254:3013'])).not.toContain(
      'http://172.18.0.12:3000/rest/basket/1',
    );
  });

  it('accepts a target given as a bare host or address', () => {
    expect(endpointsWithinTargets(crawled, ['192.168.65.254'])).toHaveLength(2);
  });

  it('matches on host alone, because a port is not an authorisation boundary', () => {
    // The scope guard authorises hosts and ranges. Filtering by port here would silently drop
    // endpoints the engagement is entitled to test.
    expect(endpointsWithinTargets(crawled, ['http://192.168.65.254:9999'])).toHaveLength(2);
  });

  it('drops anything that is not a URL rather than passing it to the guard', () => {
    expect(endpointsWithinTargets(['not a url', ''], ['http://192.168.65.254:3013'])).toEqual([]);
  });

  it('returns nothing when the target list is unusable, rather than everything', () => {
    // Failing open here would hand the guard exactly the out-of-scope URL this function exists to
    // remove, which is the bug it was written for.
    expect(endpointsWithinTargets(crawled, ['not a url'])).toEqual([]);
    expect(endpointsWithinTargets(crawled, [])).toEqual([]);
  });
});
