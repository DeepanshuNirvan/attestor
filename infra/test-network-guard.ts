/**
 * The integration suite's network guard.
 *
 * Loaded as a vitest setup file before any integration test runs. It does two things:
 *
 *   1. Refuses to start unless `ATTESTOR_TEST_NETWORK_ONLY=1`, which the runner sets only when the
 *      internal-only target network from docker-compose.test.yml is up.
 *   2. Replaces `fetch` and blocks `net.connect` for any host that is not on the allow-list, so a
 *      test that reaches for an internet host fails loudly instead of quietly succeeding.
 *
 * This exists because "CI must never make an outbound connection to a real target" is a rule that
 * has to be enforced rather than remembered. A scanner integration test that hits a live host is
 * an unauthorised scan, and the fact that it was an accident is not a defence.
 */

import net from 'node:net';
import { isIP } from 'node:net';

const ALLOWED_HOSTS = new Set([
  'localhost',
  '127.0.0.1',
  '::1',
  '0.0.0.0',
  // Service names from docker-compose.test.yml.
  'juice-shop',
  'dvwa',
  'webgoat',
  'vampi',
  'crapi-web',
  'crapi-identity',
  'crapi-postgres',
  'vulnerable-llm',
  'cleartext',
  // The platform's own services, for the end-to-end run.
  'postgres',
  'redis',
  'minio',
  'api',
  'portal-api',
]);

function hostIsAllowed(host: string): boolean {
  const cleaned = host.replace(/^\[|\]$/g, '').toLowerCase();
  if (ALLOWED_HOSTS.has(cleaned)) return true;
  // Private ranges are the docker network. Anything routable is not.
  if (isIP(cleaned) === 4) {
    return (
      cleaned.startsWith('127.') ||
      cleaned.startsWith('10.') ||
      cleaned.startsWith('192.168.') ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(cleaned)
    );
  }
  return false;
}

class OutboundBlocked extends Error {
  constructor(host: string) {
    super(
      `Integration tests may not contact "${host}". Only the local vulnerable targets are permitted; ` +
        'reaching an internet host from a scanner test is an unauthorised scan.',
    );
    this.name = 'OutboundBlocked';
  }
}

if (process.env.ATTESTOR_TEST_NETWORK_ONLY !== '1') {
  throw new Error(
    'refusing to run the integration suite without ATTESTOR_TEST_NETWORK_ONLY=1. ' +
      'Start the targets first: docker compose -f infra/docker-compose.test.yml up -d',
  );
}

const realFetch = globalThis.fetch;
// `RequestInfo` is a DOM name and this project does not load the DOM lib; take the parameter type
// from fetch itself so the guard keeps the exact signature it is replacing.
globalThis.fetch = ((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
  const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
  if (!hostIsAllowed(url.hostname)) throw new OutboundBlocked(url.hostname);
  return realFetch(input, init);
});

const realConnect = net.connect.bind(net);
// The signature is overloaded; the host arrives either as an option or as the second argument.
net.connect = ((...args: unknown[]) => {
  const first = args[0];
  const host =
    typeof first === 'object' && first !== null && 'host' in first
      ? String((first as { host?: string }).host ?? 'localhost')
      : typeof args[1] === 'string'
        ? args[1]
        : 'localhost';

  if (!hostIsAllowed(host)) throw new OutboundBlocked(host);
  return (realConnect as (...inner: unknown[]) => net.Socket)(...args);
});

export {};
