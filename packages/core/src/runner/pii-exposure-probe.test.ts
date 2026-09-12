import { describe, expect, it } from 'vitest';
import { createLogger } from '@attestor/shared';
import { resolvePolicy } from '@attestor/policy';
import { looksOpaque, piiExposureProbe } from './pii-exposure-probe.ts';
import type { ProbeContext } from './run-probe-for-engagement.ts';

const { policy } = resolvePolicy([{ name: 'global', yamlSource: 'modules: [web]' }]);

/** This probe sends nothing, so the request function exists only to prove it is never called. */
function context(): { context: ProbeContext; sent: unknown[] } {
  const sent: unknown[] = [];
  return {
    sent,
    context: {
      policy,
      targets: ['app.example.com'],
      logger: createLogger({ service: 'test', write: () => undefined }),
      readOnly: true,
      request: (request) => {
        sent.push(request);
        throw new Error('the PII exposure probe must not make requests');
      },
    },
  };
}

describe('piiExposureProbe', () => {
  it('sends no requests at all', async () => {
    const { context: ctx, sent } = context();

    await piiExposureProbe({
      endpoints: ['https://app.example.com/account?email=alice@example.com'],
    }).run(ctx);

    expect(sent).toEqual([]);
  });

  it('finds an email address in a query string', async () => {
    const result = await piiExposureProbe({
      endpoints: ['https://app.example.com/reset?email=alice@example.com&next=/home'],
    }).run(context().context);

    expect(result.observations).toHaveLength(1);
    expect(result.observations[0]?.location).toBe('query');
    expect(result.observations[0]?.parameterNames).toEqual(['email']);
    expect(result.observations[0]?.ruleIds).toContain('email');
  });

  it('finds personal data in a path segment, not only in a query', async () => {
    const result = await piiExposureProbe({
      endpoints: ['https://app.example.com/users/alice@example.com/orders'],
    }).run(context().context);

    expect(result.observations.map((o) => o.location)).toEqual(['path']);
  });

  // The whole point of the finding is that this value ends up in logs. Writing it into evidence
  // storage to prove the point would put it in one more place nobody audited.
  it('never carries the raw value out, only the masked URL', async () => {
    const result = await piiExposureProbe({
      endpoints: ['https://app.example.com/reset?email=alice@example.com'],
    }).run(context().context);

    const serialised = JSON.stringify(result);
    expect(serialised).not.toContain('alice@example.com');
    expect(result.observations[0]?.maskedUrl).toBe(
      'https://app.example.com/reset?email=a****@e******.com',
    );
  });

  it('says nothing about an ordinary URL', async () => {
    const result = await piiExposureProbe({
      endpoints: [
        'https://app.example.com/dashboard',
        'https://app.example.com/orders?page=2&sort=date',
        'https://app.example.com/items/1042',
      ],
    }).run(context().context);

    expect(result.observations).toEqual([]);
    expect(result.endpointsExamined).toBe(3);
  });

  /**
   * A client asking "is our personal data encrypted in the request" is really asking whether a
   * reader of the logs learns anything. An identifier that is opaque answers that, whatever
   * produced it, so the probe must not raise a finding on one.
   */
  it('does not report values that tell a log reader nothing', async () => {
    const result = await piiExposureProbe({
      endpoints: [
        'https://app.example.com/u?id=f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'https://app.example.com/u?token=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        'https://app.example.com/u?ref=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA',
      ],
    }).run(context().context);

    expect(result.observations).toEqual([]);
  });

  it('reports nothing to examine rather than a clean result', async () => {
    const result = await piiExposureProbe({ endpoints: [] }).run(context().context);

    expect(result.observations).toEqual([]);
    expect(result.skipped).toContain('crawl discovered');
  });

  it('ignores a row that is not a URL instead of calling it a finding', async () => {
    const result = await piiExposureProbe({
      endpoints: ['not a url at all', 'https://app.example.com/ok'],
    }).run(context().context);

    expect(result.observations).toEqual([]);
  });
});

describe('looksOpaque', () => {
  it.each([
    ['f47ac10b-58cc-4372-a567-0e02b2c3d479', true],
    ['9f86d081884c7d659a2feaa0c55ad015', true],
    ['Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA', true],
    ['alice@example.com', false],
    ['9876543210', false],
    ['2', false],
  ])('%s -> %s', (value, expected) => {
    expect(looksOpaque(value)).toBe(expected);
  });
});
