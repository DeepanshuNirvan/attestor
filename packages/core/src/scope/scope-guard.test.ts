import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  checkScope,
  isInsideTestWindow,
  validateScopeItem,
  type EngagementScopeContext,
  type ScopeItem,
} from './scope-guard.ts';

const NOW = new Date('2026-08-19T09:00:00Z'); // a Wednesday

function scopeItem(overrides: Partial<ScopeItem> & Pick<ScopeItem, 'kind' | 'value'>): ScopeItem {
  return { id: `scope-${overrides.value}`, included: true, ...overrides };
}

function context(overrides: Partial<EngagementScopeContext> = {}): EngagementScopeContext {
  return {
    engagementId: 'eng-1',
    state: 'running',
    authorisation: {
      id: 'auth-1',
      signedAt: new Date('2026-08-01T00:00:00Z'),
      revokedAt: null,
      validFrom: new Date('2026-08-17T00:00:00Z'),
      validUntil: new Date('2026-08-24T00:00:00Z'),
    },
    scopeItems: [scopeItem({ kind: 'wildcard', value: '*.client.example' })],
    testWindows: [],
    timezone: 'UTC',
    ownedPrivateRanges: [],
    thirdPartyInfrastructureAcknowledged: true,
    cloudTestingPolicyAcknowledged: false,
    panicStopActive: false,
    ...overrides,
  };
}

/** Every test injects its own resolver: no test in this suite may perform a DNS lookup. */
const resolvesTo = (...addresses: string[]) => () => Promise.resolve(addresses);
const publicAddress = resolvesTo('93.184.216.34');

describe('checkScope — the happy path', () => {
  it('allows an in-scope host that resolves to a public address', async () => {
    const decision = await checkScope(context(), 'https://app.client.example/login', {
      now: NOW,
      resolve: publicAddress,
    });
    expect(decision.allowed).toBe(true);
    if (decision.allowed) {
      expect(decision.hostname).toBe('app.client.example');
      expect(decision.resolvedAddresses).toEqual(['93.184.216.34']);
      expect(decision.matchedScopeItemId).toBe('scope-*.client.example');
    }
  });

  it('records the port when one is given', async () => {
    const decision = await checkScope(context(), 'https://app.client.example:8443/', {
      now: NOW,
      resolve: publicAddress,
    });
    expect(decision.allowed && decision.port).toBe(8443);
  });
});

describe('checkScope — authorisation', () => {
  it('refuses with no authorisation at all', async () => {
    const decision = await checkScope(context({ authorisation: null }), 'app.client.example', {
      now: NOW,
      resolve: publicAddress,
    });
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.rule).toBe('noAuthorisation');
  });

  it('refuses an unsigned authorisation', async () => {
    const base = context();
    const decision = await checkScope(
      context({ authorisation: { ...base.authorisation!, signedAt: null } }),
      'app.client.example',
      { now: NOW, resolve: publicAddress },
    );
    expect(!decision.allowed && decision.rule).toBe('authorisationUnsigned');
  });

  it('refuses a revoked authorisation', async () => {
    const base = context();
    const decision = await checkScope(
      context({
        authorisation: { ...base.authorisation!, revokedAt: new Date('2026-08-18T00:00:00Z') },
      }),
      'app.client.example',
      { now: NOW, resolve: publicAddress },
    );
    expect(!decision.allowed && decision.rule).toBe('authorisationRevoked');
  });

  it('refuses before the window opens and after it closes', async () => {
    const before = await checkScope(context(), 'app.client.example', {
      now: new Date('2026-08-16T09:00:00Z'),
      resolve: publicAddress,
    });
    expect(!before.allowed && before.rule).toBe('authorisationNotYetValid');

    const after = await checkScope(context(), 'app.client.example', {
      now: new Date('2026-08-25T09:00:00Z'),
      resolve: publicAddress,
    });
    expect(!after.allowed && after.rule).toBe('authorisationExpired');
  });

  it('treats the validUntil instant as already expired', async () => {
    const decision = await checkScope(context(), 'app.client.example', {
      now: new Date('2026-08-24T00:00:00Z'),
      resolve: publicAddress,
    });
    expect(!decision.allowed && decision.rule).toBe('authorisationExpired');
  });
});

describe('checkScope — engagement state', () => {
  it('refuses in every state that is not an execution state', async () => {
    const forbidden = [
      'draft',
      'scoped',
      'authorised',
      'advancePaid',
      'readyToRun',
      'reportDraft',
      'reportReview',
      'released',
      'retestComplete',
      'closed',
    ] as const;

    for (const state of forbidden) {
      const decision = await checkScope(context({ state }), 'app.client.example', {
        now: NOW,
        resolve: publicAddress,
      });
      expect(!decision.allowed && decision.rule, state).toBe('engagementStateForbidsExecution');
    }
  });

  it('allows the states where testing actually happens', async () => {
    for (const state of ['running', 'triage', 'manualTesting', 'retestPending'] as const) {
      const decision = await checkScope(context({ state }), 'app.client.example', {
        now: NOW,
        resolve: publicAddress,
      });
      expect(decision.allowed, state).toBe(true);
    }
  });
});

describe('checkScope — scope matching', () => {
  it('refuses a host that matches nothing', async () => {
    const decision = await checkScope(context(), 'app.someoneelse.example', {
      now: NOW,
      resolve: publicAddress,
    });
    expect(!decision.allowed && decision.rule).toBe('targetNotInScope');
  });

  it('refuses the apex when only a wildcard is in scope', async () => {
    const decision = await checkScope(context(), 'client.example', {
      now: NOW,
      resolve: publicAddress,
    });
    expect(!decision.allowed && decision.rule).toBe('targetNotInScope');
  });

  it('exclusion beats inclusion', async () => {
    const decision = await checkScope(
      context({
        scopeItems: [
          scopeItem({ kind: 'wildcard', value: '*.client.example' }),
          scopeItem({ kind: 'domain', value: 'legacy.client.example', included: false }),
        ],
      }),
      'legacy.client.example',
      { now: NOW, resolve: publicAddress },
    );
    expect(!decision.allowed && decision.rule).toBe('targetExplicitlyExcluded');
  });

  it('does not let a repository or cloud account scope item authorise a host', async () => {
    const decision = await checkScope(
      context({
        scopeItems: [
          scopeItem({ kind: 'repo', value: 'github.com/client/app' }),
          scopeItem({ kind: 'cloudAccount', value: '123456789012' }),
        ],
      }),
      'app.client.example',
      { now: NOW, resolve: publicAddress },
    );
    expect(!decision.allowed && decision.rule).toBe('targetNotInScope');
  });

  it('matches an explicit address scope item', async () => {
    const decision = await checkScope(
      context({ scopeItems: [scopeItem({ kind: 'cidr', value: '93.184.216.0/24' })] }),
      'https://93.184.216.42/',
      { now: NOW, resolve: publicAddress },
    );
    expect(decision.allowed).toBe(true);
  });
});

describe('checkScope — the never-touch list', () => {
  it('refuses regardless of what the scope says', async () => {
    for (const host of ['portal.gov.in', 'api.uidai.gov.in', 'x.nic.in', 'api.stripe.com', 'attestorsecurity.com']) {
      const decision = await checkScope(
        context({ scopeItems: [scopeItem({ kind: 'domain', value: host })] }),
        host,
        { now: NOW, resolve: publicAddress },
      );
      expect(!decision.allowed && decision.rule, host).toBe('neverTouchHost');
    }
  });

  it('is checked before authorisation, so a missing authorisation is not the reported reason', async () => {
    const decision = await checkScope(context({ authorisation: null }), 'portal.gov.in', {
      now: NOW,
      resolve: publicAddress,
    });
    expect(!decision.allowed && decision.rule).toBe('neverTouchHost');
  });
});

describe('checkScope — DNS rebinding and shared hosting', () => {
  it('refuses an in-scope name that resolves to loopback', async () => {
    const decision = await checkScope(context(), 'app.client.example', {
      now: NOW,
      resolve: resolvesTo('127.0.0.1'),
    });
    expect(!decision.allowed && decision.rule).toBe('forbiddenAddress');
    expect(!decision.allowed && decision.detail).toContain('127.0.0.1');
  });

  it('refuses an in-scope name that resolves to the cloud metadata endpoint', async () => {
    const decision = await checkScope(context(), 'app.client.example', {
      now: NOW,
      resolve: resolvesTo('169.254.169.254'),
    });
    expect(!decision.allowed && decision.rule).toBe('forbiddenAddress');
    expect(!decision.allowed && decision.detail).toContain('metadata');
  });

  it('refuses when any one of several answers is forbidden', async () => {
    const decision = await checkScope(context(), 'app.client.example', {
      now: NOW,
      resolve: resolvesTo('93.184.216.34', '10.0.0.5'),
    });
    expect(!decision.allowed && decision.rule).toBe('forbiddenAddress');
  });

  it('refuses a resolved address outside an explicitly listed range', async () => {
    const decision = await checkScope(
      context({
        scopeItems: [
          scopeItem({ kind: 'wildcard', value: '*.client.example' }),
          scopeItem({ kind: 'cidr', value: '93.184.216.0/24' }),
        ],
      }),
      'app.client.example',
      { now: NOW, resolve: resolvesTo('8.8.8.8') },
    );
    expect(!decision.allowed && decision.rule).toBe('resolvedAddressNotInScope');
  });

  it('requires an acknowledgement when a name looks like shared hosting', async () => {
    const decision = await checkScope(
      context({ thirdPartyInfrastructureAcknowledged: false }),
      'app.client.example',
      { now: NOW, resolve: resolvesTo('93.184.216.34', '151.101.1.69') },
    );
    expect(!decision.allowed && decision.rule).toBe('thirdPartyInfrastructureUnacknowledged');
  });

  it('refuses when resolution fails rather than proceeding blind', async () => {
    const decision = await checkScope(context(), 'app.client.example', {
      now: NOW,
      resolve: () => Promise.reject(new Error('ENOTFOUND')),
    });
    expect(!decision.allowed && decision.rule).toBe('dnsResolutionFailed');
  });

  it('refuses when resolution returns nothing', async () => {
    const decision = await checkScope(context(), 'app.client.example', {
      now: NOW,
      resolve: resolvesTo(),
    });
    expect(!decision.allowed && decision.rule).toBe('dnsResolutionFailed');
  });
});

describe('checkScope — panic stop and malformed input', () => {
  it('refuses everything while a panic stop is in force', async () => {
    const decision = await checkScope(context({ panicStopActive: true }), 'app.client.example', {
      now: NOW,
      resolve: publicAddress,
    });
    expect(!decision.allowed && decision.rule).toBe('panicStopActive');
  });

  it('refuses schemes and shapes the platform will not contact', async () => {
    for (const target of [
      'file:///etc/passwd',
      'gopher://app.client.example',
      'https://app.client.example@attacker.net/',
      '',
      'not a url at all',
    ]) {
      const decision = await checkScope(context(), target, { now: NOW, resolve: publicAddress });
      expect(!decision.allowed && decision.rule, target).toBe('unparseableTarget');
    }
  });

  it('refuses an obfuscated loopback literal', async () => {
    // 0x7f.1 canonicalises to 127.0.0.1, which the address rules then refuse.
    const decision = await checkScope(
      context({ scopeItems: [scopeItem({ kind: 'ip', value: '127.0.0.1' })] }),
      'http://0x7f.1/',
      { now: NOW, resolve: publicAddress },
    );
    expect(!decision.allowed && decision.rule).toBe('forbiddenAddress');
  });
});

describe('checkScope — cloud policy acknowledgement', () => {
  it('refuses a cloud run until the provider policy is acknowledged', async () => {
    const decision = await checkScope(context(), 'app.client.example', {
      now: NOW,
      resolve: publicAddress,
      requiresCloudPolicyAcknowledgement: true,
    });
    expect(!decision.allowed && decision.rule).toBe('cloudTestingPolicyUnacknowledged');
  });

  it('allows once it is acknowledged', async () => {
    const decision = await checkScope(
      context({ cloudTestingPolicyAcknowledged: true }),
      'app.client.example',
      { now: NOW, resolve: publicAddress, requiresCloudPolicyAcknowledgement: true },
    );
    expect(decision.allowed).toBe(true);
  });
});

describe('test windows', () => {
  const businessHours = [{ daysOfWeek: [1, 2, 3, 4, 5], startMinute: 9 * 60, endMinute: 17 * 60 }];

  it('is open inside the window and closed outside it', () => {
    expect(isInsideTestWindow(businessHours, new Date('2026-08-19T10:00:00Z'), 'UTC')).toBe(true);
    expect(isInsideTestWindow(businessHours, new Date('2026-08-19T08:59:00Z'), 'UTC')).toBe(false);
    expect(isInsideTestWindow(businessHours, new Date('2026-08-19T17:00:00Z'), 'UTC')).toBe(false);
    expect(isInsideTestWindow(businessHours, new Date('2026-08-22T12:00:00Z'), 'UTC')).toBe(false);
  });

  it('is evaluated in the client timezone, not in UTC', () => {
    // 05:00 UTC is 10:30 in Kolkata, which is inside business hours there and outside them in UTC.
    const instant = new Date('2026-08-19T05:00:00Z');
    expect(isInsideTestWindow(businessHours, instant, 'Asia/Kolkata')).toBe(true);
    expect(isInsideTestWindow(businessHours, instant, 'UTC')).toBe(false);
  });

  it('treats an empty window list as no restriction', () => {
    expect(isInsideTestWindow([], new Date('2026-08-22T03:00:00Z'), 'UTC')).toBe(true);
  });

  it('refuses a run outside the window', async () => {
    const decision = await checkScope(
      context({ testWindows: businessHours, timezone: 'UTC' }),
      'app.client.example',
      { now: new Date('2026-08-19T22:00:00Z'), resolve: publicAddress },
    );
    expect(!decision.allowed && decision.rule).toBe('outsideTestWindow');
  });
});

describe('checkScope — properties', () => {
  it('never allows a target when the engagement has no authorisation', async () => {
    await fc.assert(
      fc.asyncProperty(fc.string(), async (target) => {
        const decision = await checkScope(context({ authorisation: null }), target, {
          now: NOW,
          resolve: publicAddress,
        });
        expect(decision.allowed).toBe(false);
      }),
      { numRuns: 300 },
    );
  });

  it('never allows anything at all while a panic stop is in force', async () => {
    await fc.assert(
      fc.asyncProperty(fc.string(), async (target) => {
        const decision = await checkScope(context({ panicStopActive: true }), target, {
          now: NOW,
          resolve: publicAddress,
        });
        expect(decision.allowed).toBe(false);
      }),
      { numRuns: 300 },
    );
  });

  it('never allows a host outside the scoped domain, whatever the label soup', async () => {
    const noise = fc.stringMatching(/^[a-z0-9-]{1,12}$/);
    await fc.assert(
      fc.asyncProperty(noise, noise, async (left, right) => {
        for (const target of [
          `${left}client.example`,
          `client.example.${right}.net`,
          `${left}.client.example.${right}`,
          `client-example.${right}`,
        ]) {
          const decision = await checkScope(context(), target, { now: NOW, resolve: publicAddress });
          if (decision.allowed) {
            expect.fail(`allowed out-of-scope target: ${target}`);
          }
        }
      }),
      { numRuns: 300 },
    );
  });

  it('always returns a decision, never throws', async () => {
    await fc.assert(
      fc.asyncProperty(fc.string(), async (target) => {
        const decision = await checkScope(context(), target, { now: NOW, resolve: publicAddress });
        expect(typeof decision.allowed).toBe('boolean');
        if (!decision.allowed) expect(decision.detail.length).toBeGreaterThan(0);
      }),
      { numRuns: 500 },
    );
  });
});

describe('validateScopeItem', () => {
  it('accepts well-formed items', () => {
    expect(validateScopeItem({ kind: 'domain', value: 'app.client.example' })).toBeNull();
    expect(validateScopeItem({ kind: 'wildcard', value: '*.client.example' })).toBeNull();
    expect(validateScopeItem({ kind: 'wildcard', value: 'client.example' })).toBeNull();
    // A routable address. 203.0.113.0/24 is TEST-NET-3 and the run-time guard refuses it, so
    // accepting it here would be the entry check disagreeing with the check that matters.
    expect(validateScopeItem({ kind: 'ip', value: '93.184.216.34' })).toBeNull();
    expect(validateScopeItem({ kind: 'cidr', value: '10.20.0.0/16' })).toBeNull();
    expect(validateScopeItem({ kind: 'url', value: 'https://app.client.example/api' })).toBeNull();
    expect(validateScopeItem({ kind: 'mobilePackage', value: 'com.client.app' })).toBeNull();
  });

  it('refuses what the run-time guard would refuse anyway', () => {
    // Each of these was accepted at entry before, sat in the engagement record, and then refused
    // the entire run on test day.
    expect(validateScopeItem({ kind: 'ip', value: '127.0.0.1' })).not.toBeNull();
    expect(validateScopeItem({ kind: 'ip', value: '169.254.169.254' })).not.toBeNull();
    expect(validateScopeItem({ kind: 'ip', value: '10.0.0.5' })).not.toBeNull();
    expect(validateScopeItem({ kind: 'wildcard', value: '*.gov.in' })).not.toBeNull();
    expect(validateScopeItem({ kind: 'domain', value: 'portal.gov.in' })).not.toBeNull();
    expect(validateScopeItem({ kind: 'domain', value: 'api.stripe.com' })).not.toBeNull();
    expect(validateScopeItem({ kind: 'url', value: 'http://169.254.169.254/latest/meta-data/' })).not.toBeNull();
  });

  it('refuses a wildcard that covers a whole registry', () => {
    expect(validateScopeItem({ kind: 'wildcard', value: '*.com' })).not.toBeNull();
    expect(validateScopeItem({ kind: 'wildcard', value: '*.in' })).not.toBeNull();
    expect(validateScopeItem({ kind: 'wildcard', value: '*.co.uk' })).not.toBeNull();
    expect(validateScopeItem({ kind: 'cidr', value: '0.0.0.0/0' })).not.toBeNull();
  });

  it('allows a private address only inside a range the client has declared', () => {
    expect(validateScopeItem({ kind: 'ip', value: '10.20.30.40' })).not.toBeNull();
    expect(
      validateScopeItem({ kind: 'ip', value: '10.20.30.40' }, { ownedPrivateRanges: ['10.20.0.0/16'] }),
    ).toBeNull();
  });

  it('rejects typos at entry time, so they are not discovered on test day', () => {
    expect(validateScopeItem({ kind: 'domain', value: 'app client.example' })).not.toBeNull();
    expect(validateScopeItem({ kind: 'wildcard', value: '*client.example' })).not.toBeNull();
    expect(validateScopeItem({ kind: 'ip', value: '203.0.113.999' })).not.toBeNull();
    expect(validateScopeItem({ kind: 'cidr', value: '203.0.113.0/33' })).not.toBeNull();
    expect(validateScopeItem({ kind: 'url', value: 'ftp://files.client.example' })).not.toBeNull();
    expect(validateScopeItem({ kind: 'mobilePackage', value: 'clientapp' })).not.toBeNull();
    expect(validateScopeItem({ kind: 'domain', value: '' })).not.toBeNull();
  });
});
