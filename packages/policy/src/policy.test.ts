import { describe, expect, it } from 'vitest';
import { mergePolicyFragments, PolicyError, resolvePolicy, windowsToMinutes } from './resolve.ts';
import { RATE_CEILINGS } from './schema.ts';
import { listProfileFiles, loadProfile, PROFILE_IDS } from './profiles.ts';
import { CLOUD_TESTING_POLICIES, DENIAL_OF_SERVICE_CAPABILITY } from './cloud-testing-policies.ts';

const minimal = 'modules: [web]';

describe('resolvePolicy', () => {
  it('applies defaults for everything not stated', () => {
    const { policy } = resolvePolicy([{ name: 'global', yamlSource: minimal }]);
    expect(policy.intensity).toBe('standard');
    expect(policy.phases.preLogin).toBe(true);
    expect(policy.evidence.retentionDays).toBe(90);
    expect(policy.report.cvssVersion).toBe('4.0');
    expect(policy.ai.aiAssistEnabled).toBe(false);
    expect(policy.ai.agenticEnabled).toBe(false);
  });

  it('layers client over global and engagement over client', () => {
    const { policy } = resolvePolicy([
      { name: 'global', yamlSource: 'modules: [recon, web]\nintensity: safe' },
      { name: 'client', yamlSource: 'intensity: standard\nreadOnlyMode: true' },
      { name: 'engagement', yamlSource: 'modules: [web]' },
    ]);
    expect(policy.modules).toEqual(['web']);
    expect(policy.intensity).toBe('standard');
    expect(policy.readOnlyMode).toBe(true);
  });

  it('replaces arrays instead of concatenating them, so an override can narrow scope', () => {
    const { policy } = resolvePolicy([
      { name: 'global', yamlSource: 'modules: [recon, web, api, cloud]' },
      { name: 'engagement', yamlSource: 'modules: [llm]' },
    ]);
    expect(policy.modules).toEqual(['llm']);
  });

  it('rejects a policy with no modules', () => {
    expect(() => resolvePolicy([{ name: 'global', yamlSource: 'intensity: safe' }])).toThrow(
      PolicyError,
    );
  });

  it('rejects invalid YAML with the layer named', () => {
    try {
      resolvePolicy([{ name: 'client', yamlSource: 'modules: [web\nbroken' }]);
      expect.fail('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(PolicyError);
      expect((error as PolicyError).layer).toBe('client');
    }
  });

  it('rejects a top-level list, which is a common paste error', () => {
    expect(() => resolvePolicy([{ name: 'run', yamlSource: '- web\n- api' }])).toThrow(/mapping/);
  });
});

describe('rate ceilings', () => {
  it('refuses a policy that asks for more than the ceiling', () => {
    expect(() =>
      resolvePolicy([
        {
          name: 'engagement',
          yamlSource: `${minimal}\nrateLimits:\n  globalRequestsPerSecond: 500`,
        },
      ]),
    ).toThrow(PolicyError);

    expect(() =>
      resolvePolicy([
        { name: 'engagement', yamlSource: `${minimal}\nrateLimits:\n  concurrency: 200` },
      ]),
    ).toThrow(PolicyError);
  });

  it('never produces an effective rate above the ceiling, even through politeMode', () => {
    const { policy } = resolvePolicy([
      {
        name: 'engagement',
        yamlSource: `${minimal}\nrateLimits:\n  globalRequestsPerSecond: ${RATE_CEILINGS.globalRequestsPerSecond}\n  perTargetRequestsPerSecond: ${RATE_CEILINGS.perTargetRequestsPerSecond}\n  concurrency: ${RATE_CEILINGS.concurrency}`,
      },
    ]);
    expect(policy.rateLimits.globalRequestsPerSecond).toBeLessThanOrEqual(
      RATE_CEILINGS.globalRequestsPerSecond,
    );
    expect(policy.rateLimits.perTargetRequestsPerSecond).toBeLessThanOrEqual(
      RATE_CEILINGS.perTargetRequestsPerSecond,
    );
    expect(policy.rateLimits.concurrency).toBeLessThanOrEqual(RATE_CEILINGS.concurrency);
  });

  it('halves every limit in polite mode', () => {
    const { policy } = resolvePolicy([
      {
        name: 'engagement',
        yamlSource: `${minimal}\nrateLimits:\n  globalRequestsPerSecond: 10\n  perTargetRequestsPerSecond: 4\n  concurrency: 4\n  politeMode: true`,
      },
    ]);
    expect(policy.rateLimits.globalRequestsPerSecond).toBe(5);
    expect(policy.rateLimits.perTargetRequestsPerSecond).toBe(2);
    expect(policy.rateLimits.concurrency).toBe(2);
  });

  it('has no way to express denial-of-service testing', () => {
    // If this ever fails, somebody has added a setting that must not exist.
    expect(DENIAL_OF_SERVICE_CAPABILITY).toBe(false);
    const { policy } = resolvePolicy([{ name: 'global', yamlSource: minimal }]);
    expect(JSON.stringify(policy).toLowerCase()).not.toContain('denialofservice');
    expect(JSON.stringify(policy).toLowerCase()).not.toContain('flood');
    expect(JSON.stringify(policy).toLowerCase()).not.toContain('stresstest');
  });
});

describe('warnings', () => {
  it('warns when post-login is on but no authentication profile exists', () => {
    const { warnings } = resolvePolicy([{ name: 'global', yamlSource: minimal }]);
    expect(warnings.join(' ')).toContain('no authentication profiles');
  });

  it('warns when an authentication profile has no session indicator', () => {
    const { warnings } = resolvePolicy([
      {
        name: 'global',
        yamlSource: `${minimal}\nauthProfiles:\n  - id: customer\n    roleName: customer\n    type: formLogin\n    credentialSetId: cred-1`,
      },
    ]);
    expect(warnings.join(' ')).toContain('session indicator');
  });

  it('warns when a role names no second account, because horizontal access control needs two', () => {
    const { warnings } = resolvePolicy([
      {
        name: 'global',
        yamlSource: `${minimal}\nauthProfiles:\n  - id: customer\n    roleName: customer\n    type: formLogin\n    credentialSetId: cred-1\n    sessionIndicator:\n      selector: '#account-menu'`,
      },
    ]);
    expect(warnings.join(' ')).toContain('second account');
  });

  it('warns when cost-abuse testing has no ceiling or no acknowledgement', () => {
    const noCeiling = resolvePolicy([{ name: 'global', yamlSource: 'modules: [llm]' }]);
    expect(noCeiling.warnings.join(' ')).toContain('no spend or token ceiling');

    const unacknowledged = resolvePolicy([
      {
        name: 'global',
        yamlSource: 'modules: [llm]\nllm:\n  budget:\n    maxSpendUsd: 25',
      },
    ]);
    expect(unacknowledged.warnings.join(' ')).toContain('has not acknowledged');
  });

  it('warns when agentic testing is enabled with no spend ceiling', () => {
    const { warnings } = resolvePolicy([
      { name: 'global', yamlSource: `${minimal}\nai:\n  agenticEnabled: true` },
    ]);
    expect(warnings.join(' ')).toContain('no spend ceiling');
  });
});

describe('profiles', () => {
  it('ships exactly the five documented profiles and no orphans', async () => {
    const files = await listProfileFiles();
    expect(files.sort()).toEqual([...PROFILE_IDS].map((id) => `${id}.yaml`).sort());
  });

  it('every profile loads and validates', async () => {
    for (const id of PROFILE_IDS) {
      const { policy, warnings } = await loadProfile(id);
      expect(policy.modules.length, id).toBeGreaterThan(0);
      expect(policy.description, id).not.toBe('');
      expect(Array.isArray(warnings), id).toBe(true);
    }
  });

  it('the llm-only profile runs no web scanning at all', async () => {
    const { policy } = await loadProfile('llm-only');
    expect(policy.modules).toEqual(['llm']);
    expect(policy.accessControlMatrix.enabled).toBe(false);
  });

  it('the cloud-review profile is read-only and touches no network module', async () => {
    const { policy } = await loadProfile('cloud-review');
    expect(policy.modules).toEqual(['cloud']);
    expect(policy.readOnlyMode).toBe(true);
  });

  it('the quick-external profile never sends a state-changing request', async () => {
    const { policy } = await loadProfile('quick-external');
    expect(policy.readOnlyMode).toBe(true);
    expect(policy.phases.postLogin).toBe(false);
  });

  it('says so out loud when a policy layer drops nuclei informational templates', () => {
    const { warnings } = resolvePolicy([
      { name: 'engagement', yamlSource: `modules: [web]
checks:
  nucleiSeverities: [critical, high]
` },
    ]);
    expect(warnings.join(' ')).toContain('informational templates are excluded');
  });

  it('no profile drops nuclei informational templates', async () => {
    // Every exposure, metafile and exposed-panel template nuclei ships is `info`, and the catalogue
    // claims nuclei automates checks that only those templates can perform. A profile that trims
    // `info` off the severity list therefore removes a whole class of check from the run while the
    // report goes on saying the check was covered. Three profiles were doing exactly that, which is
    // invisible from the outside: an absent finding and an unperformed check look identical.
    for (const id of PROFILE_IDS) {
      const { policy } = await loadProfile(id);
      expect(policy.checks.nucleiSeverities, id).toContain('info');
    }
  });
});

describe('mergePolicyFragments', () => {
  it('merges nested objects key by key', () => {
    const merged = mergePolicyFragments(
      { rateLimits: { globalRequestsPerSecond: 10, concurrency: 4 } },
      { rateLimits: { concurrency: 2 } },
    );
    expect(merged).toEqual({ rateLimits: { globalRequestsPerSecond: 10, concurrency: 2 } });
  });

  it('ignores undefined so an absent key does not erase a set one', () => {
    expect(mergePolicyFragments({ intensity: 'safe' }, { intensity: undefined })).toEqual({
      intensity: 'safe',
    });
  });
});

describe('windowsToMinutes', () => {
  it('converts HH:MM into minutes from midnight', () => {
    expect(
      windowsToMinutes([{ daysOfWeek: [1, 2], start: '09:30', end: '17:00' }]),
    ).toEqual([{ daysOfWeek: [1, 2], startMinute: 570, endMinute: 1020 }]);
  });
});

describe('cloud testing policies', () => {
  it('records the prohibition every provider shares', () => {
    for (const policy of CLOUD_TESTING_POLICIES) {
      expect(policy.url).toMatch(/^https:\/\//);
      expect(policy.checkedOn).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(policy.prohibited.length, policy.provider).toBeGreaterThan(0);
    }
    const aws = CLOUD_TESTING_POLICIES.find((policy) => policy.provider === 'aws');
    expect(aws?.prohibited.join(' ').toLowerCase()).toContain('denial of service');
  });
});
