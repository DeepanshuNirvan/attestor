import { describe, expect, it, vi } from 'vitest';
import { secretRegistry } from '@attestor/shared';
import {
  AiAssist,
  agenticRun,
  ungroundedClaims,
  type AiAssistDependencies,
  type AiTransportRequest,
  type AiTransportResponse,
} from './ai-assist.ts';

/**
 * Every one of these is a rule the brief states as non-negotiable, tested as a property of the code
 * rather than as an instruction in a prompt.
 */

function dependencies(
  overrides: Partial<AiAssistDependencies> = {},
  response: Partial<AiTransportResponse> = {},
): AiAssistDependencies & { sent: { userContent: string; model: string }[]; recorded: unknown[] } {
  const sent: { userContent: string; model: string }[] = [];
  const recorded: unknown[] = [];

  const base: AiAssistDependencies = {
    config: {
      enabled: true,
      provider: 'anthropic',
      modelDrafting: 'claude-sonnet-5',
      modelTriage: 'claude-haiku-4-5-20251001',
      monthlyBudgetUsd: 50,
      inputCostPerMillionUsd: 3,
      outputCostPerMillionUsd: 15,
    },
    transport: vi.fn((request: AiTransportRequest) => {
      sent.push({ userContent: request.userContent, model: request.model });
      return Promise.resolve({
        text: 'The application at app.client.example returned the record without a check.',
        inputTokens: 1_000,
        outputTokens: 200,
        ...response,
      });
    }),
    engagementEnabled: () => Promise.resolve(true),
    spentThisMonthUsd: () => Promise.resolve(0),
    record: (entry) => {
      recorded.push(entry);
      return Promise.resolve();
    },
    ...overrides,
  };

  return Object.assign(base, { sent, recorded });
}

const request = {
  engagementId: 'eng-1',
  purpose: 'findingProse' as const,
  evidence: ['GET /api/orders/41 returned order 41 for a user who owns order 40 at app.client.example'],
  instruction: 'Describe the issue and its impact.',
};

describe('the two switches', () => {
  it('refuses when the deployment has the AI layer off', async () => {
    const deps = dependencies({ config: { ...dependencies().config, enabled: false } });
    const outcome = await new AiAssist(deps).draft(request);

    expect(outcome.status).toBe('refused');
    if (outcome.status !== 'refused') return;
    expect(outcome.rule).toBe('deploymentDisabled');
    expect(deps.sent).toHaveLength(0);
  });

  it('refuses when no provider is configured', async () => {
    const deps = dependencies({ config: { ...dependencies().config, provider: 'none' } });
    const outcome = await new AiAssist(deps).draft(request);

    expect(outcome.status).toBe('refused');
    if (outcome.status !== 'refused') return;
    expect(outcome.rule).toBe('noProvider');
    expect(deps.sent).toHaveLength(0);
  });

  it('refuses when the engagement has not opted in, even with the deployment flag on', async () => {
    const deps = dependencies({ engagementEnabled: () => Promise.resolve(false) });
    const outcome = await new AiAssist(deps).draft(request);

    expect(outcome.status).toBe('refused');
    if (outcome.status !== 'refused') return;
    expect(outcome.rule).toBe('engagementDisabled');
    // The point of the test: nothing was sent to a third party.
    expect(deps.sent).toHaveLength(0);
  });
});

describe('what leaves the building', () => {
  it('redacts registered secrets before the request is built', async () => {
    secretRegistry.add('hunter2-the-client-password');
    const deps = dependencies();

    await new AiAssist(deps).draft({
      ...request,
      evidence: [`${request.evidence[0]!} using password hunter2-the-client-password`],
    });

    expect(deps.sent).toHaveLength(1);
    expect(deps.sent[0]!.userContent).not.toContain('hunter2-the-client-password');
    secretRegistry.clear();
  });

  it('redacts the instruction too, not only the evidence', async () => {
    secretRegistry.add('sk-live-abcdef123456');
    const deps = dependencies();

    await new AiAssist(deps).draft({ ...request, instruction: 'Explain the key sk-live-abcdef123456' });

    expect(deps.sent[0]!.userContent).not.toContain('sk-live-abcdef123456');
    secretRegistry.clear();
  });

  it('sends nothing at all when there is no evidence to ground a draft in', async () => {
    const deps = dependencies();
    const outcome = await new AiAssist(deps).draft({ ...request, evidence: ['', '   '] });

    expect(outcome.status).toBe('refused');
    if (outcome.status !== 'refused') return;
    expect(outcome.rule).toBe('noEvidence');
    expect(deps.sent).toHaveLength(0);
  });
});

describe('the budget', () => {
  it('refuses once the monthly ceiling is reached', async () => {
    const deps = dependencies({ spentThisMonthUsd: () => Promise.resolve(50) });
    const outcome = await new AiAssist(deps).draft(request);

    expect(outcome.status).toBe('refused');
    if (outcome.status !== 'refused') return;
    expect(outcome.rule).toBe('budgetExhausted');
    expect(deps.sent).toHaveLength(0);
  });

  it('refuses everything when the ceiling is zero, which is the default', async () => {
    const deps = dependencies({ config: { ...dependencies().config, monthlyBudgetUsd: 0 } });
    const outcome = await new AiAssist(deps).draft(request);

    expect(outcome.status).toBe('refused');
    if (outcome.status !== 'refused') return;
    expect(outcome.rule).toBe('budgetExhausted');
  });

  it('estimates the cost from the token counts the provider reported', async () => {
    const deps = dependencies();
    const outcome = await new AiAssist(deps).draft(request);

    expect(outcome.status).toBe('drafted');
    if (outcome.status !== 'drafted') return;
    // 1000 in at $3/M plus 200 out at $15/M.
    expect(outcome.estimatedCostUsd).toBeCloseTo(0.003 + 0.003, 6);
  });
});

describe('grounding', () => {
  it('discards a draft that names a host the evidence never mentioned', async () => {
    const deps = dependencies({}, { text: 'The issue also affects admin.other-company.example.' });
    const outcome = await new AiAssist(deps).draft(request);

    expect(outcome.status).toBe('refused');
    if (outcome.status !== 'refused') return;
    expect(outcome.rule).toBe('ungrounded');
    expect(outcome.detail).toContain('admin.other-company.example');
  });

  it('discards a draft that invents a CVE', async () => {
    const deps = dependencies({}, { text: 'This is CVE-2021-44228 in app.client.example.' });
    const outcome = await new AiAssist(deps).draft(request);

    expect(outcome.status).toBe('refused');
    if (outcome.status !== 'refused') return;
    expect(outcome.rule).toBe('ungrounded');
  });

  it('accepts a draft that only repeats what the evidence contains', async () => {
    const deps = dependencies();
    const outcome = await new AiAssist(deps).draft(request);

    expect(outcome.status).toBe('drafted');
  });

  it('records the usage even when the output is discarded, because the money was spent', async () => {
    const deps = dependencies({}, { text: 'See evil.example.com for details.' });
    await new AiAssist(deps).draft(request);

    expect(deps.recorded).toHaveLength(1);
  });

  it('finds an invented URL among grounded text', () => {
    expect(
      ungroundedClaims('Fixed at https://good.example/a and https://bad.example/b', [
        'https://good.example/a',
      ]),
    ).toEqual(['https://bad.example/b']);
  });
});

describe('provenance', () => {
  it('always returns a draft, never approved text', async () => {
    const outcome = await new AiAssist(dependencies()).draft(request);

    expect(outcome.status).toBe('drafted');
    if (outcome.status !== 'drafted') return;
    expect(outcome.isDraft).toBe(true);
  });

  it('records the model and a prompt hash, so a sentence can be traced a year later', async () => {
    const deps = dependencies();
    const outcome = await new AiAssist(deps).draft(request);

    expect(outcome.status).toBe('drafted');
    if (outcome.status !== 'drafted') return;
    expect(outcome.model).toBe('claude-sonnet-5');
    expect(outcome.promptSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(deps.recorded[0]).toMatchObject({ model: 'claude-sonnet-5', purpose: 'findingProse' });
  });

  it('uses the cheaper model for triage work', async () => {
    const deps = dependencies();
    await new AiAssist(deps).draft({ ...request, purpose: 'toolOutputExplanation' });

    expect(deps.sent[0]!.model).toBe('claude-haiku-4-5-20251001');
  });
});

describe('agentic testing', () => {
  it('is refused, always, with a reason a person can act on', () => {
    const outcome = agenticRun();

    expect(outcome.status).toBe('refused');
    expect(outcome.detail).toContain('not enabled in this build');
  });
});
