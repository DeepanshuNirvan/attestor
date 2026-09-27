import type { AiTransport, AiTransportRequest, AiTransportResponse } from '@attestor/core';

/**
 * The provider transport.
 *
 * Written against the HTTP API rather than a vendor SDK, because an SDK is a dependency that can
 * add telemetry, retries and a second code path for something that is one POST. The whole file is
 * replaceable: everything that matters — the switches, the redaction, the grounding check, the
 * usage record — lives in `AiAssist`, and this only carries bytes.
 *
 * There is no default. `AI_PROVIDER=none` means `noTransport`, which throws if anything ever
 * reaches it, and `AiAssist` refuses long before that.
 */

interface AnthropicResponse {
  content?: { type: string; text?: string }[];
  usage?: { input_tokens?: number; output_tokens?: number };
}

interface OpenAiResponse {
  choices?: { message?: { content?: string } }[];
  usage?: { prompt_tokens?: number; completion_tokens?: number };
}

export function noTransport(): AiTransport {
  return () => {
    throw new Error(
      'no AI provider is configured. This transport exists so that a misconfiguration fails loudly rather than silently sending nothing.',
    );
  };
}

export function anthropicTransport(apiKey: string): AiTransport {
  return async (request: AiTransportRequest): Promise<AiTransportResponse> => {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: request.model,
        max_tokens: request.maxTokens,
        system: request.system,
        messages: [{ role: 'user', content: request.userContent }],
      }),
    });

    if (!response.ok) {
      // The body can echo the prompt back. Only the status is surfaced.
      throw new Error(`the model provider responded ${response.status}`);
    }

    const body = (await response.json()) as AnthropicResponse;
    const text = (body.content ?? [])
      .filter((block) => block.type === 'text')
      .map((block) => block.text ?? '')
      .join('');

    return {
      text,
      inputTokens: body.usage?.input_tokens ?? 0,
      outputTokens: body.usage?.output_tokens ?? 0,
    };
  };
}

/**
 * The OpenAI chat-completions format, which OpenAI, Gemini and self-hosted servers such as vLLM all
 * speak. They differ in where they live, whether they need a key, and what the output limit is
 * called: OpenAI's current models refuse `max_tokens` and want `max_completion_tokens`, while Gemini
 * and vLLM take `max_tokens`.
 */
export function openAiCompatibleTransport(options: {
  baseUrl: string;
  apiKey?: string;
  tokenLimitParameter: 'max_tokens' | 'max_completion_tokens';
}): AiTransport {
  const url = `${options.baseUrl.replace(/\/+$/, '')}/chat/completions`;

  return async (request: AiTransportRequest): Promise<AiTransportResponse> => {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(options.apiKey ? { authorization: `Bearer ${options.apiKey}` } : {}),
      },
      body: JSON.stringify({
        model: request.model,
        [options.tokenLimitParameter]: request.maxTokens,
        messages: [
          { role: 'system', content: request.system },
          { role: 'user', content: request.userContent },
        ],
      }),
    });

    if (!response.ok) throw new Error(`the model provider responded ${response.status}`);

    const body = (await response.json()) as OpenAiResponse;
    const raw = body.choices?.[0]?.message?.content ?? '';

    return {
      // Reasoning models served with thinking switched on put it inline. It is working, not an
      // answer, and it must not reach a client's report.
      text: raw.replace(/<think>[\s\S]*?<\/think>/g, '').trim(),
      inputTokens: body.usage?.prompt_tokens ?? 0,
      outputTokens: body.usage?.completion_tokens ?? 0,
    };
  };
}

const DEFAULT_BASE_URL: Record<string, string> = {
  openai: 'https://api.openai.com/v1',
  gemini: 'https://generativelanguage.googleapis.com/v1beta/openai',
};

export function transportFor(
  provider: string,
  apiKey: string | undefined,
  baseUrl?: string,
): AiTransport {
  if (provider === 'anthropic' && apiKey) return anthropicTransport(apiKey);

  if (provider === 'openai' || provider === 'gemini' || provider === 'vllm') {
    const url = baseUrl ?? DEFAULT_BASE_URL[provider];
    // A hosted provider without a key, or vLLM without an address, is a misconfiguration; config
    // loading refuses both, and this refuses them again rather than sending an unauthenticated call.
    if (url === undefined || (provider !== 'vllm' && !apiKey)) return noTransport();
    return openAiCompatibleTransport({
      baseUrl: url,
      apiKey,
      tokenLimitParameter: provider === 'openai' ? 'max_completion_tokens' : 'max_tokens',
    });
  }

  return noTransport();
}
