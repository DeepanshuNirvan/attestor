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

export function openAiTransport(apiKey: string): AiTransport {
  return async (request: AiTransportRequest): Promise<AiTransportResponse> => {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({
        model: request.model,
        max_completion_tokens: request.maxTokens,
        messages: [
          { role: 'system', content: request.system },
          { role: 'user', content: request.userContent },
        ],
      }),
    });

    if (!response.ok) throw new Error(`the model provider responded ${response.status}`);

    const body = (await response.json()) as OpenAiResponse;

    return {
      text: body.choices?.[0]?.message?.content ?? '',
      inputTokens: body.usage?.prompt_tokens ?? 0,
      outputTokens: body.usage?.completion_tokens ?? 0,
    };
  };
}

export function transportFor(provider: string, apiKey: string | undefined): AiTransport {
  if (provider === 'anthropic' && apiKey) return anthropicTransport(apiKey);
  if (provider === 'openai' && apiKey) return openAiTransport(apiKey);
  return noTransport();
}
