import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { transportFor } from './ai-transport.ts';

/**
 * vLLM, Gemini and OpenAI all speak the chat-completions format. These run the real transport
 * against a local stand-in for such a server, so what is asserted is the request that actually
 * leaves the process, not a mock of it.
 */

interface Captured {
  url: string;
  authorization: string | undefined;
  body: Record<string, unknown>;
}

let server: Server;
let baseUrl: string;
const captured: Captured[] = [];
let reply = '';

function readBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    request.on('data', (chunk: Buffer) => (data += chunk.toString('utf8')));
    request.on('end', () => resolve(data));
  });
}

beforeAll(async () => {
  const handle = async (request: IncomingMessage, response: ServerResponse) => {
    captured.push({
      url: request.url ?? '',
      authorization: request.headers.authorization,
      body: JSON.parse(await readBody(request)) as Record<string, unknown>,
    });
    response.setHeader('content-type', 'application/json');
    response.end(
      JSON.stringify({
        choices: [{ message: { content: reply } }],
        usage: { prompt_tokens: 11, completion_tokens: 7 },
      }),
    );
  };
  server = createServer((request, response) => {
    void handle(request, response);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1`;
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

const request = { model: 'chatbot-llm', maxTokens: 500, system: 'sys', userContent: 'hello', purpose: 'executiveSummary' as const };

describe('transportFor', () => {
  it('talks to a self-hosted vLLM server with no key', async () => {
    reply = 'A draft.';
    captured.length = 0;

    const result = await transportFor('vllm', undefined, baseUrl)(request);

    expect(result).toEqual({ text: 'A draft.', inputTokens: 11, outputTokens: 7 });
    expect(captured[0]?.url).toBe('/v1/chat/completions');
    expect(captured[0]?.authorization).toBeUndefined();
    expect(captured[0]?.body.model).toBe('chatbot-llm');
    expect(captured[0]?.body.max_tokens).toBe(500);
  });

  it('sends the key and the parameter OpenAI expects', async () => {
    captured.length = 0;
    await transportFor('openai', 'sk-test', baseUrl)(request);

    expect(captured[0]?.authorization).toBe('Bearer sk-test');
    expect(captured[0]?.body.max_completion_tokens).toBe(500);
    expect(captured[0]?.body.max_tokens).toBeUndefined();
  });

  it('keeps a reasoning model’s working out of the report', async () => {
    reply = '<think>let me consider the findings…</think>\n\nThe application exposes customer data.';
    const result = await transportFor('vllm', undefined, baseUrl)(request);

    expect(result.text).toBe('The application exposes customer data.');
  });

  it('refuses rather than calling out when it is misconfigured', () => {
    expect(() => transportFor('vllm', undefined, undefined)(request)).toThrow(
      'no AI provider is configured',
    );
    expect(() => transportFor('gemini', undefined)(request)).toThrow('no AI provider is configured');
  });
});
