import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import { registerOriginGuard } from './origin-guard.ts';

/**
 * These exist because the protection they cover was previously registered and never applied. A
 * plugin that is imported but not used looks like a control in review and is not one, so the test
 * asserts the behaviour rather than the presence of the wiring.
 */

async function buildApp() {
  const app = Fastify({ logger: false });
  registerOriginGuard(app, 'https://console.attestorsecurity.com');
  app.get('/thing', () => ({ ok: true }));
  app.post('/thing', () => ({ ok: true }));
  app.delete('/thing', () => ({ ok: true }));
  await app.ready();
  return app;
}

describe('origin guard', () => {
  it('refuses a state-changing request from another origin', async () => {
    const app = await buildApp();
    const response = await app.inject({
      method: 'POST',
      url: '/thing',
      headers: { origin: 'https://evil.example' },
    });
    expect(response.statusCode).toBe(403);
    await app.close();
  });

  it('allows a state-changing request from the configured origin', async () => {
    const app = await buildApp();
    const response = await app.inject({
      method: 'POST',
      url: '/thing',
      headers: { origin: 'https://console.attestorsecurity.com' },
    });
    expect(response.statusCode).toBe(200);
    await app.close();
  });

  it('allows a caller that sends no origin, because the console calls from its server', async () => {
    const app = await buildApp();
    const response = await app.inject({ method: 'POST', url: '/thing' });
    expect(response.statusCode).toBe(200);
    await app.close();
  });

  it('covers every state-changing method, not just POST', async () => {
    const app = await buildApp();
    const response = await app.inject({
      method: 'DELETE',
      url: '/thing',
      headers: { origin: 'https://evil.example' },
    });
    expect(response.statusCode).toBe(403);
    await app.close();
  });

  it('leaves reads alone', async () => {
    const app = await buildApp();
    const response = await app.inject({
      method: 'GET',
      url: '/thing',
      headers: { origin: 'https://evil.example' },
    });
    expect(response.statusCode).toBe(200);
    await app.close();
  });

  it('treats an opaque origin as something to refuse nothing on', async () => {
    const app = await buildApp();
    const response = await app.inject({
      method: 'POST',
      url: '/thing',
      headers: { origin: 'null' },
    });
    expect(response.statusCode).toBe(200);
    await app.close();
  });
});
