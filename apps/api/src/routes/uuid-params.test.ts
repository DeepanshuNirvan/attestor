import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import { registerUuidParamGuard } from './uuid-params.ts';

/**
 * A mistyped id used to reach Postgres, which refuses a malformed uuid with a type error rather
 * than an empty result. That surfaced as a 500 from whichever handler ran the first query — an
 * unhandled error on a request that was never valid, on a surface that is public.
 */

async function buildApp() {
  const app = Fastify({ logger: false });
  registerUuidParamGuard(app);
  app.get('/engagements/:id', () => ({ ok: true }));
  app.get('/findings/:findingId', () => ({ ok: true }));
  app.get('/queue/scan/:jobId/retry', () => ({ ok: true }));
  app.get('/findings/by-reference/:reference', () => ({ ok: true }));
  await app.ready();
  return app;
}

describe('uuid parameter guard', () => {
  it('refuses a malformed id instead of letting it reach the database', async () => {
    const app = await buildApp();
    const response = await app.inject({ method: 'GET', url: '/engagements/not-a-uuid' });
    expect(response.statusCode).toBe(400);
    await app.close();
  });

  it('says nothing more than a missing row would', async () => {
    const app = await buildApp();
    const response = await app.inject({ method: 'GET', url: '/engagements/not-a-uuid' });
    expect(response.json()).toEqual({ error: 'not found' });
    await app.close();
  });

  it('allows a well-formed id through', async () => {
    const app = await buildApp();
    const response = await app.inject({
      method: 'GET',
      url: '/engagements/1b4e28ba-2fa1-11d2-883f-0016d3cca427',
    });
    expect(response.statusCode).toBe(200);
    await app.close();
  });

  it('covers every id-shaped parameter, not only :id', async () => {
    const app = await buildApp();
    const response = await app.inject({ method: 'GET', url: '/findings/nonsense' });
    expect(response.statusCode).toBe(400);
    await app.close();
  });

  it('leaves parameters that are not uuids alone', async () => {
    const app = await buildApp();
    // A queue job id is the queue's own counter, and a finding reference is not an id at all.
    expect((await app.inject({ method: 'GET', url: '/queue/scan/17/retry' })).statusCode).toBe(200);
    expect(
      (await app.inject({ method: 'GET', url: '/findings/by-reference/ATT-2026-001-F04' })).statusCode,
    ).toBe(200);
    await app.close();
  });
});
