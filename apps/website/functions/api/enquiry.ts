/**
 * Cloudflare Pages Function backing the contact form.
 *
 * It validates, checks the honeypot, verifies the Turnstile token and forwards the enquiry to an
 * inbox. Nothing is stored: there is no database on this site and adding one would be adding a
 * target for no benefit.
 *
 * Required environment: TURNSTILE_SECRET, RESEND_API_KEY, ENQUIRY_TO, ENQUIRY_FROM.
 */

interface Env {
  TURNSTILE_SECRET: string;
  RESEND_API_KEY: string;
  ENQUIRY_TO: string;
  ENQUIRY_FROM: string;
}

interface EnquiryFields {
  name: string;
  email: string;
  company: string;
  message: string;
}

const LIMITS = { name: 120, email: 200, company: 150, message: 4000 } as const;

function json(status: number, body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

function readField(form: FormData, key: keyof typeof LIMITS): string {
  const value = form.get(key);
  return typeof value === 'string' ? value.trim().slice(0, LIMITS[key]) : '';
}

async function turnstilePasses(token: string, secret: string, remoteIp: string): Promise<boolean> {
  const body = new FormData();
  body.append('secret', secret);
  body.append('response', token);
  if (remoteIp) body.append('remoteip', remoteIp);

  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body,
  });
  const outcome = (await response.json()) as { success?: boolean };
  return outcome.success === true;
}

export const onRequestPost = async ({
  request,
  env,
}: {
  request: Request;
  env: Env;
}): Promise<Response> => {
  const form = await request.formData();

  // The honeypot is named after a field a form filler would expect, and is hidden from people.
  if (typeof form.get('companyWebsite') === 'string' && form.get('companyWebsite') !== '') {
    // Answer as though it worked. Telling a bot it failed only teaches it.
    return json(200, { ok: true });
  }

  const fields: EnquiryFields = {
    name: readField(form, 'name'),
    email: readField(form, 'email'),
    company: readField(form, 'company'),
    message: readField(form, 'message'),
  };

  const missing = Object.entries(fields)
    .filter(([, value]) => value === '')
    .map(([key]) => key);
  if (missing.length > 0) {
    return json(400, { ok: false, error: `missing: ${missing.join(', ')}` });
  }
  if (!/^[^@\s]+@[^@\s.]+\.[^@\s]+$/.test(fields.email)) {
    return json(400, { ok: false, error: 'that email address does not look right' });
  }

  const token = form.get('cf-turnstile-response');
  if (typeof token !== 'string' || token === '') {
    return json(400, { ok: false, error: 'challenge missing' });
  }
  const remoteIp = request.headers.get('CF-Connecting-IP') ?? '';
  if (!(await turnstilePasses(token, env.TURNSTILE_SECRET, remoteIp))) {
    return json(400, { ok: false, error: 'challenge failed' });
  }

  const text = [
    `Name: ${fields.name}`,
    `Email: ${fields.email}`,
    `Company: ${fields.company}`,
    '',
    fields.message,
  ].join('\n');

  const sent = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: env.ENQUIRY_FROM,
      to: [env.ENQUIRY_TO],
      reply_to: fields.email,
      subject: `Enquiry from ${fields.company}`,
      text,
    }),
  });

  if (!sent.ok) {
    // Do not echo the provider's response: it can contain the API key in an error envelope.
    return json(502, { ok: false, error: 'could not send, please email us directly' });
  }

  return json(200, { ok: true });
};

export const onRequest = (): Response =>
  json(405, { ok: false, error: 'this endpoint accepts POST only' });
