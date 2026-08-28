import { cookies } from 'next/headers';
import { currentSurface } from '@/lib/surface';

/**
 * The API client.
 *
 * Every call is server-side and forwards the caller's session cookie. Nothing in the browser holds
 * a token: the session cookie is HttpOnly and the page fetches on the user's behalf, so an XSS in
 * the console cannot read a credential it never had.
 *
 * `surface` decides which API this deployment talks to. A portal deployment cannot reach the
 * console API because its base URL does not point there.
 */

function baseUrl(): string {
  const url =
    currentSurface() === 'portal'
      ? process.env.ATTESTOR_PORTAL_API_URL
      : process.env.ATTESTOR_API_URL;
  if (!url) {
    throw new Error(
      `${currentSurface() === 'portal' ? 'ATTESTOR_PORTAL_API_URL' : 'ATTESTOR_API_URL'} is not set`,
    );
  }
  return url.replace(/\/$/, '');
}

export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;

  constructor(status: number, body: unknown) {
    super(`api responded ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const store = await cookies();
  const cookieHeader = store
    .getAll()
    .map((entry) => `${entry.name}=${entry.value}`)
    .join('; ');

  const response = await fetch(`${baseUrl()}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(cookieHeader ? { cookie: cookieHeader } : {}),
      ...init.headers,
    },
    // Engagement data changes while a run is in flight; a cached page would show a stale queue.
    cache: 'no-store',
  });

  await forwardSessionCookies(response);

  const text = await response.text();
  const body: unknown = text === '' ? null : JSON.parse(text);

  if (!response.ok) throw new ApiError(response.status, body);
  return body as T;
}

/**
 * Pass the API's `Set-Cookie` on to the browser.
 *
 * Without this the session cookie the API issues at sign-in is read into this process and dropped:
 * the browser never receives it, the next request carries nothing, and the second factor is
 * answered with "not signed in". Nobody can sign in to either surface at all.
 *
 * It is invisible to a build, a typecheck and the test suite, and invisible to a stub API too,
 * because a stub has no session to issue.
 */
async function forwardSessionCookies(response: Response): Promise<void> {
  const headers = response.headers.getSetCookie();
  if (headers.length === 0) return;

  const store = await cookies();
  for (const header of headers) {
    const parsed = parseSetCookie(header);
    if (!parsed) continue;
    try {
      store.set(parsed.name, parsed.value, parsed.options);
    } catch {
      // Cookies can only be written from a Server Action or a Route Handler. A read during a page
      // render has no business setting one, so there is nothing to do here.
      return;
    }
  }
}

interface ParsedCookie {
  name: string;
  value: string;
  options: {
    path?: string;
    expires?: Date;
    maxAge?: number;
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: 'strict' | 'lax' | 'none';
  };
}

function parseSetCookie(header: string): ParsedCookie | null {
  const [pair, ...attributes] = header.split(';');
  if (!pair) return null;
  const equals = pair.indexOf('=');
  if (equals === -1) return null;

  const parsed: ParsedCookie = {
    name: pair.slice(0, equals).trim(),
    value: pair.slice(equals + 1).trim(),
    options: {},
  };

  for (const attribute of attributes) {
    const [rawName, ...rest] = attribute.split('=');
    const name = rawName?.trim().toLowerCase();
    const value = rest.join('=').trim();

    if (name === 'path') parsed.options.path = value;
    else if (name === 'expires') {
      const date = new Date(value);
      if (!Number.isNaN(date.getTime())) parsed.options.expires = date;
    } else if (name === 'max-age') {
      const seconds = Number(value);
      if (Number.isFinite(seconds)) parsed.options.maxAge = seconds;
    } else if (name === 'httponly') parsed.options.httpOnly = true;
    else if (name === 'secure') parsed.options.secure = true;
    else if (name === 'samesite') {
      const lowered = value.toLowerCase();
      if (lowered === 'strict' || lowered === 'lax' || lowered === 'none') {
        parsed.options.sameSite = lowered;
      }
    }
  }

  return parsed;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, payload?: unknown) =>
    request<T>(path, { method: 'POST', body: payload === undefined ? undefined : JSON.stringify(payload) }),
  put: <T>(path: string, payload?: unknown) =>
    request<T>(path, { method: 'PUT', body: payload === undefined ? undefined : JSON.stringify(payload) }),
  delete: <T>(path: string, payload?: unknown) =>
    request<T>(path, { method: 'DELETE', body: payload === undefined ? undefined : JSON.stringify(payload) }),
};

/** Returns null instead of throwing when the caller is not signed in, so a page can redirect. */
export async function tryGet<T>(path: string): Promise<T | null> {
  try {
    return await request<T>(path);
  } catch (error) {
    if (error instanceof ApiError && (error.status === 401 || error.status === 403)) return null;
    throw error;
  }
}

/**
 * Fetches a non-JSON response (a rendered report, a PDF) with the caller's session forwarded.
 *
 * The API sets its session cookie SameSite=strict, so a browser navigating straight to the API
 * origin would send nothing and get a 401. The bytes therefore come through this server instead.
 */
export async function fetchRaw(path: string): Promise<Response> {
  const store = await cookies();
  const cookieHeader = store
    .getAll()
    .map((entry) => `${entry.name}=${entry.value}`)
    .join('; ');

  return fetch(`${baseUrl()}${path}`, {
    headers: cookieHeader ? { cookie: cookieHeader } : {},
    cache: 'no-store',
  });
}
