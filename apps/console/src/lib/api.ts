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

  const text = await response.text();
  const body: unknown = text === '' ? null : JSON.parse(text);

  if (!response.ok) throw new ApiError(response.status, body);
  return body as T;
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
