// OpenAI-compatible upstream adapter. Used by provider tests, model discovery and central chat routing.
// Capabilities are never inferred from names; this adapter only reports what the provider answered.
import { fail } from '../http/util.ts';

export type UpstreamFailure = 'auth' | 'rate_limited' | 'timeout' | 'unreachable' | 'rejected' | 'server' | 'bad_response';

export class UpstreamError extends Error {
  readonly kind: UpstreamFailure;
  readonly status?: number;
  constructor(kind: UpstreamFailure, message: string, status?: number) {
    super(message);
    this.name = 'UpstreamError';
    this.kind = kind;
    this.status = status;
  }
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);
const BLOCKED_HOSTS = new Set(['169.254.169.254', '100.100.100.200', 'metadata.google.internal', 'metadata']);

/**
 * Validates and normalizes a provider base URL (for example https://api.example.com/v1).
 * Plain HTTP is allowed only for loopback hosts. Credentials, queries and fragments are refused.
 * Cloud metadata endpoints are refused for every provider.
 */
export function normalizeBaseUrl(input: string): string {
  let u: URL;
  try {
    u = new URL(input.trim());
  } catch {
    fail(400, 'invalid_request', 'baseUrl must be a full URL such as https://api.example.com/v1');
  }
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && LOOPBACK.has(u.hostname))) {
    fail(400, 'invalid_request', 'baseUrl must use https (plain http is allowed only for localhost)');
  }
  if (u.username || u.password) fail(400, 'invalid_request', 'baseUrl must not contain a username or password');
  if (u.search || u.hash) fail(400, 'invalid_request', 'baseUrl must not contain a query string or fragment');
  if (BLOCKED_HOSTS.has(u.hostname) || /^169\.254\./.test(u.hostname)) fail(400, 'invalid_request', 'this address is not allowed as a provider');
  const path = u.pathname.replace(/\/+$/, '');
  return `${u.protocol}//${u.host}${path}`;
}

/** Calls GET {base}/models. Used for provider tests and discovery. The response body is never returned verbatim. */
export async function listUpstreamModels(
  f: typeof fetch,
  baseUrl: string,
  apiKey: string | null,
  timeoutMs: number,
): Promise<string[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res: Response;
  try {
    res = await f(`${baseUrl}/models`, {
      method: 'GET',
      headers: apiKey ? { authorization: `Bearer ${apiKey}`, accept: 'application/json' } : { accept: 'application/json' },
      signal: controller.signal,
    });
  } catch (e) {
    if ((e as Error).name === 'AbortError') throw new UpstreamError('timeout', `the provider did not answer within ${Math.round(timeoutMs / 1000)} seconds`);
    throw new UpstreamError('unreachable', 'the provider could not be reached; check the base URL and the network');
  } finally {
    clearTimeout(timer);
  }
  if (res.status === 401 || res.status === 403) {
    await res.body?.cancel().catch(() => undefined);
    throw new UpstreamError('auth', `the provider rejected the API key (HTTP ${res.status})`, res.status);
  }
  if (res.status === 404) {
    await res.body?.cancel().catch(() => undefined);
    throw new UpstreamError('rejected', 'the base URL did not answer like an OpenAI-compatible API (HTTP 404); check that it ends with the API version, such as /v1', 404);
  }
  if (res.status === 429) {
    await res.body?.cancel().catch(() => undefined);
    throw new UpstreamError('rate_limited', 'the provider is rate limiting requests (HTTP 429)', 429);
  }
  if (res.status >= 500) {
    await res.body?.cancel().catch(() => undefined);
    throw new UpstreamError('server', `the provider returned a server error (HTTP ${res.status})`, res.status);
  }
  if (!res.ok) {
    await res.body?.cancel().catch(() => undefined);
    throw new UpstreamError('rejected', `the provider refused the request (HTTP ${res.status})`, res.status);
  }
  let json: any;
  try {
    json = await res.json();
  } catch {
    throw new UpstreamError('bad_response', 'the provider did not return a model list in the expected format');
  }
  if (!json || !Array.isArray(json.data)) throw new UpstreamError('bad_response', 'the provider did not return a model list in the expected format');
  return json.data.map((m: any) => m?.id).filter((id: unknown): id is string => typeof id === 'string' && id.length > 0 && id.length <= 200);
}

export function describeFailure(e: unknown): { ok: false; message: string; kind: UpstreamFailure | 'internal' } {
  if (e instanceof UpstreamError) return { ok: false, message: e.message, kind: e.kind };
  return { ok: false, message: 'the provider test failed unexpectedly', kind: 'internal' };
}
