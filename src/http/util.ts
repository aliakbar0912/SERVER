// Shared HTTP helpers: errors, bounded JSON bodies, cookies, client address, a small validator and a redacting logger.
import type { IncomingMessage, ServerResponse } from 'node:http';

export class HttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly headers: Record<string, string>;
  constructor(status: number, code: string, message: string, headers: Record<string, string> = {}) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
    this.headers = headers;
  }
}

export function fail(status: number, code: string, message: string, headers?: Record<string, string>): never {
  throw new HttpError(status, code, message, headers);
}

export function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const payload = status === 204 ? '' : JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    ...headers,
  });
  res.end(payload);
}

/** Admin and API errors use a stable code and a message that never contains secrets or upstream details. */
export function sendError(res: ServerResponse, err: HttpError): void {
  sendJson(res, err.status, { error: { code: err.code, message: err.message } }, err.headers);
}

/** Chat errors use the OpenAI error shape, so existing desktop clients parse them without changes. */
export function sendOpenAiError(res: ServerResponse, status: number, code: string, message: string, headers: Record<string, string> = {}): void {
  const type = status >= 500 ? 'server_error' : status === 429 ? 'rate_limit_error' : status === 401 || status === 403 ? 'authentication_error' : 'invalid_request_error';
  sendJson(res, status, { error: { message, type, code } }, headers);
}

/** Reads a request body up to `limit` bytes and parses it as a JSON object. */
export async function readJson(req: IncomingMessage, limit: number): Promise<Record<string, unknown>> {
  const declared = Number(req.headers['content-length'] ?? 0);
  if (declared > limit) fail(413, 'payload_too_large', 'the request body is too large');
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > limit) {
      req.destroy();
      fail(413, 'payload_too_large', 'the request body is too large');
    }
    chunks.push(chunk as Buffer);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  if (!text.trim()) return {};
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    fail(400, 'invalid_json', 'the request body is not valid JSON');
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(400, 'invalid_request', 'the request body must be a JSON object');
  return value as Record<string, unknown>;
}

export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 1) continue;
    const k = part.slice(0, eq).trim();
    if (!(k in out)) out[k] = decodeURIComponent(part.slice(eq + 1).trim());
  }
  return out;
}

export function setCookie(name: string, value: string, opts: { maxAgeSeconds: number; secure: boolean }): string {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${opts.maxAgeSeconds}${opts.secure ? '; Secure' : ''}`;
}

export function clearCookie(name: string, secure: boolean): string {
  return `${name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? '; Secure' : ''}`;
}

/** The address used for rate limits. X-Forwarded-For is trusted only when TRUST_PROXY is on (behind the Dokploy proxy). */
export function clientAddress(req: IncomingMessage, trustProxy: boolean): string {
  if (trustProxy) {
    const xff = req.headers['x-forwarded-for'];
    const last = (Array.isArray(xff) ? xff.join(',') : xff ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .pop();
    if (last) return last.slice(0, 64);
  }
  return (req.socket.remoteAddress ?? 'unknown').slice(0, 64);
}

export function userAgent(req: IncomingMessage): string {
  const ua = req.headers['user-agent'];
  return (Array.isArray(ua) ? ua[0] : ua ?? '').slice(0, 300);
}

// ---- validation -------------------------------------------------------------

type Json = Record<string, unknown>;

export function requireObject(v: unknown, what = 'body'): Json {
  if (!v || typeof v !== 'object' || Array.isArray(v)) fail(400, 'invalid_request', `${what} must be an object`);
  return v as Json;
}

export function rejectUnknown(body: Json, allowed: string[]): void {
  for (const k of Object.keys(body)) if (!allowed.includes(k)) fail(400, 'invalid_request', `unknown field "${k}"`);
}

export function str(body: Json, key: string, opts: { min?: number; max: number; optional?: boolean; pattern?: RegExp; trim?: boolean }): string | undefined {
  const raw = body[key];
  if (raw === undefined || raw === null) {
    if (opts.optional) return undefined;
    fail(400, 'invalid_request', `${key} is required`);
  }
  if (typeof raw !== 'string') fail(400, 'invalid_request', `${key} must be a string`);
  const value = opts.trim === false ? raw : raw.trim();
  if (value.length < (opts.min ?? 0)) fail(400, 'invalid_request', `${key} is too short`);
  if (value.length > opts.max) fail(400, 'invalid_request', `${key} is longer than ${opts.max} characters`);
  if (opts.pattern && value && !opts.pattern.test(value)) fail(400, 'invalid_request', `${key} has an invalid format`);
  return value;
}

export function int(body: Json, key: string, opts: { min: number; max: number; optional?: boolean }): number | undefined {
  const raw = body[key];
  if (raw === undefined || raw === null) {
    if (opts.optional) return undefined;
    fail(400, 'invalid_request', `${key} is required`);
  }
  if (typeof raw !== 'number' || !Number.isInteger(raw) || raw < opts.min || raw > opts.max) {
    fail(400, 'invalid_request', `${key} must be an integer from ${opts.min} to ${opts.max}`);
  }
  return raw;
}

export function bool(body: Json, key: string, opts: { optional?: boolean; def?: boolean } = {}): boolean | undefined {
  const raw = body[key];
  if (raw === undefined || raw === null) {
    if (opts.optional || opts.def !== undefined) return opts.def;
    fail(400, 'invalid_request', `${key} is required`);
  }
  if (typeof raw !== 'boolean') fail(400, 'invalid_request', `${key} must be true or false`);
  return raw;
}

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function uuidParam(value: string | undefined): string {
  if (!value || !UUID.test(value)) fail(404, 'not_found', 'not found');
  return value;
}

// ---- logging ------------------------------------------------------------------

const SENSITIVE_KEYS = /authorization|cookie|apikey|api_key|password|token|secret|content|messages|prompt/i;

/** Structured JSON lines to stdout. Keys that look sensitive are replaced, so prompts and secrets never reach the logs. */
export function log(level: 'info' | 'warn' | 'error', msg: string, fields: Record<string, unknown> = {}): void {
  const safe: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) safe[k] = SENSITIVE_KEYS.test(k) ? '[redacted]' : v;
  const line = JSON.stringify({ time: new Date().toISOString(), level, msg, ...safe });
  (level === 'error' ? process.stderr : process.stdout).write(line + '\n');
}
