// API keys: the owner creates keys in the admin site so scripts and integrations can call the central platform's
// OpenAI-compatible endpoints (POST /v1/chat/completions, GET /v1/models) without a desktop device.
// Only the sha256 hash of a key is stored; the `dvk_...` secret is shown once at creation. Every request made with a
// key is logged like a device request (request_logs.api_key_id), and the key's last-used time and request count update.
import type { Ctx } from '../context.ts';
import type { Queryer } from '../db/pg-wire.ts';
import crypto from 'node:crypto';
import { fail, log, readJson, rejectUnknown, requireObject, sendJson, str, uuidParam } from '../http/util.ts';
import { sha256Hex } from '../crypto.ts';
import { guardOwner } from './auth.ts';

export const KEY_PREFIX = 'dvk_';
/** Scopes a key may carry. 'chat' allows POST /v1/chat/completions; 'models' allows GET /v1/models. */
export const KEY_SCOPES = ['chat', 'models'] as const;
export type ApiKeyScope = (typeof KEY_SCOPES)[number];
const MAX_KEYS = 200;

export interface ApiKeyAuth {
  keyId: string;
  name: string;
  scopes: ApiKeyScope[];
}

function view(r: any) {
  return {
    id: r.id,
    name: r.name,
    keyPrefix: r.key_prefix,
    last4: r.last4,
    scopes: (r.scopes ?? []).filter((s: unknown) => (KEY_SCOPES as readonly string[]).includes(s as string)),
    enabled: r.enabled,
    expiresAt: r.expires_at,
    lastUsedAt: r.last_used_at,
    requestCount: Number(r.request_count ?? 0),
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

function readScopes(v: unknown): ApiKeyScope[] {
  const list = Array.isArray(v) ? v : typeof v === 'string' ? v.split(',') : v === undefined ? ['chat'] : null;
  if (!list) fail(400, 'invalid_request', 'scopes must be a list or a comma-separated string');
  const out = [...new Set(list.map((s) => String(s).trim()).filter(Boolean))];
  if (out.length === 0) fail(400, 'invalid_request', 'at least one scope is required');
  for (const s of out) {
    if (!(KEY_SCOPES as readonly string[]).includes(s)) fail(400, 'invalid_request', `unknown scope "${s}"; known scopes: ${KEY_SCOPES.join(', ')}`);
  }
  return out as ApiKeyScope[];
}

function readExpiry(v: unknown): string | null {
  if (v === undefined || v === null || v === '' || v === 'never') return null;
  const t = Date.parse(String(v));
  if (!Number.isFinite(t)) fail(400, 'invalid_request', 'expiresAt must be an ISO date or "never"');
  const d = new Date(t);
  if (d.getTime() < Date.now()) fail(400, 'invalid_request', 'expiresAt must be in the future');
  if (d.getTime() > Date.now() + 10 * 365 * 24 * 3600 * 1000) fail(400, 'invalid_request', 'expiresAt may be at most 10 years ahead');
  return d.toISOString();
}

/** Lists every key. The secret itself is never sent again after creation. */
export async function listApiKeys(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query('SELECT * FROM api_keys ORDER BY created_at DESC');
  sendJson(ctx.res, 200, { keys: rows.map(view), scopes: KEY_SCOPES });
}

/**
 * Creates a key and returns its secret exactly once. The response also carries the ready-to-use Authorization header,
 * so the owner can paste it straight into a script.
 */
export async function createApiKey(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const body = requireObject(await readJson(ctx.req, 16 * 1024));
  rejectUnknown(body, ['name', 'scopes', 'expiresAt']);
  const name = str(body, 'name', { min: 1, max: 80 })!;
  if (/[\r\n]/.test(name)) fail(400, 'invalid_request', 'the name must be a single line');
  const scopes = readScopes(body.scopes);
  const expiresAt = readExpiry(body.expiresAt);
  // dvk_ + 48 hex characters: safe in any header, no ambiguous characters, 192 bits of entropy.
  const secret = KEY_PREFIX + crypto.randomBytes(24).toString('hex');
  const hash = sha256Hex(secret);
  const id = await ctx.deps.db.transaction(async (q) => {
    const n = await q.query('SELECT count(*)::int AS n FROM api_keys');
    if (n.rows[0].n >= MAX_KEYS) fail(409, 'too_many_keys', `there are already ${MAX_KEYS} API keys; delete one first`);
    const { rows } = await q.query(
      `INSERT INTO api_keys (name, key_hash, key_prefix, last4, scopes, enabled, expires_at) VALUES ($1, $2, $3, $4, $5, true, $6) RETURNING id`,
      [name, hash, secret.slice(0, 8), secret.slice(-4), JSON.stringify(scopes), expiresAt],
    );
    return rows[0].id as string;
  });
  log('info', 'api key created', { keyId: id });
  const { rows } = await ctx.deps.db.query('SELECT * FROM api_keys WHERE id = $1', [id]);
  sendJson(ctx.res, 201, {
    key: view(rows[0]),
    secret,
    authorizationHeader: `Bearer ${secret}`,
    note: 'Store this secret now. It is not stored in plain text and cannot be shown again.',
  });
}

/** Renames, re-scopes, enables/disables or re-sets the expiry of an existing key. */
export async function updateApiKey(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 16 * 1024));
  rejectUnknown(body, ['name', 'scopes', 'enabled', 'expiresAt']);
  const sets: string[] = [];
  const vals: unknown[] = [id];
  const add = (col: string, v: unknown) => {
    vals.push(v);
    sets.push(`${col} = $${vals.length}`);
  };
  const name = str(body, 'name', { min: 1, max: 80, optional: true });
  if (name !== undefined) {
    if (/[\r\n]/.test(name)) fail(400, 'invalid_request', 'the name must be a single line');
    add('name', name);
  }
  if (body.scopes !== undefined) add('scopes', JSON.stringify(readScopes(body.scopes)));
  if (body.enabled !== undefined) {
    if (typeof body.enabled !== 'boolean') fail(400, 'invalid_request', 'enabled must be true or false');
    add('enabled', body.enabled);
  }
  if (body.expiresAt !== undefined) add('expires_at', readExpiry(body.expiresAt));
  if (!sets.length) fail(400, 'invalid_request', 'nothing to change');
  const { rowCount } = await ctx.deps.db.query(`UPDATE api_keys SET ${sets.join(', ')}, updated_at = now() WHERE id = $1`, vals);
  if (!rowCount) fail(404, 'not_found', 'key not found');
  const { rows } = await ctx.deps.db.query('SELECT * FROM api_keys WHERE id = $1', [id]);
  sendJson(ctx.res, 200, { key: view(rows[0]) });
}

export async function deleteApiKey(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const { rowCount } = await ctx.deps.db.query('DELETE FROM api_keys WHERE id = $1', [id]);
  if (!rowCount) fail(404, 'not_found', 'key not found');
  sendJson(ctx.res, 200, { deleted: true });
}

/**
 * Authenticates a `Bearer dvk_...` request. Returns null when the bearer token is not an API key (device tokens are
 * handled elsewhere), and throws 401/403 for a key that is unknown, disabled, expired or missing the required scope.
 * The key's last-used stamp is refreshed at most once a minute; the request counter is incremented on every call.
 */
export async function authenticateApiKey(ctx: Ctx, requiredScope: ApiKeyScope): Promise<ApiKeyAuth | null> {
  const m = /^Bearer\s+(\S{20,128})$/.exec(ctx.req.headers.authorization ?? '');
  const token = m?.[1] ?? '';
  if (!token.startsWith(KEY_PREFIX)) return null;
  const hash = sha256Hex(token);
  const { rows } = await ctx.deps.db.query(
    `SELECT id, name, scopes, enabled, (expires_at IS NOT NULL AND expires_at <= now()) AS expired,
            (last_used_at IS NULL OR last_used_at < now() - interval '60 seconds') AS touch
       FROM api_keys WHERE key_hash = $1`,
    [hash],
  );
  const row = rows[0];
  if (!row) fail(401, 'invalid_api_key', 'this API key is not valid; it may have been deleted');
  if (!row.enabled) fail(403, 'api_key_disabled', 'this API key has been turned off by the owner');
  if (row.expired) fail(403, 'api_key_expired', 'this API key has expired; ask the owner for a new one');
  const scopes: string[] = Array.isArray(row.scopes) ? row.scopes : [];
  if (!scopes.includes(requiredScope)) {
    fail(403, 'missing_scope', `this API key is not allowed to use "${requiredScope}"; the owner must add that scope`);
  }
  try {
    await ctx.deps.db.query(
      `UPDATE api_keys SET request_count = request_count + 1${row.touch ? ', last_used_at = now()' : ''} WHERE id = $1`,
      [row.id],
    );
  } catch (e) {
    log('warn', 'could not record API key usage', { error: e instanceof Error ? e.message : String(e) });
  }
  return { keyId: row.id, name: row.name, scopes: scopes as ApiKeyScope[] };
}

/** Per-minute rate limit for API keys (Settings page). */
export async function apiKeyRateLimit(db: Queryer): Promise<number> {
  try {
    const { rows } = await db.query("SELECT (value)::text::int AS v FROM settings WHERE key = 'api_key_rate_limit_per_minute'");
    const v = Number(rows[0]?.v ?? 30);
    return Number.isInteger(v) && v >= 1 && v <= 600 ? v : 30;
  } catch {
    return 30;
  }
}
