// Providers: upstream endpoints the owner configures. API keys are encrypted at rest and never returned.
import type { Ctx, Deps } from '../context.ts';
import type { Queryer } from '../db/pg-wire.ts';
import { openSecret, sealSecret } from '../crypto.ts';
import { bool, fail, int, readJson, requireObject, rejectUnknown, sendJson, str, uuidParam } from '../http/util.ts';
import { guardOwner } from './auth.ts';
import { bumpCatalogue } from './catalogue.ts';
import { describeFailure, listUpstreamModels, normalizeBaseUrl } from './upstream.ts';
import { discoverProvider } from './registry.ts';

const KEY_PATTERN = /^[\x21-\x7E]{8,512}$/;

export function toProvider(r: any, modelCount = 0) {
  return {
    id: r.id,
    name: r.name,
    adapter: r.adapter,
    baseUrl: r.base_url,
    authScheme: r.auth_scheme,
    enabled: r.enabled,
    timeoutMs: r.timeout_ms,
    maxRetries: r.max_retries,
    hasApiKey: r.has_key === true,
    keyVersion: r.key_version ?? null,
    modelCount,
    lastTest: r.last_test_at
      ? { ok: r.last_test_ok, at: new Date(r.last_test_at).toISOString(), latencyMs: r.last_test_latency_ms, message: r.last_test_message, kind: r.last_test_kind ?? null }
      : null,
    discovery: r.discovery_at
      ? { ok: r.discovery_ok, supported: r.discovery_supported, at: new Date(r.discovery_at).toISOString(), message: r.discovery_message }
      : null,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

const SELECT_PROVIDER = `
  SELECT p.*, (s.provider_id IS NOT NULL) AS has_key, s.key_version,
         (SELECT count(*)::int FROM models m WHERE m.provider_id = p.id) AS model_count
    FROM providers p LEFT JOIN provider_secrets s ON s.provider_id = p.id`;

export async function listProviders(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query(`${SELECT_PROVIDER} ORDER BY p.name`);
  sendJson(ctx.res, 200, { providers: rows.map((r) => toProvider(r, r.model_count)) });
}

async function loadProvider(q: Queryer, id: string) {
  const { rows } = await q.query(`${SELECT_PROVIDER} WHERE p.id = $1`, [id]);
  if (!rows[0]) fail(404, 'not_found', 'provider not found');
  return rows[0];
}

export async function createProvider(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const body = requireObject(await readJson(ctx.req, 16 * 1024));
  rejectUnknown(body, ['name', 'adapter', 'baseUrl', 'authScheme', 'enabled', 'timeoutMs', 'maxRetries']);
  const name = str(body, 'name', { min: 1, max: 80 })!;
  const adapter = str(body, 'adapter', { max: 40, optional: true }) ?? 'openai-compatible';
  if (adapter !== 'openai-compatible') fail(400, 'invalid_request', 'adapter must be openai-compatible');
  const baseUrl = normalizeBaseUrl(str(body, 'baseUrl', { min: 8, max: 2048 })!);
  const authScheme = str(body, 'authScheme', { max: 10, optional: true }) ?? 'bearer';
  if (authScheme !== 'bearer' && authScheme !== 'none') fail(400, 'invalid_request', 'authScheme must be bearer or none');
  const enabled = bool(body, 'enabled', { def: true })!;
  const timeoutMs = int(body, 'timeoutMs', { min: 1000, max: 600000, optional: true }) ?? 120000;
  const maxRetries = int(body, 'maxRetries', { min: 0, max: 3, optional: true }) ?? 0;

  const created = await ctx.deps.db.transaction(async (q) => {
    const { rows } = await q.query(
      `INSERT INTO providers (name, adapter, base_url, auth_scheme, enabled, timeout_ms, max_retries)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [name, adapter, baseUrl, authScheme, enabled, timeoutMs, maxRetries],
    );
    await bumpCatalogue(q);
    return rows[0].id as string;
  }).catch((e) => {
    if (e?.code === '23505') fail(409, 'duplicate', 'a provider with this name already exists');
    throw e;
  });
  sendJson(ctx.res, 201, toProvider(await loadProvider(ctx.deps.db, created)));
}

export async function updateProvider(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 16 * 1024));
  rejectUnknown(body, ['name', 'baseUrl', 'authScheme', 'enabled', 'timeoutMs', 'maxRetries']);
  const current = await loadProvider(ctx.deps.db, id);
  const name = str(body, 'name', { min: 1, max: 80, optional: true }) ?? current.name;
  const baseUrl = body.baseUrl === undefined ? current.base_url : normalizeBaseUrl(str(body, 'baseUrl', { min: 8, max: 2048 })!);
  const authScheme = str(body, 'authScheme', { max: 10, optional: true }) ?? current.auth_scheme;
  if (authScheme !== 'bearer' && authScheme !== 'none') fail(400, 'invalid_request', 'authScheme must be bearer or none');
  const enabled = bool(body, 'enabled', { optional: true }) ?? current.enabled;
  const timeoutMs = int(body, 'timeoutMs', { min: 1000, max: 600000, optional: true }) ?? current.timeout_ms;
  const maxRetries = int(body, 'maxRetries', { min: 0, max: 3, optional: true }) ?? current.max_retries;
  const endpointChanged = baseUrl !== current.base_url || authScheme !== current.auth_scheme;

  await ctx.deps.db.transaction(async (q) => {
    await q.query(
      `UPDATE providers SET name = $2, base_url = $3, auth_scheme = $4, enabled = $5, timeout_ms = $6, max_retries = $7,
              last_test_ok = CASE WHEN $8 THEN NULL ELSE last_test_ok END,
              last_test_at = CASE WHEN $8 THEN NULL ELSE last_test_at END,
              updated_at = now()
        WHERE id = $1`,
      [id, name, baseUrl, authScheme, enabled, timeoutMs, maxRetries, endpointChanged],
    );
    if (!enabled) await q.query('UPDATE models SET is_default = false WHERE provider_id = $1', [id]);
    await bumpCatalogue(q);
  }).catch((e) => {
    if (e?.code === '23505') fail(409, 'duplicate', 'a provider with this name already exists');
    throw e;
  });
  sendJson(ctx.res, 200, toProvider(await loadProvider(ctx.deps.db, id)));
}

export async function deleteProvider(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true, sensitive: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ['confirmName']);
  const current = await loadProvider(ctx.deps.db, id);
  if (str(body, 'confirmName', { max: 80, optional: true }) !== current.name) fail(400, 'confirmation_mismatch', 'type the provider name exactly to delete it');
  await ctx.deps.db.transaction(async (q) => {
    await q.query('DELETE FROM providers WHERE id = $1', [id]);
    await bumpCatalogue(q);
  });
  sendJson(ctx.res, 200, { deleted: true });
}

const keyAad = (providerId: string) => `provider:${providerId}`;

/** Reads and decrypts a provider key inside the server. The result is never placed in a response or a log. */
export async function providerApiKey(deps: Deps, providerId: string): Promise<string | null> {
  const { rows } = await deps.db.query('SELECT key_version, iv, ciphertext, tag FROM provider_secrets WHERE provider_id = $1', [providerId]);
  if (!rows[0]) return null;
  return openSecret(
    deps.config.keyring,
    { keyVersion: rows[0].key_version, iv: rows[0].iv, ciphertext: rows[0].ciphertext, tag: rows[0].tag },
    keyAad(providerId),
  );
}

export async function setProviderKey(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true, sensitive: true });
  const id = uuidParam(ctx.params.id);
  await loadProvider(ctx.deps.db, id);
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ['apiKey']);
  const apiKey = str(body, 'apiKey', { min: 8, max: 512, trim: false })!;
  if (!KEY_PATTERN.test(apiKey)) fail(400, 'invalid_request', 'the API key contains spaces or unsupported characters');
  const sealed = sealSecret(ctx.deps.config.keyring, apiKey, keyAad(id));
  await ctx.deps.db.query(
    `INSERT INTO provider_secrets (provider_id, key_version, iv, ciphertext, tag, updated_at)
     VALUES ($1, $2, $3, $4, $5, now())
     ON CONFLICT (provider_id) DO UPDATE SET key_version = EXCLUDED.key_version, iv = EXCLUDED.iv,
       ciphertext = EXCLUDED.ciphertext, tag = EXCLUDED.tag, updated_at = now()`,
    [id, sealed.keyVersion, sealed.iv, sealed.ciphertext, sealed.tag],
  );
  // The result of an earlier test used the previous key, so it no longer describes the stored key.
  await ctx.deps.db.query('UPDATE providers SET last_test_ok = NULL, last_test_at = NULL, last_test_message = NULL WHERE id = $1', [id]);
  sendJson(ctx.res, 200, { hasApiKey: true, keyVersion: sealed.keyVersion });
}

export async function clearProviderKey(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true, sensitive: true });
  const id = uuidParam(ctx.params.id);
  await loadProvider(ctx.deps.db, id);
  await ctx.deps.db.query('DELETE FROM provider_secrets WHERE provider_id = $1', [id]);
  sendJson(ctx.res, 200, { hasApiKey: false, keyVersion: null });
}

async function runProbe(ctx: Ctx, providerId: string) {
  const p = await loadProvider(ctx.deps.db, providerId);
  const key = p.auth_scheme === 'bearer' ? await providerApiKey(ctx.deps, providerId) : null;
  if (p.auth_scheme === 'bearer' && !key) return { ok: false, message: 'no API key is stored for this provider', status: 0, models: [] as string[], latencyMs: 0, kind: 'auth' as string | null };
  const started = Date.now();
  try {
    const models = await listUpstreamModels(ctx.deps.fetch, p.base_url, key, Math.min(p.timeout_ms, 20000));
    return { ok: true, message: `reachable; ${models.length} model${models.length === 1 ? '' : 's'} listed`, status: 200, models, latencyMs: Date.now() - started, kind: null as string | null };
  } catch (e) {
    const d = describeFailure(e);
    return { ok: false, message: d.message, status: 0, models: [] as string[], latencyMs: Date.now() - started, kind: d.kind as string | null };
  }
}

export async function testProvider(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const r = await runProbe(ctx, id);
  await ctx.deps.db.query(
    'UPDATE providers SET last_test_ok = $2, last_test_at = now(), last_test_latency_ms = $3, last_test_message = $4, last_test_kind = $5 WHERE id = $1',
    [id, r.ok, r.latencyMs, r.message, r.kind],
  );
  // Availability shown to desktops is cached briefly; a fresh test should show up right away.
  await ctx.deps.limits.cacheSet('provider-health', null, 1).catch(() => undefined);
  sendJson(ctx.res, 200, { ok: r.ok, message: r.message, latencyMs: r.latencyMs });
}

/**
 * POST /admin/api/providers/:id/discover: refreshes the provider's model list. New models are added disabled with unknown
 * capabilities. A provider without a model list is not marked as failing: add its models manually by exact id.
 */
export async function discoverModels(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  await loadProvider(ctx.deps.db, id);
  const r = await discoverProvider(ctx.deps, id);
  if (r.skipped) fail(409, 'refresh_in_progress', r.message);
  if (!r.ok && r.supported !== false) fail(502, 'upstream_failed', r.message);
  sendJson(ctx.res, 200, { found: r.found, added: r.added, supported: r.supported, message: r.message });
}
