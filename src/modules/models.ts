// Models: which upstream models are offered to desktop users, under which display name and capabilities.
import type { Ctx } from '../context.ts';
import { bool, fail, int, readJson, requireObject, rejectUnknown, sendJson, str, uuidParam } from '../http/util.ts';
import { guardOwner } from './auth.ts';
import { bumpCatalogue, normalizeCapabilities, unknownCapabilities, type Capabilities } from './catalogue.ts';

export function toModel(r: any) {
  return {
    id: r.id,
    providerId: r.provider_id,
    providerName: r.provider_name,
    providerEnabled: r.provider_enabled,
    upstreamModelId: r.upstream_model_id,
    displayName: r.display_name,
    description: r.description,
    enabled: r.enabled,
    isDefault: r.is_default,
    contextWindow: r.context_window,
    capabilities: normalizeCapabilities(r.capabilities),
    fallbackModelId: r.fallback_model_id ?? null,
    source: r.source ?? 'manual',
    lastListedAt: r.last_listed_at ?? null,
    updatedAt: r.updated_at,
  };
}

const SELECT_MODEL = `
  SELECT m.*, p.name AS provider_name, p.enabled AS provider_enabled
    FROM models m JOIN providers p ON p.id = m.provider_id`;

export async function listModels(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const q = ctx.url.searchParams;
  const where: string[] = [];
  const params: unknown[] = [];
  if (q.get('providerId')) {
    params.push(uuidParam(q.get('providerId')!));
    where.push(`m.provider_id = $${params.length}`);
  }
  if (q.get('enabled') === 'true' || q.get('enabled') === 'false') {
    params.push(q.get('enabled') === 'true');
    where.push(`m.enabled = $${params.length}`);
  }
  if (q.get('q')) {
    params.push(`%${q.get('q')!.slice(0, 80).replace(/[%_\\]/g, '\\$&')}%`);
    where.push(`(m.display_name ILIKE $${params.length} OR m.upstream_model_id ILIKE $${params.length})`);
  }
  const sql = `${SELECT_MODEL}${where.length ? ` WHERE ${where.join(' AND ')}` : ''} ORDER BY p.name, m.display_name LIMIT 500`;
  const { rows } = await ctx.deps.db.query(sql, params);
  sendJson(ctx.res, 200, { models: rows.map(toModel) });
}

async function loadModel(db: { query(sql: string, p?: unknown[]): Promise<{ rows: any[] }> }, id: string) {
  const { rows } = await db.query(`${SELECT_MODEL} WHERE m.id = $1`, [id]);
  if (!rows[0]) fail(404, 'not_found', 'model not found');
  return rows[0];
}

function parseCapabilities(body: Record<string, unknown>, fallback: Capabilities): Capabilities {
  if (body.capabilities === undefined) return fallback;
  const raw = requireObject(body.capabilities, 'capabilities');
  const allowed = ['streaming', 'tools', 'vision', 'reasoning'];
  for (const k of Object.keys(raw)) if (!allowed.includes(k)) fail(400, 'invalid_request', `unknown capability "${k}"`);
  for (const [k, v] of Object.entries(raw)) {
    const c = requireObject(v, `capabilities.${k}`);
    rejectUnknown(c, k === 'reasoning' ? ['supported', 'source', 'levels'] : ['supported', 'source']);
    if (c.supported !== undefined && c.supported !== null && typeof c.supported !== 'boolean') fail(400, 'invalid_request', `capabilities.${k}.supported must be true, false or null`);
    if (c.source !== undefined && !['unknown', 'admin', 'provider_reported', 'test'].includes(c.source as string)) fail(400, 'invalid_request', `capabilities.${k}.source is not valid`);
  }
  return normalizeCapabilities({ ...fallback, ...raw });
}

export async function createModel(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const body = requireObject(await readJson(ctx.req, 16 * 1024));
  rejectUnknown(body, ['providerId', 'upstreamModelId', 'displayName', 'description', 'contextWindow', 'capabilities', 'enabled']);
  const providerId = uuidParam(str(body, 'providerId', { min: 36, max: 36 }));
  const upstreamModelId = str(body, 'upstreamModelId', { min: 1, max: 200, trim: false })!;
  const displayName = str(body, 'displayName', { min: 1, max: 120 })!;
  const description = str(body, 'description', { max: 500, optional: true }) ?? '';
  const contextWindow = int(body, 'contextWindow', { min: 1, max: 10_000_000, optional: true }) ?? null;
  const enabled = bool(body, 'enabled', { def: false })!;
  const capabilities = parseCapabilities(body, unknownCapabilities());
  const { rows: p } = await ctx.deps.db.query('SELECT enabled FROM providers WHERE id = $1', [providerId]);
  if (!p[0]) fail(404, 'not_found', 'provider not found');
  if (enabled && !p[0].enabled) fail(409, 'provider_disabled', 'enable the provider before enabling its models');
  const id = await ctx.deps.db.transaction(async (q) => {
    const { rows } = await q.query(
      `INSERT INTO models (provider_id, upstream_model_id, display_name, description, enabled, context_window, capabilities)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [providerId, upstreamModelId, displayName, description, enabled, contextWindow, capabilities],
    );
    if (enabled) await bumpCatalogue(q);
    return rows[0].id as string;
  }).catch((e) => {
    if (e?.code === '23505') fail(409, 'duplicate', 'this provider already has that model');
    throw e;
  });
  sendJson(ctx.res, 201, toModel(await loadModel(ctx.deps.db, id)));
}

export async function updateModel(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 16 * 1024));
  rejectUnknown(body, ['enabled', 'displayName', 'description', 'contextWindow', 'capabilities', 'fallbackModelId']);
  const current = await loadModel(ctx.deps.db, id);
  const enabled = bool(body, 'enabled', { optional: true }) ?? current.enabled;
  const displayName = str(body, 'displayName', { min: 1, max: 120, optional: true }) ?? current.display_name;
  const description = str(body, 'description', { max: 500, optional: true }) ?? current.description;
  const contextWindow = body.contextWindow === undefined ? current.context_window : body.contextWindow === null ? null : int(body, 'contextWindow', { min: 1, max: 10_000_000 })!;
  const capabilities = parseCapabilities(body, normalizeCapabilities(current.capabilities));
  let fallbackModelId: string | null = current.fallback_model_id ?? null;
  if (body.fallbackModelId !== undefined) {
    fallbackModelId = body.fallbackModelId === null ? null : uuidParam(typeof body.fallbackModelId === 'string' ? body.fallbackModelId : '');
    if (fallbackModelId === id) fail(400, 'invalid_request', 'a model cannot be its own fallback');
    if (fallbackModelId) {
      const fb = await ctx.deps.db.query('SELECT 1 FROM models WHERE id = $1', [fallbackModelId]);
      if (!fb.rows[0]) fail(400, 'invalid_request', 'the fallback model does not exist');
    }
  }
  if (enabled && !current.provider_enabled) fail(409, 'provider_disabled', 'enable the provider before enabling its models');
  await ctx.deps.db.transaction(async (q) => {
    await q.query(
      `UPDATE models SET enabled = $2, display_name = $3, description = $4, context_window = $5, capabilities = $6,
              fallback_model_id = $7, is_default = CASE WHEN $2 THEN is_default ELSE false END, updated_at = now()
        WHERE id = $1`,
      [id, enabled, displayName, description, contextWindow, capabilities, fallbackModelId],
    );
    await bumpCatalogue(q);
  });
  sendJson(ctx.res, 200, toModel(await loadModel(ctx.deps.db, id)));
}

export async function setDefaultModel(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const current = await loadModel(ctx.deps.db, id);
  if (!current.enabled || !current.provider_enabled) fail(409, 'model_disabled', 'only an enabled model with an enabled provider can be the default');
  await ctx.deps.db.transaction(async (q) => {
    await q.query('UPDATE models SET is_default = false WHERE is_default');
    await q.query('UPDATE models SET is_default = true, updated_at = now() WHERE id = $1', [id]);
    await bumpCatalogue(q);
  });
  sendJson(ctx.res, 200, toModel(await loadModel(ctx.deps.db, id)));
}

export async function deleteModel(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true, sensitive: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ['confirmName']);
  const current = await loadModel(ctx.deps.db, id);
  if (str(body, 'confirmName', { max: 120, optional: true }) !== current.display_name) fail(400, 'confirmation_mismatch', 'type the model name exactly to delete it');
  await ctx.deps.db.transaction(async (q) => {
    await q.query('DELETE FROM models WHERE id = $1', [id]);
    await bumpCatalogue(q);
  });
  sendJson(ctx.res, 200, { deleted: true });
}
