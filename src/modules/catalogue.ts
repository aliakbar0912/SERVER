// The catalogue is what desktop clients see: enabled models with public fields only. Never upstream IDs, URLs or keys.
import type { Ctx } from '../context.ts';
import type { Queryer, Db } from '../db/pg-wire.ts';
import { authenticateDevice } from './devices.ts';
import { requireLoginForCentralAi } from './sessions.ts';
import { fail, sendJson, uuidParam } from '../http/util.ts';
import { allowedModelIds, isAllowed, providerHealth } from './registry.ts';

export const CAPABILITY_NAMES = ['streaming', 'tools', 'vision', 'reasoning'] as const;
export const CAPABILITY_SOURCES = ['unknown', 'admin', 'provider_reported', 'test'] as const;
export const REASONING_LEVELS = ['low', 'medium', 'high'] as const;

export type Capability = { supported: boolean | null; source: (typeof CAPABILITY_SOURCES)[number]; levels?: string[] };
export type Capabilities = Record<(typeof CAPABILITY_NAMES)[number], Capability>;

export function unknownCapabilities(): Capabilities {
  const unknown: Capability = { supported: null, source: 'unknown' };
  return { streaming: { ...unknown }, tools: { ...unknown }, vision: { ...unknown }, reasoning: { ...unknown } };
}

/** Keeps only known capability fields. A missing or null `supported` is always treated as unknown. */
export function normalizeCapabilities(input: unknown): Capabilities {
  const out = unknownCapabilities();
  if (!input || typeof input !== 'object') return out;
  for (const name of CAPABILITY_NAMES) {
    const raw = (input as Record<string, any>)[name];
    if (!raw || typeof raw !== 'object') continue;
    const supported = raw.supported === true || raw.supported === false ? raw.supported : null;
    const source = (CAPABILITY_SOURCES as readonly string[]).includes(raw.source) ? raw.source : 'unknown';
    const cap: Capability = { supported, source };
    if (name === 'reasoning' && Array.isArray(raw.levels)) {
      cap.levels = raw.levels.filter((l: unknown): l is string => (REASONING_LEVELS as readonly string[]).includes(l as string));
    }
    out[name] = cap;
  }
  return out;
}

export async function catalogueVersion(db: Queryer): Promise<number> {
  const { rows } = await db.query("SELECT (value)::text::int AS v FROM settings WHERE key = 'catalogue_version'");
  return rows[0]?.v ?? 1;
}

/** Called inside the same transaction as any change to providers, models or policy. */
export async function bumpCatalogue(q: Queryer): Promise<number> {
  const { rows } = await q.query(
    "UPDATE settings SET value = to_jsonb((value::text::int) + 1), updated_at = now() WHERE key = 'catalogue_version' RETURNING value::text::int AS v",
  );
  return rows[0].v;
}

export async function readSettings(db: Queryer): Promise<Record<string, unknown>> {
  const { rows } = await db.query('SELECT key, value FROM settings');
  return Object.fromEntries(rows.map((r) => [r.key, r.value]));
}

export interface CatalogueModel {
  id: string;
  /** Internal: used for availability; removed before the catalogue is sent. */
  providerId?: string;
  displayName: string;
  description: string;
  providerName: string;
  contextWindow: number | null;
  isDefault: boolean;
  capabilities: Capabilities;
}

async function orgSkillsVersion(db: Db): Promise<number> {
  try {
    const { rows } = await db.query("SELECT (value)::text::int AS v FROM settings WHERE key = 'skills_version'");
    return rows[0]?.v ?? 0;
  } catch {
    return 0;
  }
}

/** Mirrors search.ts `usable`: enabled, with a key (SearXNG: with an address). Kept here to avoid an import cycle. */
async function webSearchReady(db: Db): Promise<boolean> {
  try {
    const { rows } = await db.query(
      `SELECT 1 FROM search_providers p LEFT JOIN search_provider_secrets s ON s.provider_id = p.id
        WHERE p.enabled AND ((p.kind = 'searxng' AND p.base_url IS NOT NULL) OR (p.kind <> 'searxng' AND s.provider_id IS NOT NULL)
          AND (p.kind <> 'google_cse' OR coalesce(p.options->>'cx', '') <> '')) LIMIT 1`,
    );
    return rows.length > 0;
  } catch {
    return false; // before migration 8
  }
}

export async function buildCatalogue(db: Db): Promise<{ version: number; generatedAt: string; models: CatalogueModel[]; policy: Record<string, unknown> }> {
  const settings = await readSettings(db);
  const { rows } = await db.query(
    `SELECT m.id, m.provider_id, m.display_name, m.description, m.context_window, m.is_default, m.capabilities, p.name AS provider_name
       FROM models m JOIN providers p ON p.id = m.provider_id
      WHERE m.enabled AND p.enabled
      ORDER BY m.is_default DESC, m.display_name ASC`,
  );
  return {
    version: Number(settings.catalogue_version ?? 1),
    generatedAt: new Date().toISOString(),
    models: rows.map((r) => ({
      id: r.id,
      providerId: r.provider_id,
      displayName: r.display_name,
      description: r.description,
      providerName: r.provider_name,
      contextWindow: r.context_window,
      isDefault: r.is_default,
      capabilities: normalizeCapabilities(r.capabilities),
    })),
    policy: {
      allowDirectProvider: settings.allow_direct_provider === true,
      maxOutputTokens: Number(settings.max_output_tokens ?? 8192),
      // At least one web search provider is ready (desktops offer the agent's web_search tool only then).
      webSearch: await webSearchReady(db),
      // Organization skills: desktops download /v1/skills again when this changes.
      skillsVersion: await orgSkillsVersion(db),
    },
  };
}

type Catalogue = Awaited<ReturnType<typeof buildCatalogue>>;
const CATALOGUE_CACHE_SECONDS = 300;

/**
 * The catalogue for the current version, from the cache when Redis is configured. The key contains the version, and every
 * change to providers, models or policy bumps the version in the same transaction, so a cached copy is never stale.
 */
async function cachedCatalogue(ctx: Ctx): Promise<Catalogue> {
  const { db, limits } = ctx.deps;
  if (limits.kind !== 'redis') return buildCatalogue(db);
  const version = await catalogueVersion(db);
  const key = `catalogue:v${version}`;
  const hit = await limits.cacheGet<Catalogue>(key);
  if (hit && hit.version === version) return hit;
  const cat = await buildCatalogue(db);
  if (cat.version === version) await limits.cacheSet(key, cat, CATALOGUE_CACHE_SECONDS);
  return cat;
}

/** GET /v1/catalogue with ETag. A client holding the current version gets 304 and no body. */
export async function catalogueRoute(ctx: Ctx): Promise<void> {
  const device = await authenticateDevice(ctx);
  const full = await cachedCatalogue(ctx);
  const cat = await forDevice(ctx, full, device.deviceId, device.modelAccess);
  const etag = `"${cat.version}"`;
  if (ctx.req.headers['if-none-match'] === etag) {
    ctx.res.writeHead(304, { etag, 'cache-control': 'no-store' });
    ctx.res.end();
    return;
  }
  sendJson(ctx.res, 200, cat, { etag, 'cache-control': 'no-store' });
}

export async function deviceRoute(ctx: Ctx): Promise<void> {
  const d = await authenticateDevice(ctx, { central: false });
  sendJson(ctx.res, 200, {
    deviceId: d.deviceId,
    name: d.name,
    status: 'active',
    catalogueVersion: await catalogueVersion(ctx.deps.db),
    signedIn: !!d.userId,
    tokenExpiresAt: d.tokenExpiresAt,
    loginRequired: await requireLoginForCentralAi(ctx.deps.db),
  });
}

/**
 * The catalogue restricted to what this device may use. Access is read from the database on every call (never cached),
 * so a revoked grant disappears on the next sync. Granting or revoking bumps the catalogue version, which changes the ETag.
 */
async function forDevice(ctx: Ctx, cat: Catalogue, deviceId: string, access: 'all' | 'selected'): Promise<Catalogue> {
  const allowed = await allowedModelIds(ctx.deps.db, deviceId, access);
  const models = cat.models.filter((m) => isAllowed(allowed, m.id)).map(({ providerId: _p, ...m }) => m);
  return { ...cat, models };
}

const HEALTH_CACHE_SECONDS = 30;

/**
 * GET /v1/catalogue/status: current availability of the models this device may use. Separate from the catalogue, so the
 * model list keeps its version ETag while availability follows real traffic. Never blocks or removes a model.
 */
export async function catalogueStatusRoute(ctx: Ctx): Promise<void> {
  const device = await authenticateDevice(ctx);
  const { db, limits } = ctx.deps;
  const cat = await cachedCatalogue(ctx);
  const allowed = await allowedModelIds(db, device.deviceId, device.modelAccess);
  let health = await limits.cacheGet<Record<string, { availability: string; reason: string }>>('provider-health');
  if (!health) {
    health = Object.fromEntries(await providerHealth(db));
    await limits.cacheSet('provider-health', health, HEALTH_CACHE_SECONDS);
  }
  const models = cat.models
    .filter((m) => isAllowed(allowed, m.id))
    .map((m) => ({ id: m.id, ...(health![m.providerId ?? ''] ?? { availability: 'unknown', reason: 'not checked recently' }) }));
  sendJson(ctx.res, 200, { version: cat.version, checkedAt: new Date().toISOString(), models }, { 'cache-control': 'no-store' });
}

/** GET /v1/models/:id: metadata of one model this device may use. 404 for anything else, so ids cannot be probed. */
export async function modelRoute(ctx: Ctx): Promise<void> {
  const device = await authenticateDevice(ctx);
  const id = uuidParam(ctx.params.id);
  const cat = await forDevice(ctx, await cachedCatalogue(ctx), device.deviceId, device.modelAccess);
  const m = cat.models.find((x) => x.id === id);
  if (!m) fail(404, 'model_not_found', 'this model is not available to this computer');
  sendJson(ctx.res, 200, { ...m, catalogueVersion: cat.version });
}

/** GET /v1/usage?days=30: this device's own usage. A device never sees other devices' records. */
export async function deviceUsageRoute(ctx: Ctx): Promise<void> {
  const device = await authenticateDevice(ctx);
  const days = Math.min(90, Math.max(1, Number(ctx.url.searchParams.get('days') ?? 30) || 30));
  const { rows } = await ctx.deps.db.query(
    `SELECT model_id, model_name,
            count(*)::int AS requests,
            count(*) FILTER (WHERE status = 'ok')::int AS ok,
            count(*) FILTER (WHERE status = 'error')::int AS failed,
            coalesce(sum(prompt_tokens), 0)::int AS prompt_tokens,
            coalesce(sum(completion_tokens), 0)::int AS completion_tokens
       FROM request_logs
      WHERE device_id = $1 AND created_at > now() - make_interval(days => $2)
      GROUP BY model_id, model_name ORDER BY requests DESC LIMIT 100`,
    [device.deviceId, days],
  );
  sendJson(ctx.res, 200, {
    days,
    models: rows.map((r) => ({ modelId: r.model_id, modelName: r.model_name, requests: r.requests, ok: r.ok, failed: r.failed, promptTokens: r.prompt_tokens, completionTokens: r.completion_tokens })),
  });
}
