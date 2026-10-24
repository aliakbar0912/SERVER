// Web search for the agent. The owner adds search providers (Tavily, Brave, Serper, Exa, Google Programmable Search,
// self-hosted SearXNG) in the admin site; their API keys are encrypted here and never leave the server. Desktops call
// POST /v1/search with their device token and get normalized results ({ title, url, snippet, published }), with
// automatic fallback to the next enabled provider when one fails. Query text is never stored or logged.
import type { Ctx, Deps } from '../context.ts';
import type { Queryer } from '../db/pg-wire.ts';
import { openSecret, sealSecret, sha256Hex } from '../crypto.ts';
import { bool, fail, int, log, readJson, rejectUnknown, requireObject, sendJson, str, uuidParam } from '../http/util.ts';
import { guardOwner } from './auth.ts';
import { authenticateDevice } from './devices.ts';
import { readDesktopConfigCached } from './desktop-config.ts';
import { bumpCatalogue } from './catalogue.ts';
import { normalizeBaseUrl } from './upstream.ts';

export const SEARCH_KINDS = ['tavily', 'brave', 'serper', 'exa', 'google_cse', 'searxng'] as const;
export type SearchKind = (typeof SEARCH_KINDS)[number];

export interface SearchResult {
  title: string;
  url: string;
  snippet: string;
  published: string | null;
}

/** Per-kind facts for the admin site. `needsKey`: an API key is required. */
export const KIND_INFO: Record<SearchKind, { label: string; needsKey: boolean; needsBaseUrl: boolean; options: string[]; signup: string }> = {
  tavily: { label: 'Tavily', needsKey: true, needsBaseUrl: false, options: [], signup: 'tavily.com' },
  brave: { label: 'Brave Search API', needsKey: true, needsBaseUrl: false, options: [], signup: 'brave.com/search/api' },
  serper: { label: 'Serper (Google results)', needsKey: true, needsBaseUrl: false, options: [], signup: 'serper.dev' },
  exa: { label: 'Exa', needsKey: true, needsBaseUrl: false, options: [], signup: 'exa.ai' },
  google_cse: { label: 'Google Programmable Search', needsKey: true, needsBaseUrl: false, options: ['cx'], signup: 'programmablesearchengine.google.com' },
  searxng: { label: 'SearXNG (self-hosted)', needsKey: false, needsBaseUrl: true, options: [], signup: 'docs.searxng.org' },
};

const KEY_PATTERN = /^[\x21-\x7e]{8,512}$/;
const TIMEOUT_MS = 15_000;
const CACHE_SECONDS = 10 * 60;

export class SearchError extends Error {
  readonly kind: 'auth' | 'rate_limited' | 'timeout' | 'unreachable' | 'rejected' | 'bad_response' | 'config';
  constructor(kind: SearchError['kind'], message: string) {
    super(message);
    this.name = 'SearchError';
    this.kind = kind;
  }
}

interface ProviderRow {
  id: string;
  name: string;
  kind: SearchKind;
  base_url: string | null;
  options: Record<string, unknown>;
  enabled: boolean;
  is_default: boolean;
  priority: number;
  has_key: boolean;
}

const clean = (s: unknown, max: number) =>
  String(s ?? '')
    .replace(/<[^>]+>/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max);

function httpUrl(u: unknown): string | null {
  try {
    const x = new URL(String(u));
    return x.protocol === 'https:' || x.protocol === 'http:' ? x.toString() : null;
  } catch {
    return null;
  }
}

function normalize(items: Array<{ title?: unknown; url?: unknown; snippet?: unknown; published?: unknown }>, count: number): SearchResult[] {
  const out: SearchResult[] = [];
  const seen = new Set<string>();
  for (const it of items) {
    const url = httpUrl(it.url);
    if (!url || seen.has(url)) continue;
    seen.add(url);
    out.push({ title: clean(it.title, 300) || url, url, snippet: clean(it.snippet, 1000), published: it.published ? clean(it.published, 40) : null });
    if (out.length >= count) break;
  }
  return out;
}

async function call(f: typeof fetch, url: string, init: RequestInit): Promise<any> {
  let res: Response;
  try {
    res = await f(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch (e) {
    if ((e as Error).name === 'TimeoutError' || (e as Error).name === 'AbortError') throw new SearchError('timeout', 'the search provider did not answer in time');
    throw new SearchError('unreachable', 'the search provider could not be reached');
  }
  if (res.status === 401 || res.status === 403) throw new SearchError('auth', 'the search provider refused the API key');
  if (res.status === 429) throw new SearchError('rate_limited', 'the search provider rate limit or quota was reached');
  if (!res.ok) throw new SearchError(res.status >= 500 ? 'unreachable' : 'rejected', `the search provider answered with HTTP ${res.status}`);
  try {
    return await res.json();
  } catch {
    throw new SearchError('bad_response', 'the search provider sent an unexpected answer');
  }
}

/** Runs one search against one provider. The key is passed in; it is never logged or returned. */
export async function runSearch(f: typeof fetch, p: Pick<ProviderRow, 'kind' | 'base_url' | 'options'>, key: string | null, query: string, count: number): Promise<SearchResult[]> {
  const json = (body: unknown) => JSON.stringify(body);
  switch (p.kind) {
    case 'tavily': {
      const r = await call(f, 'https://api.tavily.com/search', {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${key}` },
        body: json({ query, max_results: count, search_depth: 'basic', include_answer: false }),
      });
      return normalize((r?.results ?? []).map((x: any) => ({ title: x.title, url: x.url, snippet: x.content, published: x.published_date })), count);
    }
    case 'brave': {
      const q = new URLSearchParams({ q: query, count: String(count) });
      const r = await call(f, `https://api.search.brave.com/res/v1/web/search?${q}`, { headers: { accept: 'application/json', 'x-subscription-token': key ?? '' } });
      return normalize((r?.web?.results ?? []).map((x: any) => ({ title: x.title, url: x.url, snippet: x.description, published: x.page_age ?? x.age })), count);
    }
    case 'serper': {
      const r = await call(f, 'https://google.serper.dev/search', { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': key ?? '' }, body: json({ q: query, num: count }) });
      return normalize((r?.organic ?? []).map((x: any) => ({ title: x.title, url: x.link, snippet: x.snippet, published: x.date })), count);
    }
    case 'exa': {
      const r = await call(f, 'https://api.exa.ai/search', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-api-key': key ?? '' },
        body: json({ query, numResults: count, type: 'auto', contents: { text: { maxCharacters: 600 } } }),
      });
      return normalize((r?.results ?? []).map((x: any) => ({ title: x.title, url: x.url, snippet: x.text ?? (Array.isArray(x.highlights) ? x.highlights.join(' ') : ''), published: x.publishedDate })), count);
    }
    case 'google_cse': {
      const cx = String(p.options?.cx ?? '');
      if (!cx) throw new SearchError('config', 'set the search engine id (cx) for Google Programmable Search');
      const q = new URLSearchParams({ key: key ?? '', cx, q: query, num: String(Math.min(count, 10)) });
      const r = await call(f, `https://www.googleapis.com/customsearch/v1?${q}`, { headers: { accept: 'application/json' } });
      return normalize((r?.items ?? []).map((x: any) => ({ title: x.title, url: x.link, snippet: x.snippet })), count);
    }
    case 'searxng': {
      if (!p.base_url) throw new SearchError('config', 'set the SearXNG address');
      const q = new URLSearchParams({ q: query, format: 'json' });
      const r = await call(f, `${p.base_url}/search?${q}`, { headers: { accept: 'application/json', ...(key ? { authorization: `Bearer ${key}` } : {}) } });
      return normalize((r?.results ?? []).map((x: any) => ({ title: x.title, url: x.url, snippet: x.content, published: x.publishedDate })), count);
    }
  }
}

// ------------------------------------------------------------------ storage

const keyAad = (id: string) => `search_provider:${id}`;

async function providerKey(deps: Deps, id: string): Promise<string | null> {
  const { rows } = await deps.db.query('SELECT key_version, iv, ciphertext, tag FROM search_provider_secrets WHERE provider_id = $1', [id]);
  if (!rows[0]) return null;
  return openSecret(deps.config.keyring, { keyVersion: rows[0].key_version, iv: rows[0].iv, ciphertext: rows[0].ciphertext, tag: rows[0].tag }, keyAad(id));
}

const SELECT = `SELECT p.id, p.name, p.kind, p.base_url, p.options, p.enabled, p.is_default, p.priority, p.last_test_ok, p.last_test_at,
                       p.last_test_latency_ms, p.last_test_message, p.created_at, (s.provider_id IS NOT NULL) AS has_key
                  FROM search_providers p LEFT JOIN search_provider_secrets s ON s.provider_id = p.id`;

function usable(p: ProviderRow): boolean {
  return p.enabled && (!KIND_INFO[p.kind].needsKey || p.has_key) && (!KIND_INFO[p.kind].needsBaseUrl || !!p.base_url);
}

/** True when at least one provider can serve searches (announced to desktops in the catalogue policy). */
export async function webSearchAvailable(db: Queryer): Promise<boolean> {
  const { rows } = await db.query(`${SELECT} WHERE p.enabled`);
  return rows.some((r) => usable(r as ProviderRow));
}

function view(r: any) {
  const info = KIND_INFO[r.kind as SearchKind];
  return {
    id: r.id,
    name: r.name,
    kind: r.kind,
    kindLabel: info.label,
    baseUrl: r.base_url,
    options: r.options ?? {},
    enabled: r.enabled,
    isDefault: r.is_default,
    priority: r.priority,
    hasApiKey: r.has_key,
    needsApiKey: info.needsKey,
    ready: usable(r),
    lastTest: r.last_test_at ? { ok: r.last_test_ok, at: r.last_test_at, latencyMs: r.last_test_latency_ms, message: r.last_test_message } : null,
  };
}

async function load(db: Queryer, id: string): Promise<ProviderRow> {
  const { rows } = await db.query(`${SELECT} WHERE p.id = $1`, [id]);
  if (!rows[0]) fail(404, 'not_found', 'search provider not found');
  return rows[0] as ProviderRow;
}

function readOptions(kind: SearchKind, body: Record<string, unknown>): Record<string, string> {
  const raw = body.options;
  if (raw === undefined) return {};
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail(400, 'invalid_request', 'options must be an object');
  const out: Record<string, string> = {};
  for (const k of KIND_INFO[kind].options) {
    const v = (raw as Record<string, unknown>)[k];
    if (v === undefined || v === '') continue;
    if (typeof v !== 'string' || !/^[A-Za-z0-9:_-]{1,200}$/.test(v)) fail(400, 'invalid_request', `${k} contains unsupported characters`);
    out[k] = v;
  }
  return out;
}

// ------------------------------------------------------------------ admin routes

export async function listSearchProviders(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query(`${SELECT} ORDER BY p.is_default DESC, p.priority, p.created_at`);
  const stats = await ctx.deps.db.query(
    `SELECT count(*)::int AS total, count(*) FILTER (WHERE status = 'error')::int AS failed, count(*) FILTER (WHERE status = 'cached')::int AS cached,
            coalesce(round(avg(latency_ms) FILTER (WHERE status = 'ok')), 0)::int AS avg_ms
       FROM search_logs WHERE created_at > now() - interval '7 days'`,
  );
  const settings = await ctx.deps.db.query("SELECT (value)::text::int AS v FROM settings WHERE key = 'search_per_minute'");
  sendJson(ctx.res, 200, {
    providers: rows.map(view),
    kinds: SEARCH_KINDS.map((k) => ({ kind: k, ...KIND_INFO[k] })),
    last7Days: stats.rows[0],
    perMinute: settings.rows[0]?.v ?? 20,
  });
}

export async function createSearchProvider(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const body = requireObject(await readJson(ctx.req, 8 * 1024));
  rejectUnknown(body, ['name', 'kind', 'baseUrl', 'options', 'enabled']);
  const kind = body.kind as SearchKind;
  if (!SEARCH_KINDS.includes(kind)) fail(400, 'invalid_request', `kind must be one of ${SEARCH_KINDS.join(', ')}`);
  const name = str(body, 'name', { min: 1, max: 80 })!;
  const baseUrl = KIND_INFO[kind].needsBaseUrl ? normalizeBaseUrl(str(body, 'baseUrl', { min: 8, max: 2048 })!) : null;
  const options = readOptions(kind, body);
  const enabled = bool(body, 'enabled', { optional: true, def: true }) ?? true;
  const created = await ctx.deps.db.transaction(async (q) => {
    const dup = await q.query('SELECT 1 FROM search_providers WHERE name = $1', [name]);
    if (dup.rows[0]) fail(409, 'name_taken', 'a search provider with this name exists');
    const any = await q.query('SELECT count(*)::int AS n FROM search_providers');
    const { rows } = await q.query(
      `INSERT INTO search_providers (name, kind, base_url, options, enabled, is_default, priority)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [name, kind, baseUrl, JSON.stringify(options), enabled, any.rows[0].n === 0, (any.rows[0].n + 1) * 10],
    );
    await bumpCatalogue(q);
    return rows[0].id as string;
  });
  sendJson(ctx.res, 201, { provider: view(await load(ctx.deps.db, created)) });
}

export async function updateSearchProvider(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const current = await load(ctx.deps.db, id);
  const body = requireObject(await readJson(ctx.req, 8 * 1024));
  rejectUnknown(body, ['name', 'baseUrl', 'options', 'enabled', 'isDefault', 'priority']);
  const sets: string[] = [];
  const vals: unknown[] = [id];
  const add = (col: string, v: unknown) => {
    vals.push(v);
    sets.push(`${col} = $${vals.length}`);
  };
  const name = str(body, 'name', { min: 1, max: 80, optional: true });
  if (name !== undefined) add('name', name);
  if (body.baseUrl !== undefined) {
    if (!KIND_INFO[current.kind].needsBaseUrl) fail(400, 'invalid_request', 'this provider has a fixed address');
    add('base_url', normalizeBaseUrl(str(body, 'baseUrl', { min: 8, max: 2048 })!));
  }
  if (body.options !== undefined) add('options', JSON.stringify(readOptions(current.kind, body)));
  const enabled = bool(body, 'enabled', { optional: true });
  if (enabled !== undefined) add('enabled', enabled);
  const priority = int(body, 'priority', { min: 0, max: 1000, optional: true });
  if (priority !== undefined) add('priority', priority);
  const isDefault = bool(body, 'isDefault', { optional: true });
  if (!sets.length && isDefault === undefined) fail(400, 'invalid_request', 'nothing to change');
  await ctx.deps.db.transaction(async (q) => {
    if (isDefault) await q.query('UPDATE search_providers SET is_default = false WHERE is_default AND id <> $1', [id]);
    if (isDefault !== undefined) add('is_default', isDefault);
    sets.push('updated_at = now()');
    if (body.baseUrl !== undefined || body.options !== undefined) sets.push('last_test_ok = NULL, last_test_at = NULL, last_test_message = NULL');
    try {
      await q.query(`UPDATE search_providers SET ${sets.join(', ')} WHERE id = $1`, vals);
    } catch (e) {
      if (/unique/i.test(String((e as Error).message))) fail(409, 'name_taken', 'a search provider with this name exists');
      throw e;
    }
    await bumpCatalogue(q);
  });
  sendJson(ctx.res, 200, { provider: view(await load(ctx.deps.db, id)) });
}

export async function deleteSearchProvider(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true, sensitive: true });
  const id = uuidParam(ctx.params.id);
  await load(ctx.deps.db, id);
  await ctx.deps.db.transaction(async (q) => {
    await q.query('DELETE FROM search_providers WHERE id = $1', [id]);
    await bumpCatalogue(q);
  });
  sendJson(ctx.res, 200, { deleted: true });
}

export async function setSearchProviderKey(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true, sensitive: true });
  const id = uuidParam(ctx.params.id);
  await load(ctx.deps.db, id);
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ['apiKey']);
  const apiKey = str(body, 'apiKey', { min: 8, max: 512, trim: false })!;
  if (!KEY_PATTERN.test(apiKey)) fail(400, 'invalid_request', 'the API key contains spaces or unsupported characters');
  const sealed = sealSecret(ctx.deps.config.keyring, apiKey, keyAad(id));
  await ctx.deps.db.transaction(async (q) => {
    await q.query(
      `INSERT INTO search_provider_secrets (provider_id, key_version, iv, ciphertext, tag, updated_at) VALUES ($1, $2, $3, $4, $5, now())
       ON CONFLICT (provider_id) DO UPDATE SET key_version = EXCLUDED.key_version, iv = EXCLUDED.iv, ciphertext = EXCLUDED.ciphertext, tag = EXCLUDED.tag, updated_at = now()`,
      [id, sealed.keyVersion, sealed.iv, sealed.ciphertext, sealed.tag],
    );
    await q.query('UPDATE search_providers SET last_test_ok = NULL, last_test_at = NULL, last_test_message = NULL WHERE id = $1', [id]);
    await bumpCatalogue(q);
  });
  sendJson(ctx.res, 200, { hasApiKey: true });
}

export async function clearSearchProviderKey(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true, sensitive: true });
  const id = uuidParam(ctx.params.id);
  await load(ctx.deps.db, id);
  await ctx.deps.db.transaction(async (q) => {
    await q.query('DELETE FROM search_provider_secrets WHERE provider_id = $1', [id]);
    await bumpCatalogue(q);
  });
  sendJson(ctx.res, 200, { hasApiKey: false });
}

/** POST /admin/api/search-providers/:id/test { query? }: one real search; shows the first results to the owner. */
export async function testSearchProvider(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const p = await load(ctx.deps.db, id);
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ['query']);
  const query = str(body, 'query', { min: 1, max: 200, optional: true }) ?? 'Node.js release schedule';
  const key = await providerKey(ctx.deps, id);
  const started = Date.now();
  let ok = false;
  let message = '';
  let results: SearchResult[] = [];
  if (KIND_INFO[p.kind].needsKey && !key) message = 'no API key is stored for this provider';
  else {
    try {
      results = await runSearch(ctx.deps.fetch, p, key, query, 5);
      ok = results.length > 0;
      message = ok ? `working; ${results.length} result${results.length === 1 ? '' : 's'}` : 'the provider answered but returned no results';
    } catch (e) {
      message = e instanceof SearchError ? e.message : 'the search failed';
    }
  }
  const latencyMs = Date.now() - started;
  await ctx.deps.db.query('UPDATE search_providers SET last_test_ok = $2, last_test_at = now(), last_test_latency_ms = $3, last_test_message = $4 WHERE id = $1', [id, ok, latencyMs, message.slice(0, 300)]);
  sendJson(ctx.res, 200, { ok, message, latencyMs, results });
}

// ------------------------------------------------------------------ desktop route

async function perMinute(db: Queryer): Promise<number> {
  const { rows } = await db.query("SELECT (value)::text::int AS v FROM settings WHERE key = 'search_per_minute'");
  return rows[0]?.v ?? 20;
}

/**
 * POST /v1/search { query, count? }: a web search for the agent. Central AI endpoint (sign-in rules apply). Tries the
 * default provider, then the other ready providers in priority order. Identical searches are cached for 10 minutes.
 */
export async function search(ctx: Ctx): Promise<void> {
  // Maintenance pauses server-side web search together with central chat (the desktop side hides the tool too).
  if ((await readDesktopConfigCached(ctx.deps.db)).maintenance) {
    fail(503, 'maintenance', 'web search is briefly under maintenance; try again soon', { 'retry-after': '60' });
  }
  const device = await authenticateDevice(ctx);
  const { db, limits } = ctx.deps;
  const rl = await limits.hit(`search:dev:${device.deviceId}`, await perMinute(db), 60);
  if (!rl.allowed) fail(429, 'rate_limited', 'too many web searches; wait a moment', { 'retry-after': String(rl.retryAfterSeconds) });
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ['query', 'count']);
  const query = str(body, 'query', { min: 1, max: 400 })!;
  const count = int(body, 'count', { min: 1, max: 10, optional: true }) ?? 5;

  const { rows } = await db.query(`${SELECT} WHERE p.enabled ORDER BY p.is_default DESC, p.priority, p.created_at`);
  const providers = (rows as ProviderRow[]).filter(usable);
  if (!providers.length) fail(503, 'search_not_configured', 'web search is not set up on this server yet');

  const cacheKey = `search:${sha256Hex(`${count}\n${query.toLowerCase()}`)}`;
  const cached = await limits.cacheGet<{ provider: string; results: SearchResult[] }>(cacheKey).catch(() => null);
  if (cached) {
    await db.query("INSERT INTO search_logs (device_id, provider_name, status, results) VALUES ($1, $2, 'cached', $3)", [device.deviceId, cached.provider, cached.results.length]);
    sendJson(ctx.res, 200, { provider: cached.provider, cached: true, results: cached.results });
    return;
  }
  const errors: string[] = [];
  for (const p of providers) {
    const started = Date.now();
    try {
      const key = await providerKey(ctx.deps, p.id);
      const results = await runSearch(ctx.deps.fetch, p, key, query, count);
      await db.query("INSERT INTO search_logs (device_id, provider_id, provider_name, status, results, latency_ms) VALUES ($1, $2, $3, 'ok', $4, $5)", [device.deviceId, p.id, p.name, results.length, Date.now() - started]);
      await limits.cacheSet(cacheKey, { provider: p.name, results }, CACHE_SECONDS).catch(() => undefined);
      sendJson(ctx.res, 200, { provider: p.name, cached: false, results });
      return;
    } catch (e) {
      const kind = e instanceof SearchError ? e.kind : 'error';
      errors.push(`${p.name}: ${e instanceof SearchError ? e.message : 'failed'}`);
      log('warn', 'search provider failed', { provider: p.name, kind });
      await db.query("INSERT INTO search_logs (device_id, provider_id, provider_name, status, error_code, latency_ms) VALUES ($1, $2, $3, 'error', $4, $5)", [device.deviceId, p.id, p.name, kind, Date.now() - started]);
    }
  }
  fail(502, 'search_failed', `web search failed with every provider (${errors.join('; ').slice(0, 400)})`);
}

/** Deletes search logs older than the retention period (with the request logs). */
export async function pruneSearchLogs(db: Queryer, days: number): Promise<number> {
  const { rowCount } = await db.query('DELETE FROM search_logs WHERE created_at < now() - make_interval(days => $1)', [days]);
  return rowCount;
}
