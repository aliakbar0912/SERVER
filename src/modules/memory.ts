// Device memory sync: the desktop's long-term agent memory ("brain") mirrored to the central platform.
//
// One endpoint does both directions in a single round trip: the device pushes its local memories (idempotent
// upserts keyed by a deterministic client key, last write wins by the client clock) and pulls everything that
// changed on the server since its cursor. Memory belongs to one device: another computer can never read it,
// and a revoked device loses access with everything else. Secrets are refused, mirroring the desktop's own guard.
import type { Ctx } from '../context.ts';
import { fail, readJson, rejectUnknown, requireObject, sendJson, str, bool, int, UUID, uuidParam } from '../http/util.ts';
import { guardOwner } from './auth.ts';
import { authenticateDevice } from './devices.ts';

const SYNC_PER_DEVICE = 40;
const SYNC_WINDOW_SECONDS = 5 * 60;
const MAX_CHANGES = 200;
const MAX_PULL = 800;
const BODY_LIMIT = 512 * 1024;
const KINDS = new Set(['fact', 'preference', 'lesson', 'decision']);
const SOURCES = new Set(['user', 'agent', 'system']);
const CLIENT_KEY = /^[A-Za-z0-9_-]{16,128}$/;
/** Same shape as the desktop guard: obvious secrets never enter server storage either. */
const SECRET_RE =
  /-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:sk|ghp|xox[baprs])-?[A-Za-z0-9_-]{16,}|\bAKIA[0-9A-Z]{16}\b|\b(?:api[_-]?key|secret|token|password|passwd|bearer)\b\s*[:=]\s*\S{12,}/i;
const SECRET_SKIP = /(your[_-]|example|placeholder|changeme|xxxx|\$\{|process\.env|os\.environ|getenv|<[^>]+>)/i;

interface IncomingChange {
  clientKey: string;
  scope: 'global' | 'project';
  projectKey: string;
  kind: string;
  content: string;
  tags: string[];
  source: string;
  confidence: number;
  verified: boolean;
  pinned: boolean;
  hits: number;
  deleted: boolean;
  clientUpdatedAt: number;
}

function parseChange(raw: unknown, index: number): IncomingChange {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail(400, 'invalid_request', `changes[${index}] must be an object`);
  const c = requireObject(raw as Record<string, unknown>, `changes[${index}]`);
  rejectUnknown(c, ['clientKey', 'scope', 'projectKey', 'kind', 'content', 'tags', 'source', 'confidence', 'verified', 'pinned', 'hits', 'deleted', 'updatedAt']);
  const clientKey = str(c, 'clientKey', { min: 16, max: 128, pattern: CLIENT_KEY });
  if (!clientKey) fail(400, 'invalid_request', `changes[${index}].clientKey is required`);
  const scope = str(c, 'scope', { min: 6, max: 7 });
  if (scope !== 'global' && scope !== 'project') fail(400, 'invalid_request', `changes[${index}].scope must be global or project`);
  const projectKey = str(c, 'projectKey', { max: 120 }) ?? '';
  if (scope === 'global' && projectKey) fail(400, 'invalid_request', `changes[${index}].projectKey must be empty for global memories`);
  if (scope === 'project' && !projectKey) fail(400, 'invalid_request', `changes[${index}].projectKey is required for project memories`);
  const kind = str(c, 'kind', { min: 4, max: 10 });
  if (!kind || !KINDS.has(kind)) fail(400, 'invalid_request', `changes[${index}].kind must be fact, preference, lesson or decision`);
  const content = str(c, 'content', { min: 4, max: 600 });
  if (!content) fail(400, 'invalid_request', `changes[${index}].content is required`);
  if (SECRET_RE.test(content) && !SECRET_SKIP.test(content)) {
    fail(422, 'content_refused', `changes[${index}].content looks like a secret; memories never store keys, tokens or passwords`);
  }
  const source = str(c, 'source', { min: 4, max: 6 }) ?? 'agent';
  if (!SOURCES.has(source)) fail(400, 'invalid_request', `changes[${index}].source must be user, agent or system`);
  const confidenceRaw = c.confidence;
  if (typeof confidenceRaw !== 'number' || !Number.isFinite(confidenceRaw) || confidenceRaw < 0 || confidenceRaw > 1) {
    fail(400, 'invalid_request', `changes[${index}].confidence must be a number from 0 to 1`);
  }
  const tagsRaw = c.tags ?? [];
  if (!Array.isArray(tagsRaw) || tagsRaw.length > 12) fail(400, 'invalid_request', `changes[${index}].tags must be an array of at most 12 items`);
  const tags = tagsRaw.map((t) => String(t).toLowerCase().trim().slice(0, 40)).filter((t) => t.length >= 2);
  const clientUpdatedAt = int(c, 'updatedAt', { min: 0, max: 8_999_999_999_999 });
  if (clientUpdatedAt === undefined) fail(400, 'invalid_request', `changes[${index}].updatedAt is required`);
  return {
    clientKey,
    scope,
    projectKey,
    kind,
    content,
    tags,
    source,
    confidence: confidenceRaw,
    verified: bool(c, 'verified', { def: false }) ?? false,
    pinned: bool(c, 'pinned', { def: false }) ?? false,
    hits: int(c, 'hits', { min: 0, max: 1_000_000, optional: true }) ?? 0,
    deleted: bool(c, 'deleted', { def: false }) ?? false,
    clientUpdatedAt,
  };
}

/**
 * POST /v1/memory/sync { changes: [...], since? }: push local memories, pull server changes since the cursor.
 * Returns { serverTime, applied, truncated, entries }. The device advances its cursor to the last pulled
 * entry's updatedAt (or serverTime when nothing was truncated).
 */
export async function syncMemories(ctx: Ctx): Promise<void> {
  const auth = await authenticateDevice(ctx);
  const limit = await ctx.deps.limits.hit(`memory:sync:${auth.deviceId}`, SYNC_PER_DEVICE, SYNC_WINDOW_SECONDS);
  if (!limit.allowed) fail(429, 'rate_limited', 'too many memory syncs; try again shortly', { 'retry-after': String(limit.retryAfterSeconds) });
  const body = requireObject(await readJson(ctx.req, BODY_LIMIT));
  rejectUnknown(body, ['changes', 'since']);
  const rawChanges = body.changes ?? [];
  if (!Array.isArray(rawChanges)) fail(400, 'invalid_request', 'changes must be an array');
  if (rawChanges.length > MAX_CHANGES) fail(413, 'payload_too_large', `at most ${MAX_CHANGES} memories per sync`);
  const changes = rawChanges.map(parseChange);
  const since = int(body, 'since', { min: 0, max: 8_999_999_999_999, optional: true }) ?? 0;

  const applied = await pushChanges(ctx, auth.deviceId, changes);
  const pull = await pullChanges(ctx, auth.deviceId, since);
  sendJson(ctx.res, 200, { ...pull, applied });
}

async function pushChanges(ctx: Ctx, deviceId: string, changes: IncomingChange[]): Promise<number> {
  let applied = 0;
  for (const ch of changes) {
    const { rows } = await ctx.deps.db.query(
      `INSERT INTO memory_entries
         (device_id, client_key, scope, project_key, kind, content, tags, source, confidence, verified, pinned, hits, deleted, client_updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12,$13,$14)
       ON CONFLICT (device_id, client_key) DO UPDATE SET
         scope = EXCLUDED.scope,
         project_key = EXCLUDED.project_key,
         kind = EXCLUDED.kind,
         content = EXCLUDED.content,
         tags = EXCLUDED.tags,
         source = EXCLUDED.source,
         confidence = EXCLUDED.confidence,
         verified = EXCLUDED.verified,
         pinned = EXCLUDED.pinned,
         hits = EXCLUDED.hits,
         deleted = EXCLUDED.deleted,
         client_updated_at = EXCLUDED.client_updated_at,
         updated_at = now()
       WHERE memory_entries.client_updated_at <= EXCLUDED.client_updated_at
       RETURNING id`,
      [
        deviceId,
        ch.clientKey,
        ch.scope,
        ch.projectKey,
        ch.kind,
        ch.content,
        JSON.stringify(ch.tags),
        ch.source,
        ch.confidence,
        ch.verified,
        ch.pinned,
        ch.hits,
        ch.deleted,
        ch.clientUpdatedAt,
      ],
    );
    applied += rows.length;
  }
  return applied;
}

interface PulledEntry {
  clientKey: string;
  scope: string;
  projectKey: string;
  kind: string;
  content: string;
  tags: string[];
  source: string;
  confidence: number;
  verified: boolean;
  pinned: boolean;
  hits: number;
  deleted: boolean;
  updatedAt: number;
}

async function pullChanges(ctx: Ctx, deviceId: string, since: number): Promise<{ serverTime: number; truncated: boolean; entries: PulledEntry[] }> {
  const { rows } = await ctx.deps.db.query(
    `SELECT client_key, scope, project_key, kind, content, tags, source, confidence, verified, pinned, hits, deleted,
            extract(epoch from updated_at) * 1000 AS updated_ms
       FROM memory_entries
      WHERE device_id = $1 AND updated_at > to_timestamp($2 / 1000.0)
      ORDER BY updated_at ASC
      LIMIT $3`,
    [deviceId, since, MAX_PULL + 1],
  );
  const truncated = rows.length > MAX_PULL;
  const kept = truncated ? rows.slice(0, MAX_PULL) : rows;
  const entries: PulledEntry[] = kept.map((r: any) => ({
    clientKey: r.client_key,
    scope: r.scope,
    projectKey: r.project_key,
    kind: r.kind,
    content: r.content,
    tags: Array.isArray(r.tags) ? r.tags : [],
    source: r.source,
    confidence: Number(r.confidence),
    verified: r.verified === true,
    pinned: r.pinned === true,
    hits: Number(r.hits) || 0,
    deleted: r.deleted === true,
    updatedAt: Math.round(Number(r.updated_ms)),
  }));
  // When truncated, the cursor only advances to the last returned row, so nothing is skipped.
  const serverTime = truncated && entries.length ? entries[entries.length - 1].updatedAt : Date.now();
  return { serverTime, truncated, entries };
}

// ---- admin: the owner's view of what the devices remember ----------------------------------

const ADMIN_LIMIT = 500;

interface MemoryFilter {
  where: string;
  params: unknown[];
}

/** Builds the WHERE clause for the admin list from the query string. Every value is bounded and whitelisted. */
function memoryFilter(ctx: Ctx): MemoryFilter {
  const sp = ctx.url.searchParams;
  const where: string[] = [];
  const params: unknown[] = [];
  const q = (sp.get('q') ?? '').trim().slice(0, 120);
  if (q) {
    params.push(`%${q.replace(/[\\%_]/g, (m) => `\\${m}`)}%`);
    where.push(`m.content ILIKE $${params.length}`);
  }
  const scope = sp.get('scope') ?? '';
  if (scope === 'global' || scope === 'project') {
    params.push(scope);
    where.push(`m.scope = $${params.length}`);
  }
  const kind = sp.get('kind') ?? '';
  if (['fact', 'preference', 'lesson', 'decision'].includes(kind)) {
    params.push(kind);
    where.push(`m.kind = $${params.length}`);
  }
  const deviceId = sp.get('deviceId') ?? '';
  if (UUID.test(deviceId)) {
    params.push(deviceId);
    where.push(`m.device_id = $${params.length}`);
  }
  // A Devora account's brain: the memories of every device signed in as that user.
  const userId = sp.get('userId') ?? '';
  if (/^[A-Za-z0-9_]{1,64}$/.test(userId)) {
    params.push(userId);
    where.push(`m.device_id IN (SELECT id FROM devices WHERE user_id = $${params.length})`);
  }
  return { where: where.length ? `WHERE ${where.join(' AND ')}` : '', params };
}

/**
 * GET /admin/api/memory: the owner's read-only view of stored memories, newest first. Filters: q (text search
 * in the content), scope, kind, deviceId. Returns the matching totals plus one page of rows, so the admin site
 * can page with `offset`. Contents are shown here on purpose: memory text is the owner's own data and holds no
 * secrets (the sync endpoint refuses them at write time).
 */
export async function adminListMemory(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const limitRaw = Number(ctx.url.searchParams.get('limit') ?? 100);
  const limit = Number.isInteger(limitRaw) && limitRaw >= 1 && limitRaw <= ADMIN_LIMIT ? limitRaw : 100;
  const offsetRaw = Number(ctx.url.searchParams.get('offset') ?? 0);
  const offset = Number.isInteger(offsetRaw) && offsetRaw >= 0 && offsetRaw <= 1_000_000 ? offsetRaw : 0;
  const f = memoryFilter(ctx);
  const { rows: counted } = await ctx.deps.db.query(
    `SELECT count(*)::int AS total, count(*) FILTER (WHERE m.deleted = false)::int AS active FROM memory_entries m ${f.where}`,
    f.params,
  );
  const listParams = [...f.params, limit, offset];
  const { rows } = await ctx.deps.db.query(
    `SELECT m.id, m.device_id, m.scope, m.project_key, m.kind, m.content, m.tags, m.source, m.confidence,
            m.verified, m.pinned, m.hits, m.deleted, m.created_at, m.updated_at, d.name AS device_name
       FROM memory_entries m LEFT JOIN devices d ON d.id = m.device_id
       ${f.where} ORDER BY m.updated_at DESC LIMIT $${listParams.length - 1} OFFSET $${listParams.length}`,
    listParams,
  );
  sendJson(ctx.res, 200, {
    total: counted[0]?.total ?? 0,
    active: counted[0]?.active ?? 0,
    memories: rows.map((r: Record<string, unknown>) => ({
      id: r.id,
      deviceId: r.device_id,
      deviceName: r.device_name ?? null,
      scope: r.scope,
      projectKey: r.project_key,
      kind: r.kind,
      content: r.content,
      tags: Array.isArray(r.tags) ? r.tags : [],
      source: r.source,
      confidence: Number(r.confidence),
      verified: r.verified === true,
      pinned: r.pinned === true,
      hits: Number(r.hits) || 0,
      deleted: r.deleted === true,
      createdAt: r.created_at,
      updatedAt: r.updated_at,
    })),
  });
}

async function clearMemories(ctx: Ctx, deviceId: string | null): Promise<void> {
  await guardOwner(ctx, { write: true, sensitive: true });
  const { rows } = deviceId
    ? await ctx.deps.db.query('WITH gone AS (DELETE FROM memory_entries WHERE device_id = $1 RETURNING 1) SELECT count(*)::int AS n FROM gone', [deviceId])
    : await ctx.deps.db.query('WITH gone AS (DELETE FROM memory_entries RETURNING 1) SELECT count(*)::int AS n FROM gone');
  sendJson(ctx.res, 200, { cleared: rows[0]?.n ?? 0 });
}

/** DELETE /admin/api/memory/:deviceId: forgets one computer's stored memories. Sensitive: password confirmation. */
export async function adminClearDeviceMemory(ctx: Ctx): Promise<void> {
  await clearMemories(ctx, uuidParam(ctx.params.id));
}

/** DELETE /admin/api/memory: forgets everything every device stored. Sensitive: password confirmation. */
export async function adminClearAllMemory(ctx: Ctx): Promise<void> {
  await clearMemories(ctx, null);
}
