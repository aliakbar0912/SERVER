// The brain dashboard: live heartbeats from desktops plus a summary of the memory ("brain") they mirror.
//
// POST /v1/brain/beat   a desktop reports, every ~30 s, whether its agent is working, the tasks in progress, the last
//                       tool step, local memory counts and any task events since the previous beat.
// GET  /admin/api/brain the owner's view: who is online, who is working, memory totals and growth, recent events.
//
// Beats are parsed leniently (unknown or oversized values are dropped, not rejected) so an older or newer desktop never
// gets an error for a status report. Nothing here stores code, file contents or prompts beyond a short task title.
import type { Ctx } from '../context.ts';
import { fail, readJson, requireObject, sendJson } from '../http/util.ts';
import { guardOwner } from './auth.ts';
import { authenticateDevice } from './devices.ts';

const BEATS_PER_MINUTE = 20;
const BODY_LIMIT = 32 * 1024;
/** A device counts as online when its last beat is newer than this. Desktops beat every 30 s. */
export const ONLINE_SECONDS = 90;
const EVENT_RETENTION_DAYS = 14;
const EVENT_KINDS = new Set(['task_started', 'task_completed', 'task_failed', 'task_cancelled']);
const MODES = new Set(['ask', 'build', 'plan']);

type Json = Record<string, unknown>;

function text(v: unknown, max: number): string {
  return typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max) : '';
}
function count(v: unknown, max = 10_000_000): number {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), max) : 0;
}
function obj(v: unknown): Json {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Json) : {};
}
function time(v: unknown, now: number): number {
  const t = count(v, 8_999_999_999_999);
  return t > now - 7 * 86_400_000 && t <= now + 300_000 ? t : now;
}

export interface Beat {
  state: 'idle' | 'running';
  appVersion: string;
  tasks: { title: string; mode: string; status: string; iterations: number; toolCalls: number; startedAt: number }[];
  lastStep: { kind: string; name: string; status: string; at: number } | null;
  counters: { tasksStarted: number; tasksCompleted: number; tasksFailed: number; toolCalls: number; uptimeSeconds: number };
  memory: { total: number; fact: number; preference: number; lesson: number; decision: number; pinned: number; verified: number };
}

export function parseBeat(body: Json, now = Date.now()): { beat: Beat; events: { kind: string; title: string; at: number }[] } {
  const tasks = (Array.isArray(body.tasks) ? body.tasks : []).slice(0, 10).map((raw) => {
    const t = obj(raw);
    return {
      title: text(t.title, 120),
      mode: MODES.has(String(t.mode)) ? String(t.mode) : '',
      status: text(t.status, 30),
      iterations: count(t.iterations, 100_000),
      toolCalls: count(t.toolCalls, 100_000),
      startedAt: time(t.startedAt, now),
    };
  });
  const s = obj(body.lastStep);
  const lastStep = s.kind ? { kind: text(s.kind, 20), name: text(s.name, 80), status: text(s.status, 20), at: time(s.at, now) } : null;
  const c = obj(body.counters);
  const m = obj(body.memory);
  const beat: Beat = {
    state: body.state === 'running' || tasks.length > 0 ? 'running' : 'idle',
    appVersion: text(body.appVersion, 40),
    tasks,
    lastStep,
    counters: {
      tasksStarted: count(c.tasksStarted),
      tasksCompleted: count(c.tasksCompleted),
      tasksFailed: count(c.tasksFailed),
      toolCalls: count(c.toolCalls),
      uptimeSeconds: count(c.uptimeSeconds),
    },
    memory: {
      total: count(m.total),
      fact: count(m.fact),
      preference: count(m.preference),
      lesson: count(m.lesson),
      decision: count(m.decision),
      pinned: count(m.pinned),
      verified: count(m.verified),
    },
  };
  const events = (Array.isArray(body.events) ? body.events : [])
    .slice(0, 30)
    .map((raw) => {
      const e = obj(raw);
      return { kind: String(e.kind), title: text(e.title, 120), at: time(e.at, now) };
    })
    .filter((e) => EVENT_KINDS.has(e.kind));
  return { beat, events };
}

/** POST /v1/brain/beat: one heartbeat from a desktop. */
export async function brainBeat(ctx: Ctx): Promise<void> {
  const auth = await authenticateDevice(ctx);
  const limit = await ctx.deps.limits.hit(`brain:beat:${auth.deviceId}`, BEATS_PER_MINUTE, 60);
  if (!limit.allowed) fail(429, 'rate_limited', 'too many heartbeats; slow down', { 'retry-after': String(limit.retryAfterSeconds) });
  const body = requireObject(await readJson(ctx.req, BODY_LIMIT));
  const { beat, events } = parseBeat(body);
  const db = ctx.deps.db;
  const { rows } = await db.query(
    `WITH prev AS (SELECT beat_at FROM devices WHERE id = $1)
     UPDATE devices SET beat_at = now(), beat_state = $2, beat = $3::jsonb WHERE id = $1
     RETURNING (SELECT beat_at FROM prev) AS prev_beat_at`,
    [auth.deviceId, beat.state, JSON.stringify(beat)],
  );
  const prev = rows[0]?.prev_beat_at ? new Date(rows[0].prev_beat_at as string).getTime() : 0;
  if (!prev || Date.now() - prev > ONLINE_SECONDS * 1000) {
    await db.query(`INSERT INTO brain_events (device_id, kind, title) VALUES ($1, 'online', '')`, [auth.deviceId]);
  }
  for (const e of events) {
    await db.query('INSERT INTO brain_events (device_id, kind, title, created_at) VALUES ($1, $2, $3, to_timestamp($4 / 1000.0))', [auth.deviceId, e.kind, e.title, e.at]);
  }
  // Old events are pruned now and then, on the write path, so no extra job is needed.
  if (Math.random() < 0.02) {
    await db.query('DELETE FROM brain_events WHERE created_at < now() - make_interval(days => $1)', [EVENT_RETENTION_DAYS]);
  }
  sendJson(ctx.res, 200, { ok: true, intervalSeconds: 30 });
}

const num = (v: unknown) => Number(v) || 0;

/** GET /admin/api/brain: everything the Brain page shows, in one call. */
export async function adminBrain(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const db = ctx.deps.db;
  const online = `coalesce(d.beat_at > now() - make_interval(secs => ${ONLINE_SECONDS}), false)`;

  const [devices, memory, kinds, sources, growth, events, top] = await Promise.all([
    db.query(
      `SELECT d.id, d.name, d.app_version, d.last_seen_at, d.beat_at, d.beat_state, d.beat, (${online}) AS online,
              coalesce(m.active, 0) AS mem_active, coalesce(m.lessons, 0) AS mem_lessons, coalesce(m.verified, 0) AS mem_verified,
              m.last_update AS mem_last_update
         FROM devices d
         LEFT JOIN (
           SELECT device_id, count(*) FILTER (WHERE NOT deleted) AS active,
                  count(*) FILTER (WHERE NOT deleted AND kind = 'lesson') AS lessons,
                  count(*) FILTER (WHERE NOT deleted AND verified) AS verified,
                  max(updated_at) AS last_update
             FROM memory_entries GROUP BY device_id
         ) m ON m.device_id = d.id
        WHERE d.status = 'active'
        ORDER BY (${online}) DESC, d.beat_at DESC NULLS LAST, d.last_seen_at DESC NULLS LAST
        LIMIT 200`,
    ),
    db.query(
      `SELECT count(*) FILTER (WHERE NOT deleted) AS active,
              count(*) FILTER (WHERE NOT deleted AND verified) AS verified,
              count(*) FILTER (WHERE NOT deleted AND pinned) AS pinned,
              coalesce(avg(confidence) FILTER (WHERE NOT deleted), 0) AS avg_confidence,
              coalesce(sum(hits) FILTER (WHERE NOT deleted), 0) AS hits,
              count(*) FILTER (WHERE NOT deleted AND created_at > now() - interval '1 day') AS added_today,
              count(*) FILTER (WHERE deleted AND updated_at > now() - interval '1 day') AS forgotten_today
         FROM memory_entries`,
    ),
    db.query(`SELECT kind, count(*) AS n FROM memory_entries WHERE NOT deleted GROUP BY kind`),
    db.query(`SELECT source, count(*) AS n FROM memory_entries WHERE NOT deleted GROUP BY source`),
    db.query(
      `SELECT to_char(day, 'YYYY-MM-DD') AS day,
              (SELECT count(*) FROM memory_entries m WHERE m.created_at >= day AND m.created_at < day + interval '1 day') AS added,
              (SELECT count(*) FROM brain_events e WHERE e.kind = 'task_completed' AND e.created_at >= day AND e.created_at < day + interval '1 day') AS tasks
         FROM generate_series(date_trunc('day', now()) - interval '13 days', date_trunc('day', now()), interval '1 day') AS day
        ORDER BY day`,
    ),
    db.query(
      `SELECT e.id, e.kind, e.title, e.created_at, e.device_id, d.name AS device_name
         FROM brain_events e LEFT JOIN devices d ON d.id = e.device_id
        ORDER BY e.created_at DESC LIMIT 60`,
    ),
    db.query(
      `SELECT m.id, m.kind, m.content, m.hits, m.confidence, m.verified, d.name AS device_name
         FROM memory_entries m LEFT JOIN devices d ON d.id = m.device_id
        WHERE NOT m.deleted ORDER BY m.hits DESC, m.updated_at DESC LIMIT 8`,
    ),
  ]);

  const deviceRows = devices.rows.map((r: Json) => {
    const beat = obj(r.beat) as Partial<Beat>;
    const isOnline = r.online === true;
    return {
      id: r.id,
      name: r.name,
      appVersion: r.app_version ?? beat.appVersion ?? null,
      lastSeenAt: r.last_seen_at,
      beatAt: r.beat_at,
      online: isOnline,
      working: isOnline && r.beat_state === 'running',
      tasks: isOnline && Array.isArray(beat.tasks) ? beat.tasks : [],
      lastStep: beat.lastStep ?? null,
      counters: beat.counters ?? null,
      localMemory: beat.memory ?? null,
      memory: { active: num(r.mem_active), lessons: num(r.mem_lessons), verified: num(r.mem_verified), lastUpdate: r.mem_last_update ?? null },
    };
  });
  const m = (memory.rows[0] ?? {}) as Json;
  const byKind: Record<string, number> = { fact: 0, preference: 0, lesson: 0, decision: 0 };
  for (const r of kinds.rows as Json[]) byKind[String(r.kind)] = num(r.n);
  const bySource: Record<string, number> = { user: 0, agent: 0, system: 0 };
  for (const r of sources.rows as Json[]) bySource[String(r.source)] = num(r.n);

  sendJson(ctx.res, 200, {
    onlineSeconds: ONLINE_SECONDS,
    summary: {
      devices: deviceRows.length,
      online: deviceRows.filter((d) => d.online).length,
      working: deviceRows.filter((d) => d.working).length,
      activeTasks: deviceRows.reduce((n, d) => n + d.tasks.length, 0),
    },
    memory: {
      active: num(m.active),
      verified: num(m.verified),
      pinned: num(m.pinned),
      avgConfidence: Math.round(num(m.avg_confidence) * 100) / 100,
      hits: num(m.hits),
      addedToday: num(m.added_today),
      forgottenToday: num(m.forgotten_today),
      byKind,
      bySource,
    },
    growth: (growth.rows as Json[]).map((r) => ({ day: r.day, added: num(r.added), tasks: num(r.tasks) })),
    devices: deviceRows,
    events: (events.rows as Json[]).map((r) => ({ id: String(r.id), kind: r.kind, title: r.title, at: r.created_at, deviceId: r.device_id, deviceName: r.device_name ?? null })),
    topMemories: (top.rows as Json[]).map((r) => ({ id: r.id, kind: r.kind, content: r.content, hits: num(r.hits), confidence: Number(r.confidence), verified: r.verified === true, deviceName: r.device_name ?? null })),
  });
}
