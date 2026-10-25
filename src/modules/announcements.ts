// Organization announcements: short notices the owner publishes in the admin site and every desktop shows to its user
// (a "maintenance tonight" note, a new feature, an urgent warning). A level (info, warning or critical) says how loudly
// the desktop should present it. Desktops download the enabled ones with GET /v1/announcements; the response carries an
// `announcements_version` ETag, so a desktop only downloads again when something changed. Bodies are plain text shown
// read-only on the desktop; they never contain code or scripts.
import type { Ctx } from '../context.ts';
import type { Queryer } from '../db/pg-wire.ts';
import { bool, fail, readJson, rejectUnknown, requireObject, sendJson, str, uuidParam } from '../http/util.ts';
import { guardOwner } from './auth.ts';
import { authenticateDevice } from './devices.ts';
import { bumpCatalogue } from './catalogue.ts';

export const LIMITS = { title: 120, body: 4000 };
/** The levels a desktop understands; unknown levels are rejected here so old desktops never see one. */
export const LEVELS = ['info', 'warning', 'critical'] as const;
export type AnnouncementLevel = (typeof LEVELS)[number];
const MAX_ANNOUNCEMENTS = 100;

function slugify(title: string): string {
  return (
    title
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 60) || 'announcement'
  );
}

function view(r: any) {
  return {
    id: r.id,
    slug: r.slug,
    title: r.title,
    body: r.body,
    level: r.level,
    enabled: r.enabled,
    revision: r.revision,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

async function bumpAnnouncements(q: Queryer): Promise<void> {
  await q.query("UPDATE settings SET value = to_jsonb((value::text::int) + 1), updated_at = now() WHERE key = 'announcements_version'");
  await bumpCatalogue(q);
}

/** Current announcements version (announced in the catalogue policy). 0 before migration 14. */
export async function announcementsVersion(db: Queryer): Promise<number> {
  try {
    const { rows } = await db.query("SELECT (value)::text::int AS v FROM settings WHERE key = 'announcements_version'");
    return rows[0]?.v ?? 0;
  } catch {
    return 0;
  }
}

function readLevel(v: unknown): AnnouncementLevel {
  if (typeof v !== 'string' || !(LEVELS as readonly string[]).includes(v)) {
    fail(400, 'invalid_request', `level must be one of: ${LEVELS.join(', ')}`);
  }
  return v as AnnouncementLevel;
}

function readAnnouncement(body: Record<string, unknown>, partial: boolean) {
  const title = str(body, 'title', { min: 1, max: LIMITS.title, optional: partial });
  if (title !== undefined && /[\r\n]/.test(title)) fail(400, 'invalid_request', 'the title must be a single line');
  const bodyText = str(body, 'body', { min: 1, max: LIMITS.body, optional: partial, trim: false });
  const level = body.level === undefined ? undefined : readLevel(body.level);
  const enabled = bool(body, 'enabled', { optional: true });
  return { title, body: bodyText?.trim(), level, enabled };
}

export async function listOrgAnnouncements(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query('SELECT * FROM org_announcements ORDER BY updated_at DESC');
  sendJson(ctx.res, 200, { announcements: rows.map(view), version: await announcementsVersion(ctx.deps.db), limits: LIMITS, levels: LEVELS });
}

export async function createOrgAnnouncement(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const body = requireObject(await readJson(ctx.req, 64 * 1024));
  rejectUnknown(body, ['title', 'body', 'level', 'enabled']);
  const a = readAnnouncement(body, false);
  if (a.level === undefined) fail(400, 'invalid_request', 'level is required');
  const { rows: countRows } = await ctx.deps.db.query('SELECT count(*)::int AS n FROM org_announcements');
  if (countRows[0].n >= MAX_ANNOUNCEMENTS) fail(409, 'too_many', `at most ${MAX_ANNOUNCEMENTS} announcements; delete an old one first`);
  const id = await ctx.deps.db.transaction(async (q) => {
    let slug = slugify(a.title!);
    for (let i = 2; (await q.query('SELECT 1 FROM org_announcements WHERE slug = $1', [slug])).rows.length; i++) slug = `${slugify(a.title!).slice(0, 55)}-${i}`;
    const { rows } = await q.query(
      `INSERT INTO org_announcements (slug, title, body, level, enabled) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [slug, a.title, a.body, a.level, a.enabled ?? true],
    );
    await bumpAnnouncements(q);
    return rows[0].id as string;
  });
  const { rows } = await ctx.deps.db.query('SELECT * FROM org_announcements WHERE id = $1', [id]);
  sendJson(ctx.res, 201, { announcement: view(rows[0]) });
}

export async function updateOrgAnnouncement(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 64 * 1024));
  rejectUnknown(body, ['title', 'body', 'level', 'enabled']);
  const a = readAnnouncement(body, true);
  const sets: string[] = [];
  const vals: unknown[] = [id];
  const add = (col: string, v: unknown) => {
    vals.push(v);
    sets.push(`${col} = $${vals.length}`);
  };
  if (a.title !== undefined) add('title', a.title);
  if (a.body !== undefined) add('body', a.body);
  if (a.level !== undefined) add('level', a.level);
  if (a.enabled !== undefined) add('enabled', a.enabled);
  if (!sets.length) fail(400, 'invalid_request', 'nothing to change');
  await ctx.deps.db.transaction(async (q) => {
    const { rowCount } = await q.query(`UPDATE org_announcements SET ${sets.join(', ')}, revision = revision + 1, updated_at = now() WHERE id = $1`, vals);
    if (!rowCount) fail(404, 'not_found', 'announcement not found');
    await bumpAnnouncements(q);
  });
  const { rows } = await ctx.deps.db.query('SELECT * FROM org_announcements WHERE id = $1', [id]);
  sendJson(ctx.res, 200, { announcement: view(rows[0]) });
}

export async function deleteOrgAnnouncement(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  await ctx.deps.db.transaction(async (q) => {
    const { rowCount } = await q.query('DELETE FROM org_announcements WHERE id = $1', [id]);
    if (!rowCount) fail(404, 'not_found', 'announcement not found');
    await bumpAnnouncements(q);
  });
  sendJson(ctx.res, 200, { deleted: true });
}

/** GET /v1/announcements: the enabled announcements for desktops (central endpoint; sign-in rules apply). */
export async function desktopAnnouncements(ctx: Ctx): Promise<void> {
  await authenticateDevice(ctx);
  const version = await announcementsVersion(ctx.deps.db);
  const etag = `"announcements-${version}"`;
  if (ctx.req.headers['if-none-match'] === etag) {
    ctx.res.writeHead(304, { etag, 'cache-control': 'no-store' });
    ctx.res.end();
    return;
  }
  const { rows } = await ctx.deps.db.query(
    'SELECT slug, title, body, level, revision, updated_at FROM org_announcements WHERE enabled ORDER BY updated_at DESC',
  );
  sendJson(
    ctx.res,
    200,
    {
      version,
      announcements: rows.map((r) => ({ slug: r.slug, title: r.title, body: r.body, level: r.level, revision: r.revision, updatedAt: r.updated_at })),
    },
    { etag },
  );
}
