// Organization skills: the owner writes SKILL.md-style skills in the admin site and every desktop receives them.
// The layout matches the desktop's skill format (name, description, triggers, instructions, examples), with the same
// size limits. Desktops download them with GET /v1/skills; the catalogue policy carries `skillsVersion`, so a desktop
// only downloads again when something changed.
import type { Ctx } from '../context.ts';
import type { Queryer } from '../db/pg-wire.ts';
import { bool, fail, readJson, rejectUnknown, requireObject, sendJson, str, uuidParam } from '../http/util.ts';
import { guardOwner } from './auth.ts';
import { authenticateDevice } from './devices.ts';
import { bumpCatalogue } from './catalogue.ts';

const LIMITS = { name: 80, description: 1024, trigger: 40, triggers: 20, instructions: 12_000, examples: 8_000 };

function slugify(name: string): string {
  return (
    name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 60) || 'skill'
  );
}

function readTriggers(v: unknown): string[] {
  const list = Array.isArray(v) ? v : typeof v === 'string' ? v.split(',') : v === undefined ? [] : null;
  if (!list) fail(400, 'invalid_request', 'triggers must be a list of words or a comma-separated string');
  const out = [...new Set(list.map((t) => String(t).trim().toLowerCase()).filter(Boolean))];
  if (out.length > LIMITS.triggers) fail(400, 'invalid_request', `at most ${LIMITS.triggers} triggers`);
  if (out.some((t) => t.length > LIMITS.trigger || /[\r\n]/.test(t))) fail(400, 'invalid_request', `each trigger is one line of at most ${LIMITS.trigger} characters`);
  return out;
}

function view(r: any) {
  return {
    id: r.id,
    slug: r.slug,
    name: r.name,
    description: r.description,
    triggers: r.triggers ?? [],
    instructions: r.instructions,
    examples: r.examples,
    enabled: r.enabled,
    revision: r.revision,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

async function bumpSkills(q: Queryer): Promise<void> {
  await q.query("UPDATE settings SET value = to_jsonb((value::text::int) + 1), updated_at = now() WHERE key = 'skills_version'");
  await bumpCatalogue(q);
}

/** Current skills version (announced in the catalogue policy). 0 before migration 9. */
export async function skillsVersion(db: Queryer): Promise<number> {
  try {
    const { rows } = await db.query("SELECT (value)::text::int AS v FROM settings WHERE key = 'skills_version'");
    return rows[0]?.v ?? 0;
  } catch {
    return 0;
  }
}

function readSkill(body: Record<string, unknown>, partial: boolean) {
  const name = str(body, 'name', { min: 1, max: LIMITS.name, optional: partial });
  if (name !== undefined && /[\r\n]/.test(name)) fail(400, 'invalid_request', 'the name must be a single line');
  const description = str(body, 'description', { min: 1, max: LIMITS.description, optional: partial });
  const instructions = str(body, 'instructions', { min: 1, max: LIMITS.instructions, optional: partial, trim: false });
  const examples = str(body, 'examples', { max: LIMITS.examples, optional: true, trim: false });
  const triggers = body.triggers === undefined ? undefined : readTriggers(body.triggers);
  const enabled = bool(body, 'enabled', { optional: true });
  return { name, description, instructions: instructions?.trim(), examples: examples?.trim(), triggers, enabled };
}

export async function listOrgSkills(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query('SELECT * FROM org_skills ORDER BY name');
  sendJson(ctx.res, 200, { skills: rows.map(view), version: await skillsVersion(ctx.deps.db), limits: LIMITS });
}

export async function createOrgSkill(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const body = requireObject(await readJson(ctx.req, 64 * 1024));
  rejectUnknown(body, ['name', 'description', 'triggers', 'instructions', 'examples', 'enabled']);
  const s = readSkill(body, false);
  const id = await ctx.deps.db.transaction(async (q) => {
    let slug = slugify(s.name!);
    for (let i = 2; (await q.query('SELECT 1 FROM org_skills WHERE slug = $1', [slug])).rows.length; i++) slug = `${slugify(s.name!).slice(0, 55)}-${i}`;
    const { rows } = await q.query(
      `INSERT INTO org_skills (slug, name, description, triggers, instructions, examples, enabled) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [slug, s.name, s.description, JSON.stringify(s.triggers ?? []), s.instructions, s.examples ?? '', s.enabled ?? true],
    );
    await bumpSkills(q);
    return rows[0].id as string;
  });
  const { rows } = await ctx.deps.db.query('SELECT * FROM org_skills WHERE id = $1', [id]);
  sendJson(ctx.res, 201, { skill: view(rows[0]) });
}

export async function updateOrgSkill(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 64 * 1024));
  rejectUnknown(body, ['name', 'description', 'triggers', 'instructions', 'examples', 'enabled']);
  const s = readSkill(body, true);
  const sets: string[] = [];
  const vals: unknown[] = [id];
  const add = (col: string, v: unknown) => {
    vals.push(v);
    sets.push(`${col} = $${vals.length}`);
  };
  if (s.name !== undefined) add('name', s.name);
  if (s.description !== undefined) add('description', s.description);
  if (s.instructions !== undefined) add('instructions', s.instructions);
  if (s.examples !== undefined) add('examples', s.examples);
  if (s.triggers !== undefined) add('triggers', JSON.stringify(s.triggers));
  if (s.enabled !== undefined) add('enabled', s.enabled);
  if (!sets.length) fail(400, 'invalid_request', 'nothing to change');
  await ctx.deps.db.transaction(async (q) => {
    const { rowCount } = await q.query(`UPDATE org_skills SET ${sets.join(', ')}, revision = revision + 1, updated_at = now() WHERE id = $1`, vals);
    if (!rowCount) fail(404, 'not_found', 'skill not found');
    await bumpSkills(q);
  });
  const { rows } = await ctx.deps.db.query('SELECT * FROM org_skills WHERE id = $1', [id]);
  sendJson(ctx.res, 200, { skill: view(rows[0]) });
}

export async function deleteOrgSkill(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  await ctx.deps.db.transaction(async (q) => {
    const { rowCount } = await q.query('DELETE FROM org_skills WHERE id = $1', [id]);
    if (!rowCount) fail(404, 'not_found', 'skill not found');
    await bumpSkills(q);
  });
  sendJson(ctx.res, 200, { deleted: true });
}

/** GET /v1/skills: the enabled organization skills for desktops (central endpoint; sign-in rules apply). */
export async function desktopSkills(ctx: Ctx): Promise<void> {
  await authenticateDevice(ctx);
  const version = await skillsVersion(ctx.deps.db);
  const etag = `"skills-${version}"`;
  if (ctx.req.headers['if-none-match'] === etag) {
    ctx.res.writeHead(304, { etag, 'cache-control': 'no-store' });
    ctx.res.end();
    return;
  }
  const { rows } = await ctx.deps.db.query('SELECT slug, name, description, triggers, instructions, examples, revision, updated_at FROM org_skills WHERE enabled ORDER BY name');
  sendJson(
    ctx.res,
    200,
    { version, skills: rows.map((r) => ({ slug: r.slug, name: r.name, description: r.description, triggers: r.triggers ?? [], instructions: r.instructions, examples: r.examples, revision: r.revision, updatedAt: r.updated_at })) },
    { etag },
  );
}
