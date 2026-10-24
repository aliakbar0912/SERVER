// Organization agents: the owner defines reusable agent presets (name, description, instructions, access level and an
// optional suggested model) in the admin site and every desktop receives them. The desktop decides how they appear;
// the access level here can only narrow what the desktop already allows, never widen it. Desktops download them with
// GET /v1/agents; the catalogue policy carries `agentsVersion`, so a desktop only downloads again when something changed.
import type { Ctx } from '../context.ts';
import type { Queryer } from '../db/pg-wire.ts';
import { bool, fail, readJson, rejectUnknown, requireObject, sendJson, str, uuidParam } from '../http/util.ts';
import { guardOwner } from './auth.ts';
import { authenticateDevice } from './devices.ts';
import { bumpCatalogue } from './catalogue.ts';

export const LIMITS = { name: 80, description: 1024, instructions: 8_000, suggestedModel: 200 };
/** The access levels mirror the desktop's RoleAccess (src/shared/agent-roles.ts). */
export const ACCESS_LEVELS = ['read', 'commands', 'docs', 'write', 'write_commands'] as const;
export type AgentAccess = (typeof ACCESS_LEVELS)[number];

function slugify(name: string): string {
  return (
    name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 60) || 'agent'
  );
}

function view(r: any) {
  return {
    id: r.id,
    slug: r.slug,
    name: r.name,
    description: r.description,
    instructions: r.instructions,
    access: r.access,
    suggestedModel: r.suggested_model,
    enabled: r.enabled,
    revision: r.revision,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

async function bumpAgents(q: Queryer): Promise<void> {
  await q.query("UPDATE settings SET value = to_jsonb((value::text::int) + 1), updated_at = now() WHERE key = 'agents_version'");
  await bumpCatalogue(q);
}

/** Current agents version (announced in the catalogue policy). 0 before migration 11. */
export async function agentsVersion(db: Queryer): Promise<number> {
  try {
    const { rows } = await db.query("SELECT (value)::text::int AS v FROM settings WHERE key = 'agents_version'");
    return rows[0]?.v ?? 0;
  } catch {
    return 0;
  }
}

function readAgent(body: Record<string, unknown>, partial: boolean) {
  const name = str(body, 'name', { min: 1, max: LIMITS.name, optional: partial });
  if (name !== undefined && /[\r\n]/.test(name)) fail(400, 'invalid_request', 'the name must be a single line');
  const description = str(body, 'description', { min: 1, max: LIMITS.description, optional: partial });
  const instructions = str(body, 'instructions', { min: 1, max: LIMITS.instructions, optional: partial, trim: false });
  const access = body.access === undefined ? undefined : readAccess(body.access);
  let suggestedModel: string | null | undefined;
  if (body.suggestedModel !== undefined) {
    if (body.suggestedModel === null || body.suggestedModel === '') suggestedModel = null;
    else suggestedModel = str(body, 'suggestedModel', { min: 1, max: LIMITS.suggestedModel });
  }
  const enabled = bool(body, 'enabled', { optional: true });
  return { name, description, instructions: instructions?.trim(), access, suggestedModel, enabled };
}

function readAccess(v: unknown): AgentAccess {
  if (typeof v !== 'string' || !(ACCESS_LEVELS as readonly string[]).includes(v)) {
    fail(400, 'invalid_request', `access must be one of: ${ACCESS_LEVELS.join(', ')}`);
  }
  return v as AgentAccess;
}

export async function listOrgAgents(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query('SELECT * FROM org_agents ORDER BY name');
  sendJson(ctx.res, 200, { agents: rows.map(view), version: await agentsVersion(ctx.deps.db), limits: LIMITS, accessLevels: ACCESS_LEVELS });
}

export async function createOrgAgent(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const body = requireObject(await readJson(ctx.req, 64 * 1024));
  rejectUnknown(body, ['name', 'description', 'instructions', 'access', 'suggestedModel', 'enabled']);
  const a = readAgent(body, false);
  if (a.access === undefined) fail(400, 'invalid_request', 'access is required');
  const id = await ctx.deps.db.transaction(async (q) => {
    let slug = slugify(a.name!);
    for (let i = 2; (await q.query('SELECT 1 FROM org_agents WHERE slug = $1', [slug])).rows.length; i++) slug = `${slugify(a.name!).slice(0, 55)}-${i}`;
    const { rows } = await q.query(
      `INSERT INTO org_agents (slug, name, description, instructions, access, suggested_model, enabled) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [slug, a.name, a.description, a.instructions, a.access, a.suggestedModel ?? null, a.enabled ?? true],
    );
    await bumpAgents(q);
    return rows[0].id as string;
  });
  const { rows } = await ctx.deps.db.query('SELECT * FROM org_agents WHERE id = $1', [id]);
  sendJson(ctx.res, 201, { agent: view(rows[0]) });
}

export async function updateOrgAgent(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 64 * 1024));
  rejectUnknown(body, ['name', 'description', 'instructions', 'access', 'suggestedModel', 'enabled']);
  const a = readAgent(body, true);
  const sets: string[] = [];
  const vals: unknown[] = [id];
  const add = (col: string, v: unknown) => {
    vals.push(v);
    sets.push(`${col} = $${vals.length}`);
  };
  if (a.name !== undefined) add('name', a.name);
  if (a.description !== undefined) add('description', a.description);
  if (a.instructions !== undefined) add('instructions', a.instructions);
  if (a.access !== undefined) add('access', a.access);
  if (a.suggestedModel !== undefined) add('suggested_model', a.suggestedModel);
  if (a.enabled !== undefined) add('enabled', a.enabled);
  if (!sets.length) fail(400, 'invalid_request', 'nothing to change');
  await ctx.deps.db.transaction(async (q) => {
    const { rowCount } = await q.query(`UPDATE org_agents SET ${sets.join(', ')}, revision = revision + 1, updated_at = now() WHERE id = $1`, vals);
    if (!rowCount) fail(404, 'not_found', 'agent not found');
    await bumpAgents(q);
  });
  const { rows } = await ctx.deps.db.query('SELECT * FROM org_agents WHERE id = $1', [id]);
  sendJson(ctx.res, 200, { agent: view(rows[0]) });
}

export async function deleteOrgAgent(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  await ctx.deps.db.transaction(async (q) => {
    const { rowCount } = await q.query('DELETE FROM org_agents WHERE id = $1', [id]);
    if (!rowCount) fail(404, 'not_found', 'agent not found');
    await bumpAgents(q);
  });
  sendJson(ctx.res, 200, { deleted: true });
}

/** GET /v1/agents: the enabled organization agents for desktops (central endpoint; sign-in rules apply). */
export async function desktopAgents(ctx: Ctx): Promise<void> {
  await authenticateDevice(ctx);
  const version = await agentsVersion(ctx.deps.db);
  const etag = `"agents-${version}"`;
  if (ctx.req.headers['if-none-match'] === etag) {
    ctx.res.writeHead(304, { etag, 'cache-control': 'no-store' });
    ctx.res.end();
    return;
  }
  const { rows } = await ctx.deps.db.query(
    'SELECT slug, name, description, instructions, access, suggested_model, revision, updated_at FROM org_agents WHERE enabled ORDER BY name',
  );
  sendJson(
    ctx.res,
    200,
    {
      version,
      agents: rows.map((r) => ({ slug: r.slug, name: r.name, description: r.description, instructions: r.instructions, access: r.access, suggestedModel: r.suggested_model, revision: r.revision, updatedAt: r.updated_at })),
    },
    { etag },
  );
}
