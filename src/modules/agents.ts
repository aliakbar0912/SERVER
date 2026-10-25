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

/** Ready-made presets the admin site offers when writing a new agent; served with the list, stored nowhere. */
export const TEMPLATES: { name: string; description: string; instructions: string; access: AgentAccess; suggestedModel: string | null }[] = [
  {
    name: 'Code reviewer',
    description: 'Reviews recent changes for correctness, style and hidden bugs, and reports findings without editing anything.',
    instructions: `Review the changes you were given (or the most recent commit when nothing specific was given).

Steps:
1. List the files that changed and skim each diff.
2. Look for correctness bugs, missing error handling, edge cases and security issues.
3. Note style or naming problems only when they hurt readability.
4. Report findings in order of severity, each with the file, the line area and a one-line suggestion.

Rules:
- Never change any file.
- Say clearly when you found nothing worth reporting.`,
    access: 'read',
    suggestedModel: null,
  },
  {
    name: 'Test writer',
    description: 'Writes focused unit tests for a given file or feature and runs them to confirm they pass.',
    instructions: `Write tests for the feature or file you were given.

Steps:
1. Read the code under test and the existing test setup; follow the project's existing test style.
2. Cover the happy path first, then the important edge cases and error paths.
3. Add the tests to the right existing file, or a new one next to them when the project expects that.
4. Run the test suite and fix your tests until they pass.

Rules:
- Do not change production code to make a test pass; report the problem instead.
- Keep each test independent and named so a failure explains itself.`,
    access: 'commands',
    suggestedModel: null,
  },
  {
    name: 'Docs writer',
    description: 'Updates README, CHANGELOG and other documentation to match the current state of the project.',
    instructions: `Update the project documentation you were asked to touch.

Steps:
1. Read the current docs and the relevant code or changes they describe.
2. Fix anything that is out of date; prefer small, precise edits over rewrites.
3. Keep the existing tone, structure and heading style.
4. Only edit documentation files (README, CHANGELOG, docs folder) and never code.

Rules:
- Do not invent features that do not exist.
- Keep examples short and runnable.`,
    access: 'docs',
    suggestedModel: null,
  },
  {
    name: 'Dependency updater',
    description: 'Bumps outdated dependencies, runs the tests and reports what changed and what broke.',
    instructions: `Update the dependencies you were asked to update.

Steps:
1. List the current versions and the target versions.
2. Update the manifest and lockfile with the project's package manager.
3. Run the build and the test suite.
4. Summarize what was updated, what passed and what failed, with the exact error output for failures.

Rules:
- Update one dependency group at a time so failures are easy to attribute.
- Never edit a lockfile by hand; always use the package manager.`,
    access: 'write_commands',
    suggestedModel: null,
  },
  {
    name: 'Release notes writer',
    description: 'Turns recent commits and diffs into clean, user-facing release notes.',
    instructions: `Write release notes for the changes you were given.

Steps:
1. Read the commits and diffs since the last release.
2. Group them into Added, Changed, Fixed and Removed.
3. Write one line per user-visible change; skip internal chores unless they matter to users.
4. Return the notes as a markdown list, ready to paste into the changelog.

Rules:
- Never change any file.
- Describe changes from the user's point of view, not the implementation's.`,
    access: 'read',
    suggestedModel: null,
  },
  {
    name: 'Bug triage',
    description: 'Investigates a reported bug, finds the likely cause in the code and proposes a fix plan.',
    instructions: `Investigate the bug report you were given.

Steps:
1. Restate the bug in one sentence: expected behavior, actual behavior.
2. Search the code for the feature involved and trace the likely path.
3. Name the most probable cause with file and line references, and say how confident you are.
4. Propose a minimal fix plan (steps, touched files, risks) without implementing it.

Rules:
- Read-only: never change files.
- When the cause is not in the code (environment, data, config), say so and list what to check.`,
    access: 'read',
    suggestedModel: null,
  },
];

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
  sendJson(ctx.res, 200, { agents: rows.map(view), version: await agentsVersion(ctx.deps.db), limits: LIMITS, accessLevels: ACCESS_LEVELS, templates: TEMPLATES });
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
