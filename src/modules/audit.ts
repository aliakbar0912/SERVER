// The owner's audit log: every sensitive change made through the admin site is recorded here (who, what, on which
// target and the route parameters — never request bodies, so secrets and content stay out of the log). Recording is
// best-effort: a failed insert never breaks the change itself, and the log is skipped entirely before migration 15.
import type { Ctx } from '../context.ts';
import type { Queryer } from '../db/pg-wire.ts';
import { fail, sendJson } from '../http/util.ts';
import { guardOwner, ownerSession } from './auth.ts';

/** Records one audit entry. Never throws: the change that produced it must not fail because logging failed. */
export async function record(db: Queryer, actor: string, action: string, target: string, detail: Record<string, unknown> = {}): Promise<void> {
  try {
    await db.query('INSERT INTO audit_log (actor, action, target, detail) VALUES ($1, $2, $3, $4)', [
      actor.slice(0, 254),
      action.slice(0, 120),
      target.slice(0, 200),
      JSON.stringify(detail),
    ]);
  } catch {
    // The table may not exist yet (migration 15 pending) or the database may be briefly busy; logging stays best-effort.
  }
}

/**
 * Wraps an admin write handler so a successful change is audited. The action name is a stable label (for example
 * "settings.update"); the target is the :id route parameter when the route has one. The actor is resolved from the
 * admin session after the handler ran, so unauthenticated or failed requests are never recorded.
 */
export function withAudit(action: string, handler: (ctx: Ctx) => Promise<void>): (ctx: Ctx) => Promise<void> {
  return async (ctx: Ctx): Promise<void> => {
    await handler(ctx);
    try {
      const session = await ownerSession(ctx);
      await record(ctx.deps.db, session.email, action, ctx.params.id ?? '', routeDetail(ctx));
    } catch {
      // Never fail the change because auditing failed.
    }
  };
}

function routeDetail(ctx: Ctx): Record<string, unknown> {
  const detail: Record<string, unknown> = { method: ctx.req.method ?? '' };
  for (const [k, v] of Object.entries(ctx.params)) detail[k] = v;
  const query = ctx.url.searchParams.get('action');
  if (query && !detail.action) detail.queryAction = query.slice(0, 60);
  return detail;
}

/** GET /admin/api/audit: the most recent audit entries, newest first, with simple filters and a cursor. */
export async function listAudit(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const q = ctx.url.searchParams;
  const limit = Math.min(200, Math.max(1, Number(q.get('limit') ?? 50) || 50));
  const where: string[] = [];
  const params: unknown[] = [];
  if (q.get('action')) {
    params.push(q.get('action')!.slice(0, 120));
    where.push(`action = $${params.length}`);
  }
  if (q.get('actor')) {
    params.push(q.get('actor')!.slice(0, 254));
    where.push(`actor = $${params.length}`);
  }
  if (q.get('cursor')) {
    const c = Number(q.get('cursor'));
    if (!Number.isInteger(c) || c < 1) fail(400, 'invalid_request', 'cursor is not valid');
    params.push(c);
    where.push(`id < $${params.length}`);
  }
  params.push(limit + 1);
  const { rows } = await ctx.deps.db.query(
    `SELECT id, created_at, actor, action, target, detail FROM audit_log
      ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
     ORDER BY id DESC LIMIT $${params.length}`,
    params,
  );
  const page = rows.slice(0, limit);
  sendJson(ctx.res, 200, {
    entries: page.map((r) => ({ id: Number(r.id), createdAt: r.created_at, actor: r.actor, action: r.action, target: r.target, detail: r.detail ?? {} })),
    nextCursor: rows.length > limit ? String(page[page.length - 1].id) : null,
  });
}

/** Deletes audit entries older than the retention window. Called by the same maintenance loop that prunes request logs. */
export async function pruneAudit(db: Queryer, days: number): Promise<number> {
  const { rowCount } = await db.query('DELETE FROM audit_log WHERE created_at < now() - make_interval(days => $1)', [days]);
  return rowCount ?? 0;
}
