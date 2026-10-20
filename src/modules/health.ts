// Owner health view: database, Redis, schema, provider test results, and non-secret configuration. Read-only.
// It never calls a provider (that costs money and leaks requests); it reports the owner's last explicit test per provider.
import type { Ctx } from '../context.ts';
import { sendJson } from '../http/util.ts';
import { migrationStatus } from '../db/migrate.ts';
import { activeLeaseCount } from '../persistent-limits.ts';
import { guardOwner } from './auth.ts';

const STALE_TEST_HOURS = 24 * 7;

export async function adminHealth(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const { db, config } = ctx.deps;
  const checkedAt = new Date().toISOString();

  const dbStart = Date.now();
  let database: { ok: boolean; latencyMs: number | null; schemaVersion: number | null; pendingMigrations: number | null; reason: string | null };
  try {
    await db.query('SELECT 1');
    const latencyMs = Date.now() - dbStart;
    const s = await migrationStatus(db);
    database = { ok: s.pending.length === 0, latencyMs, schemaVersion: s.currentVersion, pendingMigrations: s.pending.length, reason: s.pending.length ? 'migrations are pending' : null };
  } catch {
    database = { ok: false, latencyMs: null, schemaVersion: null, pendingMigrations: null, reason: 'the database is unreachable' };
  }

  const providers = database.ok
    ? (
        await db.query(
          `SELECT count(*) FILTER (WHERE enabled)::int AS enabled,
                  count(*) FILTER (WHERE enabled AND last_test_ok IS NULL)::int AS untested,
                  count(*) FILTER (WHERE enabled AND last_test_ok IS FALSE)::int AS failing,
                  count(*) FILTER (WHERE enabled AND last_test_at < now() - make_interval(hours => $1))::int AS stale
             FROM providers`,
          [STALE_TEST_HOURS],
        )
      ).rows[0]
    : null;

  const activeLeases = database.ok ? await activeLeaseCount(db) : null;

  // Redis is optional. When it is configured it holds the rate limits, so the service cannot work without it.
  let redis: { configured: boolean; ok: boolean | null; latencyMs: number | null; target: string | null; reason: string | null };
  if (!ctx.deps.redis) redis = { configured: false, ok: null, latencyMs: null, target: null, reason: null };
  else {
    try {
      const latencyMs = await ctx.deps.redis.ping();
      redis = { configured: true, ok: true, latencyMs, target: ctx.deps.redis.target, reason: null };
    } catch (e) {
      redis = { configured: true, ok: false, latencyMs: null, target: ctx.deps.redis.target, reason: e instanceof Error ? e.message : 'unavailable' };
    }
  }
  const limitsUp = ctx.deps.limits.kind === 'redis' ? redis.ok === true : database.ok;

  const providerProblems = providers ? providers.failing + providers.untested : 0;
  const status = !database.ok || redis.ok === false ? 'down' : providerProblems > 0 || (providers?.stale ?? 0) > 0 ? 'degraded' : 'ok';

  sendJson(ctx.res, 200, {
    status,
    checkedAt,
    api: { status: 'ok', uptimeSeconds: Math.round(process.uptime()), environment: config.env },
    database,
    redis,
    providers: providers
      ? { enabled: providers.enabled, untested: providers.untested, failing: providers.failing, staleAfterHours: STALE_TEST_HOURS, stale: providers.stale }
      : null,
    activity: { activeRequests: activeLeases, rateLimitStore: limitsUp ? ctx.deps.limits.kind : 'unavailable' },
    configuration: {
      cookieSecure: config.cookieSecure,
      trustProxy: config.trustProxy,
      adminOriginConfigured: config.adminOrigin !== null,
      publicApiOriginConfigured: config.publicApiOrigin !== null,
      secretKeyringConfigured: config.keyring.size > 0,
      databaseTls: config.database.ssl === 'require',
      redisTls: config.redis ? config.redis.tls : null,
    },
  });
}
