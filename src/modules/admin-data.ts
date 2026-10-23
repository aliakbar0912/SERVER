// Owner views: overview, usage, request logs (metadata only, never content), and policy settings.
import type { Ctx } from '../context.ts';
import type { Queryer } from '../db/pg-wire.ts';
import { bool, fail, int, readJson, requireObject, rejectUnknown, sendJson } from '../http/util.ts';
import { guardOwner, requireReauth } from './auth.ts';
import { bumpCatalogue, readSettings } from './catalogue.ts';
import { forgetLoginSetting } from './sessions.ts';

export async function overview(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query(`
    SELECT
      (SELECT count(*)::int FROM providers WHERE enabled) AS providers_enabled,
      (SELECT count(*)::int FROM providers) AS providers_total,
      (SELECT count(*)::int FROM models WHERE enabled) AS models_enabled,
      (SELECT count(*)::int FROM devices WHERE status = 'active') AS devices_active,
      (SELECT count(*)::int FROM request_logs WHERE created_at > now() - interval '24 hours') AS requests_24h,
      (SELECT count(*)::int FROM request_logs WHERE created_at > now() - interval '24 hours' AND status <> 'ok') AS failed_24h,
      (SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms) FROM request_logs WHERE created_at > now() - interval '24 hours' AND status = 'ok')::int AS p50_ms,
      (SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) FROM request_logs WHERE created_at > now() - interval '24 hours' AND status = 'ok')::int AS p95_ms`);
  const providers = await ctx.deps.db.query('SELECT name, enabled, last_test_ok, last_test_at, last_test_message FROM providers ORDER BY name');
  sendJson(ctx.res, 200, {
    ...toCamel(rows[0]),
    providers: providers.rows.map((p) => ({
      name: p.name,
      enabled: p.enabled,
      lastTestOk: p.last_test_ok,
      lastTestAt: p.last_test_at,
      lastTestMessage: p.last_test_message,
    })),
  });
}

function toCamel(r: Record<string, any>): Record<string, any> {
  return Object.fromEntries(Object.entries(r).map(([k, v]) => [k.replace(/_([a-z0-9])/g, (_, c: string) => c.toUpperCase()), v]));
}

export async function usage(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const window = ctx.url.searchParams.get('window') ?? '24h';
  if (window !== '24h' && window !== '7d') fail(400, 'invalid_request', 'window must be 24h or 7d');
  const interval = window === '24h' ? '24 hours' : '7 days';
  const bucket = window === '24h' ? 'hour' : 'day';
  const q = ctx.deps.db;
  const totals = await q.query(
    `SELECT count(*)::int AS requests,
            count(*) FILTER (WHERE status = 'ok')::int AS ok,
            count(*) FILTER (WHERE status = 'error')::int AS errors,
            count(*) FILTER (WHERE status = 'cancelled')::int AS cancelled,
            coalesce(sum(prompt_tokens) FILTER (WHERE usage_source = 'provider_reported'), 0)::bigint AS prompt_tokens,
            coalesce(sum(completion_tokens) FILTER (WHERE usage_source = 'provider_reported'), 0)::bigint AS completion_tokens,
            count(*) FILTER (WHERE usage_source = 'none')::int AS without_usage
       FROM request_logs WHERE created_at > now() - interval '${interval}'`,
  );
  const byModel = await q.query(
    `SELECT model_name, count(*)::int AS requests, count(*) FILTER (WHERE status <> 'ok')::int AS failed
       FROM request_logs WHERE created_at > now() - interval '${interval}'
      GROUP BY model_name ORDER BY requests DESC LIMIT 50`,
  );
  const byError = await q.query(
    `SELECT error_code AS code, count(*)::int AS count FROM request_logs
      WHERE created_at > now() - interval '${interval}' AND error_code IS NOT NULL
      GROUP BY error_code ORDER BY count DESC LIMIT 50`,
  );
  const series = await q.query(
    `SELECT date_trunc('${bucket}', created_at) AS bucket, count(*)::int AS requests, count(*) FILTER (WHERE status <> 'ok')::int AS failed
       FROM request_logs WHERE created_at > now() - interval '${interval}'
      GROUP BY 1 ORDER BY 1`,
  );
  sendJson(ctx.res, 200, {
    window,
    totals: toCamel(totals.rows[0]),
    byModel: byModel.rows.map((r) => ({ modelName: r.model_name, requests: r.requests, failed: r.failed })),
    errorCodes: byError.rows,
    series: series.rows.map((r) => ({ at: r.bucket, requests: r.requests, failed: r.failed })),
    note: 'Token counts include only responses where the provider reported usage. Other requests are counted in withoutUsage.',
  });
}

export async function logs(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const q = ctx.url.searchParams;
  const limit = Math.min(200, Math.max(1, Number(q.get('limit') ?? 50) || 50));
  const where: string[] = [];
  const params: unknown[] = [];
  if (q.get('status') && ['ok', 'error', 'cancelled'].includes(q.get('status')!)) {
    params.push(q.get('status'));
    where.push(`r.status = $${params.length}`);
  }
  if (q.get('model')) {
    params.push(q.get('model')!.slice(0, 120));
    where.push(`r.model_name = $${params.length}`);
  }
  if (q.get('cursor')) {
    const c = Number(q.get('cursor'));
    if (!Number.isInteger(c) || c < 1) fail(400, 'invalid_request', 'cursor is not valid');
    params.push(c);
    where.push(`r.id < $${params.length}`);
  }
  params.push(limit + 1);
  const sql = `SELECT r.id, r.created_at, d.name AS device_name, r.model_name, r.provider_name, r.status, r.http_status, r.error_code,
                      r.stream, r.latency_ms, r.ttft_ms, r.prompt_tokens, r.completion_tokens, r.usage_source
                 FROM request_logs r LEFT JOIN devices d ON d.id = r.device_id
                ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
                ORDER BY r.id DESC LIMIT $${params.length}`;
  const { rows } = await ctx.deps.db.query(sql, params);
  const page = rows.slice(0, limit);
  sendJson(ctx.res, 200, {
    logs: page.map((r) => ({
      id: Number(r.id),
      createdAt: r.created_at,
      deviceName: r.device_name ?? null,
      modelName: r.model_name,
      providerName: r.provider_name,
      status: r.status,
      httpStatus: r.http_status,
      errorCode: r.error_code,
      stream: r.stream,
      latencyMs: r.latency_ms,
      ttftMs: r.ttft_ms,
      promptTokens: r.prompt_tokens,
      completionTokens: r.completion_tokens,
      usageSource: r.usage_source,
    })),
    nextCursor: rows.length > limit ? String(page[page.length - 1].id) : null,
  });
}

export async function getSettings(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  sendJson(ctx.res, 200, { ...(await currentSettings(ctx.deps.db)), accountsConfigured: !!ctx.deps.pocketbase });
}

export async function currentSettings(db: Queryer) {
  const s = await readSettings(db);
  return {
    rateLimitPerMinute: Number(s.rate_limit_per_minute ?? 60),
    maxConcurrentPerDevice: Number(s.max_concurrent_per_device ?? 2),
    maxOutputTokens: Number(s.max_output_tokens ?? 8192),
    allowDirectProvider: s.allow_direct_provider === true,
    allowAutoRegistration: s.allow_auto_registration !== false,
    requireLoginForCentralAi: s.require_login_for_central_ai === true,
  };
}

const SETTING_KEYS: Record<string, string> = {
  rateLimitPerMinute: 'rate_limit_per_minute',
  maxConcurrentPerDevice: 'max_concurrent_per_device',
  maxOutputTokens: 'max_output_tokens',
  allowDirectProvider: 'allow_direct_provider',
  allowAutoRegistration: 'allow_auto_registration',
  requireLoginForCentralAi: 'require_login_for_central_ai',
};

export async function patchSettings(ctx: Ctx): Promise<void> {
  const session = await guardOwner(ctx, { write: true });
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, Object.keys(SETTING_KEYS));
  const changes: [string, unknown][] = [];
  const rate = int(body, 'rateLimitPerMinute', { min: 1, max: 600, optional: true });
  if (rate !== undefined) changes.push(['rate_limit_per_minute', rate]);
  const conc = int(body, 'maxConcurrentPerDevice', { min: 1, max: 16, optional: true });
  if (conc !== undefined) changes.push(['max_concurrent_per_device', conc]);
  const maxOut = int(body, 'maxOutputTokens', { min: 1, max: 32768, optional: true });
  if (maxOut !== undefined) changes.push(['max_output_tokens', maxOut]);
  const direct = bool(body, 'allowDirectProvider', { optional: true });
  if (direct !== undefined) {
    requireReauth(session);
    changes.push(['allow_direct_provider', direct]);
  }
  const autoReg = bool(body, 'allowAutoRegistration', { optional: true });
  if (autoReg !== undefined) changes.push(['allow_auto_registration', autoReg]);
  const requireLogin = bool(body, 'requireLoginForCentralAi', { optional: true });
  if (requireLogin !== undefined) {
    // Changes who may use central AI: password confirmation, and only when accounts are configured on this server.
    requireReauth(session);
    if (requireLogin && !ctx.deps.pocketbase) fail(409, 'accounts_not_configured', 'set POCKETBASE_URL and the PocketBase superuser on the server first');
    changes.push(['require_login_for_central_ai', requireLogin]);
  }
  if (changes.length === 0) fail(400, 'invalid_request', 'no settings were given');
  await ctx.deps.db.transaction(async (q) => {
    for (const [k, v] of changes) {
      await q.query(
        'INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()',
        [k, JSON.stringify(v)],
      );
    }
    if (changes.some(([k]) => k === 'max_output_tokens' || k === 'allow_direct_provider')) await bumpCatalogue(q);
  });
  forgetLoginSetting(ctx.deps.db);
  sendJson(ctx.res, 200, { ...(await currentSettings(ctx.deps.db)), accountsConfigured: !!ctx.deps.pocketbase });
}

/** Deletes request logs older than the retention period. The only automatic deletion in the server. */
export async function pruneLogs(db: Queryer, days: number): Promise<number> {
  const { rowCount } = await db.query("DELETE FROM request_logs WHERE created_at < now() - make_interval(days => $1)", [days]);
  return rowCount;
}
