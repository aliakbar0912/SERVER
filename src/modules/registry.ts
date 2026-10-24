// Model registry helpers: per-device access, provider availability, and model discovery.
// Three different questions, kept apart on purpose:
//   registered  = a row in models (enabled or not)
//   permitted   = enabled, its provider enabled, and allowed for this device
//   available   = what recent real traffic and the owner's last test say about the provider right now
// Availability never removes a model from the catalogue and never blocks a request; it is information for the picker.
import type { Deps } from '../context.ts';
import type { Queryer } from '../db/pg-wire.ts';
import { log } from '../http/util.ts';
import { bumpCatalogue, unknownCapabilities } from './catalogue.ts';
import { describeFailure, listUpstreamModels, UpstreamError } from './upstream.ts';
import { providerApiKey } from './providers.ts';

export type ModelAccess = 'all' | 'selected';

/** The set of model ids a device may use, or null when it may use every enabled model. Read fresh on every call. */
export async function allowedModelIds(db: Queryer, deviceId: string | null, access: ModelAccess): Promise<Set<string> | null> {
  if (access === 'all') return null;
  // 'selected' is only used by devices; a caller without a device id (API keys use 'all') gets nothing.
  if (!deviceId) return new Set();
  const { rows } = await db.query('SELECT model_id FROM device_models WHERE device_id = $1', [deviceId]);
  return new Set(rows.map((r) => r.model_id as string));
}

export function isAllowed(allowed: Set<string> | null, modelId: string): boolean {
  return allowed === null || allowed.has(modelId);
}

export type Availability = 'available' | 'degraded' | 'unknown';

export interface ProviderHealth {
  availability: Availability;
  /** Short reason for the owner and the desktop picker. Never contains provider messages or secrets. */
  reason: string;
}

const RECENT_MINUTES = 30;
const TEST_FRESH_DAYS = 7;
// Upstream failures that say something about the provider (not about the request or the client).
const PROVIDER_FAILURE_CODES = ['upstream_auth_failed', 'upstream_timeout', 'upstream_unreachable', 'upstream_error', 'upstream_rate_limited'];
const HARD_TEST_FAILURES = ['auth', 'timeout', 'unreachable', 'server'];

/**
 * Availability per provider from real chat outcomes in the last 30 minutes, then the owner's last connectivity test.
 * A provider whose model list is unsupported (HTTP 404 or an unexpected listing) is 'unknown', never 'degraded'.
 */
export async function providerHealth(db: Queryer): Promise<Map<string, ProviderHealth>> {
  const { rows } = await db.query(
    `SELECT p.id, p.last_test_ok, p.last_test_kind, p.last_test_at,
            (p.last_test_at > now() - make_interval(days => $2)) AS test_fresh,
            recent.outcomes
       FROM providers p
       LEFT JOIN LATERAL (
         SELECT json_agg(CASE WHEN l.status = 'ok' THEN 'ok' WHEN l.error_code IN (SELECT jsonb_array_elements_text($3::jsonb)) THEN 'fail' ELSE 'other' END ORDER BY l.created_at DESC) AS outcomes
           FROM (SELECT status, error_code, created_at FROM request_logs
                  WHERE provider_id = p.id AND created_at > now() - make_interval(mins => $1) AND status <> 'cancelled'
                  ORDER BY created_at DESC LIMIT 5) l
       ) recent ON true`,
    [RECENT_MINUTES, TEST_FRESH_DAYS, PROVIDER_FAILURE_CODES],
  );
  const out = new Map<string, ProviderHealth>();
  for (const r of rows) {
    const outcomes: string[] = (r.outcomes ?? []).filter((o: string) => o !== 'other');
    let h: ProviderHealth;
    if (outcomes[0] === 'ok') h = { availability: 'available', reason: 'answering requests' };
    else if (outcomes.length >= 3 && outcomes.slice(0, 3).every((o) => o === 'fail')) h = { availability: 'degraded', reason: 'recent requests failed' };
    else if (r.last_test_ok === true && r.test_fresh) h = { availability: 'available', reason: 'connectivity test passed' };
    else if (r.last_test_ok === false && r.test_fresh && HARD_TEST_FAILURES.includes(r.last_test_kind)) h = { availability: 'degraded', reason: 'connectivity test failed' };
    else h = { availability: 'unknown', reason: 'not checked recently' };
    out.set(r.id, h);
  }
  return out;
}

export interface DiscoveryResult {
  ok: boolean;
  /** False when the provider has no usable model list (HTTP 404 or an unexpected format). Manual models still work. */
  supported: boolean | null;
  found: number;
  added: number;
  message: string;
  /** True when another process was already refreshing this provider; nothing was done. */
  skipped?: boolean;
}

/**
 * Lists the provider's models and records them. New models are added disabled with unknown capabilities, so discovery
 * never exposes anything to desktops by itself. Models already registered get last_listed_at updated. Concurrent refreshes
 * of the same provider are serialised with a lock (Redis when configured, otherwise a PostgreSQL advisory lock).
 */
export async function discoverProvider(deps: Deps, providerId: string): Promise<DiscoveryResult> {
  const run = async (): Promise<DiscoveryResult> => {
    const { rows } = await deps.db.query('SELECT id, base_url, auth_scheme, timeout_ms, enabled FROM providers WHERE id = $1', [providerId]);
    const p = rows[0];
    if (!p) return { ok: false, supported: null, found: 0, added: 0, message: 'provider not found' };
    const key = p.auth_scheme === 'bearer' ? await providerApiKey(deps, providerId) : null;
    if (p.auth_scheme === 'bearer' && !key) {
      return record(deps.db, providerId, { ok: false, supported: null, found: 0, added: 0, message: 'no API key is stored for this provider' });
    }
    let ids: string[];
    try {
      ids = await listUpstreamModels(deps.fetch, p.base_url, key, Math.min(p.timeout_ms, 20_000));
    } catch (e) {
      const unsupported = e instanceof UpstreamError && (e.kind === 'bad_response' || (e.kind === 'rejected' && e.status === 404));
      const message = unsupported ? 'this provider does not offer a model list; add models by their exact id' : describeFailure(e).message;
      return record(deps.db, providerId, { ok: false, supported: unsupported ? false : null, found: 0, added: 0, message });
    }
    let added = 0;
    await deps.db.transaction(async (q) => {
      for (const upstreamId of ids) {
        const res = await q.query(
          `INSERT INTO models (provider_id, upstream_model_id, display_name, enabled, capabilities, source, last_listed_at)
           VALUES ($1, $2, $2, false, $3, 'discovered', now())
           ON CONFLICT (provider_id, upstream_model_id) DO UPDATE SET last_listed_at = now()
           RETURNING (xmax = 0) AS inserted`,
          [providerId, upstreamId, unknownCapabilities()],
        );
        if (res.rows[0]?.inserted) added += 1;
      }
    });
    return record(deps.db, providerId, {
      ok: true,
      supported: true,
      found: ids.length,
      added,
      message: `${ids.length} model${ids.length === 1 ? '' : 's'} listed, ${added} new`,
    });
  };
  const result = await withProviderLock(deps, providerId, run);
  return result ?? { ok: false, supported: null, found: 0, added: 0, message: 'a refresh of this provider is already running', skipped: true };
}

async function withProviderLock<T>(deps: Deps, providerId: string, fn: () => Promise<T>): Promise<T | null> {
  if (deps.limits.kind === 'redis') return deps.limits.withLock(`discover:${providerId}`, 60_000, fn);
  // Without Redis: a session advisory lock held on one pooled connection for the duration of the refresh.
  return deps.db.transaction(async (q) => {
    const { rows } = await q.query('SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0)) AS got', [`discover:${providerId}`]);
    if (!rows[0].got) return null;
    return fn();
  });
}

async function record(db: Queryer, providerId: string, r: DiscoveryResult): Promise<DiscoveryResult> {
  await db.query(
    `UPDATE providers SET discovery_at = now(), discovery_ok = $2, discovery_message = $3,
            discovery_supported = COALESCE($4, discovery_supported)
      WHERE id = $1`,
    [providerId, r.ok, r.message.slice(0, 300), r.supported],
  );
  return r;
}

/** Periodic refresh of every enabled provider. Only adds disabled entries, so it is safe to run unattended. */
export async function scheduledDiscovery(deps: Deps): Promise<void> {
  const { rows } = await deps.db.query(
    `SELECT p.id, p.name FROM providers p
      WHERE p.enabled AND (p.discovery_supported IS DISTINCT FROM false)
        AND (p.auth_scheme = 'none' OR EXISTS (SELECT 1 FROM provider_secrets s WHERE s.provider_id = p.id))`,
  );
  for (const p of rows) {
    try {
      const r = await discoverProvider(deps, p.id);
      if (!r.skipped) log(r.ok ? 'info' : 'warn', 'model discovery', { provider: p.name, ok: r.ok, found: r.found, added: r.added });
    } catch (e) {
      log('error', 'model discovery failed', { provider: p.name, error: e instanceof Error ? e.name : 'unknown' });
    }
  }
}

/** Replaces a device's model access. Bumps the catalogue so desktops pick up the change on their next sync. */
export async function setDeviceAccess(db: { transaction<T>(fn: (q: Queryer) => Promise<T>): Promise<T> }, deviceId: string, access: ModelAccess, modelIds: string[]): Promise<void> {
  await db.transaction(async (q) => {
    await q.query('UPDATE devices SET model_access = $2 WHERE id = $1', [deviceId, access]);
    await q.query('DELETE FROM device_models WHERE device_id = $1', [deviceId]);
    if (access === 'selected' && modelIds.length) {
      await q.query('INSERT INTO device_models (device_id, model_id) SELECT $1, (jsonb_array_elements_text($2::jsonb))::uuid ON CONFLICT DO NOTHING', [deviceId, modelIds]);
    }
    await bumpCatalogue(q);
  });
}
