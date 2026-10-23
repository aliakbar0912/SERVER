// Desktop devices: automatic registration (no codes), per-device tokens (hashed, blockable), and device listing.
//
// A desktop app registers itself the first time it starts: it sends a random installation id it generated and keeps,
// and gets a device token. The owner sees every registered computer in the admin site and can block it. A blocked
// installation stays blocked when it registers again. New registrations can be switched off in Settings.
import type { Ctx, DeviceAuth } from '../context.ts';
import { randomToken, sha256Hex } from '../crypto.ts';
import { fail, readJson, requireObject, rejectUnknown, sendJson, str, uuidParam, clientAddress } from '../http/util.ts';
import { guardOwner } from './auth.ts';
import { catalogueVersion, readSettings } from './catalogue.ts';
import { setDeviceAccess } from './registry.ts';

const REGISTER_PER_IP = 10;
const REGISTER_WINDOW_SECONDS = 15 * 60;
const DEVICE_TOUCH_SECONDS = 60;
const INSTALL_ID = /^[A-Za-z0-9_-]{16,64}$/;

/**
 * POST /v1/devices/register { installId, deviceName }: returns a device token for this installation.
 * The same installation registering again gets a fresh token (the old one stops working). A blocked one is refused.
 */
export async function registerDevice(ctx: Ctx): Promise<void> {
  const { db, config } = ctx.deps;
  const ip = clientAddress(ctx.req, config.trustProxy);
  // Persistent, so a restart does not reset the counter. Shared by every process.
  const limit = await ctx.deps.limits.hit(`register:ip:${ip}`, REGISTER_PER_IP, REGISTER_WINDOW_SECONDS);
  if (!limit.allowed) fail(429, 'rate_limited', 'too many registrations from this network; try again later', { 'retry-after': String(limit.retryAfterSeconds) });
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ['installId', 'deviceName']);
  const installId = str(body, 'installId', { min: 16, max: 64 })!;
  if (!INSTALL_ID.test(installId)) fail(400, 'invalid_request', 'installId must be 16 to 64 letters, digits, _ or -');
  const deviceName = str(body, 'deviceName', { min: 1, max: 80 })!;
  const token = randomToken(32);

  const result = await db.transaction(async (q) => {
    const { rows } = await q.query('SELECT id, status FROM devices WHERE install_id = $1 FOR UPDATE', [installId]);
    const existing = rows[0];
    if (existing) {
      if (existing.status !== 'active') return { blocked: true as const };
      await q.query('UPDATE devices SET token_hash = $2, name = $3, last_seen_at = now() WHERE id = $1', [existing.id, sha256Hex(token), deviceName]);
      return { id: existing.id as string, created: false };
    }
    const settings = await readSettings(q);
    if (settings.allow_auto_registration === false) return { closed: true as const };
    const dev = await q.query(
      `INSERT INTO devices (name, token_hash, install_id, registered_via, last_seen_at) VALUES ($1, $2, $3, 'auto', now()) RETURNING id`,
      [deviceName, sha256Hex(token), installId],
    );
    return { id: dev.rows[0].id as string, created: true };
  });
  if ('blocked' in result) fail(403, 'device_blocked', 'the owner has blocked this computer');
  if ('closed' in result) fail(403, 'registration_closed', 'the owner is not accepting new computers right now');
  sendJson(ctx.res, result.created ? 201 : 200, { deviceId: result.id, token, catalogueVersion: await catalogueVersion(db) });
}

/** Authenticates the Bearer device token. Revoked devices are refused on every request. */
export async function authenticateDevice(ctx: Ctx): Promise<DeviceAuth> {
  const header = ctx.req.headers.authorization ?? '';
  const match = /^Bearer\s+([A-Za-z0-9_-]{20,128})$/.exec(header);
  if (!match) fail(401, 'unauthenticated', 'a device token is required');
  const { rows } = await ctx.deps.db.query(
    `SELECT id, name, status, model_access, app_version, (last_seen_at IS NULL OR last_seen_at < now() - make_interval(secs => $2)) AS touch
       FROM devices WHERE token_hash = $1`,
    [sha256Hex(match[1]), DEVICE_TOUCH_SECONDS],
  );
  const row = rows[0];
  if (!row || row.status !== 'active') fail(401, 'device_revoked', 'this device is not allowed to use the service');
  // Desktop apps report their version (x-devora-version) so the owner can follow an update's rollout.
  const reported = String(ctx.req.headers['x-devora-version'] ?? '');
  const version = /^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]{1,30})?$/.test(reported) ? reported : null;
  if (version && version !== row.app_version) await ctx.deps.db.query('UPDATE devices SET last_seen_at = now(), app_version = $2 WHERE id = $1', [row.id, version]);
  else if (row.touch) await ctx.deps.db.query('UPDATE devices SET last_seen_at = now() WHERE id = $1', [row.id]);
  return { deviceId: row.id, name: row.name, modelAccess: row.model_access };
}

export async function listDevices(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query(
    `SELECT d.id, d.name, d.status, d.created_at, d.last_seen_at, d.revoked_at, d.model_access, d.registered_via, d.app_version,
            (SELECT count(*)::int FROM device_models dm WHERE dm.device_id = d.id) AS granted,
            (SELECT count(*)::int FROM memory_entries me WHERE me.device_id = d.id AND me.deleted = false) AS memories
       FROM devices d ORDER BY d.created_at DESC LIMIT 500`,
  );
  sendJson(ctx.res, 200, {
    devices: rows.map((r) => ({
      id: r.id,
      name: r.name,
      status: r.status,
      createdAt: r.created_at,
      lastSeenAt: r.last_seen_at,
      revokedAt: r.revoked_at,
      modelAccess: r.model_access,
      registeredVia: r.registered_via,
      grantedModels: r.granted,
      memories: r.memories,
      appVersion: r.app_version ?? null,
    })),
  });
}

export async function revokeDevice(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true, sensitive: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ['confirmName']);
  const confirm = str(body, 'confirmName', { max: 80, optional: true });
  const { rows } = await ctx.deps.db.query('SELECT name, status FROM devices WHERE id = $1', [id]);
  if (!rows[0]) fail(404, 'not_found', 'device not found');
  if (confirm !== rows[0].name) fail(400, 'confirmation_mismatch', 'type the device name exactly to block it');
  if (rows[0].status === 'revoked') fail(409, 'already_revoked', 'this device is already blocked');
  await ctx.deps.db.query("UPDATE devices SET status = 'revoked', revoked_at = now() WHERE id = $1", [id]);
  sendJson(ctx.res, 200, { id, status: 'revoked' });
}

/** POST /admin/api/devices/:id/unblock: the computer may register again; it gets a new token the next time it connects. */
export async function unblockDevice(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true, sensitive: true });
  const id = uuidParam(ctx.params.id);
  const { rows } = await ctx.deps.db.query('SELECT status FROM devices WHERE id = $1', [id]);
  if (!rows[0]) fail(404, 'not_found', 'device not found');
  if (rows[0].status === 'active') fail(409, 'not_blocked', 'this device is not blocked');
  // A new random token hash: the old token stays invalid, the desktop registers again to get a working one.
  await ctx.deps.db.query("UPDATE devices SET status = 'active', revoked_at = NULL, token_hash = $2 WHERE id = $1", [id, sha256Hex(randomToken(32))]);
  sendJson(ctx.res, 200, { id, status: 'active' });
}


/** GET /admin/api/devices/:id/models: the device's access mode and the models granted to it. */
export async function getDeviceModels(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const id = uuidParam(ctx.params.id);
  const { rows } = await ctx.deps.db.query('SELECT model_access FROM devices WHERE id = $1', [id]);
  if (!rows[0]) fail(404, 'not_found', 'device not found');
  const granted = await ctx.deps.db.query('SELECT model_id FROM device_models WHERE device_id = $1 ORDER BY created_at', [id]);
  sendJson(ctx.res, 200, { modelAccess: rows[0].model_access, modelIds: granted.rows.map((r) => r.model_id) });
}

/** PUT /admin/api/devices/:id/models { modelAccess: 'all' | 'selected', modelIds: uuid[] }. Takes effect on the next request. */
export async function putDeviceModels(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 64 * 1024));
  rejectUnknown(body, ['modelAccess', 'modelIds']);
  const access = body.modelAccess;
  if (access !== 'all' && access !== 'selected') fail(400, 'invalid_request', 'modelAccess must be all or selected');
  const raw = body.modelIds ?? [];
  if (!Array.isArray(raw) || raw.length > 1000) fail(400, 'invalid_request', 'modelIds must be a list of model ids');
  const modelIds = [...new Set(raw.map((v) => uuidParam(typeof v === 'string' ? v : '')))];
  const { rows } = await ctx.deps.db.query('SELECT status FROM devices WHERE id = $1', [id]);
  if (!rows[0]) fail(404, 'not_found', 'device not found');
  if (modelIds.length) {
    const found = await ctx.deps.db.query('SELECT count(*)::int AS n FROM models WHERE id IN (SELECT (jsonb_array_elements_text($1::jsonb))::uuid)', [modelIds]);
    if (found.rows[0].n !== modelIds.length) fail(400, 'invalid_request', 'one or more models do not exist');
  }
  await setDeviceAccess(ctx.deps.db, id, access, access === 'selected' ? modelIds : []);
  sendJson(ctx.res, 200, { modelAccess: access, modelIds: access === 'selected' ? modelIds : [] });
}
