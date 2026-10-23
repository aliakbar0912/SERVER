// Desktop devices: automatic registration (no codes), per-device tokens (hashed, blockable), and device listing.
//
// A desktop app registers itself the first time it starts: it sends a random installation id it generated and keeps,
// and gets a device token. The owner sees every registered computer in the admin site and can block it. A blocked
// installation stays blocked when it registers again. New registrations can be switched off in Settings.
import type { Ctx, DeviceAuth } from '../context.ts';
import { randomToken, sha256Hex } from '../crypto.ts';
import { fail, log, readJson, requireObject, rejectUnknown, sendJson, str, uuidParam, clientAddress } from '../http/util.ts';
import { guardOwner } from './auth.ts';
import { catalogueVersion, readSettings } from './catalogue.ts';
import { setDeviceAccess } from './registry.ts';
import { endSession, OFFLINE_GRACE_SECONDS, RECHECK_SECONDS, recheckUser, requireLoginForCentralAi } from './sessions.ts';

const REGISTER_PER_IP = 10;
const REGISTER_WINDOW_SECONDS = 15 * 60;
const DEVICE_TOUCH_SECONDS = 60;
const INSTALL_ID = /^[A-Za-z0-9_-]{16,64}$/;

/**
 * POST /v1/devices/register { installId, deviceName }: returns a device token for this installation.
 * An unclaimed (legacy) installation registering again gets a fresh token (the old one stops working), exactly as before
 * accounts existed: the owner's "unblock" relies on it. A blocked one is refused. An installation that belongs to a signed-in
 * user is never given a token here, whoever asks: knowing an installation id must not be enough to take over an account's
 * device. It gets tokens only through a sign-in (/v1/auth/*).
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
    const { rows } = await q.query('SELECT id, status, user_id FROM devices WHERE install_id = $1 FOR UPDATE', [installId]);
    const existing = rows[0];
    if (existing) {
      if (existing.status !== 'active') return { blocked: true as const };
      if (existing.user_id) return { account: true as const };
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
  if ('account' in result) fail(409, 'account_device', 'this computer is signed in to a Devora account; sign in again to continue');
  if ('closed' in result) fail(403, 'registration_closed', 'the owner is not accepting new computers right now');
  sendJson(ctx.res, result.created ? 201 : 200, { deviceId: result.id, token, catalogueVersion: await catalogueVersion(db) });
}

/** The Bearer token of the request, or null. */
export function bearerToken(ctx: Ctx): string | null {
  const m = /^Bearer\s+([A-Za-z0-9_-]{20,128})$/.exec(ctx.req.headers.authorization ?? '');
  return m ? m[1] : null;
}

/**
 * Authenticates the Bearer device token. Revoked devices are refused on every request.
 * `central` (the default) marks a central AI endpoint: when the owner requires sign-in, a device without a signed-in user
 * is refused there. Updates and device info pass `central: false`, so even a legacy computer can still update itself.
 * Signed-in devices also have: token expiry, rotation reuse detection, owner blocking of the account, and a re-check with
 * PocketBase every 15 minutes (the account must still exist and be verified).
 */
export async function authenticateDevice(ctx: Ctx, opts: { central?: boolean } = {}): Promise<DeviceAuth> {
  const central = opts.central !== false;
  const token = bearerToken(ctx);
  if (!token) fail(401, 'unauthenticated', 'a device token is required');
  const hash = sha256Hex(token);
  const { rows } = await ctx.deps.db.query(
    `SELECT d.id, d.name, d.status, d.model_access, d.app_version, d.user_id, d.token_expires_at,
            (d.token_hash = $1) AS current,
            (d.prev_token_grace_until IS NOT NULL AND d.prev_token_grace_until > now()) AS in_grace,
            (d.token_expires_at IS NOT NULL AND d.token_expires_at <= now()) AS expired,
            (d.user_checked_at IS NULL OR d.user_checked_at < now() - make_interval(secs => $3)) AS recheck,
            (d.user_checked_at IS NOT NULL AND d.user_checked_at > now() - make_interval(secs => $4)) AS recently_checked,
            u.status AS user_status,
            (d.last_seen_at IS NULL OR d.last_seen_at < now() - make_interval(secs => $2)) AS touch
       FROM devices d LEFT JOIN app_users u ON u.user_id = d.user_id
      WHERE d.token_hash = $1 OR d.prev_token_hash = $1`,
    [hash, DEVICE_TOUCH_SECONDS, RECHECK_SECONDS, OFFLINE_GRACE_SECONDS],
  );
  const row = rows[0];
  if (!row || row.status !== 'active') fail(401, 'device_revoked', 'this device is not allowed to use the service');
  if (!row.current && !row.in_grace) {
    // A token replaced by a rotation was used again after the grace period: someone else holds a copy. End the session.
    await endSession(ctx.deps.db, row.id, 'token_reuse');
    log('warn', 'rotated device token reused; session ended', { deviceId: row.id });
    fail(401, 'session_revoked', 'this sign-in was ended for security reasons; sign in again');
  }
  if (row.expired) fail(401, 'token_expired', 'this sign-in has expired; sign in again');
  if (row.user_id) {
    if (row.user_status === 'blocked') fail(403, 'account_blocked', 'this account has been blocked by the administrator');
    if (row.user_status === 'deleting' || row.user_status === 'deleted') fail(401, 'account_deleted', 'this account has been deleted');
    if (row.recheck) {
      const r = await recheckUser(ctx.deps, row.user_id);
      if (r === 'deleted') fail(401, 'account_deleted', 'this account has been deleted');
      if (r === 'unverified') fail(403, 'email_not_verified', 'verify your email address to use Devora AI');
      if (r === 'unavailable' && !row.recently_checked) {
        fail(503, 'accounts_unavailable', 'the account service is temporarily unavailable; local features keep working', { 'retry-after': '30' });
      }
    }
  } else if (central && (await requireLoginForCentralAi(ctx.deps.db))) {
    fail(403, 'login_required', 'sign in to your Devora account to use Devora AI');
  }
  // Desktop apps report their version (x-devora-version) so the owner can follow an update's rollout.
  const reported = String(ctx.req.headers['x-devora-version'] ?? '');
  const version = /^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]{1,30})?$/.test(reported) ? reported : null;
  if (version && version !== row.app_version) await ctx.deps.db.query('UPDATE devices SET last_seen_at = now(), app_version = $2 WHERE id = $1', [row.id, version]);
  else if (row.touch) await ctx.deps.db.query('UPDATE devices SET last_seen_at = now() WHERE id = $1', [row.id]);
  return {
    deviceId: row.id,
    name: row.name,
    modelAccess: row.model_access,
    userId: row.user_id ?? null,
    tokenHash: hash,
    tokenExpiresAt: row.token_expires_at ? new Date(row.token_expires_at).toISOString() : null,
  };
}

export async function listDevices(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query(
    `SELECT d.id, d.name, d.status, d.created_at, d.last_seen_at, d.revoked_at, d.model_access, d.registered_via, d.app_version,
            d.user_id, d.signed_out_at, d.token_expires_at,
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
      userId: r.user_id ?? null,
      signedIn: !!r.user_id && !r.signed_out_at,
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
