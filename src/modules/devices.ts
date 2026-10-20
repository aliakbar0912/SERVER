// Desktop devices: owner-issued enrollment codes (one use, short-lived), per-device tokens (hashed, revocable), and device listing.
import type { Ctx, DeviceAuth } from '../context.ts';
import { enrollmentCode, normalizeEnrollmentCode, randomToken, sha256Hex } from '../crypto.ts';
import { fail, readJson, requireObject, rejectUnknown, sendJson, str, uuidParam, clientAddress } from '../http/util.ts';
import { guardOwner } from './auth.ts';
import { catalogueVersion } from './catalogue.ts';
import { setDeviceAccess } from './registry.ts';

const CODE_MINUTES = 15;
const MAX_OUTSTANDING_CODES = 20;
const ENROLL_PER_IP = 10;
const ENROLL_WINDOW_SECONDS = 15 * 60;
const DEVICE_TOUCH_SECONDS = 60;

/** Owner: creates a one-time enrollment code. The code is returned once; only its hash is stored. */
export async function createEnrollmentCode(ctx: Ctx): Promise<void> {
  const s = await guardOwner(ctx, { write: true, sensitive: true });
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ['label']);
  const label = str(body, 'label', { max: 80, optional: true }) ?? '';
  const { rows: outstanding } = await ctx.deps.db.query('SELECT count(*)::int AS n FROM enrollment_codes WHERE used_at IS NULL AND expires_at > now()');
  if (outstanding[0].n >= MAX_OUTSTANDING_CODES) fail(409, 'too_many_codes', 'too many enrollment codes are waiting; let them expire or use one first');
  const code = enrollmentCode();
  const { rows } = await ctx.deps.db.query(
    `INSERT INTO enrollment_codes (code_hash, label, created_by, expires_at)
     VALUES ($1, $2, $3, now() + make_interval(mins => $4))
     RETURNING expires_at`,
    [sha256Hex(normalizeEnrollmentCode(code)), label, s.ownerId, CODE_MINUTES],
  );
  sendJson(ctx.res, 201, { code, label, expiresAt: new Date(rows[0].expires_at).toISOString() });
}

export async function listEnrollmentCodes(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query(
    `SELECT id, label, created_at, expires_at, used_at, device_id,
            (used_at IS NULL AND expires_at > now()) AS usable
       FROM enrollment_codes ORDER BY created_at DESC LIMIT 100`,
  );
  sendJson(ctx.res, 200, {
    codes: rows.map((r) => ({
      id: r.id,
      label: r.label,
      createdAt: r.created_at,
      expiresAt: r.expires_at,
      usedAt: r.used_at,
      deviceId: r.device_id,
      status: r.used_at ? 'used' : r.usable ? 'waiting' : 'expired',
    })),
  });
}

/** Desktop: exchanges a valid code for a device token. Every failure returns the same message. */
export async function enrollDevice(ctx: Ctx): Promise<void> {
  const { db, config } = ctx.deps;
  const ip = clientAddress(ctx.req, config.trustProxy);
  // Persistent, so a restart does not reset the counter. Shared by every process.
  const limit = await ctx.deps.limits.hit(`enroll:ip:${ip}`, ENROLL_PER_IP, ENROLL_WINDOW_SECONDS);
  if (!limit.allowed) fail(429, 'rate_limited', 'too many enrollment attempts; try again later', { 'retry-after': String(limit.retryAfterSeconds) });
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ['code', 'deviceName']);
  const code = str(body, 'code', { min: 16, max: 40 })!;
  const deviceName = str(body, 'deviceName', { min: 1, max: 80 })!;
  const invalid = () => fail(400, 'invalid_enrollment_code', 'the enrollment code is not valid, has expired, or was already used');
  const token = randomToken(32);

  const result = await db.transaction(async (q) => {
    const { rows } = await q.query(
      `SELECT id FROM enrollment_codes WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now() FOR UPDATE`,
      [sha256Hex(normalizeEnrollmentCode(code))],
    );
    if (!rows[0]) return null;
    const dev = await q.query(
      `INSERT INTO devices (name, token_hash, created_by, last_seen_at)
       SELECT $1, $2, created_by, now() FROM enrollment_codes WHERE id = $3
       RETURNING id`,
      [deviceName, sha256Hex(token), rows[0].id],
    );
    await q.query('UPDATE enrollment_codes SET used_at = now(), device_id = $2 WHERE id = $1', [rows[0].id, dev.rows[0].id]);
    return dev.rows[0].id as string;
  });
  if (!result) invalid();
  await ctx.deps.limits.clear(`enroll:ip:${ip}`);
  sendJson(ctx.res, 201, { deviceId: result, token, catalogueVersion: await catalogueVersion(db) });
}

/** Authenticates the Bearer device token. Revoked devices are refused on every request. */
export async function authenticateDevice(ctx: Ctx): Promise<DeviceAuth> {
  const header = ctx.req.headers.authorization ?? '';
  const match = /^Bearer\s+([A-Za-z0-9_-]{20,128})$/.exec(header);
  if (!match) fail(401, 'unauthenticated', 'a device token is required');
  const { rows } = await ctx.deps.db.query(
    `SELECT id, name, status, model_access, (last_seen_at IS NULL OR last_seen_at < now() - make_interval(secs => $2)) AS touch
       FROM devices WHERE token_hash = $1`,
    [sha256Hex(match[1]), DEVICE_TOUCH_SECONDS],
  );
  const row = rows[0];
  if (!row || row.status !== 'active') fail(401, 'device_revoked', 'this device is not allowed to use the service; sign in to the desktop app again after the owner re-enrolls it');
  if (row.touch) await ctx.deps.db.query('UPDATE devices SET last_seen_at = now() WHERE id = $1', [row.id]);
  return { deviceId: row.id, name: row.name, modelAccess: row.model_access };
}

export async function listDevices(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query(
    `SELECT d.id, d.name, d.status, d.created_at, d.last_seen_at, d.revoked_at, d.model_access,
            (SELECT count(*)::int FROM device_models dm WHERE dm.device_id = d.id) AS granted
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
      grantedModels: r.granted,
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
  if (confirm !== rows[0].name) fail(400, 'confirmation_mismatch', 'type the device name exactly to revoke it');
  if (rows[0].status === 'revoked') fail(409, 'already_revoked', 'this device is already revoked');
  await ctx.deps.db.query("UPDATE devices SET status = 'revoked', revoked_at = now() WHERE id = $1", [id]);
  sendJson(ctx.res, 200, { id, status: 'revoked' });
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
