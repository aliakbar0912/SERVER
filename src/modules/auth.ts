// Owner authentication: login with lockout, server-side sessions with CSRF tokens, and reauthentication for sensitive changes.
import crypto from 'node:crypto';
import type { Ctx, OwnerSession } from '../context.ts';
import { burnPasswordTime, randomToken, sha256Hex, verifyPassword } from '../crypto.ts';
import { clearCookie, clientAddress, fail, readJson, requireObject, rejectUnknown, sendJson, setCookie, str, userAgent } from '../http/util.ts';

export const SESSION_COOKIE = 'devora_admin';
const SESSION_HOURS = 12;
const REAUTH_MINUTES = 5;
const LOCK_FAILURES = 5;
const LOCK_MINUTES = 15;
const LOGIN_PER_IP = 20;
const LOGIN_WINDOW_SECONDS = 15 * 60;
const INVALID = 'invalid email or password';

export async function login(ctx: Ctx): Promise<void> {
  const { db, config, limits } = ctx.deps;
  const ipKey = `login:ip:${ctx.ip}`;
  const ipLimit = await limits.hit(ipKey, LOGIN_PER_IP, LOGIN_WINDOW_SECONDS);
  if (!ipLimit.allowed) fail(429, 'rate_limited', 'too many login attempts; try again later', { 'retry-after': String(ipLimit.retryAfterSeconds) });

  const body = requireObject(await readJson(ctx.req, 8 * 1024));
  rejectUnknown(body, ['email', 'password']);
  const email = str(body, 'email', { min: 3, max: 254 })!.toLowerCase();
  const password = str(body, 'password', { min: 1, max: 256, trim: false })!;

  const { rows } = await db.query('SELECT id, email, password_hash, locked_until FROM owners WHERE email = $1', [email]);
  const owner = rows[0];
  const now = await dbNow(db);
  if (!owner) {
    await burnPasswordTime(password);
    fail(401, 'invalid_credentials', INVALID);
  }
  if (owner.locked_until && new Date(owner.locked_until) > now) fail(401, 'invalid_credentials', INVALID);

  const ok = await verifyPassword(password, owner.password_hash);
  if (!ok) {
    await db.query(
      `UPDATE owners SET
         failed_logins = CASE WHEN failed_logins + 1 >= $2 THEN 0 ELSE failed_logins + 1 END,
         locked_until = CASE WHEN failed_logins + 1 >= $2 THEN now() + make_interval(mins => $3) ELSE locked_until END
       WHERE id = $1`,
      [owner.id, LOCK_FAILURES, LOCK_MINUTES],
    );
    fail(401, 'invalid_credentials', INVALID);
  }
  await limits.clear(ipKey);
  await db.query('UPDATE owners SET failed_logins = 0, locked_until = NULL WHERE id = $1', [owner.id]);

  const token = randomToken(32);
  const csrf = randomToken(32);
  await db.query(
    `INSERT INTO admin_sessions (owner_id, token_hash, csrf_token, expires_at, ip, user_agent)
     VALUES ($1, $2, $3, now() + make_interval(hours => $4), $5, $6)`,
    [owner.id, sha256Hex(token), csrf, SESSION_HOURS, clientAddress(ctx.req, config.trustProxy), userAgent(ctx.req)],
  );
  sendJson(
    ctx.res,
    200,
    { csrfToken: csrf, owner: { email: owner.email } },
    { 'set-cookie': setCookie(SESSION_COOKIE, token, { maxAgeSeconds: SESSION_HOURS * 3600, secure: config.cookieSecure }) },
  );
}

async function dbNow(db: { query(sql: string): Promise<{ rows: any[] }> }): Promise<Date> {
  const { rows } = await db.query('SELECT now() AS t');
  return new Date(rows[0].t);
}

/** Loads the owner session from the cookie. Throws 401 when missing, expired, revoked, or the owner was removed. */
export async function ownerSession(ctx: Ctx): Promise<OwnerSession> {
  const token = cookieValue(ctx.req.headers.cookie, SESSION_COOKIE);
  if (!token) fail(401, 'unauthenticated', 'sign in required');
  const { rows } = await ctx.deps.db.query(
    `SELECT s.id, s.owner_id, s.csrf_token, s.expires_at, s.reauth_until, s.revoked_at, o.email, now() AS db_now
       FROM admin_sessions s JOIN owners o ON o.id = s.owner_id
      WHERE s.token_hash = $1`,
    [sha256Hex(token)],
  );
  const row = rows[0];
  const now = row ? new Date(row.db_now) : new Date();
  if (!row || row.revoked_at || new Date(row.expires_at) <= now) fail(401, 'unauthenticated', 'sign in required');
  await ctx.deps.db.query('UPDATE admin_sessions SET last_seen_at = now() WHERE id = $1 AND last_seen_at < now() - interval \'1 minute\'', [row.id]);
  return {
    sessionId: row.id,
    ownerId: row.owner_id,
    email: row.email,
    csrfToken: row.csrf_token,
    reauthUntil: row.reauth_until ? new Date(row.reauth_until) : null,
    dbNow: now,
  };
}

/** For state-changing requests: the X-CSRF-Token header must match the session's token (compared in constant time). */
export function requireCsrf(ctx: Ctx, session: OwnerSession): void {
  const sent = ctx.req.headers['x-csrf-token'];
  const value = Array.isArray(sent) ? sent[0] : sent ?? '';
  const a = Buffer.from(value, 'utf8');
  const b = Buffer.from(session.csrfToken, 'utf8');
  if (a.length === 0 || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    fail(403, 'csrf_failed', 'the request could not be verified; reload the page and try again');
  }
}

export function requireReauth(session: OwnerSession): void {
  if (!session.reauthUntil || session.reauthUntil <= session.dbNow) {
    fail(403, 'reauth_required', 'confirm your password to make this change');
  }
}

export async function sessionInfo(ctx: Ctx): Promise<void> {
  const s = await ownerSession(ctx);
  sendJson(ctx.res, 200, {
    csrfToken: s.csrfToken,
    owner: { email: s.email },
    reauthUntil: s.reauthUntil && s.reauthUntil > s.dbNow ? s.reauthUntil.toISOString() : null,
  });
}

export async function logout(ctx: Ctx): Promise<void> {
  const s = await ownerSession(ctx);
  requireCsrf(ctx, s);
  await ctx.deps.db.query('UPDATE admin_sessions SET revoked_at = now() WHERE id = $1', [s.sessionId]);
  ctx.res.setHeader('set-cookie', clearCookie(SESSION_COOKIE, ctx.deps.config.cookieSecure));
  ctx.res.writeHead(204);
  ctx.res.end();
}

export async function reauth(ctx: Ctx): Promise<void> {
  const s = await ownerSession(ctx);
  requireCsrf(ctx, s);
  const ipKey = `reauth:ip:${ctx.ip}`;
  const limit = await ctx.deps.limits.hit(ipKey, LOGIN_PER_IP, LOGIN_WINDOW_SECONDS);
  if (!limit.allowed) fail(429, 'rate_limited', 'too many attempts; try again later', { 'retry-after': String(limit.retryAfterSeconds) });
  const body = requireObject(await readJson(ctx.req, 8 * 1024));
  rejectUnknown(body, ['password']);
  const password = str(body, 'password', { min: 1, max: 256, trim: false })!;
  const { rows } = await ctx.deps.db.query('SELECT password_hash FROM owners WHERE id = $1', [s.ownerId]);
  if (!rows[0] || !(await verifyPassword(password, rows[0].password_hash))) {
    fail(401, 'invalid_credentials', 'the password is not correct');
  }
  await ctx.deps.limits.clear(ipKey);
  const { rows: up } = await ctx.deps.db.query(
    `UPDATE admin_sessions SET reauth_until = now() + make_interval(mins => $2) WHERE id = $1 RETURNING reauth_until`,
    [s.sessionId, REAUTH_MINUTES],
  );
  sendJson(ctx.res, 200, { reauthUntil: new Date(up[0].reauth_until).toISOString() });
}

/** Guard for every admin route. Writes need CSRF; sensitive writes also need a recent password confirmation. */
export async function guardOwner(ctx: Ctx, opts: { write: boolean; sensitive?: boolean }): Promise<OwnerSession> {
  const s = await ownerSession(ctx);
  if (opts.write) requireCsrf(ctx, s);
  if (opts.sensitive) requireReauth(s);
  return s;
}

function cookieValue(header: string | undefined, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0 && part.slice(0, eq).trim() === name) return decodeURIComponent(part.slice(eq + 1).trim());
  }
  return null;
}
