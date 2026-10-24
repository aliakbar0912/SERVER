// Devora accounts on the API: sign-in (email/password through PocketBase, or Google/GitHub through a browser), the
// desktop handoff, signed-in device tokens, the account page and account deletion. PocketBase owns identities; this module
// never stores passwords, provider tokens or PocketBase user tokens (a user token is held encrypted for at most the 10
// minutes of a browser sign-in, then cleared).
//
// Browser sign-in (Google, GitHub, any PocketBase OAuth2 provider):
//   1. Desktop: POST /v1/auth/oauth/start { provider, purpose, loopbackPort, loopbackNonce } -> { authUrl, handoffSecret }.
//      The server asks PocketBase for a fresh state + PKCE verifier, keeps the verifier and hashes of the state and of
//      the random handoff secret, and returns the provider URL with our exact callback as redirect_uri.
//   2. The system browser signs in at the provider, which redirects to GET /v1/auth/oauth/callback?code&state.
//   3. The server finds the sign-in by the state hash (single use, 10 minutes), lets PocketBase exchange the code (PocketBase
//      holds the client secret and checks PKCE and the redirect URI), and checks the resulting user.
//   4. The browser is redirected to http://127.0.0.1:<loopbackPort>/devora-auth?code=<60 s single-use code>&nonce=<nonce>,
//      the desktop's own listener. Only the computer that started the sign-in receives the code.
//   5. Desktop: POST /v1/auth/exchange { code, handoffSecret, installId, deviceName } -> device token. The code only works
//      together with the secret from step 1 (never in a URL), once, within 60 seconds.
import crypto from 'node:crypto';
import type { Ctx, Deps } from '../context.ts';
import { openSecret, randomToken, sealSecret, sha256Hex, type SealedSecret } from '../crypto.ts';
import { fail, int, log, readJson, rejectUnknown, requireObject, sendJson, str, uuidParam } from '../http/util.ts';
import { PbError, type PbUser } from '../pocketbase.ts';
import { authenticateDevice, bearerToken } from './devices.ts';
import { bindDevice, endSession, endUserSessions, markDeleted, requireLoginForCentralAi, rotateToken, runDeletion } from './sessions.ts';
import { guardOwner } from './auth.ts';

const INSTALL_ID = /^[A-Za-z0-9_-]{16,64}$/;
const HANDOFF_SECONDS = 10 * 60;
const RESULT_SECONDS = 60;
const WINDOW = 15 * 60;

function pb(deps: Deps) {
  if (!deps.pocketbase) fail(503, 'accounts_not_configured', 'Devora accounts are not set up on this server');
  return deps.pocketbase;
}

async function limit(ctx: Ctx, key: string, max: number, windowSeconds = WINDOW): Promise<void> {
  const r = await ctx.deps.limits.hit(key, max, windowSeconds);
  if (!r.allowed) fail(429, 'rate_limited', 'too many attempts; try again later', { 'retry-after': String(r.retryAfterSeconds) });
}

/** Maps a PocketBase failure to a generic answer: no account enumeration, no upstream details. */
function pbFail(e: unknown, what = 'the sign-in is not valid or has expired'): never {
  if (e instanceof PbError && e.status === 0) fail(503, 'accounts_unavailable', 'the account service is temporarily unavailable; try again shortly', { 'retry-after': '15' });
  if (e instanceof PbError && e.status >= 500) fail(503, 'accounts_unavailable', 'the account service is temporarily unavailable; try again shortly', { 'retry-after': '15' });
  if (e instanceof PbError && e.status === 429) fail(429, 'too_many_attempts', 'too many wrong codes; request a new code and try again in a few minutes');
  if (e instanceof PbError) fail(401, 'invalid_credentials', what);
  throw e;
}

function publicUser(u: PbUser) {
  return { id: u.id, email: u.email, name: u.name, verified: u.verified };
}

/** The bound device's token and expiry, plus the user. */
async function signIn(ctx: Ctx, user: PbUser, installId: string, deviceName: string) {
  if (!user.verified) fail(403, 'email_not_verified', 'verify your email address first: open the link PocketBase emailed to you');
  const proof = bearerToken(ctx);
  const bound = await bindDevice(ctx.deps.db, { userId: user.id, installId, deviceName, proofHash: proof ? sha256Hex(proof) : null });
  log('info', 'device signed in', { deviceId: bound.deviceId, claimed: bound.claimed });
  return { deviceId: bound.deviceId, token: bound.token, tokenExpiresAt: bound.expiresAt, claimed: bound.claimed, user: publicUser(user) };
}

// ------------------------------------------------------------------ public

/** GET /v1/auth/config: whether accounts are on, the PocketBase address, enabled providers, and the sign-in policy. */
export async function authConfig(ctx: Ctx): Promise<void> {
  const p = ctx.deps.pocketbase;
  const loginRequired = await requireLoginForCentralAi(ctx.deps.db);
  if (!p) {
    sendJson(ctx.res, 200, { enabled: false, loginRequired, pocketbaseUrl: null, usersCollection: null, providers: [] });
    return;
  }
  let providers: { name: string; displayName: string }[] = [];
  let available = true;
  try {
    if (ctx.deps.config.publicApiOrigin) providers = (await p.providers()).map((x) => ({ name: x.name, displayName: x.displayName }));
  } catch {
    available = false;
  }
  sendJson(ctx.res, 200, { enabled: true, available, loginRequired, pocketbaseUrl: p.cfg.url, usersCollection: p.cfg.usersCollection, providers });
}

/**
 * POST /v1/auth/session { pbToken, installId, deviceName }: email/password sign-in. The desktop signed in with PocketBase
 * itself (so PocketBase's own rate limits see the user's address); the server verifies that token with PocketBase,
 * re-reads the user as superuser (exists, verified), binds the device and returns a Devora device token. The PocketBase
 * token is not stored. An optional Bearer device token proves ownership of the computer's current registration.
 */
export async function createSession(ctx: Ctx): Promise<void> {
  const p = pb(ctx.deps);
  await limit(ctx, `auth:session:ip:${ctx.ip}`, 30);
  const body = requireObject(await readJson(ctx.req, 16 * 1024));
  rejectUnknown(body, ['pbToken', 'installId', 'deviceName']);
  const pbToken = str(body, 'pbToken', { min: 20, max: 4096 })!;
  const installId = str(body, 'installId', { min: 16, max: 64 })!;
  if (!INSTALL_ID.test(installId)) fail(400, 'invalid_request', 'installId must be 16 to 64 letters, digits, _ or -');
  const deviceName = str(body, 'deviceName', { min: 1, max: 80 })!;
  let user: PbUser;
  try {
    const fromToken = await p.verifyUserToken(pbToken);
    // auth-refresh proves the token; the superuser read gives the current state of the account.
    const current = await p.getUser(fromToken.id);
    if (!current) fail(401, 'invalid_credentials', 'the sign-in is not valid or has expired');
    user = current;
  } catch (e) {
    pbFail(e);
  }
  sendJson(ctx.res, 200, await signIn(ctx, user, installId, deviceName));
}

/**
 * POST /v1/auth/password-reset { otpId, otpCode, password }: "forgot password" without email links. The user asked
 * PocketBase for an email code; the server checks that code itself (proving control of the address), then sets the new
 * password as superuser. PocketBase renews the user's tokenKey, so old PocketBase sessions end. Devora device sessions are
 * ended too, so a stolen device cannot outlive a password reset.
 */
export async function resetPassword(ctx: Ctx): Promise<void> {
  const p = pb(ctx.deps);
  await limit(ctx, `auth:reset:ip:${ctx.ip}`, 10);
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ['otpId', 'otpCode', 'password']);
  const otpId = str(body, 'otpId', { min: 1, max: 64 })!;
  const otpCode = str(body, 'otpCode', { min: 4, max: 12 })!;
  const password = str(body, 'password', { min: 8, max: 200, trim: false })!;
  let user: PbUser;
  try {
    user = await p.checkOtp(otpId, otpCode);
    await p.setPassword(user.id, password);
  } catch (e) {
    if (e instanceof PbError && e.status === 400) fail(400, 'weak_password', 'use a password of at least 8 characters');
    pbFail(e, 'the code is not correct or has expired');
  }
  await ctx.deps.db.transaction((q) => endUserSessions(q, user.id, 'password_reset'));
  log('info', 'password reset with email code', {});
  sendJson(ctx.res, 200, { reset: true });
}

/** POST /v1/auth/oauth/start { provider, purpose, loopbackPort, loopbackNonce, pbToken? }. */
export async function oauthStart(ctx: Ctx): Promise<void> {
  const deps = ctx.deps;
  const p = pb(deps);
  await limit(ctx, `auth:oauth:start:ip:${ctx.ip}`, 30);
  if (!deps.config.publicApiOrigin) fail(503, 'oauth_not_configured', 'browser sign-in needs PUBLIC_API_ORIGIN on the server');
  if (deps.config.keyring.size === 0) fail(503, 'oauth_not_configured', 'browser sign-in needs DEVORA_SECRET_KEYS on the server');
  const body = requireObject(await readJson(ctx.req, 16 * 1024));
  rejectUnknown(body, ['provider', 'purpose', 'loopbackPort', 'loopbackNonce', 'pbToken']);
  const providerName = str(body, 'provider', { min: 1, max: 40, pattern: /^[a-z0-9_]+$/ })!;
  const purpose = body.purpose ?? 'login';
  if (purpose !== 'login' && purpose !== 'link' && purpose !== 'reauth') fail(400, 'invalid_request', 'purpose must be login, link or reauth');
  const loopbackPort = int(body, 'loopbackPort', { min: 1024, max: 65535 })!;
  const loopbackNonce = str(body, 'loopbackNonce', { min: 16, max: 64, pattern: /^[A-Za-z0-9_-]+$/ })!;

  // Linking and re-authentication belong to a signed-in device; the user is taken from its token, never from the body.
  let deviceId: string | null = null;
  let expectedUserId: string | null = null;
  let userToken: string | null = null;
  if (purpose !== 'login') {
    const device = await authenticateDevice(ctx, { central: false });
    if (!device.userId) fail(403, 'not_signed_in', 'sign in first');
    deviceId = device.deviceId;
    expectedUserId = device.userId;
    if (purpose === 'link') {
      userToken = str(body, 'pbToken', { min: 20, max: 4096 })!;
      try {
        const u = await p.verifyUserToken(userToken);
        if (u.id !== expectedUserId) fail(403, 'account_mismatch', 'this sign-in belongs to a different account');
      } catch (e) {
        pbFail(e);
      }
    }
  } else if (body.pbToken !== undefined) fail(400, 'invalid_request', 'pbToken is only used for linking');

  let providers;
  try {
    providers = await p.providers();
  } catch (e) {
    pbFail(e);
  }
  const provider = providers.find((x) => x.name === providerName);
  if (!provider) fail(404, 'provider_not_enabled', 'this sign-in method is not enabled');
  if (provider.codeChallengeMethod && provider.codeChallengeMethod !== 'S256') fail(503, 'oauth_not_configured', 'this provider is not configured for PKCE S256');
  if (!provider.authURL.endsWith('redirect_uri=')) fail(502, 'oauth_not_configured', 'the account service returned an unexpected sign-in address');
  const authUrlBase = new URL(provider.authURL);
  if (deps.config.env === 'production' && authUrlBase.protocol !== 'https:') fail(502, 'oauth_not_configured', 'the provider sign-in address must use https');
  if (authUrlBase.searchParams.get('state') !== provider.state) fail(502, 'oauth_not_configured', 'the account service returned an inconsistent sign-in state');

  const redirectUri = `${deps.config.publicApiOrigin}/v1/auth/oauth/callback`;
  const id = crypto.randomUUID();
  const secret = randomToken(32);
  const sealed = userToken ? sealJson(deps, sealSecret(deps.config.keyring, userToken, `auth_handoff:${id}`)) : null;
  await deps.db.query(
    `INSERT INTO auth_handoffs (id, purpose, provider, state_hash, secret_hash, code_verifier, redirect_uri, loopback_port, loopback_nonce,
                                device_id, expected_user_id, user_token_sealed, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now() + make_interval(secs => $13))`,
    [id, purpose, provider.name, sha256Hex(provider.state), sha256Hex(secret), provider.codeVerifier, redirectUri, loopbackPort, loopbackNonce, deviceId, expectedUserId, sealed, HANDOFF_SECONDS],
  );
  sendJson(ctx.res, 200, { authUrl: provider.authURL + encodeURIComponent(redirectUri), handoffSecret: secret, expiresIn: HANDOFF_SECONDS, provider: provider.name });
}

function sealJson(_deps: Deps, s: SealedSecret) {
  return { k: s.keyVersion, iv: s.iv.toString('base64'), c: s.ciphertext.toString('base64'), t: s.tag.toString('base64') };
}

function openJson(deps: Deps, v: any, id: string): string {
  return openSecret(deps.config.keyring, { keyVersion: v.k, iv: Buffer.from(v.iv, 'base64'), ciphertext: Buffer.from(v.c, 'base64'), tag: Buffer.from(v.t, 'base64') }, `auth_handoff:${id}`);
}

const PAGE_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

function page(ctx: Ctx, status: number, title: string, text: string): void {
  const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
  const html = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#000;color:#fff;font:15px/1.5 system-ui,sans-serif}main{max-width:420px;padding:24px;text-align:center}h1{font-size:20px;margin:0 0 8px}p{color:#a1a1aa;margin:0}</style>
<main><h1>${esc(title)}</h1><p>${esc(text)}</p></main>`;
  ctx.res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': PAGE_CSP, 'cache-control': 'no-store' });
  ctx.res.end(html);
}

/** GET /v1/auth/oauth/callback?code&state: the provider's redirect. Never shows or forwards a token. */
export async function oauthCallback(ctx: Ctx): Promise<void> {
  const deps = ctx.deps;
  await limit(ctx, `auth:oauth:callback:ip:${ctx.ip}`, 60);
  const q = ctx.url.searchParams;
  const state = q.get('state') ?? '';
  if (!/^[A-Za-z0-9_.~-]{8,200}$/.test(state)) return page(ctx, 400, 'Sign-in failed', 'This sign-in link is not valid. Start again from the Devora app.');
  // Claim the sign-in atomically: a second callback with the same state finds nothing.
  const { rows } = await deps.db.query(
    `UPDATE auth_handoffs SET status = 'failed', error_code = 'in_progress'
      WHERE state_hash = $1 AND status = 'pending' AND expires_at > now()
      RETURNING id, purpose, provider, code_verifier, redirect_uri, loopback_port, loopback_nonce, expected_user_id, user_token_sealed`,
    [sha256Hex(state)],
  );
  const h = rows[0];
  if (!h) return page(ctx, 400, 'Sign-in expired', 'This sign-in was already used or has expired. Start again from the Devora app.');
  const back = (params: Record<string, string>) => {
    const u = new URL(`http://127.0.0.1:${h.loopback_port}/devora-auth`);
    u.searchParams.set('nonce', h.loopback_nonce);
    for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
    ctx.res.writeHead(302, { location: u.toString(), 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' });
    ctx.res.end();
  };
  const failWith = async (code: string) => {
    await deps.db.query("UPDATE auth_handoffs SET status = 'failed', error_code = $2, user_token_sealed = NULL WHERE id = $1", [h.id, code]);
    back({ error: code });
  };
  const code = q.get('code') ?? '';
  if (q.get('error') || !code || code.length > 2048) return failWith(q.get('error') === 'access_denied' ? 'cancelled' : 'provider_error');
  let userToken: string | undefined;
  try {
    if (h.user_token_sealed) userToken = openJson(deps, h.user_token_sealed, h.id);
  } catch {
    return failWith('server_error');
  }
  let user: PbUser;
  let pbToken: string;
  try {
    const r = await pb(deps).finishOAuth({ provider: h.provider, code, codeVerifier: h.code_verifier, redirectUrl: h.redirect_uri, userToken });
    user = r.user;
    pbToken = r.token;
    const current = await pb(deps).getUser(user.id);
    if (!current) return failWith('invalid_account');
    user = current;
  } catch (e) {
    log('warn', 'oauth sign-in failed', { reason: e instanceof PbError ? e.status : 'error' });
    return failWith(e instanceof PbError && e.status === 0 ? 'accounts_unavailable' : 'sign_in_failed');
  }
  if (h.expected_user_id && user.id !== h.expected_user_id) return failWith(h.purpose === 'link' ? 'identity_in_use' : 'account_mismatch');
  if (h.purpose === 'login' && !user.verified) return failWith('email_not_verified');
  const resultCode = randomToken(32);
  const sealed = h.purpose === 'login' ? sealJson(deps, sealSecret(deps.config.keyring, pbToken, `auth_handoff:${h.id}`)) : null;
  await deps.db.query(
    `UPDATE auth_handoffs SET status = 'completed', error_code = NULL, user_id = $2, result_code_hash = $3,
            result_expires_at = now() + make_interval(secs => $4), user_token_sealed = $5
      WHERE id = $1`,
    [h.id, user.id, sha256Hex(resultCode), RESULT_SECONDS, sealed],
  );
  back({ code: resultCode });
}

/** Consumes a completed handoff: the code and the secret must match, once, within 60 seconds. */
async function consumeHandoff(ctx: Ctx, code: string, secret: string, purpose: 'login' | 'link' | 'reauth') {
  const { rows } = await ctx.deps.db.query(
    `UPDATE auth_handoffs h SET status = 'consumed', consumed_at = now(), user_token_sealed = NULL
       FROM (SELECT id, user_token_sealed FROM auth_handoffs WHERE result_code_hash = $1 FOR UPDATE) old
      WHERE h.id = old.id AND h.status = 'completed' AND h.result_expires_at > now()
      RETURNING h.id, h.purpose, h.provider, h.secret_hash, h.user_id, h.device_id, old.user_token_sealed AS sealed_before`,
    [sha256Hex(code)],
  );
  const h = rows[0];
  // The row is burnt either way: a wrong secret or purpose means someone else holds the code.
  if (!h || h.secret_hash !== sha256Hex(secret) || h.purpose !== purpose) fail(400, 'invalid_code', 'this sign-in code is not valid or has expired; start again');
  return h;
}

/** POST /v1/auth/exchange { code, handoffSecret, installId, deviceName }: finishes a browser sign-in or link. */
export async function exchange(ctx: Ctx): Promise<void> {
  const deps = ctx.deps;
  pb(deps);
  await limit(ctx, `auth:exchange:ip:${ctx.ip}`, 30);
  const body = requireObject(await readJson(ctx.req, 8 * 1024));
  rejectUnknown(body, ['code', 'handoffSecret', 'installId', 'deviceName']);
  const code = str(body, 'code', { min: 20, max: 128 })!;
  const secret = str(body, 'handoffSecret', { min: 20, max: 128 })!;
  // Purpose decides the shape: a link answers without a device token.
  const kind = await deps.db.query("SELECT purpose FROM auth_handoffs WHERE result_code_hash = $1 AND status = 'completed'", [sha256Hex(code)]);
  const purpose = kind.rows[0]?.purpose;
  if (purpose === 'link') {
    const device = await authenticateDevice(ctx, { central: false });
    const h = await consumeHandoff(ctx, code, secret, 'link');
    if (h.device_id !== device.deviceId || h.user_id !== device.userId) fail(400, 'invalid_code', 'this sign-in code is not valid or has expired; start again');
    sendJson(ctx.res, 200, { linked: true, provider: h.provider });
    return;
  }
  const installId = str(body, 'installId', { min: 16, max: 64 })!;
  if (!INSTALL_ID.test(installId)) fail(400, 'invalid_request', 'installId must be 16 to 64 letters, digits, _ or -');
  const deviceName = str(body, 'deviceName', { min: 1, max: 80 })!;
  const h = await consumeHandoff(ctx, code, secret, 'login');
  let pbToken: string | null = null;
  try {
    pbToken = h.sealed_before ? openJson(deps, h.sealed_before, h.id) : null;
  } catch {
    pbToken = null;
  }
  let user: PbUser | null;
  try {
    user = await pb(deps).getUser(h.user_id);
  } catch (e) {
    pbFail(e);
  }
  if (!user) fail(401, 'invalid_credentials', 'the sign-in is not valid or has expired');
  // The PocketBase token is the user's own (for profile changes on the desktop); it is returned in the body only.
  sendJson(ctx.res, 200, { ...(await signIn(ctx, user, installId, deviceName)), pbToken });
}

// ------------------------------------------------------------------ signed-in device

async function signedIn(ctx: Ctx) {
  const device = await authenticateDevice(ctx, { central: false });
  if (!device.userId) fail(403, 'not_signed_in', 'this computer is not signed in to a Devora account');
  return device as typeof device & { userId: string };
}

/** POST /v1/auth/refresh: rotates the signed-in device token (the old one works for 2 more minutes). */
export async function refresh(ctx: Ctx): Promise<void> {
  const device = await signedIn(ctx);
  await limit(ctx, `auth:refresh:dev:${device.deviceId}`, 30, 3600);
  const t = await rotateToken(ctx.deps.db, device.deviceId, device.tokenHash);
  sendJson(ctx.res, 200, { token: t.token, tokenExpiresAt: t.expiresAt });
}

/** POST /v1/auth/logout: ends this device's session. Local projects and data on the computer are not touched. */
export async function logout(ctx: Ctx): Promise<void> {
  const token = bearerToken(ctx);
  if (!token) fail(401, 'unauthenticated', 'a device token is required');
  const { rows } = await ctx.deps.db.query('SELECT id, user_id FROM devices WHERE token_hash = $1 OR prev_token_hash = $1', [sha256Hex(token)]);
  // Idempotent: an already ended or unknown session is a successful logout.
  if (rows[0]?.user_id) await endSession(ctx.deps.db, rows[0].id, 'logout');
  sendJson(ctx.res, 200, { signedOut: true });
}

/** GET /v1/account: the signed-in user (fresh from PocketBase), linked sign-in methods and the account's devices. */
export async function account(ctx: Ctx): Promise<void> {
  const device = await signedIn(ctx);
  const p = pb(ctx.deps);
  let user: PbUser | null;
  let identities;
  try {
    user = await p.getUser(device.userId);
    identities = user ? await p.externalAuths(user.id) : [];
  } catch (e) {
    pbFail(e);
  }
  if (!user) fail(401, 'account_deleted', 'this account has been deleted');
  const { rows } = await ctx.deps.db.query(
    `SELECT id, name, created_at, last_seen_at, app_version, signed_out_at FROM devices
      WHERE user_id = $1 ORDER BY (signed_out_at IS NULL) DESC, last_seen_at DESC NULLS LAST LIMIT 50`,
    [device.userId],
  );
  sendJson(ctx.res, 200, {
    user: { ...publicUser(user), created: user.created, hasAvatar: !!user.avatar },
    identities,
    tokenExpiresAt: device.tokenExpiresAt,
    devices: rows.map((r) => ({ id: r.id, name: r.name, createdAt: r.created_at, lastSeenAt: r.last_seen_at, appVersion: r.app_version, signedIn: !r.signed_out_at, current: r.id === device.deviceId })),
  });
}

/** POST /v1/account/devices/:id/sign-out: ends another session of the same account. */
export async function signOutDevice(ctx: Ctx): Promise<void> {
  const device = await signedIn(ctx);
  const id = uuidParam(ctx.params.id);
  const { rows } = await ctx.deps.db.query('SELECT user_id, signed_out_at FROM devices WHERE id = $1', [id]);
  // Another user's device answers exactly like a missing one.
  if (!rows[0] || rows[0].user_id !== device.userId) fail(404, 'not_found', 'device not found');
  if (!rows[0].signed_out_at) await endSession(ctx.deps.db, id, 'signed_out_remotely');
  sendJson(ctx.res, 200, { id, signedIn: false });
}

/**
 * POST /v1/account/delete { otpId, otpCode } (email code), { password }, or { code, handoffSecret } (a browser re-authentication, purpose "reauth").
 * Re-authenticates, then records the deletion and ends every session before anything is removed; the remaining steps are
 * resumed by the background job if they cannot finish now.
 */
export async function deleteAccount(ctx: Ctx): Promise<void> {
  const deps = ctx.deps;
  const device = await signedIn(ctx);
  const p = pb(deps);
  await limit(ctx, `account:delete:dev:${device.deviceId}`, 5, 3600);
  const body = requireObject(await readJson(ctx.req, 8 * 1024));
  rejectUnknown(body, ['password', 'code', 'handoffSecret', 'otpId', 'otpCode']);
  if (typeof body.otpId === 'string') {
    // Email code: the server checks it with PocketBase itself, so the re-authentication is fresh and proven here.
    const otpId = str(body, 'otpId', { min: 1, max: 64 })!;
    const otpCode = str(body, 'otpCode', { min: 4, max: 12 })!;
    try {
      const checked = await p.checkOtp(otpId, otpCode);
      if (checked.id !== device.userId) fail(401, 'invalid_credentials', 'the code is not correct');
    } catch (e) {
      pbFail(e, 'the code is not correct');
    }
  } else if (typeof body.password === 'string') {
    const password = str(body, 'password', { min: 1, max: 200, trim: false })!;
    try {
      const u = await p.getUser(device.userId);
      if (!u) fail(401, 'account_deleted', 'this account has been deleted');
      const checked = await p.checkPassword(u.email, password);
      if (checked.id !== device.userId) fail(401, 'invalid_credentials', 'the password is not correct');
    } catch (e) {
      pbFail(e, 'the password is not correct');
    }
  } else {
    const code = str(body, 'code', { min: 20, max: 128 })!;
    const secret = str(body, 'handoffSecret', { min: 20, max: 128 })!;
    const h = await consumeHandoff(ctx, code, secret, 'reauth');
    if (h.user_id !== device.userId || h.device_id !== device.deviceId) fail(400, 'invalid_code', 'this sign-in code is not valid or has expired; start again');
  }
  await markDeleted(deps.db, device.userId, 'devices');
  const status = await runDeletion(deps, device.userId);
  log('info', 'account deletion requested', { status });
  sendJson(ctx.res, status === 'done' ? 200 : 202, { status });
}

// ------------------------------------------------------------------ admin (owner session; PocketBase superuser stays here)

const USER_ID = /^[A-Za-z0-9_]{1,64}$/;

function userParam(v: string | undefined): string {
  if (!v || !USER_ID.test(v)) fail(400, 'invalid_request', 'invalid user id');
  return v;
}

/** GET /admin/api/users?page=1&search=: PocketBase users with Devora's state (blocked, deleting) and device counts. */
export async function adminListUsers(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const p = ctx.deps.pocketbase;
  if (!p) {
    sendJson(ctx.res, 200, { configured: false, users: [], total: 0, page: 1, perPage: 50 });
    return;
  }
  const page = Math.max(1, Math.min(1000, Number(ctx.url.searchParams.get('page') ?? 1) || 1));
  const search = (ctx.url.searchParams.get('search') ?? '').slice(0, 100);
  let list;
  try {
    list = await p.listUsers({ page, perPage: 50, search });
  } catch (e) {
    pbFail(e);
  }
  const ids = list.items.map((u) => u.id);
  const state = ids.length
    ? await ctx.deps.db.query(
        `SELECT u.user_id, u.status, u.last_login_at, u.deletion_step, u.deletion_error,
                (SELECT count(*)::int FROM devices d WHERE d.user_id = u.user_id AND d.signed_out_at IS NULL) AS devices
           FROM app_users u WHERE u.user_id IN (SELECT jsonb_array_elements_text($1::jsonb))`,
        [ids],
      )
    : { rows: [] as any[] };
  const byId = new Map(state.rows.map((r: any) => [r.user_id, r]));
  sendJson(ctx.res, 200, {
    configured: true,
    page,
    perPage: 50,
    total: list.total,
    users: list.items.map((u) => {
      const s: any = byId.get(u.id);
      return {
        id: u.id,
        email: u.email,
        name: u.name,
        verified: u.verified,
        createdAt: u.created,
        status: s?.status ?? 'active',
        lastLoginAt: s?.last_login_at ?? null,
        signedInDevices: s?.devices ?? 0,
        deletionError: s?.deletion_error ?? null,
      };
    }),
  });
}

/** GET /admin/api/users/:id: one user with linked sign-in methods and devices. */
export async function adminGetUser(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const id = userParam(ctx.params.id);
  const p = pb(ctx.deps);
  let user: PbUser | null;
  let identities;
  try {
    user = await p.getUser(id);
    identities = user ? await p.externalAuths(id) : [];
  } catch (e) {
    pbFail(e);
  }
  const s = await ctx.deps.db.query('SELECT status, first_seen_at, last_login_at, deletion_step, deletion_error, deleted_at FROM app_users WHERE user_id = $1', [id]);
  if (!user && !s.rows[0]) fail(404, 'not_found', 'user not found');
  const devices = await ctx.deps.db.query(
    `SELECT id, name, status, created_at, last_seen_at, app_version, signed_out_at, signed_out_reason FROM devices WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100`,
    [id],
  );
  sendJson(ctx.res, 200, {
    user: user ? { id: user.id, email: user.email, name: user.name, verified: user.verified, createdAt: user.created } : null,
    state: s.rows[0] ?? null,
    identities,
    devices: devices.rows.map((r) => ({ id: r.id, name: r.name, status: r.status, createdAt: r.created_at, lastSeenAt: r.last_seen_at, appVersion: r.app_version, signedIn: !r.signed_out_at, signedOutReason: r.signed_out_reason })),
  });
}

/** POST /admin/api/users/:id/block | unblock | sign-out | delete. */
export async function adminUserAction(ctx: Ctx): Promise<void> {
  const action = ctx.params.action;
  if (!['block', 'unblock', 'sign-out', 'delete'].includes(action)) fail(404, 'not_found', 'not found');
  const sensitive = action !== 'sign-out';
  await guardOwner(ctx, { write: true, sensitive });
  const id = userParam(ctx.params.id);
  const db = ctx.deps.db;
  if (action === 'sign-out') {
    const n = await db.transaction((q) => endUserSessions(q, id, 'signed_out_by_owner'));
    sendJson(ctx.res, 200, { signedOutDevices: n });
    return;
  }
  if (action === 'block' || action === 'unblock') {
    const n = await db.transaction(async (q) => {
      const r = await q.query(
        `INSERT INTO app_users (user_id, status, blocked_at) VALUES ($1, $2, CASE WHEN $2 = 'blocked' THEN now() END)
         ON CONFLICT (user_id) DO UPDATE SET status = EXCLUDED.status, blocked_at = EXCLUDED.blocked_at
         WHERE app_users.status IN ('active', 'blocked') RETURNING status`,
        [id, action === 'block' ? 'blocked' : 'active'],
      );
      if (!r.rows[0]) fail(409, 'account_deleted', 'this account is being deleted');
      return action === 'block' ? endUserSessions(q, id, 'blocked_by_owner') : 0;
    });
    sendJson(ctx.res, 200, { status: action === 'block' ? 'blocked' : 'active', signedOutDevices: n });
    return;
  }
  // delete: the owner types the email to confirm, like blocking a device.
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ['confirmEmail']);
  const confirm = str(body, 'confirmEmail', { max: 320, optional: true }) ?? '';
  let user: PbUser | null = null;
  try {
    user = ctx.deps.pocketbase ? await ctx.deps.pocketbase.getUser(id) : null;
  } catch (e) {
    pbFail(e);
  }
  const existing = await db.query('SELECT status FROM app_users WHERE user_id = $1', [id]);
  if (!user && !existing.rows[0]) fail(404, 'not_found', 'user not found');
  if (user && confirm.toLowerCase() !== user.email.toLowerCase()) fail(400, 'confirmation_mismatch', "type the user's email exactly to delete the account");
  await markDeleted(db, id, 'devices');
  const status = await runDeletion(ctx.deps, id);
  sendJson(ctx.res, status === 'done' ? 200 : 202, { status });
}
