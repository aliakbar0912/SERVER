// Devora accounts against a real PocketBase (fresh instance per run) and a real PostgreSQL. Google/GitHub are replaced by
// a local OpenID Connect provider configured in PocketBase as its "oidc" provider, so PocketBase's real OAuth2 code
// exchange (client secret, exact redirect_uri, PKCE) runs; only the identity provider is a test double.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import net, { type AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { createTestDb, SKIP_NO_PG, type TestDb } from './helpers.ts';
import { startPocketBase, SKIP_NO_PB, type TestPocketBase } from './pocketbase-helper.ts';
import { startOidcMock, type OidcMock } from './oidc-mock.ts';
import { loadConfig } from '../src/config.ts';
import { createServer } from '../src/app.ts';
import { hashPassword } from '../src/crypto.ts';
import { loadMigrations, migrateUp } from '../src/db/migrate.ts';
import { PocketBase } from '../src/pocketbase.ts';
import { accountMaintenance } from '../src/modules/sessions.ts';
import { DatabaseLimitStore } from '../src/limits.ts';

const OWNER_PASSWORD = 'correct horse battery staple';
let tdb: TestDb | null = null;
let pbt: TestPocketBase | null = null;
let idp: OidcMock;
let server: Server;
let base = '';
/** When set, requests from the API server to PocketBase matching this test fail as if PocketBase were unreachable. */
let pbOutage: ((url: string, method: string) => boolean) | null = null;
let deps: any;

const j = async (r: Response) => {
  const t = await r.text();
  try {
    return { status: r.status, body: t ? JSON.parse(t) : null, headers: r.headers };
  } catch {
    return { status: r.status, body: t, headers: r.headers };
  }
};
const post = (p: string, body?: unknown, token?: string) =>
  fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body ?? {}) }).then(j);
const get = (p: string, token?: string) => fetch(base + p, { headers: token ? { authorization: `Bearer ${token}` } : {} }).then(j);
const installId = () => crypto.randomBytes(18).toString('base64url');

before(async () => {
  tdb = await createTestDb();
  if (!tdb) return;
  pbt = await startPocketBase();
  if (!pbt) return;
  await migrateUp(tdb.db, loadMigrations());
  await tdb.db.query('INSERT INTO owners (email, password_hash) VALUES ($1, $2)', ['owner@example.test', await hashPassword(OWNER_PASSWORD)]);
  idp = await startOidcMock();
  const patched = await pbt.su('PATCH', '/api/collections/users', {
    oauth2: {
      enabled: true,
      providers: [{ name: 'oidc', displayName: 'Test sign-in', clientId: idp.clientId, clientSecret: idp.clientSecret, authURL: `${idp.url}/authorize`, tokenURL: `${idp.url}/token`, userInfoURL: `${idp.url}/userinfo`, pkce: true }],
    },
  });
  assert.equal(patched.status, 200, JSON.stringify(patched.body));

  const pw = encodeURIComponent(tdb.config.password);
  const port = await new Promise<number>((r) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => {
      const p = (s.address() as AddressInfo).port;
      s.close(() => r(p));
    });
  });
  base = `http://127.0.0.1:${port}`;
  const config = loadConfig({
    DEVORA_ENV: 'development',
    DATABASE_URL: `postgres://${tdb.config.user}:${pw}@${tdb.config.host}:${tdb.config.port}/${tdb.config.database}`,
    DEVORA_SECRET_KEYS: `1=${crypto.randomBytes(32).toString('base64')}`,
    DEVORA_SECRET_ACTIVE_KEY: '1',
    ADMIN_ORIGIN: 'https://admin.example.test',
    COOKIE_SECURE: 'false',
    PUBLIC_API_ORIGIN: base,
    POCKETBASE_URL: pbt.url,
    POCKETBASE_ADMIN_EMAIL: pbt.adminEmail,
    POCKETBASE_ADMIN_PASSWORD: pbt.adminPassword,
  });
  const guardedFetch: typeof fetch = (input, init) => {
    const url = String(input instanceof Request ? input.url : input);
    if (pbOutage && url.startsWith(pbt!.url) && pbOutage(url, init?.method ?? 'GET')) return Promise.reject(new TypeError('fetch failed'));
    return fetch(input, init);
  };
  deps = { db: tdb.db, config, fetch: guardedFetch, limits: new DatabaseLimitStore(tdb.db), redis: null, pocketbase: new PocketBase(config.pocketbase!, guardedFetch) };
  server = createServer(deps);
  await new Promise<void>((r) => server.listen(port, '127.0.0.1', r));
});

after(async () => {
  server?.closeAllConnections?.();
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  await idp?.close();
  await pbt?.stop();
  await tdb?.drop();
});

const skip = (t: any) => {
  if (!tdb) return t.skip(SKIP_NO_PG), true;
  if (!pbt) return t.skip(SKIP_NO_PB), true;
  return false;
};

async function owner() {
  const login = await fetch(`${base}/admin/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'owner@example.test', password: OWNER_PASSWORD }) });
  const cookie = (login.headers.get('set-cookie') ?? '').split(';')[0];
  const csrf = ((await login.json()) as any).csrfToken;
  const call = (method: string, p: string, body?: unknown) =>
    fetch(base + p, { method, headers: { cookie, 'x-csrf-token': csrf, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }).then(j);
  return { call, reauth: () => call('POST', '/admin/api/auth/reauth', { password: OWNER_PASSWORD }) };
}

async function setRequireLogin(on: boolean) {
  const o = await owner();
  assert.equal((await o.reauth()).status, 200);
  const r = await o.call('PATCH', '/admin/api/settings', { requireLoginForCentralAi: on });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.requireLoginForCentralAi, on);
}

async function legacyDevice(id = installId()) {
  const r = await post('/v1/devices/register', { installId: id, deviceName: 'Legacy PC' });
  assert.ok(r.status === 201 || r.status === 200, JSON.stringify(r.body));
  return { installId: id, token: r.body.token as string, deviceId: r.body.deviceId as string };
}

async function passwordSignIn(email: string, password: string, id = installId(), proof?: string) {
  const pbToken = await pbt!.passwordToken(email, password);
  const r = await post('/v1/auth/session', { pbToken, installId: id, deviceName: 'Laptop' }, proof);
  return { ...r, installId: id, pbToken };
}

/** Plays the browser: provider login, our callback, then reads the redirect the desktop's loopback listener would get. */
async function browserSignIn(identity: { sub: string; email: string; emailVerified?: boolean }, opts: { purpose?: 'login' | 'link' | 'reauth'; token?: string; pbToken?: string } = {}) {
  const nonce = crypto.randomBytes(16).toString('base64url');
  const start = await post('/v1/auth/oauth/start', { provider: 'oidc', purpose: opts.purpose ?? 'login', loopbackPort: 49152, loopbackNonce: nonce, ...(opts.pbToken ? { pbToken: opts.pbToken } : {}) }, opts.token);
  assert.equal(start.status, 200, JSON.stringify(start.body));
  idp.setNextIdentity(identity);
  const atProvider = await fetch(start.body.authUrl, { redirect: 'manual' });
  const callbackUrl = atProvider.headers.get('location')!;
  assert.ok(callbackUrl.startsWith(`${base}/v1/auth/oauth/callback?`), callbackUrl);
  const cb = await fetch(callbackUrl, { redirect: 'manual' });
  const loopback = new URL(cb.headers.get('location') ?? 'http://invalid/');
  return { start: start.body, callbackUrl, callbackStatus: cb.status, loopback, nonce };
}

describe('legacy devices and the register takeover fix', () => {
  test('legacy clients keep working exactly as before while sign-in is optional', async (t) => {
    if (skip(t)) return;
    const d = await legacyDevice();
    assert.equal((await get('/v1/catalogue', d.token)).status, 200);
    const info = await get('/v1/device', d.token);
    assert.equal(info.body.signedIn, false);
    assert.equal(info.body.loginRequired, false);
    // Re-registering an unclaimed installation still rotates its token (the owner's "unblock" depends on this).
    const again = await post('/v1/devices/register', { installId: d.installId, deviceName: 'Legacy PC' });
    assert.equal(again.status, 200);
    assert.equal(again.body.deviceId, d.deviceId);
    assert.equal((await get('/v1/catalogue', d.token)).status, 401);
    assert.equal((await get('/v1/catalogue', again.body.token)).status, 200);
  });

  test('knowing the install id of a signed-in device never yields a token', async (t) => {
    if (skip(t)) return;
    await pbt!.createUser('takeover@example.test', 'takeover-pass-1');
    const s = await passwordSignIn('takeover@example.test', 'takeover-pass-1');
    assert.equal(s.status, 200, JSON.stringify(s.body));
    const attack = await post('/v1/devices/register', { installId: s.installId, deviceName: 'Attacker' });
    assert.equal(attack.status, 409);
    assert.equal(attack.body.error.code, 'account_device');
    assert.equal(attack.body.token, undefined);
    // The real device's token is untouched.
    assert.equal((await get('/v1/catalogue', s.body.token)).status, 200);
    const { rows } = await tdb!.db.query('SELECT name FROM devices WHERE id = $1', [s.body.deviceId]);
    assert.equal(rows[0].name, 'Laptop');
  });

  test('claiming a legacy device needs its current token; memory stays with the device', async (t) => {
    if (skip(t)) return;
    await pbt!.createUser('claim@example.test', 'claim-pass-123');
    const d = await legacyDevice();
    await tdb!.db.query(
      `INSERT INTO memory_entries (device_id, client_key, scope, kind, content, source, confidence, client_updated_at) VALUES ($1, $2, 'global', 'fact', 'prefers tabs', 'user', 1, 1)`,
      [d.deviceId, 'k'.repeat(20)],
    );
    const noProof = await passwordSignIn('claim@example.test', 'claim-pass-123', d.installId);
    assert.equal(noProof.status, 409);
    assert.equal(noProof.body.error.code, 'device_proof_required');
    assert.equal((await get('/v1/catalogue', d.token)).status, 200, 'the failed attempt changed nothing');
    const withProof = await passwordSignIn('claim@example.test', 'claim-pass-123', d.installId, d.token);
    assert.equal(withProof.status, 200, JSON.stringify(withProof.body));
    assert.equal(withProof.body.claimed, 'legacy');
    assert.equal(withProof.body.deviceId, d.deviceId);
    const mem = await tdb!.db.query('SELECT count(*)::int AS n FROM memory_entries WHERE device_id = $1', [d.deviceId]);
    assert.equal(mem.rows[0].n, 1);
    assert.equal((await get('/v1/catalogue', d.token)).status, 401, 'the legacy token was replaced');
  });

  test('a device signed in as one user is never moved to another user without proof', async (t) => {
    if (skip(t)) return;
    await pbt!.createUser('first@example.test', 'first-pass-123');
    await pbt!.createUser('second@example.test', 'second-pass-123');
    const a = await passwordSignIn('first@example.test', 'first-pass-123');
    const b = await passwordSignIn('second@example.test', 'second-pass-123', a.installId);
    assert.equal(b.status, 409);
    const b2 = await passwordSignIn('second@example.test', 'second-pass-123', a.installId, a.body.token);
    assert.equal(b2.status, 200);
    assert.equal(b2.body.claimed, 'switched');
    assert.notEqual(b2.body.deviceId, a.body.deviceId);
    assert.equal((await get('/v1/catalogue', a.body.token)).status, 401);
    const old = await tdb!.db.query('SELECT user_id, signed_out_reason FROM devices WHERE id = $1', [a.body.deviceId]);
    assert.equal(old.rows[0].signed_out_reason, 'switched_account');
    assert.ok(old.rows[0].user_id, 'the old device (and its memory) stays with the first user');
  });
});

describe('email and password', () => {
  test('signup, verification email, then sign-in; unverified accounts get no device token', async (t) => {
    if (skip(t)) return;
    const email = 'newuser@example.test';
    const created = await pbt!.api('POST', '/api/collections/users/records', { email, password: 'new-user-pass1', passwordConfirm: 'new-user-pass1' });
    assert.equal(created.status, 200);
    const early = await passwordSignIn(email, 'new-user-pass1');
    assert.equal(early.status, 403);
    assert.equal(early.body.error.code, 'email_not_verified');
    assert.equal(early.body.token, undefined);
    assert.equal((await pbt!.api('POST', '/api/collections/users/request-verification', { email })).status, 204);
    const token = await pbt!.waitForMailToken(email, 'confirm-verification');
    assert.equal((await pbt!.api('POST', '/api/collections/users/confirm-verification', { token })).status, 204);
    const ok = await passwordSignIn(email, 'new-user-pass1');
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.equal(ok.body.user.verified, true);
    assert.equal(ok.body.claimed, 'new');
    assert.ok(Date.parse(ok.body.tokenExpiresAt) > Date.now() + 29 * 86400_000);
    const info = await get('/v1/device', ok.body.token);
    assert.equal(info.body.signedIn, true);
  });

  test('password reset email is delivered and the new password works', async (t) => {
    if (skip(t)) return;
    const email = 'reset@example.test';
    await pbt!.createUser(email, 'old-password-1');
    assert.equal((await pbt!.api('POST', '/api/collections/users/request-password-reset', { email })).status, 204);
    const token = await pbt!.waitForMailToken(email, 'confirm-password-reset');
    assert.equal((await pbt!.api('POST', '/api/collections/users/confirm-password-reset', { token, password: 'new-password-2', passwordConfirm: 'new-password-2' })).status, 204);
    assert.equal((await passwordSignIn(email, 'new-password-2')).status, 200);
  });

  test('a forged or foreign token is refused with a generic error', async (t) => {
    if (skip(t)) return;
    const forged = await post('/v1/auth/session', { pbToken: 'eyJhbGciOiJIUzI1NiJ9.eyJpZCI6ImFiYyJ9.' + 'x'.repeat(43), installId: installId(), deviceName: 'X' });
    assert.equal(forged.status, 401);
    assert.equal(forged.body.error.code, 'invalid_credentials');
    // A PocketBase superuser token is not a user token.
    const su = await post('/v1/auth/session', { pbToken: await pbt!.superToken(), installId: installId(), deviceName: 'X' });
    assert.equal(su.status, 401);
  });
});

describe('browser sign-in (OAuth2 through PocketBase)', () => {
  test('state, PKCE, exact redirect URI, loopback handoff and single-use 60 s code', async (t) => {
    if (skip(t)) return;
    const flow = await browserSignIn({ sub: 'oidc-alice', email: 'alice@example.test' });
    assert.ok(!flow.start.authUrl.includes(flow.start.handoffSecret), 'the handoff secret is never in a URL');
    assert.equal(flow.callbackStatus, 302);
    assert.equal(flow.loopback.origin, 'http://127.0.0.1:49152');
    assert.equal(flow.loopback.searchParams.get('nonce'), flow.nonce);
    const code = flow.loopback.searchParams.get('code')!;
    assert.ok(code && code.length >= 40);
    const tokenReq = idp.tokenRequests.at(-1)!;
    assert.equal(tokenReq.redirect_uri, `${base}/v1/auth/oauth/callback`);
    assert.ok(tokenReq.code_verifier && tokenReq.code_verifier.length >= 43, 'PKCE verifier sent by PocketBase');

    // The same provider redirect cannot be replayed.
    const replayCb = await fetch(flow.callbackUrl, { redirect: 'manual' });
    assert.equal(replayCb.status, 400);

    const id = installId();
    const ok = await post('/v1/auth/exchange', { code, handoffSecret: flow.start.handoffSecret, installId: id, deviceName: 'Desk' });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.equal(ok.body.user.email, 'alice@example.test');
    assert.ok(ok.body.pbToken, 'the user gets their own PocketBase token for profile changes');
    assert.equal((await get('/v1/catalogue', ok.body.token)).status, 200);
    const replay = await post('/v1/auth/exchange', { code, handoffSecret: flow.start.handoffSecret, installId: id, deviceName: 'Desk' });
    assert.equal(replay.status, 400);
    assert.equal(replay.body.error.code, 'invalid_code');
    const stored = await tdb!.db.query("SELECT user_token_sealed, status FROM auth_handoffs WHERE status = 'consumed'");
    assert.ok(stored.rows.every((r) => r.user_token_sealed === null), 'no PocketBase token is left in the database');
  });

  test('a stolen code is useless without the secret, and a wrong secret burns it', async (t) => {
    if (skip(t)) return;
    const flow = await browserSignIn({ sub: 'oidc-bob', email: 'bob@example.test' });
    const code = flow.loopback.searchParams.get('code')!;
    const wrong = await post('/v1/auth/exchange', { code, handoffSecret: 'x'.repeat(43), installId: installId(), deviceName: 'Thief' });
    assert.equal(wrong.status, 400);
    const right = await post('/v1/auth/exchange', { code, handoffSecret: flow.start.handoffSecret, installId: installId(), deviceName: 'Desk' });
    assert.equal(right.status, 400, 'burnt after the failed attempt');
  });

  test('an expired code is refused', async (t) => {
    if (skip(t)) return;
    const flow = await browserSignIn({ sub: 'oidc-carol', email: 'carol@example.test' });
    await tdb!.db.query("UPDATE auth_handoffs SET result_expires_at = now() - interval '1 second' WHERE status = 'completed'");
    const r = await post('/v1/auth/exchange', { code: flow.loopback.searchParams.get('code')!, handoffSecret: flow.start.handoffSecret, installId: installId(), deviceName: 'Desk' });
    assert.equal(r.status, 400);
  });

  test('an unknown or forged state is refused without redirecting anywhere', async (t) => {
    if (skip(t)) return;
    const r = await fetch(`${base}/v1/auth/oauth/callback?code=abc&state=forged-state-value`, { redirect: 'manual' });
    assert.equal(r.status, 400);
    assert.equal(r.headers.get('location'), null);
    assert.match(r.headers.get('content-security-policy') ?? '', /default-src 'none'/);
  });

  test('provider identity without a verified email does not sign in', async (t) => {
    if (skip(t)) return;
    const flow = await browserSignIn({ sub: 'oidc-unverified', email: 'unverified-oauth@example.test', emailVerified: false });
    const err = flow.loopback.searchParams.get('error');
    const code = flow.loopback.searchParams.get('code');
    if (code) {
      // PocketBase marked the account verified on its own: then sign-in is legitimately allowed.
      const u = await pbt!.su('GET', `/api/collections/users/records?filter=${encodeURIComponent("email='unverified-oauth@example.test'")}`);
      assert.equal(u.body.items[0]?.verified, true);
    } else assert.ok(err === 'email_not_verified' || err === 'sign_in_failed', String(err));
  });

  test('linking Google/GitHub to the signed-in account uses PocketBase _externalAuths, with ownership checks', async (t) => {
    if (skip(t)) return;
    await pbt!.createUser('linker@example.test', 'linker-pass-1');
    const s = await passwordSignIn('linker@example.test', 'linker-pass-1');
    // Linking needs the signed-in device and the user's own PocketBase token for the same account.
    const other = await pbt!.createUser('someone@example.test', 'someone-pass-1');
    const otherToken = await pbt!.passwordToken('someone@example.test', 'someone-pass-1');
    const mismatch = await post('/v1/auth/oauth/start', { provider: 'oidc', purpose: 'link', loopbackPort: 49153, loopbackNonce: 'n'.repeat(20), pbToken: otherToken }, s.body.token);
    assert.equal(mismatch.status, 403);
    assert.ok(other);
    const noDevice = await post('/v1/auth/oauth/start', { provider: 'oidc', purpose: 'link', loopbackPort: 49153, loopbackNonce: 'n'.repeat(20), pbToken: s.pbToken });
    assert.equal(noDevice.status, 401);

    const flow = await browserSignIn({ sub: 'oidc-linker', email: 'linker-gh@example.test' }, { purpose: 'link', token: s.body.token, pbToken: s.pbToken });
    const code = flow.loopback.searchParams.get('code')!;
    assert.ok(code, flow.loopback.toString());
    // Another device cannot use the link code.
    const elsewhere = await legacyDevice();
    assert.equal((await post('/v1/auth/exchange', { code, handoffSecret: flow.start.handoffSecret }, elsewhere.token)).status, 400);
    const flow2 = await browserSignIn({ sub: 'oidc-linker', email: 'linker-gh@example.test' }, { purpose: 'link', token: s.body.token, pbToken: s.pbToken });
    const linked = await post('/v1/auth/exchange', { code: flow2.loopback.searchParams.get('code')!, handoffSecret: flow2.start.handoffSecret }, s.body.token);
    assert.equal(linked.status, 200, JSON.stringify(linked.body));
    const acct = await get('/v1/account', s.body.token);
    assert.equal(acct.status, 200);
    assert.deepEqual(acct.body.identities.map((i: any) => i.provider), ['oidc']);

    // The same provider identity cannot be attached to a second account.
    await pbt!.createUser('thief@example.test', 'thief-pass-123');
    const thief = await passwordSignIn('thief@example.test', 'thief-pass-123');
    const steal = await browserSignIn({ sub: 'oidc-linker', email: 'linker-gh@example.test' }, { purpose: 'link', token: thief.body.token, pbToken: thief.pbToken });
    assert.equal(steal.loopback.searchParams.get('code'), null);
    assert.ok(steal.loopback.searchParams.get('error'));
    const thiefAcct = await get('/v1/account', thief.body.token);
    assert.deepEqual(thiefAcct.body.identities, []);

    // Unlinking is the user's own call to PocketBase; its rules only allow their own records.
    const ext = acct.body.identities[0].id;
    assert.notEqual((await pbt!.api('DELETE', `/api/collections/_externalAuths/records/${ext}`, undefined, thief.pbToken)).status, 204);
    assert.equal((await pbt!.api('DELETE', `/api/collections/_externalAuths/records/${ext}`, undefined, s.pbToken)).status, 204);
    assert.deepEqual((await get('/v1/account', s.body.token)).body.identities, []);
  });
});

describe('device tokens', () => {
  test('rotation, grace period, reuse detection and expiry', async (t) => {
    if (skip(t)) return;
    await pbt!.createUser('rotate@example.test', 'rotate-pass-1');
    const s = await passwordSignIn('rotate@example.test', 'rotate-pass-1');
    const r = await post('/v1/auth/refresh', {}, s.body.token);
    assert.equal(r.status, 200);
    assert.notEqual(r.body.token, s.body.token);
    assert.equal((await get('/v1/catalogue', r.body.token)).status, 200);
    assert.equal((await get('/v1/catalogue', s.body.token)).status, 200, 'previous token within the grace period');
    await tdb!.db.query("UPDATE devices SET prev_token_grace_until = now() - interval '1 second' WHERE id = $1", [s.body.deviceId]);
    const reuse = await get('/v1/catalogue', s.body.token);
    assert.equal(reuse.status, 401);
    assert.equal(reuse.body.error.code, 'session_revoked');
    assert.equal((await get('/v1/catalogue', r.body.token)).status, 401, 'reuse of an old token ends the whole session');

    const s2 = await passwordSignIn('rotate@example.test', 'rotate-pass-1');
    await tdb!.db.query("UPDATE devices SET token_expires_at = now() - interval '1 second' WHERE id = $1", [s2.body.deviceId]);
    const exp = await get('/v1/catalogue', s2.body.token);
    assert.equal(exp.status, 401);
    assert.equal(exp.body.error.code, 'token_expired');
  });

  test('logout revokes the token and frees the installation for an anonymous registration', async (t) => {
    if (skip(t)) return;
    await pbt!.createUser('logout@example.test', 'logout-pass-1');
    const s = await passwordSignIn('logout@example.test', 'logout-pass-1');
    assert.equal((await post('/v1/auth/logout', {}, s.body.token)).status, 200);
    assert.equal((await get('/v1/catalogue', s.body.token)).status, 401);
    assert.equal((await post('/v1/auth/logout', {}, s.body.token)).status, 200, 'idempotent');
    const anon = await post('/v1/devices/register', { installId: s.installId, deviceName: 'Laptop' });
    assert.equal(anon.status, 201);
    assert.notEqual(anon.body.deviceId, s.body.deviceId);
  });

  test("a user cannot see or end another user's devices; legacy tokens cannot use account endpoints", async (t) => {
    if (skip(t)) return;
    await pbt!.createUser('owner-a@example.test', 'owner-a-pass');
    await pbt!.createUser('owner-b@example.test', 'owner-b-pass');
    const a = await passwordSignIn('owner-a@example.test', 'owner-a-pass');
    const b = await passwordSignIn('owner-b@example.test', 'owner-b-pass');
    const r = await post(`/v1/account/devices/${b.body.deviceId}/sign-out`, {}, a.body.token);
    assert.equal(r.status, 404);
    assert.equal((await get('/v1/catalogue', b.body.token)).status, 200);
    const acct = await get('/v1/account', a.body.token);
    assert.ok(acct.body.devices.every((d: any) => d.id !== b.body.deviceId));
    const legacy = await legacyDevice();
    assert.equal((await get('/v1/account', legacy.token)).status, 403);
    assert.equal((await post('/v1/account/delete', { password: 'x' }, legacy.token)).status, 403);
    assert.equal((await get('/admin/api/users')).status, 401, 'admin user list needs the owner session');
  });
});

describe('require sign-in for central AI', () => {
  test('off by default; when on, every central AI endpoint refuses legacy devices but updates still work', async (t) => {
    if (skip(t)) return;
    const legacy = await legacyDevice();
    await pbt!.createUser('central@example.test', 'central-pass-1');
    const s = await passwordSignIn('central@example.test', 'central-pass-1');
    await setRequireLogin(true);
    try {
      const central: Array<[string, string, unknown?]> = [
        ['GET', '/v1/catalogue'],
        ['GET', '/v1/catalogue/status'],
        ['GET', `/v1/models/${crypto.randomUUID()}`],
        ['GET', '/v1/usage'],
        ['POST', '/v1/chat/completions', { model: 'x', messages: [{ role: 'user', content: 'hi' }] }],
        ['POST', '/v1/memory/sync', { changes: [] }],
      ];
      for (const [method, p, body] of central) {
        const r = method === 'GET' ? await get(p, legacy.token) : await post(p, body, legacy.token);
        assert.equal(r.status, 403, `${method} ${p}`);
        assert.equal(r.body.error.code, 'login_required', `${method} ${p}`);
        const signed = method === 'GET' ? await get(p, s.body.token) : await post(p, body, s.body.token);
        assert.notEqual(signed.status, 403, `${method} ${p} for a signed-in device`);
        assert.notEqual(signed.status, 401, `${method} ${p} for a signed-in device`);
      }
      assert.equal((await get('/v1/updates/check?current=0.1.0', legacy.token)).status, 200, 'updater keeps working');
      const info = await get('/v1/device', legacy.token);
      assert.equal(info.status, 200);
      assert.equal(info.body.loginRequired, true);
    } finally {
      await setRequireLogin(false);
    }
    assert.equal((await get('/v1/catalogue', legacy.token)).status, 200);
  });
});

describe('account checks, blocking and deletion', () => {
  test('a deleted or unverified PocketBase account loses access at the next re-check', async (t) => {
    if (skip(t)) return;
    const id = await pbt!.createUser('vanish@example.test', 'vanish-pass-1');
    const s = await passwordSignIn('vanish@example.test', 'vanish-pass-1');
    await pbt!.su('PATCH', `/api/collections/users/records/${id}`, { verified: false });
    await tdb!.db.query("UPDATE devices SET user_checked_at = now() - interval '1 hour' WHERE id = $1", [s.body.deviceId]);
    const unv = await get('/v1/catalogue', s.body.token);
    assert.equal(unv.status, 403);
    assert.equal(unv.body.error.code, 'email_not_verified');
    await pbt!.su('DELETE', `/api/collections/users/records/${id}`);
    const gone = await get('/v1/catalogue', s.body.token);
    assert.equal(gone.status, 401);
    await accountMaintenance(deps);
    const state = await tdb!.db.query('SELECT status FROM app_users WHERE user_id = $1', [id]);
    assert.equal(state.rows[0].status, 'deleted');
  });

  test('while PocketBase is unreachable a recently checked user keeps working for a bounded time', async (t) => {
    if (skip(t)) return;
    await pbt!.createUser('offline@example.test', 'offline-pass-1');
    const s = await passwordSignIn('offline@example.test', 'offline-pass-1');
    pbOutage = () => true;
    try {
      await tdb!.db.query("UPDATE devices SET user_checked_at = now() - interval '1 hour' WHERE id = $1", [s.body.deviceId]);
      assert.equal((await get('/v1/catalogue', s.body.token)).status, 200);
      await tdb!.db.query("UPDATE devices SET user_checked_at = now() - interval '25 hours' WHERE id = $1", [s.body.deviceId]);
      const r = await get('/v1/catalogue', s.body.token);
      assert.equal(r.status, 503);
      assert.equal(r.body.error.code, 'accounts_unavailable');
    } finally {
      pbOutage = null;
    }
    assert.equal((await get('/v1/catalogue', s.body.token)).status, 200);
  });

  test('the owner blocks and unblocks an account from the admin API', async (t) => {
    if (skip(t)) return;
    const id = await pbt!.createUser('blocked@example.test', 'blocked-pass-1', { name: 'Blocked User' });
    const s = await passwordSignIn('blocked@example.test', 'blocked-pass-1');
    const o = await owner();
    const list = await o.call('GET', '/admin/api/users?search=blocked%40example.test');
    assert.equal(list.status, 200);
    assert.equal(list.body.users[0].email, 'blocked@example.test');
    assert.equal(list.body.users[0].signedInDevices, 1);
    assert.equal((await o.call('POST', `/admin/api/users/${id}/block`)).status, 403, 'needs password confirmation');
    await o.reauth();
    assert.equal((await o.call('POST', `/admin/api/users/${id}/block`)).status, 200);
    assert.equal((await get('/v1/catalogue', s.body.token)).status, 401);
    const again = await passwordSignIn('blocked@example.test', 'blocked-pass-1');
    assert.equal(again.status, 403);
    assert.equal(again.body.error.code, 'account_blocked');
    assert.equal((await o.call('POST', `/admin/api/users/${id}/unblock`)).status, 200);
    assert.equal((await passwordSignIn('blocked@example.test', 'blocked-pass-1')).status, 200);
  });

  test('self-service deletion needs re-authentication and removes the account everywhere', async (t) => {
    if (skip(t)) return;
    const id = await pbt!.createUser('delete-me@example.test', 'delete-me-pass');
    const s = await passwordSignIn('delete-me@example.test', 'delete-me-pass');
    const second = await passwordSignIn('delete-me@example.test', 'delete-me-pass');
    await tdb!.db.query(
      `INSERT INTO memory_entries (device_id, client_key, scope, kind, content, source, confidence, client_updated_at) VALUES ($1, $2, 'global', 'fact', 'my private fact', 'user', 1, 1)`,
      [s.body.deviceId, 'm'.repeat(20)],
    );
    const wrong = await post('/v1/account/delete', { password: 'not-my-password' }, s.body.token);
    assert.equal(wrong.status, 401);
    const del = await post('/v1/account/delete', { password: 'delete-me-pass' }, s.body.token);
    assert.equal(del.status, 200, JSON.stringify(del.body));
    assert.equal(del.body.status, 'done');
    assert.equal((await pbt!.su('GET', `/api/collections/users/records/${id}`)).status, 404);
    assert.equal((await get('/v1/catalogue', s.body.token)).status, 401);
    assert.equal((await get('/v1/catalogue', second.body.token)).status, 401);
    const mem = await tdb!.db.query('SELECT count(*)::int AS n FROM memory_entries WHERE device_id = $1', [s.body.deviceId]);
    assert.equal(mem.rows[0].n, 0);
    const linked = await tdb!.db.query('SELECT count(*)::int AS n FROM devices WHERE user_id = $1', [id]);
    assert.equal(linked.rows[0].n, 0);
  });

  test('an interrupted deletion is recorded and finished by the background job', async (t) => {
    if (skip(t)) return;
    const id = await pbt!.createUser('interrupted@example.test', 'interrupted-pass');
    const s = await passwordSignIn('interrupted@example.test', 'interrupted-pass');
    pbOutage = (url, method) => method === 'DELETE' && url.includes('/records/');
    let r;
    try {
      r = await post('/v1/account/delete', { password: 'interrupted-pass' }, s.body.token);
    } finally {
      pbOutage = null;
    }
    assert.equal(r.status, 202);
    assert.equal(r.body.status, 'pending');
    const st = await tdb!.db.query('SELECT status, deletion_step, deletion_error FROM app_users WHERE user_id = $1', [id]);
    assert.equal(st.rows[0].status, 'deleting');
    assert.equal(st.rows[0].deletion_step, 'identity');
    assert.ok(st.rows[0].deletion_error);
    assert.equal((await get('/v1/catalogue', s.body.token)).status, 401, 'access is gone before the identity is deleted');
    assert.equal((await passwordSignIn('interrupted@example.test', 'interrupted-pass')).status, 403, 'cannot sign back in mid-deletion');
    await accountMaintenance(deps);
    assert.equal((await pbt!.su('GET', `/api/collections/users/records/${id}`)).status, 404);
    const done = await tdb!.db.query('SELECT status FROM app_users WHERE user_id = $1', [id]);
    assert.equal(done.rows[0].status, 'deleted');
  });

  test('OAuth-only users re-authenticate in the browser to delete their account', async (t) => {
    if (skip(t)) return;
    const flow = await browserSignIn({ sub: 'oidc-dave', email: 'dave@example.test' });
    const s = await post('/v1/auth/exchange', { code: flow.loopback.searchParams.get('code')!, handoffSecret: flow.start.handoffSecret, installId: installId(), deviceName: 'Desk' });
    assert.equal(s.status, 200);
    // A different person's browser sign-in cannot authorize the deletion.
    const wrongUser = await browserSignIn({ sub: 'oidc-eve', email: 'eve@example.test' }, { purpose: 'reauth', token: s.body.token });
    assert.equal(wrongUser.loopback.searchParams.get('error'), 'account_mismatch');
    const re = await browserSignIn({ sub: 'oidc-dave', email: 'dave@example.test' }, { purpose: 'reauth', token: s.body.token });
    const del = await post('/v1/account/delete', { code: re.loopback.searchParams.get('code')!, handoffSecret: re.start.handoffSecret }, s.body.token);
    assert.equal(del.status, 200, JSON.stringify(del.body));
    assert.equal((await get('/v1/catalogue', s.body.token)).status, 401);
  });
});

describe('servers without accounts', () => {
  test('sign-in endpoints answer 503 and the owner cannot require sign-in', async (t) => {
    if (skip(t)) return;
    const plain = createServer({ ...deps, pocketbase: null, config: { ...deps.config, pocketbase: null } });
    await new Promise<void>((r) => plain.listen(0, '127.0.0.1', r));
    const b = `http://127.0.0.1:${(plain.address() as AddressInfo).port}`;
    try {
      const cfg = (await (await fetch(`${b}/v1/auth/config`)).json()) as any;
      assert.equal(cfg.enabled, false);
      const s = await fetch(`${b}/v1/auth/session`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
      assert.equal(s.status, 503);
      const login = await fetch(`${b}/admin/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'owner@example.test', password: OWNER_PASSWORD }) });
      const cookie = (login.headers.get('set-cookie') ?? '').split(';')[0];
      const csrf = ((await login.json()) as any).csrfToken;
      const h = { cookie, 'x-csrf-token': csrf, 'content-type': 'application/json' };
      await fetch(`${b}/admin/api/auth/reauth`, { method: 'POST', headers: h, body: JSON.stringify({ password: OWNER_PASSWORD }) });
      const r = await fetch(`${b}/admin/api/settings`, { method: 'PATCH', headers: h, body: JSON.stringify({ requireLoginForCentralAi: true }) });
      assert.equal(r.status, 409);
    } finally {
      plain.closeAllConnections?.();
      await new Promise<void>((r) => plain.close(() => r()));
    }
  });
});

describe('email codes (OTP)', () => {
  test('account deletion accepts only a fresh email code of the same user; PocketBase locks out guessing', async (t) => {
    if (skip(t)) return;
    await pbt!.createUser('otp-a@example.test', 'otp-a-pass-1');
    await pbt!.createUser('otp-b@example.test', 'otp-b-pass-1');
    const a = await passwordSignIn('otp-a@example.test', 'otp-a-pass-1');
    // B's valid code cannot delete A.
    let mark = pbt!.mails.length;
    const otherReq = await pbt!.api('POST', '/api/collections/users/request-otp', { email: 'otp-b@example.test' });
    const otherCode = await pbt!.waitForOtp('otp-b@example.test', mark);
    const cross = await post('/v1/account/delete', { otpId: otherReq.body.otpId, otpCode: otherCode }, a.body.token);
    assert.equal(cross.status, 401);
    // Wrong guesses: refused, and PocketBase soon refuses further attempts.
    mark = pbt!.mails.length;
    const req = await pbt!.api('POST', '/api/collections/users/request-otp', { email: 'otp-a@example.test' });
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) statuses.push((await post('/v1/account/delete', { otpId: req.body.otpId, otpCode: String(10000000 + i) }, a.body.token)).status);
    assert.ok(statuses.every((s) => s === 401 || s === 429), statuses.join(','));
    assert.equal((await get('/v1/catalogue', a.body.token)).status, 200, 'nothing was deleted');
    assert.ok(await pbt!.waitForOtp('otp-a@example.test', mark));
  });
});
