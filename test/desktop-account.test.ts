// End to end: the real desktop core (AppCore, CentralManager, AccountManager and the IPC dispatcher) against the real API
// server, a real PocketBase and PostgreSQL. The only test double is the identity provider behind PocketBase's "oidc"
// provider; the "browser" is this test following the redirects the system browser would follow.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net, { type AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { createTestDb, SKIP_NO_PG, type TestDb } from './helpers.ts';
import { startPocketBase, SKIP_NO_PB, type TestPocketBase } from './pocketbase-helper.ts';
import { startOidcMock, type OidcMock } from './oidc-mock.ts';
import { loadConfig } from '../src/config.ts';
import { createServer } from '../src/app.ts';
import { hashPassword } from '../src/crypto.ts';
import { loadMigrations, migrateUp } from '../src/db/migrate.ts';
import { AppCore } from '../../src/core/app-core.ts';
import { MemorySecretStore } from '../../src/core/secrets.ts';
import { dispatch } from '../../src/core/dispatcher.ts';
import { CENTRAL_TOKEN_KEY } from '../../src/core/central/config.ts';
import { ACCOUNT_PB_TOKEN_KEY } from '../../src/core/central/account.ts';

let tdb: TestDb | null = null;
let pbt: TestPocketBase | null = null;
let idp: OidcMock;
let server: Server;
let base = '';
const cores: AppCore[] = [];

before(async () => {
  tdb = await createTestDb();
  if (!tdb) return;
  pbt = await startPocketBase();
  if (!pbt) return;
  await migrateUp(tdb.db, loadMigrations());
  await tdb.db.query('INSERT INTO owners (email, password_hash) VALUES ($1, $2)', ['owner@example.test', await hashPassword('correct horse battery staple')]);
  idp = await startOidcMock();
  await pbt.su('PATCH', '/api/collections/users', {
    oauth2: { enabled: true, providers: [{ name: 'oidc', clientId: idp.clientId, clientSecret: idp.clientSecret, authURL: `${idp.url}/authorize`, tokenURL: `${idp.url}/token`, userInfoURL: `${idp.url}/userinfo`, pkce: true }] },
  });
  const port = await new Promise<number>((r) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => {
      const p = (s.address() as AddressInfo).port;
      s.close(() => r(p));
    });
  });
  base = `http://127.0.0.1:${port}`;
  server = createServer({
    db: tdb.db,
    config: loadConfig({
      DEVORA_ENV: 'development',
      DATABASE_URL: `postgres://${tdb.config.user}:${encodeURIComponent(tdb.config.password)}@${tdb.config.host}:${tdb.config.port}/${tdb.config.database}`,
      DEVORA_SECRET_KEYS: `1=${crypto.randomBytes(32).toString('base64')}`,
      DEVORA_SECRET_ACTIVE_KEY: '1',
      ADMIN_ORIGIN: 'https://admin.example.test',
      COOKIE_SECURE: 'false',
      PUBLIC_API_ORIGIN: base,
      POCKETBASE_URL: pbt.url,
      POCKETBASE_ADMIN_EMAIL: pbt.adminEmail,
      POCKETBASE_ADMIN_PASSWORD: pbt.adminPassword,
    }),
    fetch: globalThis.fetch,
  });
  await new Promise<void>((r) => server.listen(port, '127.0.0.1', r));
});

after(async () => {
  for (const c of cores) c.central.stopAutoSync();
  server?.closeAllConnections?.();
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  await idp?.close();
  await pbt?.stop();
  await tdb?.drop();
});

/** A desktop core whose "system browser" follows redirects: provider, our callback, then the 127.0.0.1 listener. */
function desktop(identity?: () => { sub: string; email: string }) {
  const secrets = new MemorySecretStore();
  const core = new AppCore({
    kind: 'harness',
    dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'devora-acct-')),
    appVersion: '1.2.3',
    electronVersion: null,
    secretStore: secrets,
    monacoAvailable: false,
    pickFolder: async () => null,
    saveTextFile: async () => null,
    openTextFile: async () => null,
    openExternal: async (url: string) => {
      if (identity) idp.setNextIdentity(identity());
      let next = url;
      for (let i = 0; i < 5; i++) {
        const r = await fetch(next, { redirect: 'manual' });
        const loc = r.headers.get('location');
        await r.arrayBuffer().catch(() => undefined);
        if (!loc) return;
        next = new URL(loc, next).toString();
      }
    },
    updates: { configured: false, reason: 'test' },
    centralConnection: { bootstrapUrl: base, bootstrapSource: 'user-file', trustedOrigins: [], connectTimeoutMs: 5000, configErrors: [] },
  } as any);
  cores.push(core);
  const call = async <T = any>(channel: string, payload?: unknown): Promise<T> => {
    const r = await dispatch(core, channel, payload);
    if (!r.ok) throw new Error(r.error);
    return r.data as T;
  };
  return { core, secrets, call };
}

const skip = (t: any) => (!tdb ? (t.skip(SKIP_NO_PG), true) : !pbt ? (t.skip(SKIP_NO_PB), true) : false);

test('desktop: email-code signup and sign-in claims the existing registration, tokens stay out of the renderer', async (t) => {
  if (skip(t)) return;
  const d = desktop();
  await d.core.centralRefresh();
  const legacyToken = d.secrets.get(CENTRAL_TOKEN_KEY);
  assert.ok(legacyToken, 'registered without an account, as before');

  const cfg = await d.call('account:config');
  assert.equal(cfg.enabled, true);
  assert.deepEqual(cfg.providers.map((p: any) => p.name), ['oidc']);

  assert.equal(cfg.otp, true, 'email codes are on');

  // IPC validation rejects bad input before it reaches the core.
  await assert.rejects(d.call('account:requestCode', { email: 'not-an-email' }), /Invalid request/);
  await assert.rejects(d.call('account:verifyCode', { email: 'desk@example.test', code: 'abc' }), /Invalid request/);
  // Sign up: name + email, then the code from the email. No password and no verification link.
  let mark = pbt!.mails.length;
  assert.deepEqual(await d.call('account:requestCode', { email: 'Desk@Example.test', name: 'Desk User', create: true }), { sent: true });
  const code = await pbt!.waitForOtp('desk@example.test', mark);
  await assert.rejects(d.call('account:verifyCode', { email: 'desk@example.test', code: '00000000' }), /not correct/);

  const deviceId = (await tdb!.db.query('SELECT id FROM devices WHERE token_hash = $1', [crypto.createHash('sha256').update(legacyToken!).digest('hex')])).rows[0].id;
  const status = await d.call('account:verifyCode', { email: 'desk@example.test', code });
  assert.equal(status.signedIn, true);
  assert.equal(status.user.email, 'desk@example.test');
  assert.ok(!JSON.stringify(status).includes(d.secrets.get(CENTRAL_TOKEN_KEY)!), 'no device token in IPC results');
  assert.ok(!JSON.stringify(status).includes(d.secrets.get(ACCOUNT_PB_TOKEN_KEY)!), 'no PocketBase token in IPC results');
  const row = (await tdb!.db.query('SELECT id, user_id FROM devices WHERE id = $1', [deviceId])).rows[0];
  assert.ok(row.user_id, 'the existing registration (and its memory) was claimed, not duplicated');
  assert.notEqual(d.secrets.get(CENTRAL_TOKEN_KEY), legacyToken);

  // Profile change goes to PocketBase with the user's own token.
  const renamed = await d.call('account:updateProfile', { name: 'Desk Renamed' });
  assert.equal(renamed.user.name, 'Desk Renamed');
  const details = await d.call('account:details');
  assert.equal(details.devices.filter((x: any) => x.current).length, 1);

  // Sign out: server session ends, local projects untouched, the computer reconnects as a new account-less installation.
  // An unknown address gets the same answer and no email (no account enumeration).
  mark = pbt!.mails.length;
  assert.deepEqual(await d.call('account:requestCode', { email: 'nobody@example.test' }), { sent: true });
  await new Promise((r) => setTimeout(r, 400));
  assert.equal(pbt!.mails.slice(mark).filter((m) => m.to.includes('nobody@example.test')).length, 0);

  const out = await d.call('account:signOut');
  assert.equal(out.signedIn, false);

  // Signing in again later uses a fresh code; the old one cannot be replayed.
  mark = pbt!.mails.length;
  await d.call('account:requestCode', { email: 'desk@example.test' });
  await assert.rejects(d.call('account:verifyCode', { email: 'desk@example.test', code }), /not correct/);
  const code2 = await pbt!.waitForOtp('desk@example.test', mark);
  assert.equal((await d.call('account:verifyCode', { email: 'desk@example.test', code: code2 })).signedIn, true);

  // Deleting the account is confirmed with a code sent to the account's own email.
  mark = pbt!.mails.length;
  assert.equal((await d.call('account:deletionCode')).email, 'desk@example.test');
  const delCode = await pbt!.waitForOtp('desk@example.test', mark);
  assert.equal((await d.call('account:delete', { code: delCode, confirmed: true })).status, 'done');
  const left = await pbt!.su('GET', `/api/collections/users/records?filter=${encodeURIComponent("email='desk@example.test'")}`);
  assert.equal(left.body.items.length, 0);
  const ended = (await tdb!.db.query('SELECT signed_out_reason FROM devices WHERE id = $1', [deviceId])).rows[0];
  assert.equal(ended.signed_out_reason, 'logout');
  assert.ok(d.core.centralStatus().enrolled, 'central access continues without an account while sign-in is optional');
});

test('desktop: Google/GitHub-style browser sign-in and account deletion with browser re-authentication', async (t) => {
  if (skip(t)) return;
  let who = { sub: 'desk-oidc-1', email: 'browser@example.test' };
  const d = desktop(() => who);
  await d.core.centralRefresh();
  await d.call('account:config');
  const s = await d.call('account:signInWithProvider', { provider: 'oidc' });
  assert.equal(s.signedIn, true);
  assert.equal(s.user.email, 'browser@example.test');
  assert.ok(d.secrets.get(ACCOUNT_PB_TOKEN_KEY), 'PocketBase token kept in the secret store for profile changes');
  const details = await d.call('account:details');
  assert.deepEqual(details.identities.map((i: any) => i.provider), ['oidc']);

  // Deleting with someone else's browser sign-in is refused; with the same identity it works.
  who = { sub: 'desk-oidc-other', email: 'other@example.test' };
  await assert.rejects(d.call('account:delete', { provider: 'oidc', confirmed: true }), /different account/);
  who = { sub: 'desk-oidc-1', email: 'browser@example.test' };
  const del = await d.call('account:delete', { provider: 'oidc', confirmed: true });
  assert.equal(del.status, 'done');
  assert.equal(d.secrets.get(ACCOUNT_PB_TOKEN_KEY), null);
  const gone = await pbt!.su('GET', `/api/collections/users/records?filter=${encodeURIComponent("email='browser@example.test'")}`);
  assert.equal(gone.body.items.length, 0);
});

test('desktop: when sign-in is required, local status says so; after sign-in Devora AI works; a server-side logout is picked up', async (t) => {
  if (skip(t)) return;
  await pbt!.createUser('required@example.test', 'required-pass-1');
  const d = desktop();
  await d.core.centralRefresh();
  await tdb!.db.query("UPDATE settings SET value = 'true' WHERE key = 'require_login_for_central_ai'");
  await new Promise((r) => setTimeout(r, 5200)); // the server caches the setting for 5 seconds
  try {
    await d.core.centralRefresh();
    assert.equal(d.core.centralStatus().loginRequired, true);
    assert.equal(d.core.centralStatus().enrolled, true, 'the device keeps its registration (updates keep working)');
    await d.call('account:config');
    const mark = pbt!.mails.length;
    await d.call('account:requestCode', { email: 'required@example.test' });
    await d.call('account:verifyCode', { email: 'required@example.test', code: await pbt!.waitForOtp('required@example.test', mark) });
    await d.core.centralRefresh();
    assert.equal(d.core.centralStatus().loginRequired, false);
    assert.equal(d.core.centralStatus().lastError, '');

    // Another device of the same user signs this one out: the desktop notices on its next sync.
    const details = await d.call('account:details');
    const me = details.devices.find((x: any) => x.current);
    await tdb!.db.query("UPDATE devices SET token_hash = 'ended', signed_out_at = now(), signed_out_reason = 'signed_out_remotely' WHERE id = $1", [me.id]);
    await d.core.centralRefresh();
    const st = await d.call('account:status');
    assert.equal(st.signedIn, false);
  } finally {
    await tdb!.db.query("UPDATE settings SET value = 'false' WHERE key = 'require_login_for_central_ai'");
  }
});
