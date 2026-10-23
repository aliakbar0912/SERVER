// Desktop updates published from the admin site: create a release, upload the installer in pieces, publish (with a password
// confirmation), and the desktop side: check, download, verify. Also the rollout view (versions reported by desktops).
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { createTestDb, SKIP_NO_PG, type TestDb } from './helpers.ts';
import { loadConfig } from '../src/config.ts';
import { createServer } from '../src/app.ts';
import { hashPassword } from '../src/crypto.ts';
import { loadMigrations, migrateUp } from '../src/db/migrate.ts';
import { compareVersions } from '../src/modules/releases.ts';

const OWNER_EMAIL = 'owner@example.test';
const OWNER_PASSWORD = 'correct horse battery staple';
const ADMIN_ORIGIN = 'https://admin.example.test';

let tdb: TestDb | null = null;
let server: Server;
let base = '';
let cookie = '';
let csrf = '';
let device = '';

async function call(method: string, path: string, opts: { body?: unknown; raw?: Buffer; session?: boolean; device?: string; headers?: Record<string, string> } = {}) {
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  if (opts.body !== undefined) headers['content-type'] = 'application/json';
  if (opts.raw) headers['content-type'] = 'application/octet-stream';
  if (opts.session) {
    headers.cookie = cookie;
    if (method !== 'GET') headers['x-csrf-token'] = csrf;
  }
  if (opts.device) headers.authorization = `Bearer ${opts.device}`;
  const res = await fetch(base + path, { method, headers, body: opts.raw ?? (opts.body === undefined ? undefined : JSON.stringify(opts.body)) });
  const buf = Buffer.from(await res.arrayBuffer());
  let json: any = null;
  try {
    json = JSON.parse(buf.toString('utf8'));
  } catch {
    json = null;
  }
  return { status: res.status, json, buf, headers: res.headers };
}

before(async () => {
  tdb = await createTestDb();
  if (!tdb) return;
  await migrateUp(tdb.db, loadMigrations());
  await tdb.db.query('INSERT INTO owners (email, password_hash) VALUES ($1, $2)', [OWNER_EMAIL, await hashPassword(OWNER_PASSWORD)]);
  const pw = encodeURIComponent(tdb.config.password);
  const config = loadConfig({
    DEVORA_ENV: 'development',
    DATABASE_URL: `postgres://${tdb.config.user}:${pw}@${tdb.config.host}:${tdb.config.port}/${tdb.config.database}`,
    DEVORA_SECRET_KEYS: `1=${crypto.randomBytes(32).toString('base64')}`,
    DEVORA_SECRET_ACTIVE_KEY: '1',
    ADMIN_ORIGIN,
    COOKIE_SECURE: 'false',
  });
  server = createServer({ db: tdb.db, config, fetch: globalThis.fetch });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const login = await call('POST', '/admin/api/auth/login', { body: { email: OWNER_EMAIL, password: OWNER_PASSWORD } });
  cookie = (login.headers.get('set-cookie') ?? '').split(';')[0];
  csrf = login.json.csrfToken;
  const reg = await call('POST', '/v1/devices/register', { body: { installId: 'install-releases-0001', deviceName: 'Laptop' } });
  device = reg.json.token;
});

after(async () => {
  server?.closeAllConnections?.();
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  await tdb?.drop();
});

test('versions are ordered like semantic versions', () => {
  assert.equal(compareVersions('1.2.10', '1.2.9'), 1);
  assert.equal(compareVersions('1.2.0-beta', '1.2.0'), -1);
  assert.equal(compareVersions('2.0.0', '2.0.0'), 0);
  assert.equal(compareVersions('0.9.9', '1.0.0'), -1);
});

describe('desktop releases', () => {
  // A fake installer: starts with "MZ" like every Windows executable, and spans several upload pieces.
  const installer = Buffer.concat([Buffer.from('MZ'), crypto.randomBytes(9 * 1024 * 1024)]);
  const sha = crypto.createHash('sha256').update(installer).digest('hex');
  let id = '';

  test('the owner creates a release and uploads the installer in pieces', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const created = await call('POST', '/admin/api/releases', { session: true, body: { version: '0.2.0', notes: '## New\n- Faster agent', fileName: 'Devora-Setup-0.2.0.exe' } });
    assert.equal(created.status, 201, JSON.stringify(created.json));
    id = created.json.release.id;
    const chunk = created.json.chunkBytes as number;
    assert.equal((await call('POST', '/admin/api/releases', { session: true, body: { version: '0.2.0' } })).json.error.code, 'version_exists');
    assert.equal((await call('POST', '/admin/api/releases', { body: { version: '0.3.0' } })).status, 401, 'owners only');

    // Publishing before the upload is refused.
    assert.equal((await call('PATCH', `/admin/api/releases/${id}`, { session: true, body: { status: 'published' } })).json.error.code, 'upload_incomplete');

    const pieces = Math.ceil(installer.length / chunk);
    assert.ok(pieces >= 3);
    // Upload out of order and re-send one piece: the result is still the same file.
    for (const seq of [2, 0, 1, 1]) {
      const part = installer.subarray(seq * chunk, Math.min(installer.length, (seq + 1) * chunk));
      const r = await call('PUT', `/admin/api/releases/${id}/chunks/${seq}`, { session: true, raw: part });
      assert.equal(r.status, 200, JSON.stringify(r.json));
    }
    assert.equal((await call('POST', `/admin/api/releases/${id}/complete`, { session: true, body: { sha256: '0'.repeat(64) } })).json.error.code, 'checksum_mismatch');
    const done = await call('POST', `/admin/api/releases/${id}/complete`, { session: true, body: { sha256: sha } });
    assert.equal(done.status, 200, JSON.stringify(done.json));
    assert.equal(done.json.release.sha256, sha);
    assert.equal(done.json.release.fileSize, installer.length);
    assert.equal((await call('PUT', `/admin/api/releases/${id}/chunks/0`, { session: true, raw: Buffer.from('MZ') })).json.error.code, 'upload_closed');
  });

  test('a file that is not a Windows installer is refused', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const r = await call('POST', '/admin/api/releases', { session: true, body: { version: '0.1.5' } });
    await call('PUT', `/admin/api/releases/${r.json.release.id}/chunks/0`, { session: true, raw: Buffer.from('not an exe') });
    assert.equal((await call('POST', `/admin/api/releases/${r.json.release.id}/complete`, { session: true, body: {} })).json.error.code, 'not_an_installer');
    assert.equal((await call('DELETE', `/admin/api/releases/${r.json.release.id}`, { session: true })).status, 200);
  });

  test('nothing is offered until the release is published, and publishing needs the password', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const before = await call('GET', '/v1/updates/check?current=0.1.0', { device });
    assert.deepEqual(before.json, { update: null });
    const noReauth = await call('PATCH', `/admin/api/releases/${id}`, { session: true, body: { status: 'published' } });
    assert.equal(noReauth.json.error.code, 'reauth_required');
    assert.equal((await call('POST', '/admin/api/auth/reauth', { session: true, body: { password: OWNER_PASSWORD } })).status, 200);
    const pub = await call('PATCH', `/admin/api/releases/${id}`, { session: true, body: { status: 'published' } });
    assert.equal(pub.json.release.status, 'published');
    assert.ok(pub.json.release.publishedAt);
  });

  test('desktops are offered the update, download it and can verify it', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    assert.equal((await call('GET', '/v1/updates/check?current=0.1.0')).status, 401, 'a device token is required');
    const check = await call('GET', '/v1/updates/check?current=0.1.0', { device, headers: { 'x-devora-version': '0.1.0' } });
    assert.equal(check.json.update.version, '0.2.0');
    assert.equal(check.json.update.mandatory, false);
    assert.equal(check.json.update.sha256, sha);
    assert.equal(check.json.update.size, installer.length);
    assert.match(check.json.update.notes, /Faster agent/);
    assert.deepEqual((await call('GET', '/v1/updates/check?current=0.2.0', { device })).json, { update: null }, 'up to date');
    const dl = await call('GET', check.json.update.download, { device });
    assert.equal(dl.status, 200);
    assert.equal(dl.buf.length, installer.length);
    assert.equal(crypto.createHash('sha256').update(dl.buf).digest('hex'), sha);
    // The public desktop configuration announces the published version.
    const cfg = await call('GET', '/v1/client-config');
    assert.equal(cfg.json.desktop.latestVersion, '0.2.0');
    assert.equal(cfg.json.desktop.minVersion, null);
  });

  test('a mandatory release raises the minimum version; the rollout view counts reported versions and downloads', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    await call('POST', '/admin/api/auth/reauth', { session: true, body: { password: OWNER_PASSWORD } });
    const m = await call('PATCH', `/admin/api/releases/${id}`, { session: true, body: { mandatory: true } });
    assert.equal(m.json.release.mandatory, true);
    assert.equal((await call('GET', '/v1/updates/check?current=0.1.0', { device })).json.update.mandatory, true);
    assert.equal((await call('GET', '/v1/client-config')).json.desktop.minVersion, '0.2.0');
    const list = await call('GET', '/admin/api/releases', { session: true });
    const rel = list.json.releases.find((r: any) => r.id === id);
    assert.equal(rel.downloads, 1);
    assert.deepEqual(list.json.adoption, [{ version: '0.1.0', devices: 1 }]);
    // Unpublishing stops the offer at once.
    await call('PATCH', `/admin/api/releases/${id}`, { session: true, body: { status: 'draft' } });
    assert.deepEqual((await call('GET', '/v1/updates/check?current=0.1.0', { device })).json, { update: null });
    assert.equal((await call('GET', `/v1/updates/${id}/download`, { device })).status, 404);
  });

  test('a release can point to an external https download with its SHA-256', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    assert.equal((await call('POST', '/admin/api/releases', { session: true, body: { version: '0.4.0', externalUrl: 'https://downloads.example.test/Devora-Setup-0.4.0.exe' } })).json.error.code, 'invalid_request');
    const r = await call('POST', '/admin/api/releases', { session: true, body: { version: '0.4.0', externalUrl: 'https://downloads.example.test/Devora-Setup-0.4.0.exe', sha256: sha, fileSize: installer.length } });
    assert.equal(r.status, 201);
    await call('POST', '/admin/api/auth/reauth', { session: true, body: { password: OWNER_PASSWORD } });
    assert.equal((await call('PATCH', `/admin/api/releases/${r.json.release.id}`, { session: true, body: { status: 'published' } })).status, 200);
    const check = await call('GET', '/v1/updates/check?current=0.1.0', { device });
    assert.equal(check.json.update.version, '0.4.0');
    assert.equal(check.json.update.download, 'https://downloads.example.test/Devora-Setup-0.4.0.exe');
  });
});
