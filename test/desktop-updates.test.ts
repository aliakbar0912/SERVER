// End to end: a release uploaded and published through the admin API reaches the desktop app's updater, which downloads
// and verifies it from the real server. This is the same code path the installed app uses.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { createTestDb, SKIP_NO_PG, type TestDb } from './helpers.ts';
import { loadConfig } from '../src/config.ts';
import { createServer } from '../src/app.ts';
import { hashPassword } from '../src/crypto.ts';
import { loadMigrations, migrateUp } from '../src/db/migrate.ts';
import { Updater, type UpdateState } from '../../src/core/updates/updater.ts';

const PASSWORD = 'correct horse battery staple';
let tdb: TestDb | null = null;
let server: Server;
let base = '';

before(async () => {
  tdb = await createTestDb();
  if (!tdb) return;
  await migrateUp(tdb.db, loadMigrations());
  await tdb.db.query('INSERT INTO owners (email, password_hash) VALUES ($1, $2)', ['owner@example.test', await hashPassword(PASSWORD)]);
  const pw = encodeURIComponent(tdb.config.password);
  server = createServer({
    db: tdb.db,
    config: loadConfig({
      DEVORA_ENV: 'development',
      DATABASE_URL: `postgres://${tdb.config.user}:${pw}@${tdb.config.host}:${tdb.config.port}/${tdb.config.database}`,
      DEVORA_SECRET_KEYS: `1=${crypto.randomBytes(32).toString('base64')}`,
      DEVORA_SECRET_ACTIVE_KEY: '1',
      ADMIN_ORIGIN: 'https://admin.example.test',
      COOKIE_SECURE: 'false',
    }),
    fetch: globalThis.fetch,
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  server?.closeAllConnections?.();
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  await tdb?.drop();
});

test('admin publishes, the desktop updater downloads and verifies, the rollout view sees the device', async (t) => {
  if (!tdb) return t.skip(SKIP_NO_PG);
  const j = (r: Response) => r.json() as Promise<any>;
  const login = await fetch(`${base}/admin/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'owner@example.test', password: PASSWORD }) });
  const cookie = (login.headers.get('set-cookie') ?? '').split(';')[0];
  const csrf = (await j(login)).csrfToken;
  const owner = (method: string, p: string, body?: unknown, raw?: Buffer) =>
    fetch(base + p, { method, headers: { cookie, 'x-csrf-token': csrf, 'content-type': raw ? 'application/octet-stream' : 'application/json' }, body: raw ?? (body === undefined ? undefined : JSON.stringify(body)) });

  const installer = Buffer.concat([Buffer.from('MZ'), crypto.randomBytes(5 * 1024 * 1024)]);
  const sha = crypto.createHash('sha256').update(installer).digest('hex');
  const created = await j(await owner('POST', '/admin/api/releases', { version: '1.0.0', notes: 'First stable release' }));
  const id = created.release.id;
  const chunk = created.chunkBytes;
  for (let seq = 0; seq * chunk < installer.length; seq++) assert.equal((await owner('PUT', `/admin/api/releases/${id}/chunks/${seq}`, undefined, installer.subarray(seq * chunk, (seq + 1) * chunk))).status, 200);
  assert.equal((await owner('POST', `/admin/api/releases/${id}/complete`, { sha256: sha })).status, 200);
  assert.equal((await owner('POST', '/admin/api/auth/reauth', { password: PASSWORD })).status, 200);
  assert.equal((await owner('PATCH', `/admin/api/releases/${id}`, { status: 'published' })).status, 200);

  const reg = await j(await fetch(`${base}/v1/devices/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ installId: 'install-e2e-updates-01', deviceName: 'Desk' }) }));
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devora-upd-e2e-'));
  const installed: string[] = [];
  const states: UpdateState[] = [];
  const updater = new Updater({
    appVersion: '0.9.0',
    dataDir,
    access: () => ({ origin: base, token: reg.token }),
    emit: (s) => states.push(s),
    log: () => undefined,
    install: async (f) => {
      installed.push(f);
    },
  });
  const checked = await updater.check();
  assert.equal(checked.status, 'available', checked.error);
  assert.equal(checked.offer?.version, '1.0.0');
  assert.equal(checked.offer?.notes, 'First stable release');
  const done = await updater.download();
  assert.equal(done.status, 'ready', done.error);
  assert.ok(states.some((s) => s.status === 'downloading' && s.received > 0), 'progress is reported');
  await updater.install();
  assert.ok(fs.readFileSync(installed[0]).equals(installer));

  const list = await j(await owner('GET', '/admin/api/releases'));
  assert.equal(list.releases[0].downloads, 1);
  assert.deepEqual(list.adoption, [{ version: '0.9.0', devices: 1 }]);
});
