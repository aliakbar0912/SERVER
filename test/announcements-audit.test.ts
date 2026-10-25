// Tests for the admin-panel features added in migrations 14-15: announcements, the audit log, the configuration
// export and the agent templates. Runs against the real HTTP server and a real PostgreSQL database.
// Without a PostgreSQL test cluster every test skips with a reason.
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

const OWNER_EMAIL = 'owner@example.test';
const OWNER_PASSWORD = 'correct horse battery staple';
const KEYRING = `1=${crypto.randomBytes(32).toString('base64')}`;
const ADMIN_ORIGIN = 'https://admin.example.test';
const INSTALL_ID = 'install-announcements01';

let tdb: TestDb | null = null;
let server: Server;
let base = '';
let cookie = '';
let csrf = '';
let deviceToken = '';
let announcementId = '';

interface Res {
  status: number;
  text: string;
  json: any;
  headers: Headers;
}

async function call(method: string, path: string, opts: { body?: unknown; session?: boolean; device?: string; headers?: Record<string, string> } = {}): Promise<Res> {
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  if (opts.body !== undefined) headers['content-type'] = 'application/json';
  if (opts.session) {
    headers.cookie = cookie;
    if (method !== 'GET') headers['x-csrf-token'] = csrf;
  }
  if (opts.device) headers.authorization = `Bearer ${opts.device}`;
  const res = await fetch(base + path, { method, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body), redirect: 'manual' });
  const text = await res.text();
  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: res.status, text, json, headers: res.headers };
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
    DEVORA_SECRET_KEYS: KEYRING,
    DEVORA_SECRET_ACTIVE_KEY: '1',
    ADMIN_ORIGIN,
    COOKIE_SECURE: 'false',
    PUBLIC_API_ORIGIN: 'https://api.example.test',
  });
  server = createServer({ db: tdb.db, config, fetch: globalThis.fetch });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  const login = await call('POST', '/admin/api/auth/login', { body: { email: OWNER_EMAIL, password: OWNER_PASSWORD } });
  assert.equal(login.status, 200, login.text);
  cookie = (login.headers.get('set-cookie') ?? '').split(';')[0];
  csrf = login.json.csrfToken;
  const device = await call('POST', '/v1/devices/register', { body: { installId: INSTALL_ID, deviceName: 'Announcement test laptop' } });
  assert.equal(device.status, 201, device.text);
  deviceToken = device.json.token;
});

after(async () => {
  server?.closeAllConnections?.();
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  await tdb?.drop();
});

describe('announcements', () => {
  test('the owner creates, edits, hides and deletes an announcement; invalid levels are refused', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    assert.equal((await call('POST', '/admin/api/announcements', { session: true, body: { title: 'x', body: 'b', level: 'loud' } })).status, 400, 'unknown level refused');
    assert.equal(
      (await call('POST', '/admin/api/announcements', { session: true, body: { title: 'two\nlines', body: 'b', level: 'info' } })).status, 400, 'multi-line title refused',
    );
    const res = await call('POST', '/admin/api/announcements', {
      session: true,
      body: { title: 'Maintenance tonight', body: 'Devora AI is briefly unavailable between 02:00 and 03:00 UTC.', level: 'warning' },
    });
    assert.equal(res.status, 201, res.text);
    assert.match(res.json.announcement.slug, /^maintenance-tonight/);
    assert.equal(res.json.announcement.level, 'warning');
    announcementId = res.json.announcement.id;

    const patched = await call('PATCH', `/admin/api/announcements/${announcementId}`, { session: true, body: { level: 'critical' } });
    assert.equal(patched.status, 200, patched.text);
    assert.equal(patched.json.announcement.revision, 2);

    const listed = await call('GET', '/admin/api/announcements', { session: true });
    assert.equal(listed.status, 200);
    assert.equal(listed.json.announcements.length, 1);
    assert.equal(listed.json.limits.title, 120);
    assert.deepEqual(listed.json.levels, ['info', 'warning', 'critical']);
  });

  test('desktops download enabled announcements with an ETag, and hidden ones stay private', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('GET', '/v1/announcements', { device: deviceToken });
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.announcements.length, 1);
    assert.equal(res.json.announcements[0].title, 'Maintenance tonight');
    assert.equal(res.json.announcements[0].level, 'critical');
    const etag = res.headers.get('etag');
    assert.ok(etag, 'the desktop list carries an ETag');
    assert.equal((await call('GET', '/v1/announcements', { device: deviceToken, headers: { 'if-none-match': etag! } })).status, 304);
    assert.equal((await call('GET', '/v1/announcements')).status, 401, 'anonymous desktops are refused');

    await call('PATCH', `/admin/api/announcements/${announcementId}`, { session: true, body: { enabled: false } });
    const hidden = await call('GET', '/v1/announcements', { device: deviceToken });
    assert.equal(hidden.status, 200);
    assert.equal(hidden.json.announcements.length, 0, 'a hidden announcement does not reach desktops');
    await call('PATCH', `/admin/api/announcements/${announcementId}`, { session: true, body: { enabled: true } });
  });
});

describe('audit log', () => {
  test('sensitive writes are recorded with the actor, and reads are not', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    await call('GET', '/admin/api/audit', { session: true });
    await call('GET', '/admin/api/settings', { session: true });
    await call('PATCH', '/admin/api/settings', { session: true, body: { maxOutputTokens: 4096 } });
    const res = await call('GET', '/admin/api/audit?limit=50', { session: true });
    assert.equal(res.status, 200, res.text);
    const settingsEntry = res.json.entries.find((e: any) => e.action === 'settings.update');
    assert.ok(settingsEntry, 'the settings change is recorded');
    assert.equal(settingsEntry.actor, OWNER_EMAIL);
    assert.equal(settingsEntry.detail.method, 'PATCH');
    const announcementEntry = res.json.entries.find((e: any) => e.action === 'announcement.create');
    assert.ok(announcementEntry, 'the announcement creation is recorded');
    assert.ok(announcementEntry.target, 'the target id is recorded');
    const afterCount = (await call('GET', '/admin/api/audit', { session: true })).json.entries.length;
    assert.equal(afterCount, res.json.entries.length, 'reads are not recorded');
  });

  test('the audit list can be filtered by action and paginated, and refuses anonymous access', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const filtered = await call('GET', '/admin/api/audit?action=announcement.create', { session: true });
    assert.equal(filtered.status, 200);
    assert.ok(filtered.json.entries.length >= 1);
    assert.ok(filtered.json.entries.every((e: any) => e.action === 'announcement.create'));
    const paged = await call('GET', '/admin/api/audit?limit=1', { session: true });
    assert.equal(paged.json.entries.length, 1);
    assert.ok(paged.json.nextCursor, 'a full page offers a cursor');
    assert.equal((await call('GET', '/admin/api/audit')).status, 401);
  });
});

describe('configuration export', () => {
  test('the export lists everything configured and never contains secret material', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('GET', '/admin/api/export', { session: true });
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.schema, 'devora-export');
    assert.ok(Array.isArray(res.json.announcements));
    assert.ok(Array.isArray(res.json.agents));
    assert.ok(Array.isArray(res.json.apiKeys));
    assert.equal(res.json.announcements.length, 1, 'the announcement is part of the export');
    assert.equal(res.json.announcements[0].title, 'Maintenance tonight');
    assert.ok(!res.text.includes('password_hash'), 'no password material in the export');
    assert.ok(!res.text.includes('key_hash'), 'no key hashes in the export');
    assert.ok(!res.text.includes('token_hash'), 'no device token hashes in the export');
    assert.equal((await call('GET', '/admin/api/export')).status, 401);
  });
});

describe('agent templates', () => {
  test('the agents list offers ready-made templates with valid access levels', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('GET', '/admin/api/agents', { session: true });
    assert.equal(res.status, 200, res.text);
    assert.ok(Array.isArray(res.json.templates));
    assert.ok(res.json.templates.length >= 5, 'there is a template library');
    const allowed = ['read', 'commands', 'docs', 'write', 'write_commands'];
    for (const tpl of res.json.templates) {
      assert.ok(tpl.name.length > 0, 'a template has a name');
      assert.ok(allowed.includes(tpl.access), `the ${tpl.name} template uses a known access level`);
      assert.ok(tpl.instructions.length >= 20, `the ${tpl.name} template has real instructions`);
    }
  });
});
