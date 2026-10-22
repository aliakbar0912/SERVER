// Memory sync endpoint tests: device auth, idempotent upsert, last-write-wins, tombstones, pull cursor and guards.
// Uses the real HTTP server and a real PostgreSQL database (skipped without a local test cluster, like api.test.ts).
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

const KEYRING = `1=${crypto.randomBytes(32).toString('base64')}`;
const INSTALL_ID = 'install-0123456789abcdef';
const OWNER_EMAIL = 'owner@example.test';
const OWNER_PASSWORD = 'correct horse battery staple';

let tdb: TestDb | null = null;
let server: Server;
let base = '';
let deviceToken = '';
let ownerCookie = '';
let csrf = '';

interface Res {
  status: number;
  json: any;
}

async function call(method: string, path: string, opts: { body?: unknown; device?: string; session?: boolean } = {}): Promise<Res> {
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) headers['content-type'] = 'application/json';
  if (opts.device) headers.authorization = `Bearer ${opts.device}`;
  if (opts.session) {
    headers.cookie = ownerCookie;
    if (method !== 'GET') headers['x-csrf-token'] = csrf;
  }
  const res = await fetch(base + path, { method, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body), redirect: 'manual' });
  const text = await res.text();
  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: res.status, json };
}

const KEY_PREF = 'k'.repeat(16) + '-pref-0001';
const KEY_FACT = 'f'.repeat(16) + '-fact-0001';
const KEY_LESSON = 'l'.repeat(16) + '-lesson-01';

before(async () => {
  tdb = await createTestDb();
  if (!tdb) return;
  await migrateUp(tdb.db, loadMigrations());
  await tdb.db.query('INSERT INTO owners (email, password_hash) VALUES ($1, $2)', [OWNER_EMAIL, await hashPassword(OWNER_PASSWORD)]);
  const pw = encodeURIComponent(tdb.config.password);
  const env = {
    DEVORA_ENV: 'development',
    DATABASE_URL: `postgres://${tdb.config.user}:${pw}@${tdb.config.host}:${tdb.config.port}/${tdb.config.database}`,
    DEVORA_SECRET_KEYS: KEYRING,
    DEVORA_SECRET_ACTIVE_KEY: '1',
    ADMIN_ORIGIN: 'https://admin.example.test',
    COOKIE_SECURE: 'false',
  };
  const config = loadConfig(env);
  server = createServer({ db: tdb.db, config, fetch: globalThis.fetch });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const login = await fetch(base + '/admin/api/auth/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: OWNER_EMAIL, password: OWNER_PASSWORD }),
  });
  ownerCookie = (login.headers.get('set-cookie') ?? '').split(';')[0];
  const session = (await (await fetch(base + '/admin/api/auth/session', { headers: { cookie: ownerCookie } })).json()) as { csrfToken: string };
  csrf = session.csrfToken;
  const reg = await call('POST', '/v1/devices/register', { body: { installId: INSTALL_ID, deviceName: 'test-box' } });
  deviceToken = reg.json.token;
});

after(async () => {
  server?.closeAllConnections?.();
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  await tdb?.drop();
});

describe('memory sync', { skip: !tdb && SKIP_NO_PG }, () => {
  test('requires a device token', async () => {
    const res = await call('POST', '/v1/memory/sync', { body: { changes: [] } });
    assert.equal(res.status, 401);
    assert.equal(res.json.error.code, 'unauthenticated');
  });

  test('pushes and pulls back the same memory (idempotent by client key)', async () => {
    const entry = { clientKey: KEY_PREF, scope: 'global', projectKey: '', kind: 'preference', content: 'the user prefers pnpm over npm', source: 'user', confidence: 0.95, verified: false, pinned: false, hits: 0, deleted: false, updatedAt: 1000 };
    const first = await call('POST', '/v1/memory/sync', { device: deviceToken, body: { changes: [entry] } });
    assert.equal(first.status, 200);
    assert.equal(first.json.applied, 1);
    // Same key and same client time: the second push is a no-op (LWW keeps the row).
    const again = await call('POST', '/v1/memory/sync', { device: deviceToken, body: { changes: [entry] } });
    assert.equal(again.status, 200);
    assert.equal(again.json.applied, 0);
    // A full pull (since 0) returns it in the desktop shape.
    const pull = await call('POST', '/v1/memory/sync', { device: deviceToken, body: { changes: [], since: 0 } });
    assert.equal(pull.status, 200);
    const rows = pull.json.entries.filter((e: any) => e.clientKey === KEY_PREF);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].content, 'the user prefers pnpm over npm');
    assert.equal(rows[0].scope, 'global');
    assert.equal(Array.isArray(rows[0].tags), true);
  });

  test('last write wins: a newer client update replaces, an older one does not', async () => {
    const newer = { clientKey: KEY_FACT, scope: 'project', projectKey: 'proj-1', kind: 'fact', content: 'tests run with pnpm vitest', source: 'agent', confidence: 0.8, verified: true, pinned: false, hits: 2, deleted: false, updatedAt: 5000 };
    const pushed = await call('POST', '/v1/memory/sync', { device: deviceToken, body: { changes: [newer] } });
    assert.equal(pushed.json.applied, 1);
    const older = { ...newer, content: 'stale content', updatedAt: 4000 };
    const stale = await call('POST', '/v1/memory/sync', { device: deviceToken, body: { changes: [older] } });
    assert.equal(stale.json.applied, 0);
    const updated = await call('POST', '/v1/memory/sync', { device: deviceToken, body: { changes: [{ ...newer, content: 'tests run with vitest, not jest', updatedAt: 6000 }] } });
    assert.equal(updated.json.applied, 1);
    const pull = await call('POST', '/v1/memory/sync', { device: deviceToken, body: { changes: [], since: 0 } });
    const row = pull.json.entries.find((e: any) => e.clientKey === KEY_FACT);
    assert.equal(row.content, 'tests run with vitest, not jest');
  });

  test('pull cursor only returns rows changed since `since`', async () => {
    const full = await call('POST', '/v1/memory/sync', { device: deviceToken, body: { changes: [], since: 0 } });
    assert.ok(full.json.serverTime > 0);
    const incremental = await call('POST', '/v1/memory/sync', { device: deviceToken, body: { changes: [], since: full.json.serverTime } });
    assert.equal(incremental.json.entries.length, 0);
  });

  test('tombstones delete on the server and come back marked deleted', async () => {
    const lesson = { clientKey: KEY_LESSON, scope: 'project', projectKey: 'proj-1', kind: 'lesson', content: 'always run typecheck before committing', source: 'system', confidence: 0.6, verified: false, pinned: false, hits: 1, deleted: false, updatedAt: 2000 };
    await call('POST', '/v1/memory/sync', { device: deviceToken, body: { changes: [lesson] } });
    const tomb = await call('POST', '/v1/memory/sync', { device: deviceToken, body: { changes: [{ ...lesson, deleted: true, updatedAt: 3000 }] } });
    assert.equal(tomb.json.applied, 1);
    const pull = await call('POST', '/v1/memory/sync', { device: deviceToken, body: { changes: [], since: 0 } });
    const row = pull.json.entries.find((e: any) => e.clientKey === KEY_LESSON);
    assert.equal(row.deleted, true);
  });

  test('secrets are refused', async () => {
    const bad = { clientKey: 's'.repeat(16) + '-secret-001', scope: 'global', projectKey: '', kind: 'fact', content: 'the api key is sk-abcdefghijklmnopqrstuvwxyz012345', source: 'agent', confidence: 0.7, updatedAt: 100 };
    const res = await call('POST', '/v1/memory/sync', { device: deviceToken, body: { changes: [bad] } });
    assert.equal(res.status, 422);
    assert.equal(res.json.error.code, 'content_refused');
  });

  test('invalid changes give a stable 400', async () => {
    const noKey = await call('POST', '/v1/memory/sync', { device: deviceToken, body: { changes: [{ scope: 'global', kind: 'fact', content: 'missing client key here', updatedAt: 1 }] } });
    assert.equal(noKey.status, 400);
    const badScope = await call('POST', '/v1/memory/sync', { device: deviceToken, body: { changes: [{ clientKey: 'a'.repeat(20), scope: 'weird', projectKey: '', kind: 'fact', content: 'bad scope value', updatedAt: 1 }] } });
    assert.equal(badScope.status, 400);
    const tooMany = await call('POST', '/v1/memory/sync', { device: deviceToken, body: { changes: Array.from({ length: 201 }, (_, i) => ({ clientKey: `x`.repeat(16) + String(i).padStart(6, '0'), scope: 'global', projectKey: '', kind: 'fact', content: 'entry number ' + i, updatedAt: i })) } });
    assert.equal(tooMany.status, 413);
  });

  test('another device cannot see memories of the first device', async () => {
    const reg2 = await call('POST', '/v1/devices/register', { body: { installId: 'install-fedcba9876543210', deviceName: 'other-box' } });
    const pull = await call('POST', '/v1/memory/sync', { device: reg2.json.token, body: { changes: [], since: 0 } });
    assert.equal(pull.json.entries.length, 0);
  });
});

describe('admin memory API', { skip: !tdb && SKIP_NO_PG }, () => {
  test('the memory list is owner-only', async () => {
    const anon = await call('GET', '/admin/api/memory');
    assert.equal(anon.status, 401);
    const device = await call('GET', '/admin/api/memory', { device: deviceToken });
    assert.equal(device.status, 401);
  });

  test('the owner sees stored memories with device names, totals and filters', async () => {
    const list = await call('GET', '/admin/api/memory?limit=50', { session: true });
    assert.equal(list.status, 200);
    assert.ok(list.json.total >= 3, 'the earlier pushes are visible');
    assert.ok(list.json.active >= 2);
    const row = list.json.memories.find((m: any) => m.content === 'tests run with vitest, not jest');
    assert.ok(row, 'the newest fact is in the list');
    assert.equal(row.deviceName, 'test-box');
    assert.equal(row.kind, 'fact');
    assert.equal(typeof row.updatedAt, 'string');
    assert.equal(list.json.memories.every((m: any) => !('client_key' in m)), 'rows are camelCase');
    const facts = await call('GET', '/admin/api/memory?kind=lesson', { session: true });
    assert.equal(facts.json.total, 1);
    const search = await call('GET', '/admin/api/memory?q=vitest', { session: true });
    assert.equal(search.json.total, 1);
    const none = await call('GET', '/admin/api/memory?q=no-such-memory-text', { session: true });
    assert.equal(none.json.total, 0);
  });

  test('the devices list carries the memory count per device', async () => {
    const list = await call('GET', '/admin/api/devices', { session: true });
    assert.equal(list.status, 200);
    const box = list.json.devices.find((d: any) => d.name === 'test-box');
    assert.ok(box.memories >= 2);
  });

  test('clearing needs CSRF and the password confirmation', async () => {
    const noCsrf = await fetch(base + '/admin/api/memory', { method: 'DELETE', headers: { cookie: ownerCookie } });
    assert.equal(noCsrf.status, 403);
    const noReauth = await call('DELETE', '/admin/api/memory', { session: true });
    assert.equal(noReauth.status, 403);
    assert.equal(noReauth.json.error.code, 'reauth_required');
  });

  test('after the password confirmation the owner can clear one device, then everything', async () => {
    const reauth = await call('POST', '/admin/api/auth/reauth', { session: true, body: { password: OWNER_PASSWORD } });
    assert.equal(reauth.status, 200);
    const other = await call('POST', '/v1/devices/register', { body: { installId: 'install-aaaabbbbccccdddd', deviceName: 'clear-box' } });
    await call('POST', '/v1/memory/sync', { device: other.json.token, body: { changes: [{ clientKey: 'd'.repeat(16) + '-other-0001', scope: 'global', projectKey: '', kind: 'fact', content: 'memories on the second device', source: 'agent', confidence: 0.5, updatedAt: 100 }] } });

    const box = (await call('GET', '/admin/api/devices', { session: true })).json.devices.find((d: any) => d.name === 'test-box');
    const clearedOne = await call('DELETE', `/admin/api/memory/${box.id}`, { session: true });
    assert.equal(clearedOne.status, 200);
    assert.ok(clearedOne.json.cleared >= 3);
    const left = await call('GET', '/admin/api/memory', { session: true });
    assert.equal(left.json.total, 1, 'only the second device still has memory');
    assert.equal(left.json.memories[0].deviceName, 'clear-box');

    const clearedAll = await call('DELETE', '/admin/api/memory', { session: true });
    assert.equal(clearedAll.status, 200);
    assert.equal(clearedAll.json.cleared, 1);
    const empty = await call('GET', '/admin/api/memory', { session: true });
    assert.equal(empty.json.total, 0);
    // The devices keep working: the next sync starts over and the desktop restores itself from its local copy.
    const repush = await call('POST', '/v1/memory/sync', { device: other.json.token, body: { changes: [{ clientKey: 'd'.repeat(16) + '-other-0001', scope: 'global', projectKey: '', kind: 'fact', content: 'memories on the second device', source: 'agent', confidence: 0.5, updatedAt: 200 }] } });
    assert.equal(repush.json.applied, 1);
  });
});
