// Organization skills end to end: the owner publishes in the admin API, the real desktop core downloads them during
// central sync and the agent's skill list shows them as read-only "organization" skills. Also: per-user activity.
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
import { AppCore } from '../../src/core/app-core.ts';
import { MemorySecretStore } from '../../src/core/secrets.ts';

const PASSWORD = 'correct horse battery staple';
let tdb: TestDb | null = null;
let server: Server;
let base = '';

before(async () => {
  tdb = await createTestDb();
  if (!tdb) return;
  await migrateUp(tdb.db, loadMigrations());
  await tdb.db.query('INSERT INTO owners (email, password_hash) VALUES ($1, $2)', ['owner@example.test', await hashPassword(PASSWORD)]);
  server = createServer({
    db: tdb.db,
    config: loadConfig({
      DEVORA_ENV: 'development',
      DATABASE_URL: `postgres://${tdb.config.user}:${encodeURIComponent(tdb.config.password)}@${tdb.config.host}:${tdb.config.port}/${tdb.config.database}`,
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

const j = async (r: Response) => ({ status: r.status, body: (await r.json().catch(() => null)) as any, headers: r.headers });

async function owner() {
  const login = await fetch(`${base}/admin/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'owner@example.test', password: PASSWORD }) });
  const cookie = (login.headers.get('set-cookie') ?? '').split(';')[0];
  const csrf = ((await login.json()) as any).csrfToken;
  return (method: string, p: string, body?: unknown) =>
    fetch(base + p, { method, headers: { cookie, 'x-csrf-token': csrf, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }).then(j);
}

function desktop() {
  return new AppCore({
    kind: 'harness',
    dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'devora-skills-')),
    appVersion: '1.2.3',
    electronVersion: null,
    secretStore: new MemorySecretStore(),
    monacoAvailable: false,
    pickFolder: async () => null,
    saveTextFile: async () => null,
    openTextFile: async () => null,
    openExternal: async () => undefined,
    updates: { configured: false, reason: 'test' },
    centralConnection: { bootstrapUrl: base, bootstrapSource: 'user-file', trustedOrigins: [], connectTimeoutMs: 5000, configErrors: [] },
  } as any);
}

test('admin publishes skills; desktops download them read-only and follow every change', async (t) => {
  if (!tdb) return t.skip(SKIP_NO_PG);
  const call = await owner();
  assert.equal((await call('POST', '/admin/api/skills', { name: 'X', description: '', instructions: 'y' })).status, 400, 'description required');
  assert.equal((await call('POST', '/admin/api/skills', { name: 'X', description: 'd', instructions: 'y', triggers: Array.from({ length: 21 }, (_, i) => `t${i}`) })).status, 400, 'too many triggers');
  const created = await call('POST', '/admin/api/skills', {
    name: 'Release checklist',
    description: 'Use when preparing a release or changelog.',
    triggers: 'release, changelog, Deploy',
    instructions: '1. Run the tests.\n2. Update CHANGELOG.md.',
    examples: 'Release 1.2.0',
  });
  assert.equal(created.status, 201);
  assert.equal(created.body.skill.slug, 'release-checklist');
  assert.deepEqual(created.body.skill.triggers, ['release', 'changelog', 'deploy']);
  const dup = await call('POST', '/admin/api/skills', { name: 'Release checklist', description: 'd', instructions: 'i' });
  assert.equal(dup.body.skill.slug, 'release-checklist-2', 'same name gets a unique slug');

  const core = desktop();
  try {
    await core.centralRefresh();
    let mine = core.skills.list().filter((s) => s.source === 'organization');
    assert.deepEqual(mine.map((s) => s.name).sort(), ['Release checklist', 'Release checklist'].sort());
    const skill = mine.find((s) => s.id === 'org-release-checklist')!;
    assert.equal(skill.enabled, true);
    assert.match(skill.instructions, /CHANGELOG/);
    assert.throws(() => core.skills.remove(skill.id), /administrator/, 'read-only on the desktop');
    core.skills.setEnabled(skill.id, false);
    assert.equal(core.skills.get(skill.id)!.enabled, false, 'a user can turn one off for themselves');

    // Edit, disable and delete on the server: the desktop follows on its next sync.
    await call('PATCH', `/admin/api/skills/${created.body.skill.id}`, { instructions: '1. Run the tests.\n2. Tag the release.' });
    await call('PATCH', `/admin/api/skills/${dup.body.skill.id}`, { enabled: false });
    await core.centralRefresh();
    mine = core.skills.list().filter((s) => s.source === 'organization');
    assert.deepEqual(mine.map((s) => s.id), ['org-release-checklist']);
    assert.match(mine[0].instructions, /Tag the release/);
    assert.equal(mine[0].enabled, false, "the user's own off switch survives updates");
    await call('DELETE', `/admin/api/skills/${created.body.skill.id}`);
    await core.centralRefresh();
    assert.equal(core.skills.list().filter((s) => s.source === 'organization').length, 0);
  } finally {
    core.central.stopAutoSync();
  }

  // ETag: an unchanged list is not downloaded again.
  const reg = await j(await fetch(`${base}/v1/devices/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ installId: 'install-skills-etag-0001', deviceName: 'PC' }) }));
  const first = await fetch(`${base}/v1/skills`, { headers: { authorization: `Bearer ${reg.body.token}` } });
  const etag = first.headers.get('etag')!;
  assert.equal((await fetch(`${base}/v1/skills`, { headers: { authorization: `Bearer ${reg.body.token}`, 'if-none-match': etag } })).status, 304);
  assert.equal((await fetch(`${base}/v1/skills`)).status, 401, 'needs a device token');
  assert.equal((await fetch(`${base}/admin/api/skills`)).status, 401, 'admin list needs the owner');
});

test("the owner sees one account's requests and brain, and only that account's", async (t) => {
  if (!tdb) return t.skip(SKIP_NO_PG);
  const call = await owner();
  const mk = async (user: string, install: string) => {
    await tdb!.db.query('INSERT INTO app_users (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [user]);
    const { rows } = await tdb!.db.query("INSERT INTO devices (name, token_hash, install_id, user_id) VALUES ($1, $2, $3, $4) RETURNING id", [`${user}-pc`, crypto.randomBytes(16).toString('hex'), install, user]);
    return rows[0].id as string;
  };
  const a = await mk('useraaaaaaaaaaa', 'install-activity-a-001');
  const b = await mk('userbbbbbbbbbbb', 'install-activity-b-001');
  for (const [dev, model] of [[a, 'model-a'], [a, 'model-a'], [b, 'model-b']])
    await tdb.db.query("INSERT INTO request_logs (device_id, model_name, provider_name, status, http_status, latency_ms, prompt_tokens, completion_tokens) VALUES ($1, $2, 'p', 'ok', 200, 120, 10, 5)", [dev, model]);
  await tdb.db.query("INSERT INTO memory_entries (device_id, client_key, scope, kind, content, source, confidence, client_updated_at) VALUES ($1, 'kkkkkkkkkkkkkkkkka', 'global', 'preference', 'A likes tabs', 'user', 1, 1)", [a]);
  await tdb.db.query("INSERT INTO memory_entries (device_id, client_key, scope, kind, content, source, confidence, client_updated_at) VALUES ($1, 'kkkkkkkkkkkkkkkkkb', 'global', 'preference', 'B likes spaces', 'user', 1, 1)", [b]);
  const act = await call('GET', '/admin/api/users/useraaaaaaaaaaa/activity');
  assert.equal(act.status, 200);
  assert.equal(act.body.totals.requests, 2);
  assert.equal(act.body.totals.prompt_tokens, 20);
  assert.deepEqual(act.body.byModel.map((m: any) => m.model), ['model-a']);
  assert.deepEqual(act.body.brain.latest.map((m: any) => m.content), ['A likes tabs']);
  const mem = await call('GET', '/admin/api/memory?userId=userbbbbbbbbbbb');
  assert.deepEqual(mem.body.memories.map((m: any) => m.content), ['B likes spaces']);
  assert.equal((await fetch(`${base}/admin/api/users/useraaaaaaaaaaa/activity`)).status, 401);
});
