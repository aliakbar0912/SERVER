// Tests for the three admin-panel features added in migrations 10-12: API keys, organization agents and the desktop
// announcement settings. Runs against the real HTTP server, a real PostgreSQL database and the mock OpenAI upstream.
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
import { startMockOpenAI, type MockServer } from '../../tests/fixtures/mock-openai.ts';

const OWNER_EMAIL = 'owner@example.test';
const OWNER_PASSWORD = 'correct horse battery staple';
const UPSTREAM_KEY = 'sk-mock-admin-features';
const KEYRING = `1=${crypto.randomBytes(32).toString('base64')}`;
const ADMIN_ORIGIN = 'https://admin.example.test';
const INSTALL_ID = 'install-adminfeatures01';

let tdb: TestDb | null = null;
let server: Server;
let base = '';
let mock: MockServer;
let cookie = '';
let csrf = '';
let deviceToken = '';
let modelId = '';
let keyChat = '';
let keyDisabled = '';

interface Res {
  status: number;
  text: string;
  json: any;
  headers: Headers;
}

async function call(method: string, path: string, opts: { body?: unknown; session?: boolean; device?: string; key?: string; headers?: Record<string, string> } = {}): Promise<Res> {
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  if (opts.body !== undefined) headers['content-type'] = 'application/json';
  if (opts.session) {
    headers.cookie = cookie;
    if (method !== 'GET') headers['x-csrf-token'] = csrf;
  }
  if (opts.device) headers.authorization = `Bearer ${opts.device}`;
  if (opts.key) headers.authorization = `Bearer ${opts.key}`;
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
  mock = await startMockOpenAI({
    requireKey: UPSTREAM_KEY,
    models: ['mock-coder'],
    script: (body) => {
      const last = body.messages[body.messages.length - 1];
      return { content: `echo:${typeof last?.content === 'string' ? last.content : 'parts'}`, usage: { prompt_tokens: 5, completion_tokens: 3 } };
    },
  });
  const pw = encodeURIComponent(tdb.config.password);
  const config = loadConfig({
    DEVORA_ENV: 'development',
    DATABASE_URL: `postgres://${tdb.config.user}:${pw}@${tdb.config.host}:${tdb.config.port}/${tdb.config.database}`,
    DEVORA_SECRET_KEYS: KEYRING,
    DEVORA_SECRET_ACTIVE_KEY: '1',
    ADMIN_ORIGIN,
    COOKIE_SECURE: 'false',
    PUBLIC_API_ORIGIN: 'https://api.example.test',
    DEVORA_STATUS_MESSAGE: 'env notice',
  });
  server = createServer({ db: tdb.db, config, fetch: globalThis.fetch });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  // Sign in once; every test uses this session.
  const login = await call('POST', '/admin/api/auth/login', { body: { email: OWNER_EMAIL, password: OWNER_PASSWORD } });
  assert.equal(login.status, 200, login.text);
  cookie = (login.headers.get('set-cookie') ?? '').split(';')[0];
  csrf = login.json.csrfToken;
  // One enabled model so chat and model-list requests have something to return.
  const provider = await call('POST', '/admin/api/providers', { session: true, body: { name: 'Mock upstream', baseUrl: mock.url, authScheme: 'bearer', timeoutMs: 5000 } });
  assert.equal(provider.status, 201, provider.text);
  await call('POST', '/admin/api/auth/reauth', { session: true, body: { password: OWNER_PASSWORD } });
  await call('PUT', `/admin/api/providers/${provider.json.id}/api-key`, { session: true, body: { apiKey: UPSTREAM_KEY } });
  await call('POST', `/admin/api/providers/${provider.json.id}/discover`, { session: true });
  const list = await call('GET', '/admin/api/models', { session: true });
  modelId = list.json.models[0].id;
  await call('PATCH', `/admin/api/models/${modelId}`, { session: true, body: { enabled: true, displayName: 'Coder (feature test)', capabilities: { tools: { supported: true, source: 'admin' }, streaming: { supported: true, source: 'admin' } } } });
  const device = await call('POST', '/v1/devices/register', { body: { installId: INSTALL_ID, deviceName: 'Feature test laptop' } });
  assert.equal(device.status, 201, device.text);
  deviceToken = device.json.token;
});

after(async () => {
  server?.closeAllConnections?.();
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  await mock?.close();
  await tdb?.drop();
});

describe('api keys', () => {
  test('a key is created with a secret shown exactly once, and never again', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('POST', '/admin/api/api-keys', { session: true, body: { name: 'Build script', scopes: ['chat', 'models'], expiresAt: 'never' } });
    assert.equal(res.status, 201, res.text);
    assert.match(res.json.secret, /^dvk_[a-f0-9]{48}$/);
    assert.equal(res.json.authorizationHeader, `Bearer ${res.json.secret}`);
    keyChat = res.json.secret;
    const list = await call('GET', '/admin/api/api-keys', { session: true });
    assert.equal(list.json.keys.length, 1);
    assert.ok(!list.text.includes(keyChat), 'the secret is never listed again');
    assert.equal(list.json.keys[0].keyPrefix, keyChat.slice(0, 8));
    assert.equal(list.json.keys[0].last4, keyChat.slice(-4));
  });

  test('a key with the models scope lists models in the OpenAI shape, device tokens do not', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('GET', '/v1/models', { key: keyChat });
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.object, 'list');
    assert.equal(res.json.data.length, 1);
    assert.equal(res.json.data[0].id, modelId);
    assert.equal(res.json.data[0].object, 'model');
    assert.equal((await call('GET', '/v1/models')).status, 401);
    assert.equal((await call('GET', '/v1/models', { device: deviceToken })).status, 401);
  });

  test('a key with the chat scope can call chat completions, and usage is recorded', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('POST', '/v1/chat/completions', { key: keyChat, body: { model: modelId, messages: [{ role: 'user', content: 'from a script' }] } });
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.choices[0].message.content, 'echo:from a script');
    const { rows } = await tdb!.db.query('SELECT request_count, last_used_at FROM api_keys ORDER BY created_at DESC LIMIT 1', []);
    assert.equal(Number(rows[0].request_count), 1);
    assert.ok(rows[0].last_used_at, 'last_used_at is stamped');
    const logs = await call('GET', '/admin/api/logs?limit=5', { session: true });
    const entry = logs.json.logs.find((l: any) => l.apiKeyName === 'Build script');
    assert.ok(entry, 'the request log names the API key');
    assert.equal(entry.deviceName, null);
  });

  test('an unknown, disabled or deleted key is refused with stable codes', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    assert.equal((await call('POST', '/v1/chat/completions', { key: 'dvk_' + 'x'.repeat(32), body: { model: modelId, messages: [{ role: 'user', content: 'hi' }] } })).status, 401);
    const created = await call('POST', '/admin/api/api-keys', { session: true, body: { name: 'Doomed', scopes: ['chat'] } });
    keyDisabled = created.json.secret;
    await call('PATCH', `/admin/api/api-keys/${created.json.key.id}`, { session: true, body: { enabled: false } });
    const off = await call('POST', '/v1/chat/completions', { key: keyDisabled, body: { model: modelId, messages: [{ role: 'user', content: 'hi' }] } });
    assert.equal(off.status, 403);
    assert.equal(off.json.error.code, 'api_key_disabled');
    await call('DELETE', `/admin/api/api-keys/${created.json.key.id}`, { session: true });
    const gone = await call('POST', '/v1/chat/completions', { key: keyDisabled, body: { model: modelId, messages: [{ role: 'user', content: 'hi' }] } });
    assert.equal(gone.status, 401);
    assert.equal(gone.json.error.code, 'invalid_api_key');
  });

  test('a key without the chat scope cannot chat; unknown scopes are refused at creation', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const created = await call('POST', '/admin/api/api-keys', { session: true, body: { name: 'Models only', scopes: ['models'] } });
    assert.equal(created.status, 201);
    const res = await call('POST', '/v1/chat/completions', { key: created.json.secret, body: { model: modelId, messages: [{ role: 'user', content: 'hi' }] } });
    assert.equal(res.status, 403);
    assert.equal(res.json.error.code, 'missing_scope');
    const bad = await call('POST', '/admin/api/api-keys', { session: true, body: { name: 'Bad scope', scopes: ['root'] } });
    assert.equal(bad.status, 400);
  });

  test('key writes need the owner session; anonymous writes are refused', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    assert.equal((await call('GET', '/admin/api/api-keys')).status, 401);
    assert.equal((await call('POST', '/admin/api/api-keys', { body: { name: 'Anon' } })).status, 401);
    const empty = await call('PATCH', `/admin/api/api-keys/${crypto.randomUUID()}`, { session: true, body: {} });
    assert.equal(empty.status, 400, 'an empty patch is refused');
  });
});

describe('organization agents', () => {
  test('the owner creates an agent and invalid access levels are refused', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const bad = await call('POST', '/admin/api/agents', { session: true, body: { name: 'Bad', description: 'd', instructions: 'i', access: 'root' } });
    assert.equal(bad.status, 400);
    const res = await call('POST', '/admin/api/agents', {
      session: true,
      body: { name: 'Release notes writer', description: 'Writes release notes from merged commits.', instructions: 'Follow docs/CHANGELOG.md style.', access: 'read', suggestedModel: null },
    });
    assert.equal(res.status, 201, res.text);
    assert.match(res.json.agent.slug, /^release-notes-writer/);
  });

  test('desktops download enabled agents with an ETag, and the catalogue announces the version', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('GET', '/v1/agents', { device: deviceToken });
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.agents.length, 1);
    assert.equal(res.json.agents[0].access, 'read');
    assert.ok(res.json.version >= 1);
    const cached = await call('GET', '/v1/agents', { device: deviceToken, headers: { 'if-none-match': res.headers.get('etag')! } });
    assert.equal(cached.status, 304);
    const cat = await call('GET', '/v1/catalogue', { device: deviceToken });
    assert.equal(typeof cat.json.policy.agentsVersion, 'number');
    assert.equal((await call('GET', '/v1/agents')).status, 401);
  });

  test('turning an agent off removes it from desktops and bumps the version', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const list = await call('GET', '/admin/api/agents', { session: true });
    const id = list.json.agents[0].id;
    const before = (await call('GET', '/v1/agents', { device: deviceToken })).json.version;
    await call('PATCH', `/admin/api/agents/${id}`, { session: true, body: { enabled: false } });
    const afterList = await call('GET', '/v1/agents', { device: deviceToken });
    assert.equal(afterList.json.agents.length, 0);
    assert.ok(afterList.json.version > before, 'the version moved so clients re-download');
  });
});

describe('desktop announcement', () => {
  test('the announcement starts empty and the environment values apply', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('GET', '/admin/api/desktop-config', { session: true });
    assert.equal(res.status, 200);
    assert.equal(res.json.statusMessage, '');
    assert.equal(res.json.environment.statusMessage, 'env notice');
    const cfg = await call('GET', '/v1/client-config');
    assert.equal(cfg.json.status.message, 'env notice', 'the environment notice shows until overridden');
    assert.equal(cfg.json.features.maintenance, false);
  });

  test('a saved notice, maintenance flag and download URL reach the desktops', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('PATCH', '/admin/api/desktop-config', {
      session: true,
      body: { statusMessage: 'Maintenance Sunday 02:00-03:00 UTC', downloadUrl: 'https://www.example.test/download', maintenance: true },
    });
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.maintenance, true);
    const cfg = await call('GET', '/v1/client-config');
    assert.equal(cfg.json.status.message, 'Maintenance Sunday 02:00-03:00 UTC', 'the admin notice replaces the environment one');
    assert.equal(cfg.json.desktop.downloadUrl, 'https://www.example.test/download');
    assert.equal(cfg.json.features.maintenance, true);
  });

  test('raising the minimum version needs a password confirmation', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const refused = await call('PATCH', '/admin/api/desktop-config', { session: true, body: { minVersion: '9.9.9' } });
    assert.equal(refused.status, 403);
    assert.equal(refused.json.error.code, 'reauth_required');
    await call('POST', '/admin/api/auth/reauth', { session: true, body: { password: OWNER_PASSWORD } });
    const ok = await call('PATCH', '/admin/api/desktop-config', { session: true, body: { minVersion: '9.9.9' } });
    assert.equal(ok.status, 200);
    const cfg = await call('GET', '/v1/client-config');
    assert.equal(cfg.json.desktop.minVersion, '9.9.9', 'the override is stronger than the environment');
    const bad = await call('PATCH', '/admin/api/desktop-config', { session: true, body: { minVersion: 'not-a-version' } });
    assert.equal(bad.status, 400);
  });

  test('an unsafe download URL is refused', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const bad = await call('PATCH', '/admin/api/desktop-config', { session: true, body: { downloadUrl: 'http://www.example.test/download' } });
    assert.equal(bad.status, 400);
  });
});
