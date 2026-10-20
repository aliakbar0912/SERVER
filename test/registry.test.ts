// Model registry end to end: per-device access, discovery (with and without a provider model list), server-side fallback,
// availability, model metadata and device usage. Real HTTP server, real PostgreSQL, local mock upstreams.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
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
const GOOD_KEY = 'sk-good-provider-key-0001';
const BROKEN_KEY = 'sk-broken-provider-key-0002';

let tdb: TestDb | null = null;
let server: Server;
let base = '';
let good: MockServer;
let broken: MockServer;
let noList: http.Server;
let noListUrl = '';
let cookie = '';
let csrf = '';
const ids: Record<string, string> = {};
const tokens: Record<string, string> = {};
const deviceIds: Record<string, string> = {};

interface Res {
  status: number;
  text: string;
  json: any;
  headers: Headers;
}

async function call(method: string, path: string, opts: { body?: unknown; owner?: boolean; device?: string } = {}): Promise<Res> {
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) headers['content-type'] = 'application/json';
  if (opts.owner) {
    headers.cookie = cookie;
    if (method !== 'GET') headers['x-csrf-token'] = csrf;
  }
  if (opts.device) headers.authorization = `Bearer ${opts.device}`;
  const res = await fetch(base + path, { method, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body) });
  const text = await res.text();
  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: res.status, text, json, headers: res.headers };
}

const chat = (device: string, model: string, extra: Record<string, unknown> = {}) =>
  call('POST', '/v1/chat/completions', { device, body: { model, messages: [{ role: 'user', content: 'hello' }], ...extra } });

/** An OpenAI-compatible server without a model list: GET /models is 404, chat works. */
async function startNoListServer(): Promise<http.Server> {
  const s = http.createServer(async (req, res) => {
    if (req.method === 'POST' && req.url?.endsWith('/chat/completions')) {
      let raw = '';
      for await (const c of req) raw += c;
      const body = JSON.parse(raw);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ id: 'x', choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: `nolist:${body.model}` } }], usage: { prompt_tokens: 3, completion_tokens: 2 } }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  return s;
}

before(async () => {
  tdb = await createTestDb();
  if (!tdb) return;
  await migrateUp(tdb.db, loadMigrations());
  await tdb.db.query('INSERT INTO owners (email, password_hash) VALUES ($1, $2)', [OWNER_EMAIL, await hashPassword(OWNER_PASSWORD)]);
  good = await startMockOpenAI({ requireKey: GOOD_KEY, models: ['good-a', 'good-b'], script: (b) => ({ content: `good:${b.model}`, usage: { prompt_tokens: 5, completion_tokens: 4 } }) });
  broken = await startMockOpenAI({ requireKey: BROKEN_KEY, models: ['broken-x'], script: () => ({ status: 503, errorMessage: 'overloaded' }) });
  noList = await startNoListServer();
  noListUrl = `http://127.0.0.1:${(noList.address() as AddressInfo).port}/v1`;
  const pw = encodeURIComponent(tdb.config.password);
  const config = loadConfig({
    DEVORA_ENV: 'development',
    DATABASE_URL: `postgres://${tdb.config.user}:${pw}@${tdb.config.host}:${tdb.config.port}/${tdb.config.database}`,
    DEVORA_SECRET_KEYS: `1=${crypto.randomBytes(32).toString('base64')}`,
    DEVORA_SECRET_ACTIVE_KEY: '1',
    COOKIE_SECURE: 'false',
  });
  server = createServer({ db: tdb.db, config, fetch: globalThis.fetch });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  const login = await call('POST', '/admin/api/auth/login', { body: { email: OWNER_EMAIL, password: OWNER_PASSWORD } });
  cookie = (login.headers.get('set-cookie') ?? '').split(';')[0];
  csrf = login.json.csrfToken;
  assert.equal((await call('POST', '/admin/api/auth/reauth', { owner: true, body: { password: OWNER_PASSWORD } })).status, 200);

  const provider = async (name: string, baseUrl: string, key: string | null) => {
    const p = await call('POST', '/admin/api/providers', { owner: true, body: { name, adapter: 'openai-compatible', baseUrl, authScheme: key ? 'bearer' : 'none' } });
    assert.equal(p.status, 201, p.text);
    if (key) assert.equal((await call('PUT', `/admin/api/providers/${p.json.id}/api-key`, { owner: true, body: { apiKey: key } })).status, 200);
    return p.json.id as string;
  };
  ids.good = await provider('Good', good.url, GOOD_KEY);
  ids.broken = await provider('Broken', broken.url, BROKEN_KEY);
  ids.noList = await provider('NoList', noListUrl, null);

  for (const code of ['A', 'B']) {
    const e = await call('POST', '/v1/devices/register', { body: { installId: `registry-install-${code}-0000`, deviceName: `device ${code}` } });
    assert.equal(e.status, 201, e.text);
    tokens[code] = e.json.token;
    deviceIds[code] = e.json.deviceId;
  }
});

after(async () => {
  server?.closeAllConnections?.();
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  await good?.close();
  await broken?.close();
  await new Promise<void>((r) => (noList ? (noList.closeAllConnections?.(), noList.close(() => r())) : r()));
  await tdb?.drop();
});

describe('model registry', () => {
  test('a provider without a model list is not marked failing; discovery says to add models by id', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const d = await call('POST', `/admin/api/providers/${ids.noList}/discover`, { owner: true });
    assert.equal(d.status, 200, d.text);
    assert.equal(d.json.supported, false);
    assert.match(d.json.message, /exact id/);
    const list = await call('GET', '/admin/api/providers', { owner: true });
    const p = list.json.providers.find((x: any) => x.id === ids.noList);
    assert.equal(p.discovery.supported, false);
    assert.equal(p.lastTest, null, 'discovery does not write a failed connectivity test');
    const m = await call('POST', '/admin/api/models', { owner: true, body: { providerId: ids.noList, upstreamModelId: 'nolist-1', displayName: 'No-list model', enabled: true } });
    assert.equal(m.status, 201, m.text);
    assert.equal(m.json.source, 'manual');
    ids.nolist1 = m.json.id;
  });

  test('concurrent refreshes of one provider never create duplicates, and new models arrive disabled', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const results = await Promise.all([1, 2, 3].map(() => call('POST', `/admin/api/providers/${ids.good}/discover`, { owner: true })));
    for (const r of results) assert.ok(r.status === 200 || r.status === 409, r.text);
    const added = results.filter((r) => r.status === 200).reduce((n, r) => n + r.json.added, 0);
    assert.equal(added, 2);
    const { rows } = await tdb!.db.query('SELECT upstream_model_id, enabled, source, last_listed_at FROM models WHERE provider_id = $1 ORDER BY 1', [ids.good]);
    assert.deepEqual(rows.map((r) => r.upstream_model_id), ['good-a', 'good-b']);
    assert.ok(rows.every((r) => r.enabled === false && r.source === 'discovered' && r.last_listed_at));
    await call('POST', `/admin/api/providers/${ids.broken}/discover`, { owner: true });
    const all = await call('GET', '/admin/api/models', { owner: true });
    for (const m of all.json.models) ids[m.upstreamModelId] = m.id;
    const enable = (id: string, extra: Record<string, unknown> = {}) => call('PATCH', `/admin/api/models/${id}`, { owner: true, body: { enabled: true, ...extra } });
    assert.equal((await enable(ids['good-a'], { capabilities: { tools: { supported: true, source: 'admin' } } })).status, 200);
    assert.equal((await enable(ids['good-b'])).status, 200);
    const fb = await enable(ids['broken-x'], { fallbackModelId: ids['good-a'] });
    assert.equal(fb.status, 200, fb.text);
    assert.equal(fb.json.fallbackModelId, ids['good-a']);
    assert.equal((await call('PATCH', `/admin/api/models/${ids['good-a']}`, { owner: true, body: { fallbackModelId: ids['good-a'] } })).status, 400, 'no self fallback');
  });

  test('every device sees all enabled models until the owner restricts it', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const a = await call('GET', '/v1/catalogue', { device: tokens.A });
    assert.equal(a.status, 200);
    assert.deepEqual(new Set(a.json.models.map((m: any) => m.id)), new Set([ids.nolist1, ids['good-a'], ids['good-b'], ids['broken-x']]));
    assert.equal(a.text.includes(GOOD_KEY) || a.text.includes('providerId') || a.text.includes('upstream'), false, 'no keys or upstream routing in the catalogue');
  });

  test('restricting a device changes its catalogue version and list, and other devices are unaffected', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const before = (await call('GET', '/v1/catalogue', { device: tokens.B })).json.version;
    const put = await call('PUT', `/admin/api/devices/${deviceIds.B}/models`, { owner: true, body: { modelAccess: 'selected', modelIds: [ids['good-a']] } });
    assert.equal(put.status, 200, put.text);
    const b = await call('GET', '/v1/catalogue', { device: tokens.B });
    assert.ok(b.json.version > before);
    assert.deepEqual(b.json.models.map((m: any) => m.id), [ids['good-a']]);
    const stale = await fetch(`${base}/v1/catalogue`, { headers: { authorization: `Bearer ${tokens.B}`, 'if-none-match': `"${before}"` } });
    assert.equal(stale.status, 200, 'an old ETag does not hide the change');
    assert.equal((await call('GET', '/v1/catalogue', { device: tokens.A })).json.models.length, 4);
    const listed = await call('GET', '/admin/api/devices', { owner: true });
    const row = listed.json.devices.find((d: any) => d.id === deviceIds.B);
    assert.deepEqual([row.modelAccess, row.grantedModels], ['selected', 1]);
    const got = await call('GET', `/admin/api/devices/${deviceIds.B}/models`, { owner: true });
    assert.deepEqual(got.json, { modelAccess: 'selected', modelIds: [ids['good-a']] });
  });

  test('a device cannot use or even look up a model it was not granted', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const denied = await chat(tokens.B, ids['good-b']);
    assert.equal(denied.status, 404);
    assert.equal(denied.json.error.code, 'model_not_found');
    assert.equal((await call('GET', `/v1/models/${ids['good-b']}`, { device: tokens.B })).status, 404);
    const ok = await chat(tokens.B, ids['good-a']);
    assert.equal(ok.status, 200, ok.text);
    assert.equal(ok.json.choices[0].message.content, 'good:good-a', 'routed to the upstream id from the registry');
    assert.equal(ok.json.model, ids['good-a']);
    const meta = await call('GET', `/v1/models/${ids['good-a']}`, { device: tokens.B });
    assert.equal(meta.status, 200);
    assert.equal(meta.json.capabilities.tools.supported, true);
    assert.equal(meta.text.includes(GOOD_KEY), false);
  });

  test('a manually added model on a provider without a model list works', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const r = await chat(tokens.A, ids.nolist1);
    assert.equal(r.status, 200, r.text);
    assert.equal(r.json.choices[0].message.content, 'nolist:nolist-1');
  });

  test('when the upstream fails, the configured fallback answers and the response says so', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const r = await chat(tokens.A, ids['broken-x']);
    assert.equal(r.status, 200, r.text);
    assert.equal(r.headers.get('x-devora-fallback-from'), ids['broken-x']);
    assert.equal(r.headers.get('x-devora-model'), ids['good-a']);
    assert.equal(r.json.model, ids['good-a']);
    assert.equal(r.json.choices[0].message.content, 'good:good-a');

    const s = await fetch(`${base}/v1/chat/completions`, {
      method: 'POST',
      headers: { authorization: `Bearer ${tokens.A}`, 'content-type': 'application/json' },
      body: JSON.stringify({ model: ids['broken-x'], stream: true, messages: [{ role: 'user', content: 'hello' }] }),
    });
    assert.equal(s.status, 200);
    assert.equal(s.headers.get('x-devora-fallback-from'), ids['broken-x']);
    const text = await s.text();
    assert.match(text, /good:good-a|good:go/);
    assert.match(text, /\[DONE\]/);

    // The log row of a stream is written right after the last byte; wait for it.
    let rows: any[] = [];
    for (let i = 0; i < 40 && rows.length < 4; i++) {
      if (i) await new Promise((r) => setTimeout(r, 50));
      rows = (
        await tdb!.db.query("SELECT model_id, status, error_code FROM request_logs WHERE device_id = $1 AND model_id IN ($2, $3) ORDER BY id", [
          deviceIds.A,
          ids['broken-x'],
          ids['good-a'],
        ])
      ).rows;
    }
    assert.deepEqual(rows.map((r) => [r.model_id === ids['broken-x'] ? 'broken' : 'good', r.status]), [['broken', 'error'], ['good', 'ok'], ['broken', 'error'], ['good', 'ok']]);
  });

  test('the fallback is skipped when it does not support what the request uses, or is not granted', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const image = { model: ids['broken-x'], messages: [{ role: 'user', content: [{ type: 'text', text: 'see' }, { type: 'image_url', image_url: { url: 'data:image/png;base64,iVBORw0KGgo=' } }] }] };
    const r = await call('POST', '/v1/chat/completions', { device: tokens.A, body: image });
    assert.equal(r.status, 502, 'good-a has unknown vision support, so it is not used for an image request');
    assert.equal(r.json.error.code, 'upstream_error');
    assert.equal(r.headers.get('x-devora-fallback-from'), null);
  });

  test('availability follows real traffic, and an unsupported model list alone is never "degraded"', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const st = await call('GET', '/v1/catalogue/status', { device: tokens.A });
    assert.equal(st.status, 200);
    const by = Object.fromEntries(st.json.models.map((m: any) => [m.id, m.availability]));
    assert.equal(by[ids['good-a']], 'available');
    assert.equal(by[ids['broken-x']], 'degraded', 'three recent upstream failures');
    assert.equal(by[ids.nolist1], 'available', 'answered a real request');
    // A connectivity test that fails only because the model list is missing does not degrade the provider.
    await tdb!.db.query("DELETE FROM request_logs WHERE provider_id = $1", [ids.noList]);
    await call('POST', `/admin/api/providers/${ids.noList}/test`, { owner: true });
    const again = await call('GET', '/v1/catalogue/status', { device: tokens.A });
    assert.equal(again.json.models.find((m: any) => m.id === ids.nolist1).availability, 'unknown');
    const b = await call('GET', '/v1/catalogue/status', { device: tokens.B });
    assert.deepEqual(b.json.models.map((m: any) => m.id), [ids['good-a']], 'status only covers granted models');
    assert.equal(st.text.includes(GOOD_KEY) || st.text.includes(BROKEN_KEY), false);
  });

  test('disabling a model or removing a grant takes effect on the very next request', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    assert.equal((await call('PATCH', `/admin/api/models/${ids['good-a']}`, { owner: true, body: { enabled: false } })).status, 200);
    const off = await chat(tokens.B, ids['good-a']);
    assert.equal(off.status, 403);
    assert.equal(off.json.error.code, 'model_disabled');
    assert.equal((await call('GET', '/v1/catalogue', { device: tokens.B })).json.models.length, 0);
    assert.equal((await call('PATCH', `/admin/api/models/${ids['good-a']}`, { owner: true, body: { enabled: true } })).status, 200);
    assert.equal((await chat(tokens.B, ids['good-a'])).status, 200);
    assert.equal((await call('PUT', `/admin/api/devices/${deviceIds.B}/models`, { owner: true, body: { modelAccess: 'selected', modelIds: [] } })).status, 200);
    assert.equal((await chat(tokens.B, ids['good-a'])).status, 404);
    assert.equal((await call('PUT', `/admin/api/devices/${deviceIds.B}/models`, { owner: true, body: { modelAccess: 'all' } })).status, 200);
    assert.equal((await chat(tokens.B, ids['good-b'])).status, 200, 'back to all models');
  });

  test('device usage shows only that device', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const b = await call('GET', '/v1/usage', { device: tokens.B });
    assert.equal(b.status, 200);
    const names = b.json.models.map((m: any) => m.modelName);
    assert.ok(names.length > 0);
    assert.ok(!names.includes('No-list model'), 'A-only traffic is not visible to B');
    assert.equal((await call('GET', '/v1/usage')).status, 401);
  });

  test('access changes are validated and owner-only', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const bad = await call('PUT', `/admin/api/devices/${deviceIds.B}/models`, { owner: true, body: { modelAccess: 'selected', modelIds: [crypto.randomUUID()] } });
    assert.equal(bad.status, 400);
    assert.equal((await call('PUT', `/admin/api/devices/${deviceIds.B}/models`, { owner: true, body: { modelAccess: 'some' } })).status, 400);
    const anon = await fetch(`${base}/admin/api/devices/${deviceIds.B}/models`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: '{"modelAccess":"all"}' });
    assert.equal(anon.status, 401);
    const asDevice = await fetch(`${base}/admin/api/devices/${deviceIds.B}/models`, { headers: { authorization: `Bearer ${tokens.B}` } });
    assert.equal(asDevice.status, 401);
  });
});
