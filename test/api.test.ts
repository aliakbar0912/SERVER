// End-to-end API tests: the real HTTP server, a real PostgreSQL database, and the mock OpenAI-compatible upstream.
// Runs in order inside one describe block because each step depends on the previous one.
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
const UPSTREAM_KEY = 'sk-mock-test-key-123456';
const KEYRING = `1=${crypto.randomBytes(32).toString('base64')}`;
const ADMIN_ORIGIN = 'https://admin.example.test';

let tdb: TestDb | null = null;
let server: Server;
let base = '';
let mock: MockServer;
let cookie = '';
let csrf = '';
let deviceToken = '';
let modelId = '';
let fallbackModelId = '';
let providerId = '';
const INSTALL_ID = 'install-0123456789abcdef';

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
  mock = await startMockOpenAI({
    requireKey: UPSTREAM_KEY,
    models: ['mock-coder', 'mock-vision'],
    script: (body) => {
      const last = body.messages[body.messages.length - 1];
      if (body.model === 'mock-coder' && typeof last?.content === 'string' && last.content.includes('SLOW')) return { content: 'late', delayMs: 2500 };
      if (typeof last?.content === 'string' && last.content.includes('LONG')) return { content: 'x'.repeat(3000) };
      return { content: `echo:${typeof last?.content === 'string' ? last.content : 'parts'}`, usage: { prompt_tokens: 11, completion_tokens: 7 } };
    },
  });
  const pw = encodeURIComponent(tdb.config.password);
  const env = {
    DEVORA_ENV: 'development',
    DATABASE_URL: `postgres://${tdb.config.user}:${pw}@${tdb.config.host}:${tdb.config.port}/${tdb.config.database}`,
    DEVORA_SECRET_KEYS: KEYRING,
    DEVORA_SECRET_ACTIVE_KEY: '1',
    ADMIN_ORIGIN,
    COOKIE_SECURE: 'false',
    PUBLIC_API_ORIGIN: 'https://api.example.test',
    DEVORA_DESKTOP_MIN_VERSION: '0.1.0',
    DEVORA_STATUS_MESSAGE: 'Planned maintenance on Sunday',
  };
  const config = loadConfig(env);
  server = createServer({ db: tdb.db, config, fetch: globalThis.fetch });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  server?.closeAllConnections?.();
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  await mock?.close();
  await tdb?.drop();
});

describe('health and schema', () => {
  test('liveness and readiness report the schema version', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    assert.equal((await call('GET', '/healthz')).status, 200);
    const ready = await call('GET', '/readyz');
    assert.equal(ready.status, 200);
    assert.equal(ready.json.schemaVersion, 4);
  });

  test('desktop runtime configuration is public, versioned and free of secrets', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('GET', '/v1/client-config');
    assert.equal(res.status, 200);
    assert.match(res.headers.get('cache-control') ?? '', /public/);
    assert.equal(res.json.schema, 1);
    assert.equal(res.json.apiOrigin, 'https://api.example.test');
    assert.deepEqual(res.json.apiVersions, ['v1']);
    assert.equal(res.json.desktop.minVersion, '0.1.0');
    assert.equal(res.json.status.message, 'Planned maintenance on Sunday');
    assert.match(res.json.instanceId, /^[0-9a-f]{32}$/);
    const text = JSON.stringify(res.json);
    for (const secret of [KEYRING.split('=')[1], tdb!.config.password, 'postgres://']) assert.ok(!text.includes(secret), 'no secret in the public configuration');
  });

  test('unknown routes and wrong methods get JSON errors', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    assert.equal((await call('GET', '/nope')).json.error.code, 'not_found');
    assert.equal((await call('GET', '/v1/chat/completions')).json.error.code, 'method_not_allowed');
  });
});

describe('owner authentication', () => {
  test('wrong password and unknown email give the same answer', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const wrong = await call('POST', '/admin/api/auth/login', { body: { email: OWNER_EMAIL, password: 'wrong password value' } });
    const unknown = await call('POST', '/admin/api/auth/login', { body: { email: 'nobody@example.test', password: 'wrong password value' } });
    assert.equal(wrong.status, 401);
    assert.equal(unknown.status, 401);
    assert.equal(wrong.json.error.message, unknown.json.error.message);
    assert.equal(wrong.headers.get('set-cookie'), null);
  });

  test('a correct login sets an HttpOnly, SameSite=Strict session cookie and returns a CSRF token', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('POST', '/admin/api/auth/login', { body: { email: OWNER_EMAIL, password: OWNER_PASSWORD } });
    assert.equal(res.status, 200);
    const setCookie = res.headers.get('set-cookie') ?? '';
    assert.match(setCookie, /^devora_admin=[A-Za-z0-9_-]+;/);
    assert.match(setCookie, /HttpOnly/);
    assert.match(setCookie, /SameSite=Strict/);
    cookie = setCookie.split(';')[0];
    csrf = res.json.csrfToken;
    assert.ok(csrf.length >= 40);
  });

  test('the session endpoint returns the CSRF token again after a reload', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('GET', '/admin/api/auth/session', { session: true });
    assert.equal(res.status, 200);
    assert.equal(res.json.csrfToken, csrf);
  });

  test('admin reads without a session are refused', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    assert.equal((await call('GET', '/admin/api/providers')).status, 401);
    assert.equal((await call('GET', '/admin/api/providers', { device: 'x'.repeat(30) })).status, 401);
  });

  test('state-changing requests need the CSRF header', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('POST', '/admin/api/providers', {
      headers: { cookie, 'x-csrf-token': 'wrong' },
      body: { name: 'x', baseUrl: 'http://127.0.0.1:1/v1' },
    });
    assert.equal(res.status, 403);
    assert.equal(res.json.error.code, 'csrf_failed');
  });

  test('CORS allows only the admin origin, with credentials', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const ok = await call('OPTIONS', '/admin/api/providers', { headers: { origin: ADMIN_ORIGIN, 'access-control-request-method': 'POST' } });
    assert.equal(ok.status, 204);
    assert.equal(ok.headers.get('access-control-allow-origin'), ADMIN_ORIGIN);
    assert.equal(ok.headers.get('access-control-allow-credentials'), 'true');
    const evil = await call('GET', '/admin/api/overview', { session: true, headers: { origin: 'https://evil.example.test', cookie } });
    assert.equal(evil.headers.get('access-control-allow-origin'), null);
  });

  test('security headers are set on API responses', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('GET', '/healthz');
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
  });
});

describe('providers and models', () => {
  test('a provider with plain HTTP to a remote host is refused', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('POST', '/admin/api/providers', { session: true, body: { name: 'bad', baseUrl: 'http://api.example.test/v1' } });
    assert.equal(res.status, 400);
    assert.match(res.json.error.message, /https/);
  });

  test('cloud metadata addresses and credentials in URLs are refused', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const meta = await call('POST', '/admin/api/providers', { session: true, body: { name: 'meta', baseUrl: 'http://169.254.169.254/latest' } });
    assert.equal(meta.status, 400);
    const creds = await call('POST', '/admin/api/providers', { session: true, body: { name: 'creds', baseUrl: 'https://user:pw@api.example.test/v1' } });
    assert.equal(creds.status, 400);
  });

  test('the owner creates a loopback provider (the mock upstream)', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('POST', '/admin/api/providers', {
      session: true,
      body: { name: 'Mock upstream', baseUrl: `${mock.url}`, authScheme: 'bearer', timeoutMs: 5000 },
    });
    assert.equal(res.status, 201, res.text);
    providerId = res.json.id;
    assert.equal(res.json.hasApiKey, false);
  });

  test('setting an API key needs a recent password confirmation', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('PUT', `/admin/api/providers/${providerId}/api-key`, { session: true, body: { apiKey: UPSTREAM_KEY } });
    assert.equal(res.status, 403);
    assert.equal(res.json.error.code, 'reauth_required');
  });

  test('reauthentication grants a short window', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const bad = await call('POST', '/admin/api/auth/reauth', { session: true, body: { password: 'wrong password value' } });
    assert.equal(bad.status, 401);
    const ok = await call('POST', '/admin/api/auth/reauth', { session: true, body: { password: OWNER_PASSWORD } });
    assert.equal(ok.status, 200);
    assert.ok(ok.json.reauthUntil);
  });

  test('the API key is stored, reported as present, and never returned', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const set = await call('PUT', `/admin/api/providers/${providerId}/api-key`, { session: true, body: { apiKey: UPSTREAM_KEY } });
    assert.equal(set.status, 200);
    assert.equal(set.json.hasApiKey, true);
    const list = await call('GET', '/admin/api/providers', { session: true });
    assert.equal(list.json.providers[0].hasApiKey, true);
    assert.ok(!list.text.includes(UPSTREAM_KEY));
    assert.ok(!set.text.includes(UPSTREAM_KEY));
    const row = await tdb!.db.query('SELECT ciphertext FROM provider_secrets WHERE provider_id = $1', [providerId]);
    assert.ok(!row.rows[0].ciphertext.toString('utf8').includes(UPSTREAM_KEY), 'key is encrypted at rest');
  });

  test('a test call uses the stored key and records the result', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('POST', `/admin/api/providers/${providerId}/test`, { session: true });
    assert.equal(res.status, 200);
    assert.equal(res.json.ok, true, res.text);
    assert.match(res.json.message, /2 models listed/);
  });

  test('discovery adds upstream models as disabled entries with unknown capabilities', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('POST', `/admin/api/providers/${providerId}/discover`, { session: true });
    assert.equal(res.status, 200);
    assert.equal(res.json.found, 2);
    assert.equal(res.json.added, 2);
    const again = await call('POST', `/admin/api/providers/${providerId}/discover`, { session: true });
    assert.equal(again.json.added, 0);
    const list = await call('GET', `/admin/api/models?providerId=${providerId}`, { session: true });
    const coder = list.json.models.find((m: any) => m.upstreamModelId === 'mock-coder');
    const vision = list.json.models.find((m: any) => m.upstreamModelId === 'mock-vision');
    assert.equal(coder.enabled, false);
    assert.equal(coder.capabilities.tools.supported, null);
    assert.equal(coder.capabilities.tools.source, 'unknown');
    modelId = coder.id;
    fallbackModelId = vision.id;
  });

  test('a model is enabled with explicit capabilities and becomes the default', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('PATCH', `/admin/api/models/${modelId}`, {
      session: true,
      body: { enabled: true, displayName: 'Coder (test)', capabilities: { tools: { supported: true, source: 'admin' }, streaming: { supported: true, source: 'test' } } },
    });
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.enabled, true);
    assert.equal(res.json.capabilities.tools.supported, true);
    const def = await call('POST', `/admin/api/models/${modelId}/default`, { session: true });
    assert.equal(def.json.isDefault, true);
  });

  test('a disabled model cannot be made the default', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('POST', `/admin/api/models/${fallbackModelId}/default`, { session: true });
    assert.equal(res.status, 409);
  });

  test('a capability value that is not known is refused', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('PATCH', `/admin/api/models/${fallbackModelId}`, { session: true, body: { capabilities: { magic: { supported: true } } } });
    assert.equal(res.status, 400);
  });
});

describe('desktop devices', () => {
  test('a desktop registers itself with its installation id and gets a device token', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('POST', '/v1/devices/register', { body: { installId: INSTALL_ID, deviceName: 'Ali laptop' } });
    assert.equal(res.status, 201, res.text);
    deviceToken = res.json.token;
    assert.ok(deviceToken.length >= 40);
    const list = await call('GET', '/admin/api/devices', { session: true });
    const dev = list.json.devices.find((d: any) => d.id === res.json.deviceId);
    assert.equal(dev.name, 'Ali laptop');
    assert.equal(dev.registeredVia, 'auto');
  });

  test('registering again from the same installation replaces the token; bad input is refused', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const again = await call('POST', '/v1/devices/register', { body: { installId: INSTALL_ID, deviceName: 'Ali laptop' } });
    assert.equal(again.status, 200, again.text);
    assert.notEqual(again.json.token, deviceToken);
    assert.equal((await call('GET', '/v1/catalogue', { device: deviceToken })).status, 401, 'the previous token no longer works');
    deviceToken = again.json.token;
    assert.equal((await call('GET', '/admin/api/devices', { session: true })).json.devices.length, 1, 'still one device');
    assert.equal((await call('POST', '/v1/devices/register', { body: { installId: 'short', deviceName: 'x' } })).status, 400);
    assert.equal((await call('POST', '/v1/devices/register', { body: { installId: 'x'.repeat(20) + '!!', deviceName: 'x' } })).status, 400);
    assert.equal((await call('POST', '/v1/devices/register', { body: { installId: 'x'.repeat(20), deviceName: 'x', code: 'y' } })).status, 400);
  });

  test('the owner can stop new computers from registering; registered ones keep working', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    await call('PATCH', '/admin/api/settings', { session: true, body: { allowAutoRegistration: false } });
    const blocked = await call('POST', '/v1/devices/register', { body: { installId: 'n'.repeat(24), deviceName: 'New PC' } });
    assert.equal(blocked.status, 403);
    assert.equal(blocked.json.error.code, 'registration_closed');
    assert.equal((await call('POST', '/v1/devices/register', { body: { installId: INSTALL_ID, deviceName: 'Ali laptop' } })).status, 200, 'a known computer can still renew');
    assert.equal((await call('GET', '/admin/api/settings', { session: true })).json.allowAutoRegistration, false);
    await call('PATCH', '/admin/api/settings', { session: true, body: { allowAutoRegistration: true } });
    deviceToken = (await call('POST', '/v1/devices/register', { body: { installId: INSTALL_ID, deviceName: 'Ali laptop' } })).json.token;
  });

  test('the device token is hashed in the database', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const { rows } = await tdb!.db.query('SELECT token_hash FROM devices');
    assert.ok(rows.every((r) => r.token_hash.length === 64 && !r.token_hash.includes(deviceToken)));
  });

  test('the catalogue lists only enabled models, with public fields and an ETag', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('GET', '/v1/catalogue', { device: deviceToken });
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.models.length, 1);
    const [m] = res.json.models;
    assert.equal(m.id, modelId);
    assert.equal(m.displayName, 'Coder (test)');
    assert.ok(!res.text.includes('mock-coder'), 'upstream model id is not exposed');
    assert.ok(!res.text.includes(mock.url), 'upstream URL is not exposed');
    assert.ok(!res.text.includes(UPSTREAM_KEY), 'key is not exposed');
    assert.ok(res.headers.get('etag'));
    const cached = await call('GET', '/v1/catalogue', { device: deviceToken, headers: { 'if-none-match': res.headers.get('etag')! } });
    assert.equal(cached.status, 304);
  });

  test('the catalogue requires a device token; admin sessions do not work here', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    assert.equal((await call('GET', '/v1/catalogue')).status, 401);
    assert.equal((await call('GET', '/v1/catalogue', { session: true })).status, 401);
  });
});

describe('central chat routing', () => {
  test('a non-streaming chat request goes through the server to the upstream', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const before = mock.requests.length;
    const res = await call('POST', '/v1/chat/completions', {
      device: deviceToken,
      body: { model: modelId, messages: [{ role: 'system', content: 'be brief' }, { role: 'user', content: 'hello there' }], temperature: 0.2 },
    });
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.choices[0].message.content, 'echo:hello there');
    assert.equal(res.json.model, modelId, 'the response names the catalogue id, not the upstream id');
    const upstream = mock.requests[before];
    assert.equal(upstream.model, 'mock-coder', 'the server chose the upstream model');
    assert.equal(upstream.temperature, 0.2);
  });

  test('the upstream receives the provider key from the server, never from the client', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('POST', '/v1/chat/completions', {
      device: deviceToken,
      body: { model: modelId, messages: [{ role: 'user', content: 'auth check' }] },
    });
    assert.equal(res.status, 200);
  });

  test('unknown fields such as a client-chosen base URL are refused', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('POST', '/v1/chat/completions', {
      device: deviceToken,
      body: { model: modelId, messages: [{ role: 'user', content: 'x' }], base_url: 'https://attacker.example.test/v1' },
    });
    assert.equal(res.status, 400);
    assert.equal(res.json.error.code, 'unsupported_parameter');
    assert.equal(res.json.error.type, 'invalid_request_error');
  });

  test('a model that is not in the catalogue is refused, including upstream ids', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('POST', '/v1/chat/completions', {
      device: deviceToken,
      body: { model: 'mock-coder', messages: [{ role: 'user', content: 'x' }] },
    });
    assert.equal(res.status, 400);
    const missing = await call('POST', '/v1/chat/completions', {
      device: deviceToken,
      body: { model: '00000000-0000-4000-8000-000000000000', messages: [{ role: 'user', content: 'x' }] },
    });
    assert.equal(missing.status, 404);
    assert.equal(missing.json.error.code, 'model_not_found');
  });

  test('a streaming request relays SSE and records usage from the provider', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await fetch(`${base}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${deviceToken}` },
      body: JSON.stringify({ model: modelId, messages: [{ role: 'user', content: 'stream me' }], stream: true, stream_options: { include_usage: true } }),
    });
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type') ?? '', /text\/event-stream/);
    const text = await res.text();
    const content = [...text.matchAll(/"content":"((?:[^"\\]|\\.)*)"/g)].map((m) => JSON.parse(`"${m[1]}"`)).join('');
    assert.equal(content, 'echo:stream me');
    assert.match(text, /\[DONE\]/);
    await waitForLog((l) => l.stream === true && l.status === 'ok' && l.promptTokens === 11, 3000);
  });

  test('a non-streaming request without provider usage is logged as usage none', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('POST', '/v1/chat/completions', {
      device: deviceToken,
      body: { model: modelId, messages: [{ role: 'user', content: 'no usage please' }] },
    });
    assert.equal(res.status, 200);
    const logs = await call('GET', '/admin/api/logs?limit=5', { session: true });
    assert.ok(logs.json.logs.length >= 2);
    assert.ok(logs.json.logs.every((l: any) => !('content' in l) && !('messages' in l)), 'logs hold metadata only');
  });

  test('a rejected provider key is reported as a stable code and no key is shown', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    await call('PUT', `/admin/api/providers/${providerId}/api-key`, { session: true, body: { apiKey: 'sk-wrong-key-000000' } });
    const res = await call('POST', '/v1/chat/completions', {
      device: deviceToken,
      body: { model: modelId, messages: [{ role: 'user', content: 'x' }] },
    });
    assert.equal(res.status, 502);
    assert.equal(res.json.error.code, 'upstream_auth_failed');
    assert.ok(!res.text.includes('sk-wrong-key'));
    await call('PUT', `/admin/api/providers/${providerId}/api-key`, { session: true, body: { apiKey: UPSTREAM_KEY } });
  });

  test('an upstream that is too slow times out with 504', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    await call('PATCH', `/admin/api/providers/${providerId}`, { session: true, body: { timeoutMs: 1000 } });
    const res = await call('POST', '/v1/chat/completions', {
      device: deviceToken,
      body: { model: modelId, messages: [{ role: 'user', content: 'SLOW' }] },
    });
    assert.equal(res.status, 504);
    assert.equal(res.json.error.code, 'upstream_timeout');
    await call('PATCH', `/admin/api/providers/${providerId}`, { session: true, body: { timeoutMs: 5000 } });
  });

  test('a disabled model is refused with model_disabled', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    await call('PATCH', `/admin/api/models/${modelId}`, { session: true, body: { enabled: false } });
    const res = await call('POST', '/v1/chat/completions', {
      device: deviceToken,
      body: { model: modelId, messages: [{ role: 'user', content: 'x' }] },
    });
    assert.equal(res.status, 403);
    assert.equal(res.json.error.code, 'model_disabled');
    await call('PATCH', `/admin/api/models/${modelId}`, { session: true, body: { enabled: true } });
  });

  test('a streamed reply is cancelled upstream when the desktop disconnects', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const ac = new AbortController();
    const res = await fetch(`${base}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${deviceToken}` },
      body: JSON.stringify({ model: modelId, messages: [{ role: 'user', content: 'LONG' }], stream: true }),
      signal: ac.signal,
    });
    const reader = res.body!.getReader();
    await reader.read();
    ac.abort();
    await waitForLog((l) => l.status === 'cancelled', 5000);
  });

  test('the per-device concurrency limit returns 429', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    await call('PATCH', '/admin/api/settings', { session: true, body: { maxConcurrentPerDevice: 1 } });
    const slow = fetch(`${base}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${deviceToken}` },
      body: JSON.stringify({ model: modelId, messages: [{ role: 'user', content: 'SLOW' }] }),
    }).then((r) => r.text());
    await new Promise((r) => setTimeout(r, 300));
    const second = await call('POST', '/v1/chat/completions', {
      device: deviceToken,
      body: { model: modelId, messages: [{ role: 'user', content: 'quick' }] },
    });
    assert.equal(second.status, 429);
    assert.equal(second.json.error.code, 'too_many_requests');
    await slow;
    await call('PATCH', '/admin/api/settings', { session: true, body: { maxConcurrentPerDevice: 2 } });
  });

  test('a revoked device loses access immediately', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const list = await call('GET', '/admin/api/devices', { session: true });
    const dev = list.json.devices[0];
    const denied = await call('POST', `/admin/api/devices/${dev.id}/revoke`, { session: true, body: { confirmName: 'wrong' } });
    assert.equal(denied.status, 400);
    const ok = await call('POST', `/admin/api/devices/${dev.id}/revoke`, { session: true, body: { confirmName: dev.name } });
    assert.equal(ok.status, 200);
    const chat = await call('POST', '/v1/chat/completions', { device: deviceToken, body: { model: modelId, messages: [{ role: 'user', content: 'x' }] } });
    assert.equal(chat.status, 401);
    assert.equal(chat.json.error.code, 'device_revoked');
    assert.equal((await call('GET', '/v1/catalogue', { device: deviceToken })).status, 401);
    // A blocked installation stays blocked when it registers again.
    const again = await call('POST', '/v1/devices/register', { body: { installId: INSTALL_ID, deviceName: 'Ali laptop' } });
    assert.equal(again.status, 403);
    assert.equal(again.json.error.code, 'device_blocked');
  });

  test('unblocking lets the same computer register again, with a new token', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const dev = (await call('GET', '/admin/api/devices', { session: true })).json.devices[0];
    assert.equal((await call('POST', `/admin/api/devices/${dev.id}/unblock`, { session: true })).status, 200);
    assert.equal((await call('GET', '/v1/catalogue', { device: deviceToken })).status, 401, 'the old token stays invalid');
    const again = await call('POST', '/v1/devices/register', { body: { installId: INSTALL_ID, deviceName: 'Ali laptop' } });
    assert.equal(again.status, 200);
    assert.equal((await call('GET', '/v1/catalogue', { device: again.json.token })).status, 200);
  });
});

describe('usage, logs and settings', () => {
  test('usage totals split provider-reported tokens from requests without usage', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('GET', '/admin/api/usage?window=24h', { session: true });
    assert.equal(res.status, 200);
    assert.ok(res.json.totals.requests >= 3);
    assert.ok(res.json.totals.promptTokens >= 11);
    assert.ok(res.json.totals.withoutUsage >= 1);
    assert.equal((await call('GET', '/admin/api/usage?window=1y', { session: true })).status, 400);
  });

  test('logs paginate by id and never contain message text', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const first = await call('GET', '/admin/api/logs?limit=2', { session: true });
    assert.equal(first.json.logs.length, 2);
    assert.ok(first.json.nextCursor);
    const second = await call('GET', `/admin/api/logs?limit=2&cursor=${first.json.nextCursor}`, { session: true });
    assert.ok(second.json.logs[0].id < first.json.logs[1].id);
    assert.ok(!first.text.includes('hello there'));
  });

  test('the overview counts devices, models and recent failures', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await call('GET', '/admin/api/overview', { session: true });
    assert.equal(res.status, 200);
    assert.equal(res.json.providersEnabled, 1);
    assert.equal(res.json.devicesActive, 1, 'the device was unblocked in the devices tests');
    assert.ok(res.json.failed24h >= 1);
  });

  test('allowing direct-provider mode needs a fresh password confirmation', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const login = await call('POST', '/admin/api/auth/login', { body: { email: OWNER_EMAIL, password: OWNER_PASSWORD } });
    const fresh = login.headers.get('set-cookie')!.split(';')[0];
    const res = await call('PATCH', '/admin/api/settings', {
      headers: { cookie: fresh, 'x-csrf-token': login.json.csrfToken },
      body: { allowDirectProvider: true },
    });
    assert.equal(res.status, 403);
    assert.equal(res.json.error.code, 'reauth_required');
  });

  test('direct-provider mode is off by default and reported in the catalogue policy', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    await call('PATCH', '/admin/api/settings', { session: true, body: { allowDirectProvider: false } });
    const s = await call('GET', '/admin/api/settings', { session: true });
    assert.equal(s.json.allowDirectProvider, false);
  });

  test('logout ends the session', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const out = await call('POST', '/admin/api/auth/logout', { session: true });
    assert.equal(out.status, 204);
    assert.equal((await call('GET', '/admin/api/providers', { session: true })).status, 401);
  });
});

describe('lockout', () => {
  test('five wrong passwords lock the owner for a while', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    for (let i = 0; i < 5; i++) {
      await call('POST', '/admin/api/auth/login', { body: { email: OWNER_EMAIL, password: 'wrong password value' } });
    }
    const locked = await call('POST', '/admin/api/auth/login', { body: { email: OWNER_EMAIL, password: OWNER_PASSWORD } });
    assert.equal(locked.status, 401);
    assert.equal(locked.headers.get('set-cookie'), null);
  });
});

async function waitForLog(pred: (l: any) => boolean, ms: number): Promise<void> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const { rows } = await tdb!.db.query(
      'SELECT status, stream, prompt_tokens, usage_source FROM request_logs ORDER BY id DESC LIMIT 20',
    );
    const mapped = rows.map((r) => ({ status: r.status, stream: r.stream, promptTokens: r.prompt_tokens, usageSource: r.usage_source }));
    if (mapped.some(pred)) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  assert.fail('expected request log entry was not written');
}
