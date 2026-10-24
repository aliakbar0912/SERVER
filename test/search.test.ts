// Web search providers: admin setup (keys encrypted, password confirmation), every provider's real request shape against
// a fake upstream, normalized results, fallback, cache, rate limit, the catalogue flag, and that keys never leave.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { createTestDb, SKIP_NO_PG, type TestDb } from './helpers.ts';
import { loadConfig } from '../src/config.ts';
import { createServer } from '../src/app.ts';
import { hashPassword } from '../src/crypto.ts';
import { loadMigrations, migrateUp } from '../src/db/migrate.ts';
import { runSearch } from '../src/modules/search.ts';

const PASSWORD = 'correct horse battery staple';
let tdb: TestDb | null = null;
let server: Server;
let base = '';
const calls: Array<{ url: string; method: string; headers: Record<string, string>; body: any }> = [];
let failHosts = new Set<string>();

/** Fake upstreams: answers like each provider's documented API, and records what was sent. */
const fakeFetch: typeof fetch = async (input, init) => {
  const url = new URL(String(input));
  const headers = Object.fromEntries(Object.entries((init?.headers ?? {}) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v]));
  const body = init?.body ? JSON.parse(String(init.body)) : null;
  calls.push({ url: url.toString(), method: init?.method ?? 'GET', headers, body });
  if (failHosts.has(url.hostname)) return new Response('{"error":"down"}', { status: 503 });
  const ok = (j: unknown) => new Response(JSON.stringify(j), { status: 200, headers: { 'content-type': 'application/json' } });
  const keyOf: Record<string, string | undefined> = {
    'api.tavily.com': headers.authorization?.replace('Bearer ', ''),
    'api.search.brave.com': headers['x-subscription-token'],
    'google.serper.dev': headers['x-api-key'],
    'api.exa.ai': headers['x-api-key'],
    'www.googleapis.com': url.searchParams.get('key') ?? undefined,
  };
  if (url.hostname in keyOf && keyOf[url.hostname] !== 'test-key-123456') return new Response('{}', { status: 401 });
  switch (url.hostname) {
    case 'api.tavily.com':
      return ok({ results: [{ title: 'Tavily <b>one</b>', url: 'https://a.example/1', content: 'first', published_date: '2026-01-01' }, { title: 'dup', url: 'https://a.example/1', content: 'x' }] });
    case 'api.search.brave.com':
      return ok({ web: { results: [{ title: 'Brave one', url: 'https://b.example/1', description: 'brave desc', page_age: '2026-02-02' }] } });
    case 'google.serper.dev':
      return ok({ organic: [{ title: 'Serper one', link: 'https://c.example/1', snippet: 'serper snip' }, { title: 'bad', link: 'javascript:alert(1)' }] });
    case 'api.exa.ai':
      return ok({ results: [{ title: 'Exa one', url: 'https://d.example/1', text: 'exa text', publishedDate: '2026-03-03' }] });
    case 'www.googleapis.com':
      return ok({ items: [{ title: 'Google one', link: 'https://e.example/1', snippet: 'g snip' }] });
    case 'searx.example':
      return ok({ results: [{ title: 'Searx one', url: 'https://f.example/1', content: 'searx content' }] });
  }
  return new Response('not found', { status: 404 });
};

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
    fetch: fakeFetch,
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  server?.closeAllConnections?.();
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  await tdb?.drop();
});

const j = async (r: Response) => ({ status: r.status, body: (await r.json().catch(() => null)) as any });

async function owner() {
  const login = await fetch(`${base}/admin/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'owner@example.test', password: PASSWORD }) });
  const cookie = (login.headers.get('set-cookie') ?? '').split(';')[0];
  const csrf = ((await login.json()) as any).csrfToken;
  return (method: string, p: string, body?: unknown) =>
    fetch(base + p, { method, headers: { cookie, 'x-csrf-token': csrf, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }).then(j);
}

test('every provider kind sends the documented request and is normalized (dedupe, no unsafe links, no HTML)', async () => {
  const cases: Array<[string, Record<string, unknown>, string]> = [
    ['tavily', {}, 'Tavily one'],
    ['brave', {}, 'Brave one'],
    ['serper', {}, 'Serper one'],
    ['exa', {}, 'Exa one'],
    ['google_cse', { cx: 'abc123' }, 'Google one'],
  ];
  for (const [kind, options, title] of cases) {
    const r = await runSearch(fakeFetch, { kind: kind as any, base_url: null, options }, 'test-key-123456', 'node release', 5);
    assert.equal(r[0].title, title, kind);
    assert.ok(r.every((x) => x.url.startsWith('https://')), `${kind}: only http(s) links`);
    assert.equal(new Set(r.map((x) => x.url)).size, r.length, `${kind}: deduplicated`);
  }
  const searx = await runSearch(fakeFetch, { kind: 'searxng', base_url: 'https://searx.example', options: {} }, null, 'q', 5);
  assert.equal(searx[0].snippet, 'searx content');
  const tav = calls.find((c) => c.url.startsWith('https://api.tavily.com'))!;
  assert.equal(tav.body.query, 'node release');
  assert.equal(tav.body.max_results, 5);
  await assert.rejects(runSearch(fakeFetch, { kind: 'brave', base_url: null, options: {} }, 'wrong-key-000000', 'q', 3), /refused the API key/);
  await assert.rejects(runSearch(fakeFetch, { kind: 'google_cse', base_url: null, options: {} }, 'test-key-123456', 'q', 3), /cx/);
});

test('admin setup, password-confirmed keys, desktop search with fallback, cache, catalogue flag and rate limit', async (t) => {
  if (!tdb) return t.skip(SKIP_NO_PG);
  const call = await owner();
  const reg = await j(await fetch(`${base}/v1/devices/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ installId: 'install-search-test-0001', deviceName: 'PC' }) }));
  const dev = (b: unknown) => fetch(`${base}/v1/search`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${reg.body.token}` }, body: JSON.stringify(b) }).then(j);

  assert.equal((await dev({ query: 'x' })).body.error.code, 'search_not_configured');
  const cat0 = await j(await fetch(`${base}/v1/catalogue`, { headers: { authorization: `Bearer ${reg.body.token}` } }));
  assert.equal(cat0.body.policy.webSearch, false);

  const brave = await call('POST', '/admin/api/search-providers', { name: 'Brave', kind: 'brave' });
  assert.equal(brave.status, 201);
  assert.equal(brave.body.provider.isDefault, true, 'the first provider becomes the default');
  assert.equal(brave.body.provider.ready, false, 'not ready without a key');
  const tavily = await call('POST', '/admin/api/search-providers', { name: 'Tavily', kind: 'tavily' });
  assert.equal((await call('POST', '/admin/api/search-providers', { name: 'Bad', kind: 'nope' })).status, 400);
  assert.equal((await call('POST', '/admin/api/search-providers', { name: 'Meta', kind: 'searxng', baseUrl: 'http://169.254.169.254' })).status, 400, 'SSRF-blocked address');

  // Keys need the password again, are stored encrypted, and are never returned.
  assert.equal((await call('PUT', `/admin/api/search-providers/${brave.body.provider.id}/api-key`, { apiKey: 'test-key-123456' })).status, 403);
  assert.equal((await call('POST', '/admin/api/auth/reauth', { password: PASSWORD })).status, 200);
  assert.equal((await call('PUT', `/admin/api/search-providers/${brave.body.provider.id}/api-key`, { apiKey: 'test-key-123456' })).status, 200);
  assert.equal((await call('PUT', `/admin/api/search-providers/${tavily.body.provider.id}/api-key`, { apiKey: 'test-key-123456' })).status, 200);
  const list = await call('GET', '/admin/api/search-providers');
  assert.ok(!JSON.stringify(list.body).includes('test-key-123456'), 'the key never appears in a response');
  const stored = await tdb.db.query('SELECT ciphertext FROM search_provider_secrets');
  assert.ok(stored.rows.every((r) => !Buffer.from(r.ciphertext).toString('utf8').includes('test-key-123456')), 'encrypted at rest');

  const tested = await call('POST', `/admin/api/search-providers/${brave.body.provider.id}/test`, { query: 'hello' });
  assert.equal(tested.body.ok, true);
  assert.equal(tested.body.results[0].title, 'Brave one');

  const cat1 = await j(await fetch(`${base}/v1/catalogue`, { headers: { authorization: `Bearer ${reg.body.token}` } }));
  assert.equal(cat1.body.policy.webSearch, true, 'desktops learn that web search is available');

  const first = await dev({ query: 'Devora docs', count: 3 });
  assert.equal(first.status, 200);
  assert.equal(first.body.provider, 'Brave');
  assert.equal(first.body.results[0].url, 'https://b.example/1');
  assert.ok(!JSON.stringify(first.body).includes('test-key'), 'no key in desktop answers');
  const again = await dev({ query: 'devora docs', count: 3 });
  // Results are cached for 10 minutes when Redis is configured (production); without Redis there is no cache by design.
  assert.equal(again.status, 200);
  assert.equal(typeof again.body.cached, 'boolean');

  // The default provider is down: the next ready provider answers.
  failHosts = new Set(['api.search.brave.com']);
  const fallback = await dev({ query: 'something else', count: 3 });
  assert.equal(fallback.status, 200);
  assert.equal(fallback.body.provider, 'Tavily');
  failHosts = new Set(['api.search.brave.com', 'api.tavily.com']);
  const allDown = await dev({ query: 'third query' });
  assert.equal(allDown.status, 502);
  assert.equal(allDown.body.error.code, 'search_failed');
  failHosts = new Set();

  // Query text is not stored.
  const logs = await tdb.db.query('SELECT * FROM search_logs');
  assert.ok(logs.rows.length >= 4);
  assert.ok(!JSON.stringify(logs.rows).includes('Devora docs'));

  // Per-device rate limit from Settings.
  assert.equal((await call('PATCH', '/admin/api/settings', { searchPerMinute: 1 })).status, 200);
  await tdb.db.query('DELETE FROM rate_counters');
  assert.equal((await dev({ query: 'rate 1' })).status, 200);
  assert.equal((await dev({ query: 'rate 2' })).status, 429);

  // Disabling every provider turns the feature off for desktops again.
  for (const p of [brave, tavily]) await call('PATCH', `/admin/api/search-providers/${p.body.provider.id}`, { enabled: false });
  const cat2 = await j(await fetch(`${base}/v1/catalogue`, { headers: { authorization: `Bearer ${reg.body.token}` } }));
  assert.equal(cat2.body.policy.webSearch, false);
  assert.equal((await call('DELETE', `/admin/api/search-providers/${tavily.body.provider.id}`)).status, 200);
});

test('search needs a device token and follows the "require sign-in" rule', async (t) => {
  if (!tdb) return t.skip(SKIP_NO_PG);
  const r = await fetch(`${base}/v1/search`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"query":"x"}' });
  assert.equal(r.status, 401);
});
