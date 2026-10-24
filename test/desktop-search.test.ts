// End to end: the desktop core learns from the catalogue that web search is on, and the agent's web_search tool gets
// results through the real API server (the search provider itself is a fake upstream).
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
import { hashPassword, sealSecret, parseKeyring } from '../src/crypto.ts';
import { loadMigrations, migrateUp } from '../src/db/migrate.ts';
import { AppCore } from '../../src/core/app-core.ts';
import { MemorySecretStore } from '../../src/core/secrets.ts';
import { webSearchTool } from '../../src/core/tools/other-tools.ts';

let tdb: TestDb | null = null;
let server: Server;
let base = '';
const KEYS = `1=${crypto.randomBytes(32).toString('base64')}`;
const upstream: typeof fetch = async (input) => {
  const u = new URL(String(input));
  if (u.hostname === 'api.search.brave.com')
    return new Response(JSON.stringify({ web: { results: [{ title: 'Electron 44 release notes', url: 'https://www.electronjs.org/blog/electron-44-0', description: 'What is new in Electron 44' }] } }), { status: 200, headers: { 'content-type': 'application/json' } });
  return fetch(input);
};

before(async () => {
  tdb = await createTestDb();
  if (!tdb) return;
  await migrateUp(tdb.db, loadMigrations());
  await tdb.db.query('INSERT INTO owners (email, password_hash) VALUES ($1, $2)', ['owner@example.test', await hashPassword('correct horse battery staple')]);
  const { rows } = await tdb.db.query("INSERT INTO search_providers (name, kind, is_default) VALUES ('Brave', 'brave', true) RETURNING id");
  const sealed = sealSecret(parseKeyring(KEYS, '1'), 'test-key-123456', `search_provider:${rows[0].id}`);
  await tdb.db.query('INSERT INTO search_provider_secrets (provider_id, key_version, iv, ciphertext, tag) VALUES ($1, $2, $3, $4, $5)', [rows[0].id, sealed.keyVersion, sealed.iv, sealed.ciphertext, sealed.tag]);
  server = createServer({
    db: tdb.db,
    config: loadConfig({
      DEVORA_ENV: 'development',
      DATABASE_URL: `postgres://${tdb.config.user}:${encodeURIComponent(tdb.config.password)}@${tdb.config.host}:${tdb.config.port}/${tdb.config.database}`,
      DEVORA_SECRET_KEYS: KEYS,
      DEVORA_SECRET_ACTIVE_KEY: '1',
      ADMIN_ORIGIN: 'https://admin.example.test',
      COOKIE_SECURE: 'false',
    }),
    fetch: upstream,
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  server?.closeAllConnections?.();
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  await tdb?.drop();
});

test('the agent web_search tool returns results through the server', async (t) => {
  if (!tdb) return t.skip(SKIP_NO_PG);
  const core = new AppCore({
    kind: 'harness',
    dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'devora-search-')),
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
  try {
    assert.equal(core.central.webSearchAvailable(), false, 'off until the catalogue says so');
    await core.centralRefresh();
    assert.equal(core.central.webSearchAvailable(), true);
    const offered = core.registry.available({ hasWorkspace: false, webResearch: true, webSearch: core.central.webSearchAvailable(), preview: false }).map((x) => x.name);
    assert.ok(offered.includes('web_search'));
    assert.ok(!core.registry.available({ hasWorkspace: false, webResearch: false, webSearch: true, preview: false }).some((x) => x.name === 'web_search'), 'only with web research on');
    const services = { webSearch: (q: string, c: number, s: AbortSignal) => core.central.webSearch(q, c, s), webSearchAvailable: () => core.central.webSearchAvailable() };
    const asked: string[] = [];
    const r = await webSearchTool.execute({ query: 'electron 44 release notes', count: 3 } as any, { services, signal: new AbortController().signal, authorize: async (x: any) => (asked.push(x.title), true) } as any);
    assert.equal(r.ok, true);
    assert.match(r.content, /<untrusted_search_results/);
    assert.match(r.content, /https:\/\/www\.electronjs\.org\/blog\/electron-44-0/);
    assert.equal(asked.length, 1, 'the user is asked (or has always-allowed) before a search is sent');
  } finally {
    core.central.stopAutoSync();
  }
});
