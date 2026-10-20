// Operations tests: persistent rate limits, device request leases, idempotency keys, request IDs, and owner-only health.
// Real PostgreSQL (skipped without a test cluster). Each suite creates its own database and drops it afterwards.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { createTestDb, SKIP_NO_PG, type TestDb } from './helpers.ts';
import { Db } from '../src/db/pg-wire.ts';
import { loadMigrations, migrateUp } from '../src/db/migrate.ts';
import { loadConfig } from '../src/config.ts';
import { createServer } from '../src/app.ts';
import { hashPassword, randomToken, sha256Hex } from '../src/crypto.ts';
import { acquireSlot, hitRate, releaseSlot } from '../src/persistent-limits.ts';

const KEYRING = `1=${crypto.randomBytes(32).toString('base64')}`;
const ADMIN_ORIGIN = 'https://admin.example.test';
const OWNER_EMAIL = 'owner@example.test';
const OWNER_PASSWORD = 'correct horse battery staple';

let tdb: TestDb | null = null;

before(async () => {
  tdb = await createTestDb();
  if (tdb) await migrateUp(tdb.db, loadMigrations());
});

after(async () => {
  await tdb?.drop();
});

async function newDevice(db: Db, name: string): Promise<{ id: string; token: string }> {
  const token = randomToken(32);
  const { rows } = await db.query('INSERT INTO devices (name, token_hash) VALUES ($1, $2) RETURNING id', [name, sha256Hex(token)]);
  return { id: rows[0].id, token };
}

describe('persistent rate limits', () => {
  test('counts are shared across connections and survive a restart', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const first = new Db(tdb.config, 2);
    const key = `rl:${crypto.randomUUID()}`;
    try {
      assert.equal((await hitRate(first, key, 3, 60)).allowed, true);
      assert.equal((await hitRate(first, key, 3, 60)).allowed, true);
      assert.equal((await hitRate(first, key, 3, 60)).allowed, true);
      const blocked = await hitRate(first, key, 3, 60);
      assert.equal(blocked.allowed, false);
      assert.ok(blocked.retryAfterSeconds >= 1 && blocked.retryAfterSeconds <= 60);
    } finally {
      await first.close();
    }
    // A second pool stands in for a restarted process: the count is still there.
    const restarted = new Db(tdb.config, 2);
    try {
      assert.equal((await hitRate(restarted, key, 3, 60)).allowed, false);
    } finally {
      await restarted.close();
    }
  });

  test('concurrent hits never exceed the limit', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const key = `rl-burst:${crypto.randomUUID()}`;
    const results = await Promise.all(Array.from({ length: 20 }, () => hitRate(tdb!.db, key, 5, 60)));
    assert.equal(results.filter((r) => r.allowed).length, 5);
  });
});

describe('device request leases', () => {
  test('a device runs at most the configured number of requests, and a finished request frees its slot', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const dev = await newDevice(tdb.db, 'slots-a');
    const ids = Array.from({ length: 6 }, () => crypto.randomUUID());
    const outcomes = await Promise.all(
      ids.map((id) => acquireSlot(tdb!.db, { deviceId: dev.id, requestId: id, clientRequestId: null, maxConcurrent: 2, leaseSeconds: 900 })),
    );
    assert.equal(outcomes.filter((o) => o === 'ok').length, 2);
    assert.equal(outcomes.filter((o) => o === 'busy').length, 4);
    const winner = ids[outcomes.indexOf('ok')];
    await releaseSlot(tdb.db, winner);
    const again = await acquireSlot(tdb.db, { deviceId: dev.id, requestId: crypto.randomUUID(), clientRequestId: null, maxConcurrent: 2, leaseSeconds: 900 });
    assert.equal(again, 'ok');
  });

  test("one device's requests do not use another device's slots", async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const a = await newDevice(tdb.db, 'iso-a');
    const b = await newDevice(tdb.db, 'iso-b');
    for (let i = 0; i < 2; i++) {
      assert.equal(await acquireSlot(tdb.db, { deviceId: a.id, requestId: crypto.randomUUID(), clientRequestId: null, maxConcurrent: 2, leaseSeconds: 900 }), 'ok');
    }
    assert.equal(await acquireSlot(tdb.db, { deviceId: a.id, requestId: crypto.randomUUID(), clientRequestId: null, maxConcurrent: 2, leaseSeconds: 900 }), 'busy');
    assert.equal(await acquireSlot(tdb.db, { deviceId: b.id, requestId: crypto.randomUUID(), clientRequestId: null, maxConcurrent: 2, leaseSeconds: 900 }), 'ok');
  });

  test('a lease left behind by a crashed request expires and frees the slot', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const dev = await newDevice(tdb.db, 'crash');
    await tdb.db.query(
      `INSERT INTO device_request_leases (device_id, request_id, expires_at) VALUES ($1, 'crashed', now() - interval '1 second'), ($1, 'crashed-2', now() + interval '10 minutes')`,
      [dev.id],
    );
    // One live lease and one expired one: with a limit of 2 the device still has room for one more.
    assert.equal(await acquireSlot(tdb.db, { deviceId: dev.id, requestId: crypto.randomUUID(), clientRequestId: null, maxConcurrent: 2, leaseSeconds: 900 }), 'ok');
    assert.equal(await acquireSlot(tdb.db, { deviceId: dev.id, requestId: crypto.randomUUID(), clientRequestId: null, maxConcurrent: 2, leaseSeconds: 900 }), 'busy');
  });

  test('a repeated Idempotency-Key is refused while it is in flight and after it completed', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const dev = await newDevice(tdb.db, 'idem');
    const key = 'idem-' + crypto.randomUUID();
    const req = () => ({ deviceId: dev.id, requestId: crypto.randomUUID(), clientRequestId: key, maxConcurrent: 4, leaseSeconds: 900 });
    const rid = crypto.randomUUID();
    assert.equal(await acquireSlot(tdb.db, { ...req(), requestId: rid }), 'ok');
    assert.equal(await acquireSlot(tdb.db, req()), 'duplicate');
    await releaseSlot(tdb.db, rid);
    // Completed: the usage row exists, so a retry is still refused (it must not run twice).
    await tdb.db.query(
      `INSERT INTO request_logs (device_id, model_name, provider_name, status, http_status, latency_ms, usage_source, request_id, client_request_id)
       VALUES ($1, 'm', 'p', 'ok', 200, 5, 'none', $2, $3)`,
      [dev.id, crypto.randomUUID(), key],
    );
    assert.equal(await acquireSlot(tdb.db, req()), 'duplicate');
    // The same key on a different device is a different request.
    const other = await newDevice(tdb.db, 'idem-other');
    assert.equal(await acquireSlot(tdb.db, { ...req(), deviceId: other.id }), 'ok');
  });

  test('a duplicate usage row for one key is rejected by the database', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const dev = await newDevice(tdb.db, 'unique');
    const key = 'uniq-' + crypto.randomUUID();
    const insert = `INSERT INTO request_logs (device_id, model_name, provider_name, status, http_status, latency_ms, usage_source, client_request_id)
       VALUES ($1, 'm', 'p', 'ok', 200, 5, 'none', $2) ON CONFLICT DO NOTHING`;
    const a = await tdb.db.query(insert, [dev.id, key]);
    const b = await tdb.db.query(insert, [dev.id, key]);
    assert.equal(a.rowCount, 1);
    assert.equal(b.rowCount, 0);
  });
});

describe('HTTP: request IDs, owner-only health, device checks', () => {
  let server: Server;
  let base = '';
  let ownerCookie = '';
  let devToken = '';
  let devId = '';

  before(async () => {
    if (!tdb) return;
    await tdb.db.query('INSERT INTO owners (email, password_hash) VALUES ($1, $2)', [OWNER_EMAIL, await hashPassword(OWNER_PASSWORD)]);
    const pw = encodeURIComponent(tdb.config.password);
    const config = loadConfig({
      DEVORA_ENV: 'development',
      DATABASE_URL: `postgres://${tdb.config.user}:${pw}@${tdb.config.host}:${tdb.config.port}/${tdb.config.database}`,
      DEVORA_SECRET_KEYS: KEYRING,
      DEVORA_SECRET_ACTIVE_KEY: '1',
      ADMIN_ORIGIN,
      COOKIE_SECURE: 'false',
    });
    server = createServer({ db: tdb.db, config, fetch: globalThis.fetch });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const login = await fetch(base + '/admin/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: OWNER_EMAIL, password: OWNER_PASSWORD }),
    });
    ownerCookie = (login.headers.get('set-cookie') ?? '').split(';')[0];
    const dev = await newDevice(tdb.db, 'http-device');
    devToken = dev.token;
    devId = dev.id;
  });

  after(async () => {
    server?.closeAllConnections?.();
    await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  });

  test('every response carries a server-generated request id', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const a = await fetch(base + '/healthz');
    const b = await fetch(base + '/healthz');
    const ida = a.headers.get('x-request-id') ?? '';
    const idb = b.headers.get('x-request-id') ?? '';
    assert.match(ida, /^[0-9a-f-]{36}$/);
    assert.notEqual(ida, idb);
  });

  test('the health view is refused without an owner session and for a device token', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    assert.equal((await fetch(base + '/admin/api/health')).status, 401);
    const asDevice = await fetch(base + '/admin/api/health', { headers: { authorization: `Bearer ${devToken}` } });
    assert.equal(asDevice.status, 401);
  });

  test('the owner health view reports real state and never returns secret values', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await fetch(base + '/admin/api/health', { headers: { cookie: ownerCookie } });
    assert.equal(res.status, 200);
    const text = await res.text();
    const body = JSON.parse(text);
    assert.equal(body.database.ok, true);
    assert.equal(body.database.schemaVersion, 3);
    assert.equal(body.database.pendingMigrations, 0);
    assert.equal(body.configuration.secretKeyringConfigured, true);
    assert.equal(body.activity.rateLimitStore, 'database');
    assert.ok(!text.includes(KEYRING.split('=')[1]), 'keyring must not appear in the response');
    assert.ok(!text.includes(tdb.config.password), 'database password must not appear in the response');
  });

  test('chat refuses a malformed Idempotency-Key before any work is done', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const res = await fetch(base + '/v1/chat/completions', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${devToken}`, 'idempotency-key': 'bad key!' },
      body: JSON.stringify({}),
    });
    assert.equal(res.status, 400);
    assert.match(res.headers.get('x-request-id') ?? '', /^[0-9a-f-]{36}$/);
  });

  test('chat answers 409 for a repeated Idempotency-Key from the same device', async (t) => {
    if (!tdb) return t.skip(SKIP_NO_PG);
    const key = 'http-' + crypto.randomUUID();
    await tdb.db.query(
      `INSERT INTO request_logs (device_id, model_name, provider_name, status, http_status, latency_ms, usage_source, client_request_id)
       VALUES ($1, 'm', 'p', 'ok', 200, 5, 'none', $2)`,
      [devId, key],
    );
    const res = await fetch(base + '/v1/chat/completions', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${devToken}`, 'idempotency-key': key },
      body: JSON.stringify({}),
    });
    assert.equal(res.status, 409);
    const body = (await res.json()) as any;
    assert.equal(body.error.code, 'duplicate_request');
  });
});
