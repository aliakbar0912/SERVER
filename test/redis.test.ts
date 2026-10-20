// Redis integration tests against a real Redis server. Set DEVORA_TEST_REDIS_URL (for example redis://:PASSWORD@127.0.0.1:6379/15)
// to a disposable Redis; the tests only touch keys under a random prefix and delete them afterwards. Without it they are skipped.
// The API part also needs the PostgreSQL test cluster (see helpers.ts).
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { parseRedisUrl, Redis, RedisUnavailableError, type RedisConfig } from '../src/redis.ts';
import { RedisLimitStore } from '../src/limits.ts';
import { loadConfig } from '../src/config.ts';
import { createServer } from '../src/app.ts';
import { hashPassword } from '../src/crypto.ts';
import { loadMigrations, migrateUp } from '../src/db/migrate.ts';
import { createTestDb, type TestDb } from './helpers.ts';

const URL_ = process.env.DEVORA_TEST_REDIS_URL ?? '';
const SKIP = 'no Redis test server configured (set DEVORA_TEST_REDIS_URL)';
const PREFIX = `devora-test-${crypto.randomBytes(4).toString('hex')}`;

function cfg(over: Partial<RedisConfig> = {}): RedisConfig {
  return { ...parseRedisUrl(URL_), ...over };
}

/** A port with nothing listening on it. */
async function deadPort(): Promise<number> {
  const s = net.createServer();
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  const port = (s.address() as AddressInfo).port;
  await new Promise<void>((r) => s.close(() => r()));
  return port;
}

async function rejectsWith(p: Promise<unknown>, code: string): Promise<RedisUnavailableError> {
  try {
    await p;
  } catch (e) {
    assert.ok(e instanceof RedisUnavailableError, `expected RedisUnavailableError, got ${e}`);
    assert.equal(e.code, code, e.message);
    return e;
  }
  assert.fail(`expected ${code}`);
}

let admin: Redis | null = null;

before(async () => {
  if (URL_) admin = new Redis(cfg());
});

after(async () => {
  if (!admin) return;
  // Remove everything these tests created.
  const keys = (await admin.command('KEYS', `${PREFIX}*`)) as string[];
  if (keys.length) await admin.command('DEL', ...keys);
  await admin.close();
});

describe('REDIS_URL parsing', () => {
  test('accepts redis:// and rediss:// with username, password and database', () => {
    const c = parseRedisUrl('redis://default:s%40cret@ali-redis-database-ufuu6q:6379/2');
    assert.deepEqual([c.host, c.port, c.username, c.password, c.db, c.tls], ['ali-redis-database-ufuu6q', 6379, 'default', 's@cret', 2, false]);
    assert.equal(parseRedisUrl('rediss://h').tls, true);
    assert.equal(parseRedisUrl('redis://h').password, null);
  });

  test('rejects bad values without echoing the password', () => {
    for (const bad of ['http://x', 'redis://:pw@h:99999', 'redis://:topsecret@h/99', 'not a url']) {
      assert.throws(() => parseRedisUrl(bad), (e: Error) => !e.message.includes('topsecret'));
    }
  });

  test('loadConfig wires REDIS_URL and the key prefix', () => {
    const base = { DATABASE_URL: 'postgres://u:p@h/d' };
    assert.equal(loadConfig(base).redis, null);
    const c = loadConfig({ ...base, REDIS_URL: 'redis://default:pw@redis:6379/0', REDIS_KEY_PREFIX: 'prod' });
    assert.equal(c.redis?.host, 'redis');
    assert.equal(c.redisKeyPrefix, 'prod');
    assert.throws(() => loadConfig({ ...base, REDIS_KEY_PREFIX: 'has space' }), /REDIS_KEY_PREFIX/);
  });
});

describe('Redis client against a real server', () => {
  test('connects, authenticates and answers PING', async (t) => {
    if (!admin) return t.skip(SKIP);
    const ms = await admin.ping();
    assert.ok(ms >= 0);
    assert.equal(admin.connected, true);
    assert.equal(admin.target.includes('@'), false, 'target must not contain credentials');
  });

  test('a server that needs a password reports it clearly when none is given', async (t) => {
    if (!admin) return t.skip(SKIP);
    if (!cfg().password) return t.skip('the test Redis has no password');
    const r = new Redis(cfg({ password: null, username: null }));
    await rejectsWith(r.ping(), 'redis_auth_required');
    await r.close();
  });

  test('a wrong password is rejected and never appears in the error', async (t) => {
    if (!admin) return t.skip(SKIP);
    if (!cfg().password) return t.skip('the test Redis has no password');
    const r = new Redis(cfg({ password: 'definitely-wrong-pw' }));
    const e = await rejectsWith(r.ping(), 'redis_auth_failed');
    assert.equal(e.message.includes('definitely-wrong-pw'), false);
    await r.close();
  });

  test('an unreachable server fails fast, then backs off without reconnecting on every call', async (t) => {
    if (!admin) return t.skip(SKIP);
    const r = new Redis(cfg({ host: '127.0.0.1', port: await deadPort(), connectTimeoutMs: 1000 }));
    await rejectsWith(r.ping(), 'redis_unavailable');
    const t0 = Date.now();
    const e = await rejectsWith(r.ping(), 'redis_unavailable');
    assert.ok(Date.now() - t0 < 50, 'second call should fail immediately during backoff');
    assert.match(e.message, /retrying in/);
    await r.close();
  });

  test('a command that does not answer in time fails with a timeout and the client recovers', async (t) => {
    if (!admin) return t.skip(SKIP);
    const r = new Redis(cfg({ commandTimeoutMs: 200 }));
    await r.ping();
    // BLPOP blocks for 1 s on an empty list, longer than the 200 ms command timeout.
    await rejectsWith(r.command('BLPOP', `${PREFIX}:empty`, 1), 'redis_timeout');
    assert.ok((await r.ping()) >= 0, 'the next command reconnects');
    await r.close();
  });

  test('a dropped connection is re-established on the next command', async (t) => {
    if (!admin) return t.skip(SKIP);
    const r = new Redis(cfg());
    await r.command('CLIENT', 'SETNAME', `${PREFIX}-victim`);
    const list = String(await admin.command('CLIENT', 'LIST'));
    const id = /id=(\d+) [^\n]*name=([^ ]+)/g;
    let victim = '';
    for (const m of list.matchAll(id)) if (m[2] === `${PREFIX}-victim`) victim = m[1];
    assert.ok(victim, 'found the client to kill');
    await admin.command('CLIENT', 'KILL', 'ID', victim);
    // The kill may race the next write; whichever happens, the following command must succeed on a new connection.
    await r.ping().catch(() => undefined);
    assert.ok((await r.ping()) >= 0);
    await r.close();
  });

  test('close() quits gracefully and later commands are refused', async (t) => {
    if (!admin) return t.skip(SKIP);
    const r = new Redis(cfg());
    await r.ping();
    await r.close();
    assert.equal(r.connected, false);
    await rejectsWith(r.ping(), 'redis_closed');
  });
});

describe('Redis limit store', () => {
  test('rate limits are atomic under concurrency: exactly `limit` hits are allowed', async (t) => {
    if (!admin) return t.skip(SKIP);
    const store = new RedisLimitStore(admin, PREFIX);
    const results = await Promise.all(Array.from({ length: 40 }, () => store.hit('burst', 7, 30)));
    assert.equal(results.filter((r) => r.allowed).length, 7);
    const denied = results.find((r) => !r.allowed)!;
    assert.ok(denied.retryAfterSeconds >= 1 && denied.retryAfterSeconds <= 30);
    const ttl = (await admin.command('PTTL', `${PREFIX}:rl:burst`)) as number;
    assert.ok(ttl > 0 && ttl <= 30_000, 'the window expires on its own');
  });

  test('clear() resets a counter', async (t) => {
    if (!admin) return t.skip(SKIP);
    const store = new RedisLimitStore(admin, PREFIX);
    for (let i = 0; i < 3; i++) await store.hit('login', 2, 60);
    assert.equal((await store.hit('login', 2, 60)).allowed, false);
    await store.clear('login');
    assert.equal((await store.hit('login', 2, 60)).allowed, true);
  });

  test('the cache stores JSON with an expiry', async (t) => {
    if (!admin) return t.skip(SKIP);
    const store = new RedisLimitStore(admin, PREFIX);
    assert.equal(await store.cacheGet('nothing'), null);
    await store.cacheSet('obj', { a: 1, b: ['x'] }, 60);
    assert.deepEqual(await store.cacheGet('obj'), { a: 1, b: ['x'] });
    const ttl = (await admin.command('TTL', `${PREFIX}:cache:obj`)) as number;
    assert.ok(ttl > 0 && ttl <= 60);
  });

  test('locks are exclusive, released after use, and expire if the holder dies', async (t) => {
    if (!admin) return t.skip(SKIP);
    const store = new RedisLimitStore(admin, PREFIX);
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const first = store.withLock('job', 5000, async () => {
      await gate;
      return 'first';
    });
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(await store.withLock('job', 5000, async () => 'second'), null, 'a held lock is not taken twice');
    release();
    assert.equal(await first, 'first');
    assert.equal(await store.withLock('job', 5000, async () => 'third'), 'third', 'released after use');

    // A lock left by a crashed process expires.
    await admin.command('SET', `${PREFIX}:lock:stale`, 'someone-else', 'PX', 150);
    assert.equal(await store.withLock('stale', 1000, async () => 'x'), null);
    await new Promise((r) => setTimeout(r, 250));
    assert.equal(await store.withLock('stale', 1000, async () => 'y'), 'y');
  });

  test('a lock holder never deletes a lock that another process took after expiry', async (t) => {
    if (!admin) return t.skip(SKIP);
    const store = new RedisLimitStore(admin, PREFIX);
    await store.withLock('handover', 100, async () => {
      await new Promise((r) => setTimeout(r, 200)); // our lock expires meanwhile
      await admin!.command('SET', `${PREFIX}:lock:handover`, 'other-holder', 'PX', 5000);
    });
    assert.equal(await admin.command('GET', `${PREFIX}:lock:handover`), 'other-holder');
  });
});

describe('API server with Redis', () => {
  const OWNER_EMAIL = 'owner@example.test';
  const OWNER_PASSWORD = 'correct horse battery staple';
  let tdb: TestDb | null = null;
  let server: Server;
  let downServer: Server;
  let base = '';
  let downBase = '';
  let redis: Redis;
  let downRedis: Redis;

  before(async () => {
    if (!admin) return;
    tdb = await createTestDb();
    if (!tdb) return;
    await migrateUp(tdb.db, loadMigrations());
    await tdb.db.query('INSERT INTO owners (email, password_hash) VALUES ($1, $2)', [OWNER_EMAIL, await hashPassword(OWNER_PASSWORD)]);
    const pw = encodeURIComponent(tdb.config.password);
    const env = {
      DEVORA_ENV: 'development',
      DATABASE_URL: `postgres://${tdb.config.user}:${pw}@${tdb.config.host}:${tdb.config.port}/${tdb.config.database}`,
      DEVORA_SECRET_KEYS: `1=${crypto.randomBytes(32).toString('base64')}`,
      DEVORA_SECRET_ACTIVE_KEY: '1',
      COOKIE_SECURE: 'false',
      REDIS_URL: URL_,
      REDIS_KEY_PREFIX: PREFIX,
    };
    const config = loadConfig(env);
    redis = new Redis(config.redis!);
    server = createServer({ db: tdb.db, config, limits: new RedisLimitStore(redis, PREFIX), redis, fetch: globalThis.fetch });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    // The same API with Redis configured but unreachable.
    downRedis = new Redis({ ...config.redis!, host: '127.0.0.1', port: await deadPort(), connectTimeoutMs: 500 });
    downServer = createServer({ db: tdb.db, config, limits: new RedisLimitStore(downRedis, PREFIX), redis: downRedis, fetch: globalThis.fetch });
    await new Promise<void>((r) => downServer.listen(0, '127.0.0.1', r));
    downBase = `http://127.0.0.1:${(downServer.address() as AddressInfo).port}`;
  });

  after(async () => {
    for (const s of [server, downServer]) {
      if (!s) continue;
      s.closeAllConnections?.();
      await new Promise<void>((r) => s.close(() => r()));
    }
    await redis?.close();
    await downRedis?.close();
    await tdb?.drop();
  });

  const skip = (t: { skip: (m: string) => void }) => {
    if (!admin) return t.skip(SKIP), true;
    if (!tdb) return t.skip('no PostgreSQL test cluster configured'), true;
    return false;
  };

  async function post(b: string, path: string, body: unknown, headers: Record<string, string> = {}) {
    const res = await fetch(b + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
    return { status: res.status, headers: res.headers, json: (await res.json().catch(() => null)) as any };
  }

  test('readiness checks Redis', async (t) => {
    if (skip(t)) return;
    const ok = await fetch(`${base}/readyz`);
    assert.equal(ok.status, 200);
    const down = await fetch(`${downBase}/readyz`);
    assert.equal(down.status, 503);
    assert.equal(((await down.json()) as any).reason, 'redis is unavailable');
  });

  test('login attempts are counted in Redis and limited per IP', async (t) => {
    if (skip(t)) return;
    let last = 0;
    for (let i = 0; i < 21; i++) last = (await post(base, '/admin/api/auth/login', { email: 'nobody@example.test', password: 'x' })).status;
    assert.equal(last, 429);
    const keys = (await admin!.command('KEYS', `${PREFIX}:rl:login:ip:*`)) as string[];
    assert.equal(keys.length, 1);
    // A different store (PostgreSQL) never saw these hits: the API really used Redis.
    const { rows } = await tdb!.db.query("SELECT count(*)::int AS n FROM rate_counters WHERE key LIKE 'login:%'");
    assert.equal(rows[0].n, 0);
    await admin!.command('DEL', ...keys);
  });

  test('when Redis is down, limited routes answer 503 with a clean JSON error', async (t) => {
    if (skip(t)) return;
    const res = await post(downBase, '/v1/devices/register', { installId: 'redis-down-install-0000', deviceName: 'x' });
    assert.equal(res.status, 503);
    assert.equal(res.json.error.code, 'service_unavailable');
    assert.equal(res.headers.get('retry-after'), '5');
    assert.equal(JSON.stringify(res.json).includes('127.0.0.1'), false, 'no internal details leak');
  });

  test('the owner health view reports Redis, and the catalogue is cached by version', async (t) => {
    if (skip(t)) return;
    await admin!.command('DEL', ...(((await admin!.command('KEYS', `${PREFIX}:rl:*`)) as string[]).concat(`${PREFIX}:none`)));
    const login = await post(base, '/admin/api/auth/login', { email: OWNER_EMAIL, password: OWNER_PASSWORD });
    assert.equal(login.status, 200);
    const cookie = (login.headers.get('set-cookie') ?? '').split(';')[0];

    const health = (await (await fetch(`${base}/admin/api/health`, { headers: { cookie } })).json()) as any;
    assert.equal(health.redis.configured, true);
    assert.equal(health.redis.ok, true);
    assert.equal(health.activity.rateLimitStore, 'redis');
    assert.equal(String(health.redis.target).includes('@'), false);

    // The down instance reports Redis as down, with the API still answering.
    const downLogin = await fetch(`${downBase}/admin/api/health`, { headers: { cookie } });
    const down = (await downLogin.json()) as any;
    assert.equal(down.status, 'down');
    assert.equal(down.redis.ok, false);
    assert.equal(down.activity.rateLimitStore, 'unavailable');

    const enrolled = await post(base, '/v1/devices/register', { installId: 'redis-test-install-0000', deviceName: 'redis test' });
    assert.equal(enrolled.status, 201);
    const cat = await fetch(`${base}/v1/catalogue`, { headers: { authorization: `Bearer ${enrolled.json.token}` } });
    assert.equal(cat.status, 200);
    const version = ((await cat.json()) as any).version;
    const cached = await admin!.command('GET', `${PREFIX}:cache:catalogue:v${version}`);
    assert.equal(typeof cached, 'string');
    assert.equal(JSON.parse(cached as string).version, version);
  });
});
