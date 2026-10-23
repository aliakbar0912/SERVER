#!/usr/bin/env node
// Entry point for the backend: serve, migrate, create-owner, healthcheck.
// Usage (after `npm run build` in server/):
//   node dist/cli.mjs serve
//   node dist/cli.mjs migrate status | up | down --steps 1
//   DEVORA_OWNER_EMAIL=... DEVORA_OWNER_PASSWORD=... node dist/cli.mjs create-owner
//   node dist/cli.mjs healthcheck
//   node dist/cli.mjs create-database   (creates DATABASE_NAME on the server if it does not exist)
//   node dist/cli.mjs redis-check       (connects with REDIS_URL, reports whether a password is needed and accepted)
import { PocketBase } from './pocketbase.ts';
import { accountMaintenance } from './modules/sessions.ts';
import http from 'node:http';
import { createServer } from './app.ts';
import { hashPassword } from './crypto.ts';
import { configWarnings, loadConfig, redactedConfig } from './config.ts';
import { Db } from './db/pg-wire.ts';
import { loadMigrations, migrateDown, migrateUp, migrationStatus } from './db/migrate.ts';
import { log } from './http/util.ts';
import { pruneLogs } from './modules/admin-data.ts';
import { pruneRates } from './persistent-limits.ts';
import { DatabaseLimitStore, RedisLimitStore, type LimitStore } from './limits.ts';
import { Redis } from './redis.ts';
import { scheduledDiscovery } from './modules/registry.ts';

const HOUR = 3_600_000;

function usage(): never {
  process.stderr.write(
    [
      'usage:',
      '  serve                         start the API (refuses to start if migrations are pending)',
      '  migrate status                list applied and pending migrations',
      '  migrate up                    apply pending migrations',
      '  migrate down [--steps N]      revert the latest N migrations (default 1)',
      '  create-owner                  create the single owner (email and password from the environment)',
      '  create-database               create the configured database if it does not exist yet',
      '  redis-check                   test REDIS_URL: connection, password, round trip',
      '  healthcheck                   query the local /readyz (used by the container health check)',
      '',
    ].join('\n'),
  );
  process.exit(2);
}

async function serve(): Promise<void> {
  const config = loadConfig();
  log('info', 'configuration', redactedConfig(config));
  for (const w of configWarnings(config)) log('warn', w);
  const db = new Db(config.database, config.poolSize);
  const status = await migrationStatus(db);
  if (status.pending.length) {
    log('error', 'database migrations are pending; run "migrate up" before starting the server', { pending: status.pending.map((p) => p.name) });
    await db.close();
    process.exit(1);
  }
  const owners = await db.query('SELECT count(*)::int AS n FROM owners');
  if (owners.rows[0].n === 0) log('warn', 'no owner exists yet; run create-owner before using the admin website');

  let redis: Redis | null = null;
  let limits: LimitStore = new DatabaseLimitStore(db);
  if (config.redis) {
    redis = new Redis(config.redis, (level, msg, fields) => log(level, msg, fields));
    try {
      await redis.ping();
    } catch (e) {
      // Configured but unreachable: refuse to start rather than silently running without shared limits.
      log('error', 'redis is configured but unavailable; fix REDIS_URL or the Redis service', { target: redis.target, reason: e instanceof Error ? e.message : 'unknown' });
      await redis.close();
      await db.close();
      process.exit(1);
    }
    limits = new RedisLimitStore(redis, config.redisKeyPrefix);
  }
  log('info', 'runtime state store', { store: limits.kind, redis: redis?.target ?? null });

  // One PocketBase client for the HTTP server and the background jobs (it caches the superuser sign-in).
  const pocketbase = config.pocketbase ? new PocketBase(config.pocketbase, globalThis.fetch) : null;
  const server = createServer({ db, config, limits, redis, fetch: globalThis.fetch, pocketbase });
  await new Promise<void>((resolve) => server.listen(config.port, config.host, resolve));
  log('info', 'devora backend listening', { port: config.port, env: config.env, schemaVersion: status.currentVersion });

  // With several replicas, a Redis lock lets only one of them run each clean-up. The jobs are idempotent either way.
  const prune = async () => {
    try {
      const n = await limits.withLock('prune-logs', 10 * 60_000, () => pruneLogs(db, config.logRetentionDays));
      if (n) log('info', 'pruned old request logs', { deleted: n, retentionDays: config.logRetentionDays });
    } catch (e) {
      log('error', 'log pruning failed', { error: e instanceof Error ? e.name : 'unknown' });
    }
  };
  void prune();
  const timer = setInterval(prune, 6 * HOUR);
  timer.unref();
  const pruneCounters = async () => {
    try {
      await limits.withLock('prune-rates', 10 * 60_000, () => pruneRates(db));
    } catch (e) {
      log('error', 'rate counter pruning failed', { error: e instanceof Error ? e.name : 'unknown' });
    }
  };
  const countersTimer = setInterval(pruneCounters, HOUR);
  countersTimer.unref();

  // Refreshes provider model lists in the background. New models arrive disabled; nothing is exposed automatically.
  const deps = { db, config, limits, redis, fetch: globalThis.fetch, pocketbase };
  // Finishes interrupted account deletions and clears expired browser sign-ins.
  const accountJob = () => limits.withLock('account-maintenance', 5 * 60_000, () => accountMaintenance(deps)).catch((e) => log('error', 'account maintenance failed', { error: e instanceof Error ? e.name : 'unknown' }));
  const accountTimer = setInterval(accountJob, 10 * 60_000);
  accountTimer.unref();
  setTimeout(accountJob, 30_000).unref();
  const discover = () => scheduledDiscovery(deps).catch((e) => log('error', 'scheduled discovery failed', { error: e instanceof Error ? e.name : 'unknown' }));
  let discoveryTimer: NodeJS.Timeout | null = null;
  let firstDiscovery: NodeJS.Timeout | null = null;
  if (config.discoveryIntervalHours > 0) {
    firstDiscovery = setTimeout(discover, 60_000);
    firstDiscovery.unref();
    discoveryTimer = setInterval(discover, config.discoveryIntervalHours * HOUR);
    discoveryTimer.unref();
  }

  const stop = async (signal: string) => {
    log('info', 'shutting down', { signal });
    clearInterval(timer);
    clearInterval(countersTimer);
    clearInterval(accountTimer);
    if (discoveryTimer) clearInterval(discoveryTimer);
    if (firstDiscovery) clearTimeout(firstDiscovery);
    const closed = new Promise<void>((r) => server.close(() => r()));
    const deadline = new Promise<void>((r) => setTimeout(r, 20_000).unref());
    await Promise.race([closed, deadline]);
    server.closeAllConnections?.();
    await redis?.close();
    await db.close();
    process.exit(0);
  };
  process.on('SIGTERM', () => void stop('SIGTERM'));
  process.on('SIGINT', () => void stop('SIGINT'));
}

async function migrate(args: string[]): Promise<void> {
  const config = loadConfig();
  const db = new Db(config.database, 2);
  try {
    const [sub, ...rest] = args;
    if (sub === 'status') {
      const s = await migrationStatus(db);
      process.stdout.write(JSON.stringify(s, null, 2) + '\n');
    } else if (sub === 'up') {
      const done = await migrateUp(db, loadMigrations());
      process.stdout.write(done.length ? `applied: ${done.join(', ')}\n` : 'database is up to date\n');
    } else if (sub === 'down') {
      const i = rest.indexOf('--steps');
      const steps = i >= 0 ? Number(rest[i + 1]) : 1;
      const done = await migrateDown(db, steps, loadMigrations());
      process.stdout.write(done.length ? `reverted: ${done.join(', ')}\n` : 'nothing to revert\n');
    } else {
      usage();
    }
  } finally {
    await db.close();
  }
}

async function createOwner(): Promise<void> {
  const config = loadConfig();
  const email = (process.env.DEVORA_OWNER_EMAIL ?? '').trim().toLowerCase();
  const password = process.env.DEVORA_OWNER_PASSWORD ?? '';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) throw new Error('set DEVORA_OWNER_EMAIL to a valid email address');
  if (password.length < 12 || password.length > 256) throw new Error('set DEVORA_OWNER_PASSWORD (12 to 256 characters)');
  const db = new Db(config.database, 2);
  try {
    const { rows } = await db.query('SELECT count(*)::int AS n FROM owners');
    if (rows[0].n > 0) throw new Error('an owner already exists; this server supports one owner');
    await db.query('INSERT INTO owners (email, password_hash) VALUES ($1, $2)', [email, await hashPassword(password)]);
    process.stdout.write(`owner created: ${email}\n`);
  } finally {
    await db.close();
  }
}

async function createDatabase(): Promise<void> {
  const config = loadConfig();
  const name = config.database.database;
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(name)) throw new Error('DATABASE_NAME may contain only letters, digits and underscores');
  const db = new Db({ ...config.database, database: 'postgres' }, 1);
  try {
    const { rows } = await db.query('SELECT 1 FROM pg_database WHERE datname = $1', [name]);
    if (rows.length) {
      process.stdout.write(`database "${name}" already exists\n`);
      return;
    }
    await db.query(`CREATE DATABASE "${name}"`);
    process.stdout.write(`database "${name}" created\n`);
  } finally {
    await db.close();
  }
}

async function redisCheck(): Promise<void> {
  const config = loadConfig();
  if (!config.redis) throw new Error('REDIS_URL is not set');
  const redis = new Redis(config.redis);
  try {
    const ms = await redis.ping();
    const info = String(await redis.command('INFO', 'server'));
    const version = /redis_version:([^\r\n]+)/.exec(info)?.[1] ?? 'unknown';
    process.stdout.write(
      `redis ok: ${redis.target}, version ${version}, round trip ${ms} ms, ` +
        `${config.redis.password ? 'password accepted' : 'no password configured and none required'}, ${config.redis.tls ? 'TLS' : 'no TLS'}\n`,
    );
  } finally {
    await redis.close();
  }
}

function healthcheck(): Promise<void> {
  const port = Number(process.env.PORT ?? 8080);
  return new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port, path: '/readyz', timeout: 4000 }, (res) => {
      res.resume();
      if (res.statusCode === 200) resolve();
      else reject(new Error(`readyz returned ${res.statusCode}`));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

async function main(): Promise<void> {
  const [cmd, ...args] = process.argv.slice(2);
  switch (cmd) {
    case 'serve':
      return serve();
    case 'migrate':
      return migrate(args);
    case 'create-owner':
      return createOwner();
    case 'create-database':
      return createDatabase();
    case 'redis-check':
      return redisCheck();
    case 'healthcheck':
      return healthcheck();
    default:
      return usage();
  }
}

main().catch((e) => {
  process.stderr.write(`error: ${e instanceof Error ? e.message : String(e)}\n`);
  process.exit(1);
});
