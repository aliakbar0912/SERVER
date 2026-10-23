// Configuration comes only from environment variables, read here and nowhere else in the request path. Domains are
// placeholders in .env.example and are never hardcoded. Production refuses missing or unsafe values at startup.
import fs from 'node:fs';
import crypto from 'node:crypto';
import type { PgConfig } from './db/pg-wire.ts';
import { parseKeyring, type Keyring } from './crypto.ts';
import { parseRedisUrl, type RedisConfig } from './redis.ts';

export interface Config {
  env: 'development' | 'production';
  host: string;
  port: number;
  database: PgConfig;
  poolSize: number;
  /** Exact origin of the admin website, for CORS with credentials. Null means no browser origin is allowed. */
  adminOrigin: string | null;
  cookieSecure: boolean;
  trustProxy: boolean;
  keyring: Keyring;
  logRetentionDays: number;
  /** Public base URL of the API, announced to desktop apps in /v1/client-config. Optional. */
  publicApiOrigin: string | null;
  /** Redis for rate limits, cache and locks. Null means PostgreSQL holds the rate limits and there is no cache. */
  redis: RedisConfig | null;
  /** Prefix for every Redis key, so several environments can share one Redis safely. */
  redisKeyPrefix: string;
  /** Hours between automatic model-list refreshes of enabled providers. 0 turns it off. */
  discoveryIntervalHours: number;
  /** Settings that were present but ignored (development only), with the reason. Logged as warnings at startup. */
  ignoredSettings: string[];
  /** Longest time a request may take, including streamed chat responses (REQUEST_TIMEOUT_MS). */
  requestTimeoutMs: number;
  /** Longest time to receive request headers (HEADERS_TIMEOUT_MS). */
  headersTimeoutMs: number;
  /** Public, non-secret settings served to desktop apps at GET /v1/client-config. */
  desktop: DesktopReleaseConfig;
  /**
   * Stable, non-secret id of this deployment. A desktop app only moves to a new API domain when the new domain reports the
   * same id, so a changed domain can never point its device token at a different server.
   */
  instanceId: string;
  /** Devora accounts (PocketBase). Null = accounts are off: sign-in endpoints answer 503 and devices work as before. */
  pocketbase: PocketBaseConfig | null;
}

export interface PocketBaseConfig {
  /** Base URL of the PocketBase server (POCKETBASE_URL). https in production. */
  url: string;
  /** Auth collection holding Devora users (POCKETBASE_USERS_COLLECTION, default users). */
  usersCollection: string;
  /** A dedicated PocketBase superuser for this server only. Never sent to a desktop or to the admin website. */
  adminEmail: string;
  adminPassword: string;
}

export interface DesktopReleaseConfig {
  /** Oldest desktop version this server still supports (DEVORA_DESKTOP_MIN_VERSION), or null. */
  minVersion: string | null;
  /** Newest released desktop version (DEVORA_DESKTOP_LATEST_VERSION), or null. */
  latestVersion: string | null;
  /** https page where users download the installer (DEVORA_DESKTOP_DOWNLOAD_URL), or null. */
  downloadUrl: string | null;
  /** Short notice shown in the desktop app, for example planned maintenance (DEVORA_STATUS_MESSAGE). */
  statusMessage: string;
}

function bool(v: string | undefined, fallback: boolean): boolean {
  if (v === undefined || v === '') return fallback;
  if (['1', 'true', 'yes', 'on'].includes(v.toLowerCase())) return true;
  if (['0', 'false', 'no', 'off'].includes(v.toLowerCase())) return false;
  throw new Error(`expected true or false, got "${v}"`);
}

function int(v: string | undefined, fallback: number, min: number, max: number, name: string): number {
  if (v === undefined || v === '') return fallback;
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) throw new Error(`${name} must be an integer from ${min} to ${max}`);
  return n;
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/**
 * Validates an origin. A value still holding the YOUR_DOMAIN placeholder from .env.example is refused in production; in
 * development it is treated as unset (and reported through `ignored`), so a copied template never announces a fake address.
 */
function origin(v: string | undefined, name: string, production = false, ignored: string[] = []): string | null {
  if (!v) return null;
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    throw new Error(`${name} must be a URL such as https://admin.YOUR_DOMAIN`);
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error(`${name} must start with https://`);
  if (u.username || u.password) throw new Error(`${name} must not contain credentials`);
  if (u.pathname !== '/' || u.search || u.hash) throw new Error(`${name} must be an origin without a path`);
  if (!production && /YOUR_DOMAIN/i.test(u.hostname)) {
    ignored.push(`${name} still contains the YOUR_DOMAIN placeholder and is ignored; set a real address or remove the line`);
    return null;
  }
  if (production) {
    if (u.protocol !== 'https:') throw new Error(`${name} must use https in production`);
    if (LOOPBACK.has(u.hostname) || u.hostname.endsWith('.localhost')) throw new Error(`${name} must not be a local address in production`);
    if (/YOUR_DOMAIN/i.test(u.hostname)) throw new Error(`${name} still contains the YOUR_DOMAIN placeholder`);
  }
  return u.origin;
}

function httpsUrl(v: string | undefined, name: string): string | null {
  if (!v) return null;
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    throw new Error(`${name} must be an https URL`);
  }
  if (u.protocol !== 'https:' || u.username || u.password) throw new Error(`${name} must be an https URL without credentials`);
  return u.toString();
}

function version(v: string | undefined, name: string): string | null {
  if (!v) return null;
  if (!/^\d+\.\d+\.\d+$/.test(v)) throw new Error(`${name} must look like 1.2.3`);
  return v;
}

/** Resolves the environment name. NODE_ENV=production also means production, and the two may not disagree. */
function environment(env: NodeJS.ProcessEnv): 'development' | 'production' {
  const devora = env.DEVORA_ENV;
  if (devora && !['development', 'production'].includes(devora)) throw new Error('DEVORA_ENV must be development or production');
  if (devora === 'development' && env.NODE_ENV === 'production') {
    throw new Error('DEVORA_ENV=development conflicts with NODE_ENV=production; set DEVORA_ENV=production on a server');
  }
  return devora === 'production' || env.NODE_ENV === 'production' ? 'production' : 'development';
}

/** DEVORA_INSTANCE_ID, or an id derived from the lowest-numbered encryption key (stable across key rotation). */
function instanceId(env: NodeJS.ProcessEnv, keyring: Keyring): string {
  const explicit = env.DEVORA_INSTANCE_ID;
  if (explicit) {
    if (!/^[A-Za-z0-9_-]{8,64}$/.test(explicit)) throw new Error('DEVORA_INSTANCE_ID must be 8 to 64 letters, digits, _ or -');
    return explicit;
  }
  const first = [...keyring.keys.keys()].sort((a, b) => a - b)[0];
  if (first === undefined) return 'development';
  return crypto.createHmac('sha256', keyring.keys.get(first)!).update('devora-instance-id').digest('hex').slice(0, 32);
}

/** Reads DATABASE_URL (postgres://user:password@host:port/name) or the discrete DATABASE_* variables. */
export function parseDatabase(env: NodeJS.ProcessEnv, production: boolean): PgConfig {
  const sslDefault: 'disable' | 'require' = production ? 'require' : 'disable';
  let cfg: PgConfig;
  if (env.DATABASE_URL) {
    const u = new URL(env.DATABASE_URL);
    if (u.protocol !== 'postgres:' && u.protocol !== 'postgresql:') throw new Error('DATABASE_URL must start with postgres://');
    cfg = {
      host: decodeURIComponent(u.hostname),
      port: u.port ? Number(u.port) : 5432,
      user: decodeURIComponent(u.username),
      password: decodeURIComponent(u.password),
      database: decodeURIComponent(u.pathname.replace(/^\//, '')),
      ssl: sslDefault,
    };
    const mode = u.searchParams.get('sslmode');
    if (mode) {
      if (mode === 'disable') cfg.ssl = 'disable';
      else if (['require', 'verify-ca', 'verify-full'].includes(mode)) cfg.ssl = 'require';
      else throw new Error(`sslmode=${mode} is not supported; use disable or require`);
    }
  } else {
    cfg = {
      host: env.DATABASE_HOST ?? '',
      port: Number(env.DATABASE_PORT ?? 5432),
      user: env.DATABASE_USER ?? '',
      password: env.DATABASE_PASSWORD ?? '',
      database: env.DATABASE_NAME ?? '',
      ssl: sslDefault,
    };
  }
  if (env.DATABASE_SSL) {
    if (env.DATABASE_SSL !== 'disable' && env.DATABASE_SSL !== 'require') throw new Error('DATABASE_SSL must be disable or require');
    cfg.ssl = env.DATABASE_SSL;
  }
  if (!cfg.host || !cfg.user || !cfg.database) throw new Error('set DATABASE_URL, or DATABASE_HOST, DATABASE_USER, DATABASE_NAME and DATABASE_PASSWORD');
  if (!Number.isInteger(cfg.port) || cfg.port < 1 || cfg.port > 65535) throw new Error('database port is invalid');
  if (env.DATABASE_CA_FILE) {
    if (!fs.existsSync(env.DATABASE_CA_FILE)) throw new Error('DATABASE_CA_FILE does not exist');
    cfg.caFile = env.DATABASE_CA_FILE;
  }
  if (production && cfg.ssl === 'disable' && !env.DATABASE_ALLOW_PLAINTEXT_NETWORK) {
    throw new Error('production requires DATABASE_SSL=require, or DATABASE_ALLOW_PLAINTEXT_NETWORK=true when the database is on a private network only');
  }
  return cfg;
}

/** POCKETBASE_URL + a dedicated superuser. All three are needed: the server re-checks accounts with the superuser. */
function pocketbase(env: NodeJS.ProcessEnv, production: boolean): PocketBaseConfig | null {
  const raw = (env.POCKETBASE_URL ?? '').trim();
  const email = (env.POCKETBASE_ADMIN_EMAIL ?? '').trim();
  const password = env.POCKETBASE_ADMIN_PASSWORD ?? '';
  if (!raw) {
    if (email || password) throw new Error('POCKETBASE_ADMIN_EMAIL/POCKETBASE_ADMIN_PASSWORD are set but POCKETBASE_URL is not');
    return null;
  }
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error('POCKETBASE_URL must be a URL such as https://pocketbase.YOUR_DOMAIN');
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('POCKETBASE_URL must start with https://');
  if (u.username || u.password || u.search || u.hash) throw new Error('POCKETBASE_URL must not contain credentials, a query or a fragment');
  if (production && u.protocol !== 'https:') throw new Error('POCKETBASE_URL must use https in production');
  if (!email || !password) throw new Error('POCKETBASE_URL needs POCKETBASE_ADMIN_EMAIL and POCKETBASE_ADMIN_PASSWORD (a superuser dedicated to this server)');
  if (production && password.length < 12) throw new Error('POCKETBASE_ADMIN_PASSWORD is too short for production');
  const usersCollection = (env.POCKETBASE_USERS_COLLECTION ?? '').trim() || 'users';
  if (!/^[A-Za-z0-9_]{1,64}$/.test(usersCollection)) throw new Error('POCKETBASE_USERS_COLLECTION must be a collection name');
  return { url: u.toString().replace(/\/+$/, ''), usersCollection, adminEmail: email, adminPassword: password };
}

function redisPrefix(v: string | undefined): string {
  if (v === undefined || v === '') return 'devora';
  if (!/^[A-Za-z0-9_.-]{1,40}$/.test(v)) throw new Error('REDIS_KEY_PREFIX may contain only letters, digits, _ . - (up to 40)');
  return v;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const production = environment(env) === 'production';
  const cookieSecure = bool(env.COOKIE_SECURE, production);
  if (production && !cookieSecure) throw new Error('COOKIE_SECURE must be true in production');
  const keyring = parseKeyring(env.DEVORA_SECRET_KEYS ?? '', env.DEVORA_SECRET_ACTIVE_KEY ?? '');
  if (production && keyring.size === 0) throw new Error('DEVORA_SECRET_KEYS is required in production');
  const ignoredSettings: string[] = [];
  const adminOrigin = origin(env.ADMIN_ORIGIN, 'ADMIN_ORIGIN', production, ignoredSettings);
  if (production && !adminOrigin) throw new Error('ADMIN_ORIGIN is required in production (the https address of the admin website)');
  const statusMessage = (env.DEVORA_STATUS_MESSAGE ?? '').trim();
  if (statusMessage.length > 200) throw new Error('DEVORA_STATUS_MESSAGE may be at most 200 characters');
  const headersTimeoutMs = int(env.HEADERS_TIMEOUT_MS, 30_000, 1_000, 120_000, 'HEADERS_TIMEOUT_MS');
  const requestTimeoutMs = int(env.REQUEST_TIMEOUT_MS, 300_000, 10_000, 3_600_000, 'REQUEST_TIMEOUT_MS');
  if (requestTimeoutMs <= headersTimeoutMs) throw new Error('REQUEST_TIMEOUT_MS must be larger than HEADERS_TIMEOUT_MS');
  return {
    env: production ? 'production' : 'development',
    host: env.HOST || '0.0.0.0',
    port: int(env.PORT, 8080, 1, 65535, 'PORT'),
    database: parseDatabase(env, production),
    poolSize: int(env.DATABASE_POOL_SIZE, 10, 1, 50, 'DATABASE_POOL_SIZE'),
    adminOrigin,
    cookieSecure,
    trustProxy: bool(env.TRUST_PROXY, false),
    keyring,
    logRetentionDays: int(env.DEVORA_LOG_RETENTION_DAYS, 30, 1, 3650, 'DEVORA_LOG_RETENTION_DAYS'),
    publicApiOrigin: origin(env.PUBLIC_API_ORIGIN, 'PUBLIC_API_ORIGIN', production, ignoredSettings),
    redis: env.REDIS_URL ? parseRedisUrl(env.REDIS_URL, env) : null,
    redisKeyPrefix: redisPrefix(env.REDIS_KEY_PREFIX),
    discoveryIntervalHours: int(env.DEVORA_DISCOVERY_INTERVAL_HOURS, 12, 0, 168, 'DEVORA_DISCOVERY_INTERVAL_HOURS'),
    ignoredSettings,
    requestTimeoutMs,
    headersTimeoutMs,
    desktop: {
      minVersion: version(env.DEVORA_DESKTOP_MIN_VERSION, 'DEVORA_DESKTOP_MIN_VERSION'),
      latestVersion: version(env.DEVORA_DESKTOP_LATEST_VERSION, 'DEVORA_DESKTOP_LATEST_VERSION'),
      downloadUrl: httpsUrl(env.DEVORA_DESKTOP_DOWNLOAD_URL, 'DEVORA_DESKTOP_DOWNLOAD_URL'),
      statusMessage,
    },
    instanceId: instanceId(env, keyring),
    pocketbase: pocketbase(env, production),
  };
}

/** Production settings that are allowed but probably a mistake. Logged as warnings at startup. */
export function configWarnings(c: Config): string[] {
  const out: string[] = [...c.ignoredSettings];
  if (c.env === 'production' && !c.publicApiOrigin) out.push('PUBLIC_API_ORIGIN is not set: desktop apps cannot be moved to a new API domain automatically');
  if (c.env === 'production' && !c.trustProxy) out.push('TRUST_PROXY is false: behind Dokploy/Traefik every request appears to come from the proxy');
  if (c.pocketbase && !c.publicApiOrigin) out.push('PUBLIC_API_ORIGIN is not set: Google/GitHub sign-in is off because it needs the public callback address');
  if (c.env === 'production' && !c.redis) out.push('REDIS_URL is not set: rate limits use PostgreSQL and there is no cache');
  return out;
}

/** The configuration with every secret removed, safe to log at startup. */
export function redactedConfig(c: Config): Record<string, unknown> {
  return {
    env: c.env,
    host: c.host,
    port: c.port,
    database: `${c.database.host}:${c.database.port}/${c.database.database} (ssl ${c.database.ssl})`,
    adminOrigin: c.adminOrigin,
    publicApiOrigin: c.publicApiOrigin,
    cookieSecure: c.cookieSecure,
    trustProxy: c.trustProxy,
    encryptionKeys: c.keyring.size,
    redis: c.redis ? `${c.redis.host}:${c.redis.port}/${c.redis.db}${c.redis.tls ? ' (tls)' : ''}` : null,
    requestTimeoutMs: c.requestTimeoutMs,
    desktopMinVersion: c.desktop.minVersion,
    pocketbase: c.pocketbase ? `${c.pocketbase.url} (collection ${c.pocketbase.usersCollection})` : null,
  };
}
