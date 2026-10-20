// Shared runtime state behind one interface: fixed-window rate limits, a small cache, and distributed locks.
// With REDIS_URL set, everything lives in Redis. Without it, rate limits use PostgreSQL (rate_counters), the cache is off,
// and locks are skipped (the only locked jobs are idempotent clean-ups). There is no in-memory store: every backend
// replica sees the same counters. When Redis is configured but down, calls throw RedisUnavailableError (HTTP 503).
import crypto from 'node:crypto';
import type { Db } from './db/pg-wire.ts';
import { clearRate, hitRate, type RateResult } from './persistent-limits.ts';
import type { Redis } from './redis.ts';

export interface LimitStore {
  readonly kind: 'redis' | 'database';
  /** Counts one hit for `key` in the current fixed window. */
  hit(key: string, limit: number, windowSeconds: number): Promise<RateResult>;
  /** Clears the counter for `key` (for example after a successful login). */
  clear(key: string): Promise<void>;
  /** Cached JSON value, or null when missing or when caching is off. */
  cacheGet<T>(key: string): Promise<T | null>;
  cacheSet(key: string, value: unknown, ttlSeconds: number): Promise<void>;
  /** Runs `fn` while holding the named lock. Returns null without running when another process holds it. */
  withLock<T>(name: string, ttlMs: number, fn: () => Promise<T>): Promise<T | null>;
}

// INCR + set the expiry on the first hit, atomically. Returns [count, milliseconds left in the window].
const HIT_SCRIPT = `local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then redis.call('PEXPIRE', KEYS[1], ARGV[1]); ttl = tonumber(ARGV[1]) end
return {n, ttl}`;

// Deletes the lock only when it still holds our token, so an expired lock taken by another process is never released by us.
const UNLOCK_SCRIPT = `if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end`;

export class RedisLimitStore implements LimitStore {
  readonly kind = 'redis' as const;

  constructor(
    readonly redis: Redis,
    private readonly prefix = 'devora',
  ) {}

  private k(kind: string, key: string): string {
    return `${this.prefix}:${kind}:${key}`;
  }

  async hit(key: string, limit: number, windowSeconds: number): Promise<RateResult> {
    const r = (await this.redis.command('EVAL', HIT_SCRIPT, 1, this.k('rl', key), windowSeconds * 1000)) as number[];
    const [count, ttlMs] = r;
    if (count > limit) return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil(ttlMs / 1000)) };
    return { allowed: true, retryAfterSeconds: 0 };
  }

  async clear(key: string): Promise<void> {
    await this.redis.command('DEL', this.k('rl', key));
  }

  async cacheGet<T>(key: string): Promise<T | null> {
    const v = await this.redis.command('GET', this.k('cache', key));
    if (typeof v !== 'string') return null;
    try {
      return JSON.parse(v) as T;
    } catch {
      return null;
    }
  }

  async cacheSet(key: string, value: unknown, ttlSeconds: number): Promise<void> {
    await this.redis.command('SET', this.k('cache', key), JSON.stringify(value), 'EX', ttlSeconds);
  }

  async withLock<T>(name: string, ttlMs: number, fn: () => Promise<T>): Promise<T | null> {
    const key = this.k('lock', name);
    const token = crypto.randomUUID();
    const got = await this.redis.command('SET', key, token, 'NX', 'PX', ttlMs);
    if (got !== 'OK') return null;
    try {
      return await fn();
    } finally {
      await this.redis.command('EVAL', UNLOCK_SCRIPT, 1, key, token).catch(() => {
        // the lock expires on its own after ttlMs
      });
    }
  }
}

export class DatabaseLimitStore implements LimitStore {
  readonly kind = 'database' as const;

  constructor(private readonly db: Db) {}

  hit(key: string, limit: number, windowSeconds: number): Promise<RateResult> {
    return hitRate(this.db, key, limit, windowSeconds);
  }

  clear(key: string): Promise<void> {
    return clearRate(this.db, key);
  }

  async cacheGet<T>(): Promise<T | null> {
    return null;
  }

  async cacheSet(): Promise<void> {}

  async withLock<T>(_name: string, _ttlMs: number, fn: () => Promise<T>): Promise<T | null> {
    return fn();
  }
}
