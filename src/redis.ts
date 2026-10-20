// Minimal Redis client (RESP2) over node:net / node:tls. No third-party dependencies, like the PostgreSQL client.
// Supports: redis:// and rediss:// URLs, AUTH with username and password (Redis 6 ACL) or password only, SELECT,
// pipelined commands with a per-command timeout, lazy reconnection with exponential backoff, and graceful QUIT.
// The URL (and so the password) is never logged or included in error messages.
import net from 'node:net';
import tls from 'node:tls';
import fs from 'node:fs';

export interface RedisConfig {
  host: string;
  port: number;
  username: string | null;
  password: string | null;
  db: number;
  tls: boolean;
  /** Optional CA bundle for rediss:// with a private certificate authority. */
  caFile?: string;
  connectTimeoutMs: number;
  commandTimeoutMs: number;
}

export type RedisValue = string | number | null | RedisValue[];

/** Redis could not be reached, authenticated or answered in time. Maps to HTTP 503 for callers. */
export class RedisUnavailableError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'RedisUnavailableError';
    this.code = code;
  }
}

/** Redis answered with an error reply (for example a wrong command or a script error). */
export class RedisReplyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RedisReplyError';
  }
}

/** Parses REDIS_URL. Throws with a message that never contains the password. */
export function parseRedisUrl(raw: string, env: NodeJS.ProcessEnv = {}): RedisConfig {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error('REDIS_URL must look like redis://default:PASSWORD@host:6379/0');
  }
  if (u.protocol !== 'redis:' && u.protocol !== 'rediss:') throw new Error('REDIS_URL must start with redis:// or rediss://');
  if (!u.hostname) throw new Error('REDIS_URL has no host');
  const db = u.pathname && u.pathname !== '/' ? Number(u.pathname.slice(1)) : 0;
  if (!Number.isInteger(db) || db < 0 || db > 15) throw new Error('REDIS_URL database number must be 0 to 15');
  const port = u.port ? Number(u.port) : 6379;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('REDIS_URL port is invalid');
  const num = (v: string | undefined, def: number, name: string) => {
    if (v === undefined || v === '') return def;
    const n = Number(v);
    if (!Number.isInteger(n) || n < 100 || n > 60_000) throw new Error(`${name} must be an integer from 100 to 60000`);
    return n;
  };
  const cfg: RedisConfig = {
    host: u.hostname.replace(/^\[|\]$/g, ''),
    port,
    username: u.username ? decodeURIComponent(u.username) : null,
    password: u.password ? decodeURIComponent(u.password) : null,
    db,
    tls: u.protocol === 'rediss:',
    connectTimeoutMs: num(env.REDIS_CONNECT_TIMEOUT_MS, 5000, 'REDIS_CONNECT_TIMEOUT_MS'),
    commandTimeoutMs: num(env.REDIS_COMMAND_TIMEOUT_MS, 2000, 'REDIS_COMMAND_TIMEOUT_MS'),
  };
  if (env.REDIS_TLS_CA_FILE) {
    if (!cfg.tls) throw new Error('REDIS_TLS_CA_FILE needs a rediss:// URL');
    if (!fs.existsSync(env.REDIS_TLS_CA_FILE)) throw new Error('REDIS_TLS_CA_FILE does not exist');
    cfg.caFile = env.REDIS_TLS_CA_FILE;
  }
  return cfg;
}

/** Incremental RESP2 reply parser. Returns undefined until a whole reply is buffered. */
class ReplyParser {
  private buf: Buffer = Buffer.alloc(0);

  push(chunk: Buffer): void {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
  }

  /** Returns [value] for one complete reply, or null when more bytes are needed. Error replies come back as RedisReplyError values. */
  next(): [RedisValue | RedisReplyError] | null {
    const r = this.read(0);
    if (!r) return null;
    this.buf = this.buf.subarray(r[1]);
    return [r[0]];
  }

  private line(at: number): [string, number] | null {
    const end = this.buf.indexOf('\r\n', at);
    if (end < 0) return null;
    return [this.buf.toString('utf8', at, end), end + 2];
  }

  private read(at: number): [RedisValue | RedisReplyError, number] | null {
    if (at >= this.buf.length) return null;
    const type = String.fromCharCode(this.buf[at]);
    const l = this.line(at + 1);
    if (!l) return null;
    const [text, after] = l;
    switch (type) {
      case '+':
        return [text, after];
      case '-':
        return [new RedisReplyError(text), after];
      case ':':
        return [Number(text), after];
      case '$': {
        const len = Number(text);
        if (len < 0) return [null, after];
        if (this.buf.length < after + len + 2) return null;
        return [this.buf.toString('utf8', after, after + len), after + len + 2];
      }
      case '*': {
        const n = Number(text);
        if (n < 0) return [null, after];
        const out: RedisValue[] = [];
        let pos = after;
        for (let i = 0; i < n; i++) {
          const item = this.read(pos);
          if (!item) return null;
          // An error inside an array (EXEC) is kept as its message; callers here never rely on it.
          out.push(item[0] instanceof RedisReplyError ? item[0].message : item[0]);
          pos = item[1];
        }
        return [out, pos];
      }
      default:
        throw new RedisUnavailableError('redis_protocol', `unexpected reply type from Redis`);
    }
  }
}

function encode(args: (string | number)[]): Buffer {
  const parts: Buffer[] = [Buffer.from(`*${args.length}\r\n`)];
  for (const a of args) {
    const b = Buffer.from(String(a), 'utf8');
    parts.push(Buffer.from(`$${b.length}\r\n`), b, Buffer.from('\r\n'));
  }
  return Buffer.concat(parts);
}

interface Pending {
  resolve: (v: RedisValue) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
}

const BACKOFF_MIN_MS = 250;
const BACKOFF_MAX_MS = 30_000;

export class Redis {
  private socket: net.Socket | null = null;
  private connecting: Promise<net.Socket> | null = null;
  /** Each connection has its own reply queue and parser, so a dying old connection never touches a new one. */
  private conns = new Map<net.Socket, { pending: Pending[]; parser: ReplyParser }>();
  private closed = false;
  private failures = 0;
  private retryAt = 0;
  private lastError: string | null = null;

  constructor(
    private readonly cfg: RedisConfig,
    private readonly onEvent: (level: 'info' | 'warn' | 'error', msg: string, fields?: Record<string, unknown>) => void = () => {},
  ) {}

  /** Host and port only, for logs and the health view. Never includes credentials. */
  get target(): string {
    return `${this.cfg.tls ? 'rediss' : 'redis'}://${this.cfg.host}:${this.cfg.port}/${this.cfg.db}`;
  }

  get connected(): boolean {
    return this.socket !== null && !this.socket.destroyed;
  }

  get lastFailure(): string | null {
    return this.lastError;
  }

  /** Sends one command. Connects (or reconnects) first when needed; fails fast during the backoff window. */
  async command(...args: (string | number)[]): Promise<RedisValue> {
    const socket = await this.ensure();
    return this.send(socket, args);
  }

  async ping(): Promise<number> {
    const t = Date.now();
    const r = await this.command('PING');
    if (r !== 'PONG') throw new RedisUnavailableError('redis_bad_reply', 'Redis did not answer PING');
    return Date.now() - t;
  }

  /** Graceful shutdown: QUIT, then close. Pending commands are rejected. */
  async close(): Promise<void> {
    this.closed = true;
    const s = this.socket;
    if (!s || s.destroyed) return;
    try {
      await Promise.race([this.send(s, ['QUIT']), new Promise((r) => setTimeout(r, 1000).unref())]);
    } catch {
      // the connection is going away either way
    }
    s.destroy();
    this.socket = null;
  }

  private send(socket: net.Socket, args: (string | number)[]): Promise<RedisValue> {
    return new Promise<RedisValue>((resolve, reject) => {
      const timer = setTimeout(() => {
        // Replies are ordered, so one lost reply poisons the connection: drop it and fail everything pending.
        this.fail(socket, new RedisUnavailableError('redis_timeout', `Redis did not answer within ${this.cfg.commandTimeoutMs} ms`));
      }, this.cfg.commandTimeoutMs);
      timer.unref();
      const conn = this.conns.get(socket);
      if (!conn || socket.destroyed) {
        clearTimeout(timer);
        reject(new RedisUnavailableError('redis_unavailable', 'the Redis connection closed'));
        return;
      }
      conn.pending.push({ resolve, reject, timer });
      socket.write(encode(args));
    });
  }

  private ensure(): Promise<net.Socket> {
    if (this.closed) return Promise.reject(new RedisUnavailableError('redis_closed', 'the Redis client is shut down'));
    if (this.socket && !this.socket.destroyed) return Promise.resolve(this.socket);
    if (this.connecting) return this.connecting;
    const now = Date.now();
    if (now < this.retryAt) {
      return Promise.reject(new RedisUnavailableError('redis_unavailable', `Redis is unavailable (${this.lastError ?? 'connection failed'}); retrying in ${Math.ceil((this.retryAt - now) / 1000)} s`));
    }
    this.connecting = this.open().then(
      (s) => {
        if (this.failures > 0) this.onEvent('info', 'redis reconnected', { target: this.target });
        this.failures = 0;
        this.retryAt = 0;
        this.lastError = null;
        this.connecting = null;
        return s;
      },
      (e: Error) => {
        this.failures += 1;
        const delay = Math.min(BACKOFF_MAX_MS, BACKOFF_MIN_MS * 2 ** (this.failures - 1));
        this.retryAt = Date.now() + delay;
        this.lastError = e.message;
        this.connecting = null;
        this.onEvent('error', 'redis connection failed', { target: this.target, reason: e.message, retryInMs: delay });
        throw e instanceof RedisUnavailableError ? e : new RedisUnavailableError('redis_unavailable', e.message);
      },
    );
    return this.connecting;
  }

  private open(): Promise<net.Socket> {
    return new Promise<net.Socket>((resolve, reject) => {
      const c = this.cfg;
      const socket = c.tls
        ? tls.connect({ host: c.host, port: c.port, servername: net.isIP(c.host) ? undefined : c.host, ca: c.caFile ? fs.readFileSync(c.caFile) : undefined })
        : net.connect({ host: c.host, port: c.port });
      socket.setNoDelay(true);
      socket.setKeepAlive(true, 30_000);
      let settled = false;
      const timer = setTimeout(() => done(new RedisUnavailableError('redis_timeout', `could not connect to Redis within ${c.connectTimeoutMs} ms`)), c.connectTimeoutMs);
      timer.unref();
      const done = (err: Error | null) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (err) {
          socket.destroy();
          reject(err);
        } else resolve(socket);
      };
      this.conns.set(socket, { pending: [], parser: new ReplyParser() });
      socket.on('data', (chunk: Buffer) => this.onData(socket, chunk));
      socket.on('error', (e: NodeJS.ErrnoException) => {
        const err = new RedisUnavailableError('redis_unavailable', e.code ? `network error ${e.code}` : 'network error');
        if (!settled) done(err);
        else this.fail(socket, err);
      });
      socket.on('close', () => {
        if (!settled) done(new RedisUnavailableError('redis_unavailable', 'the connection closed during setup'));
        else this.fail(socket, new RedisUnavailableError('redis_unavailable', 'the Redis connection closed'));
      });
      socket.once(c.tls ? 'secureConnect' : 'connect', async () => {
        try {
          if (c.password !== null) {
            const args = c.username ? ['AUTH', c.username, c.password] : ['AUTH', c.password];
            await this.send(socket, args).catch((e) => {
              throw authError(e);
            });
          }
          if (c.db)
            await this.send(socket, ['SELECT', c.db]).catch((e) => {
              throw authError(e);
            });
          // Confirms the server accepts commands: without a password, a protected server answers NOAUTH here.
          await this.send(socket, ['PING']).catch((e) => {
            throw authError(e);
          });
          this.socket = socket;
          done(null);
        } catch (e) {
          done(e instanceof Error ? e : new Error(String(e)));
        }
      });
    });
  }

  private onData(socket: net.Socket, chunk: Buffer): void {
    const conn = this.conns.get(socket);
    if (!conn) return;
    conn.parser.push(chunk);
    for (;;) {
      let r: [RedisValue | RedisReplyError] | null;
      try {
        r = conn.parser.next();
      } catch (e) {
        this.fail(socket, e as Error);
        return;
      }
      if (!r) return;
      const p = conn.pending.shift();
      if (!p) continue;
      clearTimeout(p.timer);
      if (r[0] instanceof RedisReplyError) p.reject(r[0]);
      else p.resolve(r[0]);
    }
  }

  private fail(socket: net.Socket, err: Error): void {
    if (this.socket === socket) {
      this.socket = null;
      if (!this.closed) {
        this.lastError = err.message;
        this.onEvent('warn', 'redis connection lost', { target: this.target, reason: err.message });
      }
    }
    socket.destroy();
    const pending = this.conns.get(socket)?.pending ?? [];
    this.conns.delete(socket);
    for (const p of pending) {
      clearTimeout(p.timer);
      p.reject(err);
    }
  }
}

function authError(e: unknown): Error {
  const m = e instanceof Error ? e.message : '';
  if (/NOAUTH/i.test(m)) return new RedisUnavailableError('redis_auth_required', 'Redis requires a password; put it in REDIS_URL (redis://default:PASSWORD@host:6379/0)');
  if (/WRONGPASS|invalid password|invalid username/i.test(m)) return new RedisUnavailableError('redis_auth_failed', 'Redis rejected the username or password in REDIS_URL');
  if (/AUTH.*no password is set|without any password configured/i.test(m)) return new RedisUnavailableError('redis_auth_failed', 'REDIS_URL has a password but this Redis server has none set');
  return e instanceof Error ? e : new Error(String(e));
}
