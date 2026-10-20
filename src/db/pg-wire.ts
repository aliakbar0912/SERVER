// Minimal PostgreSQL client speaking the wire protocol (v3). Written in-repo because the npm registry was not reachable
// when the backend was built. It supports what the server needs and nothing more:
//   - startup with optional TLS (SSLRequest), SCRAM-SHA-256 authentication
//   - extended query protocol with text parameters and text results (no SQL injection surface: values are never spliced)
//   - simple query for migrations and transaction control
//   - a small pool with transactions on a dedicated connection
// The Db interface below is the only boundary the rest of the server uses.
import crypto from 'node:crypto';
import net from 'node:net';
import tls from 'node:tls';
import fs from 'node:fs';

export class PgError extends Error {
  readonly code: string;
  readonly detail?: string;
  constructor(message: string, code = '', detail?: string) {
    super(message);
    this.name = 'PgError';
    this.code = code;
    this.detail = detail;
  }
}

export interface PgConfig {
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
  /** 'disable' connects in clear text (only for a private network); 'require' negotiates TLS and verifies the server. */
  ssl: 'disable' | 'require';
  caFile?: string;
  connectTimeoutMs?: number;
  statementTimeoutMs?: number;
}

export type Row = Record<string, any>;
export interface QueryResult {
  rows: Row[];
  rowCount: number;
}
export interface Queryer {
  query(sql: string, params?: unknown[]): Promise<QueryResult>;
}

const OID = { bool: 16, bytea: 17, int8: 20, int2: 21, int4: 23, json: 114, float4: 700, float8: 701, numeric: 1700, timestamp: 1114, timestamptz: 1184, jsonb: 3802 } as const;

/** Converts a text-format value using the column's type OID. Unknown types stay strings. */
export function decodeValue(oid: number, text: string | null): unknown {
  if (text === null) return null;
  switch (oid) {
    case OID.bool:
      return text === 't';
    case OID.int2:
    case OID.int4:
    case OID.int8:
    case OID.float4:
    case OID.float8:
    case OID.numeric:
      return Number(text);
    case OID.json:
    case OID.jsonb:
      return JSON.parse(text);
    case OID.bytea:
      return text.startsWith('\\x') ? Buffer.from(text.slice(2), 'hex') : Buffer.from(text);
    case OID.timestamp:
    case OID.timestamptz:
      return parseTimestamp(text);
    default:
      return text;
  }
}

/** The session time zone is UTC, so timestamptz text ends with +00. Fractions are cut to milliseconds. */
function parseTimestamp(text: string): Date {
  let t = text.replace(' ', 'T');
  t = t.replace(/(\.\d{3})\d+/, '$1');
  if (/[+-]\d{2}$/.test(t)) t += ':00';
  else if (!/(Z|[+-]\d{2}:\d{2})$/.test(t)) t += 'Z';
  return new Date(t);
}

function encodeParam(v: unknown): Buffer | null {
  if (v === null || v === undefined) return null;
  if (typeof v === 'boolean') return Buffer.from(v ? 'true' : 'false', 'utf8');
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new PgError('non-finite number parameter');
    return Buffer.from(String(v), 'utf8');
  }
  if (Buffer.isBuffer(v)) return Buffer.from(`\\x${v.toString('hex')}`, 'utf8');
  if (v instanceof Date) return Buffer.from(v.toISOString(), 'utf8');
  if (typeof v === 'object') return Buffer.from(JSON.stringify(v), 'utf8');
  return Buffer.from(String(v), 'utf8');
}

function cstr(s: string): Buffer {
  return Buffer.concat([Buffer.from(s, 'utf8'), Buffer.of(0)]);
}

function int16(n: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeInt16BE(n, 0);
  return b;
}

function int32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeInt32BE(n, 0);
  return b;
}

function frame(type: string, body: Buffer): Buffer {
  return Buffer.concat([Buffer.from(type, 'ascii'), int32(body.length + 4), body]);
}

interface Msg {
  type: string;
  body: Buffer;
}

function parseError(body: Buffer): PgError {
  const fields: Record<string, string> = {};
  let i = 0;
  while (i < body.length && body[i] !== 0) {
    const code = String.fromCharCode(body[i]);
    const end = body.indexOf(0, i + 1);
    fields[code] = body.toString('utf8', i + 1, end);
    i = end + 1;
  }
  return new PgError(fields.M ?? 'database error', fields.C ?? '', fields.D);
}

function hmac(key: Buffer | string, data: string | Buffer): Buffer {
  return crypto.createHmac('sha256', key).update(data).digest();
}

/** One PostgreSQL connection. Queries on a connection run one at a time. */
export class PgConnection implements Queryer {
  private socket!: net.Socket | tls.TLSSocket;
  private buf: Buffer = Buffer.alloc(0);
  private inbox: Msg[] = [];
  private waiters: { resolve: (m: Msg) => void; reject: (e: Error) => void }[] = [];
  private failure: Error | null = null;
  private busy = false;
  /** True once the socket failed; the pool then discards the connection. */
  broken = false;

  static async connect(cfg: PgConfig): Promise<PgConnection> {
    const conn = new PgConnection();
    await conn.open(cfg);
    return conn;
  }

  private async open(cfg: PgConfig): Promise<void> {
    const raw = await new Promise<net.Socket>((resolve, reject) => {
      const s = net.connect({ host: cfg.host, port: cfg.port });
      const timer = setTimeout(() => {
        s.destroy();
        reject(new PgError(`connection to database timed out after ${cfg.connectTimeoutMs ?? 10000} ms`));
      }, cfg.connectTimeoutMs ?? 10000);
      s.once('connect', () => {
        clearTimeout(timer);
        resolve(s);
      });
      s.once('error', (e) => {
        clearTimeout(timer);
        reject(new PgError(`cannot reach the database: ${e.message}`));
      });
    });

    let sock: net.Socket | tls.TLSSocket = raw;
    if (cfg.ssl === 'require') {
      raw.write(Buffer.concat([int32(8), int32(80877103)]));
      const answer = await new Promise<string>((resolve, reject) => {
        raw.once('data', (d: Buffer) => resolve(d.toString('ascii', 0, 1)));
        raw.once('error', reject);
      });
      if (answer !== 'S') throw new PgError('the database does not offer TLS, but DATABASE_SSL=require');
      sock = await new Promise<tls.TLSSocket>((resolve, reject) => {
        const t = tls.connect({
          socket: raw,
          servername: cfg.host,
          rejectUnauthorized: true,
          ca: cfg.caFile ? fs.readFileSync(cfg.caFile) : undefined,
        });
        t.once('secureConnect', () => resolve(t));
        t.once('error', (e) => reject(new PgError(`TLS to the database failed: ${e.message}`)));
      });
    }
    this.socket = sock;
    this.attach();

    const params: Record<string, string> = {
      user: cfg.user,
      database: cfg.database,
      application_name: 'devora-server',
      timezone: 'UTC',
      statement_timeout: String(cfg.statementTimeoutMs ?? 30000),
      client_encoding: 'UTF8',
    };
    const kv = Buffer.concat(Object.entries(params).flatMap(([k, v]) => [cstr(k), cstr(v)]));
    const body = Buffer.concat([int32(196608), kv, Buffer.of(0)]);
    this.socket.write(Buffer.concat([int32(body.length + 4), body]));

    for (;;) {
      const m = await this.next();
      if (m.type === 'R') {
        const code = m.body.readInt32BE(0);
        if (code === 0) continue;
        if (code === 10) {
          const mechs = m.body.toString('utf8', 4).split('\0').filter(Boolean);
          if (!mechs.includes('SCRAM-SHA-256')) throw new PgError('the database requires an authentication method this server does not support');
          await this.scram(cfg.password);
          continue;
        }
        throw new PgError(`unsupported authentication method (${code}); the server requires SCRAM-SHA-256`);
      }
      if (m.type === 'E') throw parseError(m.body);
      if (m.type === 'Z') break;
    }
  }

  private attach(): void {
    this.socket.on('data', (d: Buffer) => {
      this.buf = this.buf.length ? Buffer.concat([this.buf, d]) : d;
      while (this.buf.length >= 5) {
        const len = this.buf.readInt32BE(1);
        if (this.buf.length < len + 1) break;
        const msg: Msg = { type: String.fromCharCode(this.buf[0]), body: this.buf.subarray(5, len + 1) };
        this.buf = this.buf.subarray(len + 1);
        const w = this.waiters.shift();
        if (w) w.resolve(msg);
        else this.inbox.push(msg);
      }
    });
    const fail = (e: Error) => {
      this.broken = true;
      this.failure = this.failure ?? e;
      for (const w of this.waiters.splice(0)) w.reject(this.failure);
    };
    this.socket.on('error', (e) => fail(new PgError(`database connection failed: ${e.message}`)));
    this.socket.on('close', () => fail(new PgError('database connection closed')));
  }

  private next(): Promise<Msg> {
    const m = this.inbox.shift();
    if (m) return Promise.resolve(m);
    if (this.failure) return Promise.reject(this.failure);
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
  }

  private async scram(password: string): Promise<void> {
    const nonce = crypto.randomBytes(18).toString('base64');
    const clientFirstBare = `n=,r=${nonce}`;
    const initial = Buffer.from(`n,,${clientFirstBare}`, 'utf8');
    this.socket.write(frame('p', Buffer.concat([cstr('SCRAM-SHA-256'), int32(initial.length), initial])));

    const first = await this.next();
    if (first.type === 'E') throw parseError(first.body);
    if (first.type !== 'R' || first.body.readInt32BE(0) !== 11) throw new PgError('unexpected reply during authentication');
    const serverFirst = first.body.toString('utf8', 4);
    const attrs = Object.fromEntries(serverFirst.split(',').map((p) => [p[0], p.slice(2)]));
    if (!attrs.r?.startsWith(nonce) || !attrs.s || !attrs.i) throw new PgError('invalid SCRAM challenge from the database');
    const iterations = Number(attrs.i);
    if (!Number.isInteger(iterations) || iterations < 4096 || iterations > 1_000_000) throw new PgError('unacceptable SCRAM iteration count');

    const salted = await new Promise<Buffer>((resolve, reject) =>
      crypto.pbkdf2(password, Buffer.from(attrs.s, 'base64'), iterations, 32, 'sha256', (e, k) => (e ? reject(e) : resolve(k))),
    );
    const clientKey = hmac(salted, 'Client Key');
    const storedKey = crypto.createHash('sha256').update(clientKey).digest();
    const clientFinalNoProof = `c=biws,r=${attrs.r}`;
    const authMessage = `${clientFirstBare},${serverFirst},${clientFinalNoProof}`;
    const signature = hmac(storedKey, authMessage);
    const proof = Buffer.alloc(clientKey.length);
    for (let i = 0; i < proof.length; i++) proof[i] = clientKey[i] ^ signature[i];
    const clientFinal = Buffer.from(`${clientFinalNoProof},p=${proof.toString('base64')}`, 'utf8');
    this.socket.write(frame('p', clientFinal));

    const last = await this.next();
    if (last.type === 'E') throw parseError(last.body);
    if (last.type !== 'R' || last.body.readInt32BE(0) !== 12) throw new PgError('password authentication failed');
    const serverKey = hmac(salted, 'Server Key');
    const expected = hmac(serverKey, authMessage).toString('base64');
    const got = last.body.toString('utf8', 4).replace(/^v=/, '');
    if (got !== expected) throw new PgError('the database failed to prove its identity (SCRAM)');
  }

  private async begin(): Promise<void> {
    if (this.busy) throw new PgError('connection is already running a query');
    this.busy = true;
  }

  /** Runs one parameterized statement with the extended protocol. Parameters are text values; SQL never contains them. */
  async query(sql: string, params: unknown[] = []): Promise<QueryResult> {
    await this.begin();
    try {
      const values = params.map(encodeParam);
      const bind = [
        cstr(''),
        cstr(''),
        int16(0),
        int16(values.length),
        ...values.flatMap((v) => (v === null ? [int32(-1)] : [int32(v.length), v])),
        int16(0),
      ];
      this.socket.write(
        Buffer.concat([
          frame('P', Buffer.concat([cstr(''), cstr(sql), int16(0)])),
          frame('B', Buffer.concat(bind)),
          frame('D', Buffer.concat([Buffer.from('P', 'ascii'), cstr('')])),
          frame('E', Buffer.concat([cstr(''), int32(0)])),
          frame('S', Buffer.alloc(0)),
        ]),
      );
      return await this.readResult();
    } finally {
      this.busy = false;
    }
  }

  /** Runs one or more statements with the simple protocol (no parameters). Used for migrations and transaction control. */
  async exec(sql: string): Promise<void> {
    await this.begin();
    try {
      this.socket.write(frame('Q', cstr(sql)));
      await this.readResult();
    } finally {
      this.busy = false;
    }
  }

  private async readResult(): Promise<QueryResult> {
    let cols: { name: string; oid: number }[] = [];
    const rows: Row[] = [];
    let rowCount = 0;
    let error: PgError | null = null;
    for (;;) {
      const m = await this.next();
      switch (m.type) {
        case 'T': {
          const n = m.body.readInt16BE(0);
          cols = [];
          let p = 2;
          for (let i = 0; i < n; i++) {
            const end = m.body.indexOf(0, p);
            const name = m.body.toString('utf8', p, end);
            p = end + 1;
            const oid = m.body.readInt32BE(p + 6);
            p += 18;
            cols.push({ name, oid });
          }
          break;
        }
        case 'D': {
          const n = m.body.readInt16BE(0);
          const row: Row = {};
          let p = 2;
          for (let i = 0; i < n; i++) {
            const len = m.body.readInt32BE(p);
            p += 4;
            const text = len === -1 ? null : m.body.toString('utf8', p, p + len);
            if (len !== -1) p += len;
            const col = cols[i];
            row[col.name] = decodeValue(col.oid, text);
          }
          rows.push(row);
          break;
        }
        case 'C': {
          const tag = m.body.toString('utf8', 0, m.body.indexOf(0));
          const n = Number(tag.split(' ').pop());
          if (Number.isFinite(n)) rowCount = n;
          break;
        }
        case 'E':
          error = parseError(m.body);
          break;
        case 'Z':
          if (error) throw error;
          return { rows, rowCount: rowCount || rows.length };
        default:
          // ParseComplete, BindComplete, NoData, ParameterDescription, EmptyQuery, notices and parameter status are not needed.
          break;
      }
    }
  }

  close(): void {
    try {
      this.socket.end(frame('X', Buffer.alloc(0)));
    } catch {
      /* already closed */
    }
    this.socket.destroy();
  }
}

/** A small pool. `transaction` holds one connection for the whole callback. */
export class Db {
  private idle: PgConnection[] = [];
  private total = 0;
  private waiters: ((c: PgConnection) => void)[] = [];
  private closed = false;

  constructor(
    private readonly cfg: PgConfig,
    private readonly max = 10,
  ) {}

  private async acquire(): Promise<PgConnection> {
    if (this.closed) throw new PgError('database pool is closed');
    const c = this.idle.pop();
    if (c) return c;
    if (this.total < this.max) {
      this.total++;
      try {
        return await PgConnection.connect(this.cfg);
      } catch (e) {
        this.total--;
        throw e;
      }
    }
    return new Promise((resolve) => this.waiters.push(resolve));
  }

  private release(c: PgConnection): void {
    if (c.broken) {
      this.total--;
      c.close();
      // A waiter needs a replacement connection; create one on its behalf.
      const w = this.waiters.shift();
      if (w) void this.acquire().then(w);
      return;
    }
    const w = this.waiters.shift();
    if (w) w(c);
    else this.idle.push(c);
  }

  async query(sql: string, params: unknown[] = []): Promise<QueryResult> {
    const c = await this.acquire();
    try {
      return await c.query(sql, params);
    } finally {
      this.release(c);
    }
  }

  async transaction<T>(fn: (q: Queryer) => Promise<T>): Promise<T> {
    const c = await this.acquire();
    try {
      await c.exec('BEGIN');
      try {
        const out = await fn(c);
        await c.exec('COMMIT');
        return out;
      } catch (e) {
        if (!c.broken) await c.exec('ROLLBACK').catch(() => undefined);
        throw e;
      }
    } finally {
      this.release(c);
    }
  }

  /** Runs a callback with a dedicated connection and no transaction (used by the migration runner for advisory locks). */
  async withConnection<T>(fn: (c: PgConnection) => Promise<T>): Promise<T> {
    const c = await this.acquire();
    try {
      return await fn(c);
    } finally {
      this.release(c);
    }
  }

  async close(): Promise<void> {
    this.closed = true;
    for (const c of this.idle.splice(0)) {
      c.close();
      this.total--;
    }
  }
}
