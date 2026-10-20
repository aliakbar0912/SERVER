// Versioned migrations. Files are server/migrations/NNNN_name.sql with "-- migrate:up" and "-- migrate:down" sections.
// The applied list lives in schema_migrations with a checksum per file. A changed applied file stops the runner.
// An advisory lock makes concurrent runners (two containers starting at once) wait for each other.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Db } from './pg-wire.ts';

export interface MigrationFile {
  version: number;
  name: string;
  file: string;
  checksum: string;
  up: string;
  down: string;
}

const LOCK_KEY = 727_001_001;

/** Finds server/migrations both from source (server/src/db) and from the bundle (server/dist). DEVORA_MIGRATIONS_DIR overrides. */
export function defaultMigrationsDir(): string {
  if (process.env.DEVORA_MIGRATIONS_DIR) return path.resolve(process.env.DEVORA_MIGRATIONS_DIR);
  const here = path.dirname(fileURLToPath(import.meta.url));
  for (const c of [path.join(here, '..', 'migrations'), path.join(here, '..', '..', 'migrations')]) {
    if (fs.existsSync(c)) return c;
  }
  throw new Error('migrations directory not found; set DEVORA_MIGRATIONS_DIR');
}

export function loadMigrations(dir: string = defaultMigrationsDir()): MigrationFile[] {
  const files = fs.readdirSync(dir).filter((f) => /^\d{4}_[a-z0-9_]+\.sql$/.test(f)).sort();
  const seen = new Set<number>();
  return files.map((file) => {
    const m = /^(\d{4})_([a-z0-9_]+)\.sql$/.exec(file)!;
    const version = Number(m[1]);
    if (seen.has(version)) throw new Error(`duplicate migration version ${version}`);
    seen.add(version);
    const text = fs.readFileSync(path.join(dir, file), 'utf8');
    const upIdx = text.indexOf('-- migrate:up');
    const downIdx = text.indexOf('-- migrate:down');
    if (upIdx < 0 || downIdx < 0 || downIdx < upIdx) throw new Error(`${file} must contain "-- migrate:up" followed by "-- migrate:down"`);
    return {
      version,
      name: m[2],
      file,
      checksum: crypto.createHash('sha256').update(text).digest('hex'),
      up: text.slice(upIdx + '-- migrate:up'.length, downIdx).trim(),
      down: text.slice(downIdx + '-- migrate:down'.length).trim(),
    };
  });
}

export interface AppliedRow {
  version: number;
  name: string;
  checksum: string;
  applied_at: Date;
}

export interface MigrationStatus {
  applied: { version: number; name: string; appliedAt: string }[];
  pending: { version: number; name: string }[];
  currentVersion: number;
  latestVersion: number;
}

async function ensureTable(c: { exec(sql: string): Promise<void> }): Promise<void> {
  await c.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
    version integer PRIMARY KEY,
    name text NOT NULL,
    checksum text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
  )`);
}

async function withLock<T>(db: Db, fn: (c: any) => Promise<T>): Promise<T> {
  return db.withConnection(async (c) => {
    await c.query('SELECT pg_advisory_lock($1)', [LOCK_KEY]);
    try {
      await ensureTable(c);
      return await fn(c);
    } finally {
      await c.query('SELECT pg_advisory_unlock($1)', [LOCK_KEY]).catch(() => undefined);
    }
  });
}

function verify(files: MigrationFile[], applied: AppliedRow[]): void {
  const byVersion = new Map(files.map((f) => [f.version, f]));
  for (const row of applied) {
    const f = byVersion.get(row.version);
    if (!f) throw new Error(`database has migration ${row.version} (${row.name}) that this server build does not contain; do not start an older build against a newer schema`);
    if (f.checksum !== row.checksum) throw new Error(`migration ${f.file} was changed after it was applied; create a new migration instead`);
  }
}

export async function migrationStatus(db: Db, files = loadMigrations()): Promise<MigrationStatus> {
  return withLock(db, async (c) => {
    const { rows } = await c.query('SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version');
    verify(files, rows as AppliedRow[]);
    const appliedSet = new Set((rows as AppliedRow[]).map((r) => r.version));
    return {
      applied: (rows as AppliedRow[]).map((r) => ({ version: r.version, name: r.name, appliedAt: r.applied_at.toISOString() })),
      pending: files.filter((f) => !appliedSet.has(f.version)).map((f) => ({ version: f.version, name: f.name })),
      currentVersion: rows.length ? Math.max(...(rows as AppliedRow[]).map((r) => r.version)) : 0,
      latestVersion: files.length ? files[files.length - 1].version : 0,
    };
  });
}

export async function migrateUp(db: Db, files = loadMigrations()): Promise<string[]> {
  return withLock(db, async (c) => {
    const { rows } = await c.query('SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version');
    verify(files, rows as AppliedRow[]);
    const appliedSet = new Set((rows as AppliedRow[]).map((r) => r.version));
    const done: string[] = [];
    for (const f of files) {
      if (appliedSet.has(f.version)) continue;
      await c.exec('BEGIN');
      try {
        await c.exec(f.up);
        await c.query('INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)', [f.version, f.name, f.checksum]);
        await c.exec('COMMIT');
      } catch (e) {
        await c.exec('ROLLBACK').catch(() => undefined);
        throw new Error(`migration ${f.file} failed and was rolled back: ${(e as Error).message}`);
      }
      done.push(f.file);
    }
    return done;
  });
}

/** Reverts the most recent `steps` migrations. Production rollback normally restores a backup instead; this is for development and small schema fixes. */
export async function migrateDown(db: Db, steps: number, files = loadMigrations()): Promise<string[]> {
  if (!Number.isInteger(steps) || steps < 1) throw new Error('steps must be a positive integer');
  return withLock(db, async (c) => {
    const { rows } = await c.query('SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version DESC');
    verify(files, rows as AppliedRow[]);
    const reverted: string[] = [];
    for (const row of (rows as AppliedRow[]).slice(0, steps)) {
      const f = files.find((x) => x.version === row.version)!;
      await c.exec('BEGIN');
      try {
        await c.exec(f.down);
        await c.query('DELETE FROM schema_migrations WHERE version = $1', [f.version]);
        await c.exec('COMMIT');
      } catch (e) {
        await c.exec('ROLLBACK').catch(() => undefined);
        throw new Error(`reverting ${f.file} failed and was rolled back: ${(e as Error).message}`);
      }
      reverted.push(f.file);
    }
    return reverted;
  });
}
