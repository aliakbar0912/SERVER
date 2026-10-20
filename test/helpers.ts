// Test helpers. Database tests use the local PostgreSQL cluster when DEVORA_TEST_PG_* is set (or the default local test cluster
// exists). Each test run creates its own database and drops it afterwards. Without a cluster, database tests are skipped with a reason.
import fs from 'node:fs';
import crypto from 'node:crypto';
import { Db, type PgConfig } from '../src/db/pg-wire.ts';

const DEFAULT_PW_FILE = '/var/lib/devora-pgtest/pw';

export function adminPgConfig(): PgConfig | null {
  const port = Number(process.env.DEVORA_TEST_PG_PORT ?? 54329);
  const host = process.env.DEVORA_TEST_PG_HOST ?? '127.0.0.1';
  const user = process.env.DEVORA_TEST_PG_USER ?? 'devora';
  let password = process.env.DEVORA_TEST_PG_PASSWORD ?? '';
  if (!password && fs.existsSync(DEFAULT_PW_FILE)) password = fs.readFileSync(DEFAULT_PW_FILE, 'utf8').trim();
  if (!password) return null;
  return { host, port, user, password, database: 'postgres', ssl: 'disable' };
}

export interface TestDb {
  db: Db;
  config: PgConfig;
  drop(): Promise<void>;
}

/** Creates an empty database with a unique name. Returns null when no PostgreSQL is configured. */
export async function createTestDb(): Promise<TestDb | null> {
  const admin = adminPgConfig();
  if (!admin) return null;
  const name = `devora_t_${crypto.randomBytes(6).toString('hex')}`;
  const root = new Db(admin, 1);
  await root.query(`CREATE DATABASE ${name}`);
  await root.close();
  const config = { ...admin, database: name };
  const db = new Db(config, 4);
  return {
    db,
    config,
    async drop() {
      await db.close();
      const r = new Db(admin, 1);
      await r.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()', [name]);
      await r.query(`DROP DATABASE IF EXISTS ${name}`);
      await r.close();
    },
  };
}

export const SKIP_NO_PG = 'no PostgreSQL test cluster configured (set DEVORA_TEST_PG_PASSWORD)';
