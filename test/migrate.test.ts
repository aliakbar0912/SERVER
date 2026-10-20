import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createTestDb, SKIP_NO_PG } from './helpers.ts';
import { loadMigrations, migrateUp, migrateDown, migrationStatus } from '../src/db/migrate.ts';

const repoMigrations = path.resolve(import.meta.dirname, '..', 'migrations');

test('the shipped migrations are well formed and versioned', () => {
  const files = loadMigrations(repoMigrations);
  assert.equal(files[0].version, 1);
  for (const f of files) assert.ok(f.up.length > 0 && f.down.length > 0, f.file);
});

test('migrations apply once, revert, and re-apply', { skip: false }, async (t) => {
  const tdb = await createTestDb();
  if (!tdb) return t.skip(SKIP_NO_PG);
  try {
    const first = await migrateUp(tdb.db, loadMigrations(repoMigrations));
    assert.deepEqual(first, ['0001_initial.sql', '0002_operations.sql', '0003_model_registry.sql']);
    const again = await migrateUp(tdb.db, loadMigrations(repoMigrations));
    assert.deepEqual(again, []);
    const status = await migrationStatus(tdb.db, loadMigrations(repoMigrations));
    assert.equal(status.currentVersion, 3);
    assert.equal(status.pending.length, 0);
    const { rows } = await tdb.db.query("SELECT count(*)::int AS n FROM settings WHERE key = 'catalogue_version'");
    assert.equal(rows[0].n, 1);

    // 0003 reverts cleanly on its own: the new table goes, the 0002 tables stay.
    await migrateDown(tdb.db, 1, loadMigrations(repoMigrations));
    assert.equal((await tdb.db.query("SELECT to_regclass('public.device_models') AS t")).rows[0].t, null);
    assert.notEqual((await tdb.db.query("SELECT to_regclass('public.rate_counters') AS t")).rows[0].t, null);
    await migrateDown(tdb.db, 2, loadMigrations(repoMigrations));
    const dropped = await tdb.db.query("SELECT to_regclass('public.rate_counters') AS t");
    assert.equal(dropped.rows[0].t, null);
    const gone = await tdb.db.query("SELECT to_regclass('public.providers') AS t");
    assert.equal(gone.rows[0].t, null);
    await migrateUp(tdb.db, loadMigrations(repoMigrations));
    const back = await tdb.db.query("SELECT to_regclass('public.providers') AS t");
    assert.notEqual(back.rows[0].t, null);
  } finally {
    await tdb.drop();
  }
});

test('a changed applied migration is refused', { skip: false }, async (t) => {
  const tdb = await createTestDb();
  if (!tdb) return t.skip(SKIP_NO_PG);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'devora-mig-'));
  try {
    fs.copyFileSync(path.join(repoMigrations, '0001_initial.sql'), path.join(dir, '0001_initial.sql'));
    await migrateUp(tdb.db, loadMigrations(dir));
    fs.appendFileSync(path.join(dir, '0001_initial.sql'), '\n-- tampered\n');
    await assert.rejects(migrateUp(tdb.db, loadMigrations(dir)), /changed after it was applied/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    await tdb.drop();
  }
});

test('a failing migration is rolled back completely', { skip: false }, async (t) => {
  const tdb = await createTestDb();
  if (!tdb) return t.skip(SKIP_NO_PG);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'devora-mig-'));
  try {
    fs.writeFileSync(path.join(dir, '0001_bad.sql'), '-- migrate:up\nCREATE TABLE a (id int);\nCREATE TABLE a (id int);\n-- migrate:down\nDROP TABLE a;\n');
    await assert.rejects(migrateUp(tdb.db, loadMigrations(dir)), /rolled back/);
    const r = await tdb.db.query("SELECT to_regclass('public.a') AS t");
    assert.equal(r.rows[0].t, null);
    const s = await migrationStatus(tdb.db, loadMigrations(dir));
    assert.equal(s.currentVersion, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    await tdb.drop();
  }
});
