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
    assert.deepEqual(first, ['0001_initial.sql', '0002_operations.sql', '0003_model_registry.sql', '0004_auto_registration.sql', '0005_memory.sql', '0006_desktop_releases.sql', '0007_accounts.sql', '0008_web_search.sql', '0009_org_skills.sql']);
    const again = await migrateUp(tdb.db, loadMigrations(repoMigrations));
    assert.deepEqual(again, []);
    const status = await migrationStatus(tdb.db, loadMigrations(repoMigrations));
    assert.equal(status.currentVersion, 9);
    assert.equal(status.pending.length, 0);
    const { rows } = await tdb.db.query("SELECT count(*)::int AS n FROM settings WHERE key = 'catalogue_version'");
    assert.equal(rows[0].n, 1);

    // 0009 reverts cleanly: organization skills go.
    await migrateDown(tdb.db, 1, loadMigrations(repoMigrations));
    assert.equal((await tdb.db.query("SELECT to_regclass('public.org_skills') AS t")).rows[0].t, null);
    // 0008 reverts cleanly: the web search tables and setting go.
    await migrateDown(tdb.db, 1, loadMigrations(repoMigrations));
    assert.equal((await tdb.db.query("SELECT to_regclass('public.search_providers') AS t")).rows[0].t, null);
    assert.equal((await tdb.db.query("SELECT count(*)::int AS n FROM settings WHERE key = 'search_per_minute'")).rows[0].n, 0);
    // 0007 reverts cleanly: account tables, device account columns and the setting go; devices stay.
    await migrateDown(tdb.db, 1, loadMigrations(repoMigrations));
    assert.equal((await tdb.db.query("SELECT to_regclass('public.app_users') AS t")).rows[0].t, null);
    assert.equal((await tdb.db.query("SELECT to_regclass('public.auth_handoffs') AS t")).rows[0].t, null);
    assert.equal((await tdb.db.query("SELECT count(*)::int AS n FROM information_schema.columns WHERE table_name = 'devices' AND column_name = 'user_id'")).rows[0].n, 0);
    assert.equal((await tdb.db.query("SELECT count(*)::int AS n FROM settings WHERE key = 'require_login_for_central_ai'")).rows[0].n, 0);
    // 0006 reverts cleanly: the release tables and the device version column go.
    await migrateDown(tdb.db, 1, loadMigrations(repoMigrations));
    assert.equal((await tdb.db.query("SELECT to_regclass('public.desktop_releases') AS t")).rows[0].t, null);
    assert.equal((await tdb.db.query("SELECT count(*)::int AS n FROM information_schema.columns WHERE table_name = 'devices' AND column_name = 'app_version'")).rows[0].n, 0);
    // 0005 reverts cleanly: device memory goes.
    await migrateDown(tdb.db, 1, loadMigrations(repoMigrations));
    assert.equal((await tdb.db.query("SELECT to_regclass('public.memory_entries') AS t")).rows[0].t, null);

    // 0004 reverts cleanly on its own: its columns and setting go, everything else stays.
    await migrateDown(tdb.db, 1, loadMigrations(repoMigrations));
    assert.equal((await tdb.db.query("SELECT count(*)::int AS n FROM information_schema.columns WHERE table_name = 'devices' AND column_name = 'install_id'")).rows[0].n, 0);
    assert.equal((await tdb.db.query("SELECT count(*)::int AS n FROM settings WHERE key = 'allow_auto_registration'")).rows[0].n, 0);
    assert.notEqual((await tdb.db.query("SELECT to_regclass('public.device_models') AS t")).rows[0].t, null);

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

test('0007 keeps every existing device, token, memory and log untouched', async (t) => {
  const tdb = await createTestDb();
  if (!tdb) return t.skip(SKIP_NO_PG);
  try {
    const all = loadMigrations(repoMigrations);
    await migrateUp(tdb.db, all.filter((m) => m.version <= 6));
    const dev = await tdb.db.query(
      "INSERT INTO devices (name, token_hash, install_id, registered_via) VALUES ('Old PC', 'aaaa', 'install-old-device-0001', 'auto') RETURNING id",
    );
    const id = dev.rows[0].id;
    await tdb.db.query(
      "INSERT INTO memory_entries (device_id, client_key, scope, kind, content, source, confidence, client_updated_at) VALUES ($1, 'kkkkkkkkkkkkkkkkkk', 'global', 'fact', 'old memory', 'user', 1, 1)",
      [id],
    );
    await tdb.db.query("INSERT INTO request_logs (device_id, model_name, provider_name, status, http_status, latency_ms) VALUES ($1, 'm', 'p', 'ok', 200, 5)", [id]);
    const before = (await tdb.db.query('SELECT * FROM devices WHERE id = $1', [id])).rows[0];
    assert.deepEqual(await migrateUp(tdb.db, all), ['0007_accounts.sql', '0008_web_search.sql', '0009_org_skills.sql']);
    const after = (await tdb.db.query('SELECT * FROM devices WHERE id = $1', [id])).rows[0];
    for (const k of Object.keys(before)) assert.deepEqual(after[k], before[k], k);
    assert.equal(after.user_id, null);
    assert.equal(after.token_expires_at, null, 'legacy tokens do not get an expiry');
    assert.equal((await tdb.db.query('SELECT count(*)::int AS n FROM memory_entries WHERE device_id = $1', [id])).rows[0].n, 1);
    assert.equal((await tdb.db.query('SELECT count(*)::int AS n FROM request_logs WHERE device_id = $1', [id])).rows[0].n, 1);
    assert.equal((await tdb.db.query("SELECT value FROM settings WHERE key = 'require_login_for_central_ai'")).rows[0].value, false);
  } finally {
    await tdb.drop();
  }
});
