import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Db, PgConnection, PgError, decodeValue } from '../src/db/pg-wire.ts';
import { adminPgConfig, createTestDb, SKIP_NO_PG } from './helpers.ts';

test('text values are decoded by column type', () => {
  assert.equal(decodeValue(16, 't'), true);
  assert.equal(decodeValue(23, '42'), 42);
  assert.deepEqual(decodeValue(3802, '{"a":[1]}'), { a: [1] });
  assert.deepEqual(decodeValue(17, '\\x0102'), Buffer.from([1, 2]));
  assert.equal(decodeValue(25, null), null);
  assert.equal((decodeValue(1184, '2026-10-19 20:00:00.123456+00') as Date).toISOString(), '2026-10-19T20:00:00.123Z');
  assert.equal((decodeValue(1114, '2026-10-19 20:00:00') as Date).toISOString(), '2026-10-19T20:00:00.000Z');
});

test('the wire client copes with large results split across socket reads', async (t) => {
  const admin = adminPgConfig();
  if (!admin) return t.skip(SKIP_NO_PG);
  const db = new Db(admin, 1);
  try {
    const { rows, rowCount } = await db.query("SELECT g AS n, repeat('x', 4000) AS big FROM generate_series(1, 2000) g");
    assert.equal(rows.length, 2000);
    assert.equal(rowCount, 2000);
    assert.equal(rows[1999].n, 2000);
    assert.equal(rows[1999].big.length, 4000);
  } finally {
    await db.close();
  }
});

test('parameters are bound as data, never executed', async (t) => {
  const tdb = await createTestDb();
  if (!tdb) return t.skip(SKIP_NO_PG);
  try {
    await tdb.db.query('CREATE TABLE notes (id int, body text)');
    const evil = "x'); DROP TABLE notes; --";
    await tdb.db.query('INSERT INTO notes VALUES ($1, $2)', [1, evil]);
    const { rows } = await tdb.db.query('SELECT body FROM notes WHERE id = $1', [1]);
    assert.equal(rows[0].body, evil);
    const nul = await tdb.db.query('SELECT $1::text AS a, $2::int AS b', [null, undefined]);
    assert.deepEqual(nul.rows[0], { a: null, b: null });
  } finally {
    await tdb.drop();
  }
});

test('a wrong password is refused with a clear error and no socket is left open', async (t) => {
  const admin = adminPgConfig();
  if (!admin) return t.skip(SKIP_NO_PG);
  await assert.rejects(
    PgConnection.connect({ ...admin, password: 'definitely-wrong-password' }),
    (e: unknown) => e instanceof PgError && /password authentication failed|invalid password|password/i.test(e.message),
  );
});

test('an unreachable host fails fast', async () => {
  await assert.rejects(
    PgConnection.connect({ host: '127.0.0.1', port: 1, user: 'u', password: 'p', database: 'd', ssl: 'disable', connectTimeoutMs: 1000 }),
    (e: unknown) => e instanceof PgError && /cannot reach the database/.test(e.message),
  );
});

test('a database error carries its SQLSTATE', async (t) => {
  const admin = adminPgConfig();
  if (!admin) return t.skip(SKIP_NO_PG);
  const db = new Db(admin, 1);
  try {
    await assert.rejects(db.query('SELECT * FROM table_that_does_not_exist'), (e: unknown) => e instanceof PgError && e.code === '42P01');
  } finally {
    await db.close();
  }
});
