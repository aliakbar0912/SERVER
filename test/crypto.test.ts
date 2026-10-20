import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { hashPassword, verifyPassword, randomToken, sha256Hex, parseKeyring, sealSecret, openSecret } from '../src/crypto.ts';

const key = (id: number) => `${id}=${crypto.randomBytes(32).toString('base64')}`;

test('password hashes verify only the right password and are salted', async () => {
  const h1 = await hashPassword('correct horse battery');
  const h2 = await hashPassword('correct horse battery');
  assert.notEqual(h1, h2);
  assert.equal(await verifyPassword('correct horse battery', h1), true);
  assert.equal(await verifyPassword('correct horse batterx', h1), false);
  assert.equal(await verifyPassword('x', 'not-a-hash'), false);
});

test('tokens are random and hashed for storage', () => {
  assert.notEqual(randomToken(), randomToken());
  assert.equal(randomToken().length, 43);
  assert.match(sha256Hex('abc'), /^[0-9a-f]{64}$/);
  assert.notEqual(sha256Hex('abc'), 'abc');
});

test('secrets round-trip, are bound to their row, and survive key rotation', () => {
  const ring = parseKeyring(`1=${crypto.randomBytes(32).toString('base64')},2=${crypto.randomBytes(32).toString('base64')}`, '2');
  const sealed = sealSecret(ring, 'sk-test-123', 'provider:a');
  assert.equal(sealed.keyVersion, 2);
  assert.ok(!sealed.ciphertext.toString('utf8').includes('sk-test'));
  assert.equal(openSecret(ring, sealed, 'provider:a'), 'sk-test-123');
  assert.throws(() => openSecret(ring, sealed, 'provider:b'));
  const rotated = parseKeyring(ring.keys.get(2) ? `1=${ring.keys.get(1)!.toString('base64')},2=${ring.keys.get(2)!.toString('base64')}` : '', '1');
  const old = sealSecret(rotated, 'k', 'x');
  assert.equal(old.keyVersion, 1);
  const onlyNew = parseKeyring(`2=${ring.keys.get(2)!.toString('base64')}`, '2');
  assert.throws(() => openSecret(onlyNew, old, 'x'), /key 1 is not configured/);
});

test('keyring rejects bad input', () => {
  assert.throws(() => parseKeyring(`1=${Buffer.alloc(8).toString('base64')}`, '1'), /32 bytes/);
  assert.throws(() => parseKeyring(key(1), '9'), /ACTIVE_KEY/);
  assert.equal(parseKeyring('', '').size, 0);
});
