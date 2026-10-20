import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { configWarnings, loadConfig, redactedConfig } from '../src/config.ts';

const key = `1=${crypto.randomBytes(32).toString('base64')}`;
const prod = {
  DEVORA_ENV: 'production',
  DATABASE_URL: 'postgres://devora:pw@db.internal:5432/devora',
  DEVORA_SECRET_KEYS: key,
  DEVORA_SECRET_ACTIVE_KEY: '1',
  ADMIN_ORIGIN: 'https://Admin.Example.test',
};

test('development defaults are usable on a laptop', () => {
  const c = loadConfig({ DATABASE_URL: 'postgres://u:p@127.0.0.1:5432/d' });
  assert.equal(c.env, 'development');
  assert.equal(c.cookieSecure, false, 'plain localhost development cannot use Secure cookies');
  assert.equal(c.database.ssl, 'disable');
  assert.equal(c.trustProxy, false);
  assert.equal(c.keyring.size, 0);
});

test('production needs the secret keyring, a secure cookie and an origin without a path', () => {
  assert.throws(() => loadConfig({ ...prod, DEVORA_SECRET_KEYS: '' }), /DEVORA_SECRET_KEYS is required/);
  assert.throws(() => loadConfig({ ...prod, COOKIE_SECURE: 'false' }), /COOKIE_SECURE must be true/);
  assert.throws(() => loadConfig({ ...prod, ADMIN_ORIGIN: 'https://admin.example.test/path' }), /origin without a path/);
  const c = loadConfig(prod);
  assert.equal(c.adminOrigin, 'https://admin.example.test', 'the origin is normalized to lower case');
  assert.equal(c.cookieSecure, true);
});

test('production refuses a plaintext database connection unless it is explicitly allowed for a private network', () => {
  assert.throws(() => loadConfig({ ...prod, DATABASE_SSL: 'disable' }), /requires DATABASE_SSL=require/);
  assert.equal(loadConfig({ ...prod, DATABASE_SSL: 'disable', DATABASE_ALLOW_PLAINTEXT_NETWORK: 'true' }).database.ssl, 'disable');
  assert.equal(loadConfig(prod).database.ssl, 'require');
});

test('sslmode values are mapped strictly', () => {
  assert.throws(() => loadConfig({ DATABASE_URL: 'postgres://u:p@h/d?sslmode=prefer' }), /not supported/);
  assert.equal(loadConfig({ DATABASE_URL: 'postgres://u:p@h/d?sslmode=verify-full' }).database.ssl, 'require');
});

test('invalid values fail fast with a clear message', () => {
  assert.throws(() => loadConfig({ DATABASE_URL: 'postgres://u:p@h/d', PORT: '99999' }), /PORT/);
  assert.throws(() => loadConfig({ DATABASE_URL: 'postgres://u:p@h/d', TRUST_PROXY: 'maybe' }), /true or false/);
  assert.throws(() => loadConfig({ DATABASE_URL: 'mysql://u:p@h/d' }), /postgres/);
  assert.throws(() => loadConfig({}), /DATABASE_URL/);
});

test('the admin origin is normalized and only an origin is accepted', () => {
  assert.equal(loadConfig({ DATABASE_URL: 'postgres://u:p@h/d', ADMIN_ORIGIN: 'https://ADMIN.example.test/' }).adminOrigin, 'https://admin.example.test');
  assert.throws(() => loadConfig({ DATABASE_URL: 'postgres://u:p@h/d', ADMIN_ORIGIN: 'not a url' }), /ADMIN_ORIGIN/);
});

test('production requires an https admin origin that is not local and not a placeholder', () => {
  const { ADMIN_ORIGIN: _drop, ...noAdmin } = prod;
  assert.throws(() => loadConfig(noAdmin), /ADMIN_ORIGIN is required in production/);
  assert.throws(() => loadConfig({ ...prod, ADMIN_ORIGIN: 'http://admin.example.test' }), /must use https in production/);
  assert.throws(() => loadConfig({ ...prod, ADMIN_ORIGIN: 'https://localhost' }), /local address/);
  assert.throws(() => loadConfig({ ...prod, ADMIN_ORIGIN: 'https://admin.YOUR_DOMAIN', PUBLIC_API_ORIGIN: 'https://api.YOUR_DOMAIN' }), /placeholder/);
  assert.throws(() => loadConfig({ ...prod, PUBLIC_API_ORIGIN: 'http://127.0.0.1:8080' }), /https in production/);
  // Development may use local http addresses.
  assert.equal(loadConfig({ DATABASE_URL: 'postgres://u:p@h/d', PUBLIC_API_ORIGIN: 'http://localhost:8080' }).publicApiOrigin, 'http://localhost:8080');
});

test('NODE_ENV=production switches on production rules and may not contradict DEVORA_ENV', () => {
  const { DEVORA_ENV: _e, ...rest } = prod;
  assert.equal(loadConfig({ ...rest, NODE_ENV: 'production' }).env, 'production');
  assert.throws(() => loadConfig({ ...rest, NODE_ENV: 'production', DEVORA_SECRET_KEYS: '' }), /DEVORA_SECRET_KEYS is required/);
  assert.throws(() => loadConfig({ ...prod, DEVORA_ENV: 'development', NODE_ENV: 'production' }), /conflicts/);
});

test('timeouts and desktop release settings are validated', () => {
  const base = { DATABASE_URL: 'postgres://u:p@h/d' };
  assert.equal(loadConfig(base).requestTimeoutMs, 300_000);
  assert.equal(loadConfig({ ...base, REQUEST_TIMEOUT_MS: '600000' }).requestTimeoutMs, 600_000);
  assert.throws(() => loadConfig({ ...base, REQUEST_TIMEOUT_MS: '20000', HEADERS_TIMEOUT_MS: '30000' }), /larger than/);
  assert.throws(() => loadConfig({ ...base, DEVORA_DESKTOP_MIN_VERSION: 'v1' }), /1\.2\.3/);
  assert.throws(() => loadConfig({ ...base, DEVORA_DESKTOP_DOWNLOAD_URL: 'http://downloads.example.test' }), /https URL/);
  const c = loadConfig({ ...base, DEVORA_DESKTOP_MIN_VERSION: '1.2.0', DEVORA_DESKTOP_DOWNLOAD_URL: 'https://downloads.example.test/devora' });
  assert.deepEqual(c.desktop, { minVersion: '1.2.0', latestVersion: null, downloadUrl: 'https://downloads.example.test/devora', statusMessage: '' });
});

test('the instance id is stable across key rotation and can be set explicitly', () => {
  const second = `2=${crypto.randomBytes(32).toString('base64')}`;
  const a = loadConfig(prod).instanceId;
  const b = loadConfig({ ...prod, DEVORA_SECRET_KEYS: `${key},${second}`, DEVORA_SECRET_ACTIVE_KEY: '2' }).instanceId;
  assert.equal(a, b, 'adding and activating a new key keeps the id');
  assert.match(a, /^[0-9a-f]{32}$/);
  assert.equal(loadConfig({ ...prod, DEVORA_INSTANCE_ID: 'devora-main-01' }).instanceId, 'devora-main-01');
  assert.throws(() => loadConfig({ ...prod, DEVORA_INSTANCE_ID: 'x' }), /DEVORA_INSTANCE_ID/);
});

test('the startup summary never contains secrets, and risky production choices produce warnings', () => {
  const c = loadConfig({ ...prod, DATABASE_URL: 'postgres://devora:SuperSecretPw@db.internal:5432/devora', REDIS_URL: 'redis://default:RedisSecretPw@redis.internal:6379/0' });
  const text = JSON.stringify(redactedConfig(c));
  for (const s of ['SuperSecretPw', 'RedisSecretPw', key.slice(2)]) assert.ok(!text.includes(s), `summary leaks ${s}`);
  assert.match(text, /db\.internal:5432\/devora/);
  const w = configWarnings(loadConfig(prod)).join('\n');
  assert.match(w, /PUBLIC_API_ORIGIN/);
  assert.match(w, /TRUST_PROXY/);
});

test('a YOUR_DOMAIN placeholder copied from .env.example is refused in production and ignored in development', () => {
  assert.throws(() => loadConfig({ ...prod, PUBLIC_API_ORIGIN: 'https://api.YOUR_DOMAIN' }), /placeholder/);
  const c = loadConfig({ DATABASE_URL: 'postgres://u:p@h/d', ADMIN_ORIGIN: 'http://localhost:8081', PUBLIC_API_ORIGIN: 'https://api.YOUR_DOMAIN' });
  assert.equal(c.publicApiOrigin, null, 'the desktop is never told about a fake address');
  assert.equal(c.adminOrigin, 'http://localhost:8081');
  assert.match(configWarnings(c).join('\n'), /PUBLIC_API_ORIGIN still contains the YOUR_DOMAIN placeholder/);
});
