// Cryptographic helpers. Only Node built-ins are used.
//  - Passwords: scrypt with a per-password salt, compared in constant time.
//  - Tokens (admin sessions, CSRF, device tokens, enrollment codes): random values, stored only as SHA-256 hashes.
//  - Provider API keys: AES-256-GCM with a versioned keyring. The key id is stored with each ciphertext so keys can be rotated.
import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(crypto.scrypt) as (pw: string, salt: Buffer, keylen: number, opts: crypto.ScryptOptions) => Promise<Buffer>;
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(16);
  const key = await scryptAsync(password, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${key.toString('base64')}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [N, r, p] = parts.slice(1, 4).map(Number);
  const salt = Buffer.from(parts[4], 'base64');
  const expected = Buffer.from(parts[5], 'base64');
  const key = await scryptAsync(password, salt, expected.length, { N, r, p, maxmem: 64 * 1024 * 1024 });
  return key.length === expected.length && crypto.timingSafeEqual(key, expected);
}

/** A dummy hash check so that an unknown email costs the same time as a wrong password. */
let dummyHash: Promise<string> | null = null;
export function burnPasswordTime(password: string): Promise<boolean> {
  dummyHash ??= hashPassword('devora-dummy-password-for-timing');
  return dummyHash.then((h) => verifyPassword(password, h));
}

export function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

export function constantTimeEqualHex(a: string, b: string): boolean {
  const x = Buffer.from(a, 'hex');
  const y = Buffer.from(b, 'hex');
  return x.length === y.length && x.length > 0 && crypto.timingSafeEqual(x, y);
}

const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0, O, 1, I

/** 16 characters, shown as four groups. Uniform over the alphabet. */
export function enrollmentCode(): string {
  let out = '';
  for (let i = 0; i < 16; i++) out += CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)];
  return out.match(/.{4}/g)!.join('-');
}

/** Accepts the code with or without dashes and in any case. */
export function normalizeEnrollmentCode(input: string): string {
  return input.toUpperCase().replace(/[^A-Z0-9]/g, '');
}

export interface Keyring {
  size: number;
  activeId: number;
  keys: Map<number, Buffer>;
}

/** DEVORA_SECRET_KEYS="1=<base64 32 bytes>,2=<base64 32 bytes>" and DEVORA_SECRET_ACTIVE_KEY="2". */
export function parseKeyring(spec: string, active: string): Keyring {
  const keys = new Map<number, Buffer>();
  for (const entry of spec.split(',').map((s) => s.trim()).filter(Boolean)) {
    const eq = entry.indexOf('=');
    const id = Number(entry.slice(0, eq));
    const key = Buffer.from(entry.slice(eq + 1), 'base64');
    if (eq < 1 || !Number.isInteger(id) || id < 1 || id > 999_999) throw new Error('DEVORA_SECRET_KEYS entries must look like 1=<base64>');
    if (key.length !== 32) throw new Error(`key ${id} must decode to 32 bytes`);
    if (keys.has(id)) throw new Error(`key ${id} appears twice`);
    keys.set(id, key);
  }
  if (keys.size === 0) return { size: 0, activeId: 0, keys };
  const activeId = Number(active);
  if (!Number.isInteger(activeId) || !keys.has(activeId)) throw new Error('DEVORA_SECRET_ACTIVE_KEY must name one of the ids in DEVORA_SECRET_KEYS');
  return { size: keys.size, activeId, keys };
}

export interface SealedSecret {
  keyVersion: number;
  iv: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
}

/** `aad` binds the ciphertext to its row (for example the provider id), so it cannot be moved to another row. */
export function sealSecret(keyring: Keyring, plaintext: string, aad: string): SealedSecret {
  const key = keyring.keys.get(keyring.activeId);
  if (!key) throw new Error('no encryption key is configured; set DEVORA_SECRET_KEYS and DEVORA_SECRET_ACTIVE_KEY');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return { keyVersion: keyring.activeId, iv, ciphertext, tag: cipher.getAuthTag() };
}

export function openSecret(keyring: Keyring, sealed: SealedSecret, aad: string): string {
  const key = keyring.keys.get(sealed.keyVersion);
  if (!key) throw new Error(`encryption key ${sealed.keyVersion} is not configured; restore it before reading this secret`);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, sealed.iv);
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(sealed.tag);
  return Buffer.concat([decipher.update(sealed.ciphertext), decipher.final()]).toString('utf8');
}
