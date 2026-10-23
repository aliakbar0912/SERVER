// Starts a real, throwaway PocketBase for tests (DEVORA_TEST_POCKETBASE_BIN, default /opt/pbtest/pocketbase) with a fresh
// data directory, a superuser, and SMTP pointed at a local mail catcher so verification and reset emails are actually
// delivered and can be read. Tests skip with a reason when the binary is not available.
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

export const PB_BIN = process.env.DEVORA_TEST_POCKETBASE_BIN ?? '/opt/pbtest/pocketbase';
export const SKIP_NO_PB = `no PocketBase binary for tests (set DEVORA_TEST_POCKETBASE_BIN; looked at ${PB_BIN})`;

export interface Mail {
  to: string[];
  raw: string;
}

export interface TestPocketBase {
  url: string;
  adminEmail: string;
  adminPassword: string;
  mails: Mail[];
  superToken(): Promise<string>;
  /** Superuser request helper. */
  su(method: string, p: string, body?: unknown): Promise<{ status: number; body: any }>;
  /** Public (or user-token) request helper. */
  api(method: string, p: string, body?: unknown, token?: string): Promise<{ status: number; body: any }>;
  createUser(email: string, password: string, opts?: { verified?: boolean; name?: string }): Promise<string>;
  passwordToken(email: string, password: string): Promise<string>;
  /** Waits for the next mail to `to` and returns the first token-looking path segment in it (verification/reset). */
  waitForMailToken(to: string, kind: 'confirm-verification' | 'confirm-password-reset'): Promise<string>;
  stop(): Promise<void>;
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const port = (s.address() as net.AddressInfo).port;
      s.close(() => resolve(port));
    });
  });
}

/** A minimal SMTP receiver (no TLS, no auth): enough for PocketBase to deliver mail during tests. */
async function startMailCatcher(mails: Mail[]): Promise<{ port: number; close(): Promise<void> }> {
  const server = net.createServer((sock) => {
    let buf = '';
    let inData = false;
    let to: string[] = [];
    let data = '';
    sock.write('220 devora-test ESMTP\r\n');
    sock.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      for (;;) {
        if (inData) {
          const end = buf.indexOf('\r\n.\r\n');
          if (end < 0) return;
          data += buf.slice(0, end);
          buf = buf.slice(end + 5);
          inData = false;
          mails.push({ to, raw: data });
          to = [];
          data = '';
          sock.write('250 OK queued\r\n');
          continue;
        }
        const nl = buf.indexOf('\r\n');
        if (nl < 0) return;
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        const cmd = line.slice(0, 4).toUpperCase();
        if (cmd === 'EHLO' || cmd === 'HELO') sock.write('250-devora-test\r\n250 8BITMIME\r\n');
        else if (cmd === 'MAIL') sock.write('250 OK\r\n');
        else if (cmd === 'RCPT') {
          const m = /<([^>]+)>/.exec(line);
          if (m) to.push(m[1].toLowerCase());
          sock.write('250 OK\r\n');
        } else if (cmd === 'DATA') {
          inData = true;
          sock.write('354 End data with <CR><LF>.<CR><LF>\r\n');
        } else if (cmd === 'QUIT') {
          sock.end('221 Bye\r\n');
          return;
        } else sock.write('250 OK\r\n');
      }
    });
    sock.on('error', () => undefined);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return { port: (server.address() as net.AddressInfo).port, close: () => new Promise((r) => server.close(() => r())) };
}

export async function startPocketBase(): Promise<TestPocketBase | null> {
  if (!fs.existsSync(PB_BIN)) return null;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'devora-pb-'));
  const adminEmail = 'server@devora.test';
  const adminPassword = crypto.randomBytes(12).toString('base64url');
  const up = spawnSync(PB_BIN, ['superuser', 'upsert', adminEmail, adminPassword, '--dir', dir], { encoding: 'utf8' });
  if (up.status !== 0) throw new Error(`pocketbase superuser upsert failed: ${up.stderr}`);
  const port = await freePort();
  const url = `http://127.0.0.1:${port}`;
  const proc: ChildProcess = spawn(PB_BIN, ['serve', '--http', `127.0.0.1:${port}`, '--dir', dir], { stdio: 'ignore' });
  for (let i = 0; i < 100; i++) {
    try {
      const r = await fetch(`${url}/api/health`);
      if (r.ok) break;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  const mails: Mail[] = [];
  const smtp = await startMailCatcher(mails);
  const call = async (method: string, p: string, body?: unknown, token?: string) => {
    const r = await fetch(url + p, {
      method,
      headers: { ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: token } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await r.text();
    let parsed: any = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = text;
    }
    return { status: r.status, body: parsed };
  };
  let token = '';
  const superToken = async () => {
    if (token) return token;
    const r = await call('POST', '/api/collections/_superusers/auth-with-password', { identity: adminEmail, password: adminPassword });
    token = r.body.token;
    return token;
  };
  const su = async (method: string, p: string, body?: unknown) => call(method, p, body, await superToken());
  const s = await su('PATCH', '/api/settings', {
    meta: { appName: 'Devora', appURL: url, senderName: 'Devora', senderAddress: 'no-reply@devora.test' },
    smtp: { enabled: true, host: '127.0.0.1', port: smtp.port, username: '', password: '', tls: false, authMethod: 'PLAIN', localName: '' },
  });
  if (s.status !== 200) throw new Error(`pocketbase settings failed: ${JSON.stringify(s.body)}`);
  return {
    url,
    adminEmail,
    adminPassword,
    mails,
    superToken,
    su,
    api: call,
    async createUser(email, password, opts = {}) {
      const r = await su('POST', '/api/collections/users/records', { email, password, passwordConfirm: password, verified: opts.verified ?? true, name: opts.name ?? '' });
      if (r.status !== 200) throw new Error(`create user failed: ${JSON.stringify(r.body)}`);
      return r.body.id as string;
    },
    async passwordToken(email, password) {
      const r = await call('POST', '/api/collections/users/auth-with-password', { identity: email, password });
      if (r.status !== 200) throw new Error(`password sign-in failed: ${r.status}`);
      return r.body.token as string;
    },
    async waitForMailToken(to, kind) {
      for (let i = 0; i < 100; i++) {
        const m = mails.find((x) => x.to.includes(to.toLowerCase()) && x.raw.replace(/=\r\n/g, '').includes(kind));
        if (m) {
          const body = m.raw.replace(/=\r\n/g, '').replace(/=3D/g, '=');
          const t = new RegExp(`${kind}/([A-Za-z0-9._-]+)`).exec(body);
          if (t) return t[1];
        }
        await new Promise((r) => setTimeout(r, 100));
      }
      throw new Error(`no ${kind} mail for ${to}`);
    },
    async stop() {
      proc.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 200));
      await smtp.close();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}
