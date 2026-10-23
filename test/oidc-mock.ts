// A tiny OpenID Connect identity provider for tests. PocketBase's built-in "oidc" provider is pointed at it, so the real
// PocketBase OAuth2 code exchange runs end to end (client secret check, exact redirect_uri, PKCE S256) without Google or
// GitHub. It is a test double for the *identity provider* only; PocketBase and the Devora server are the real ones.
import http from 'node:http';
import crypto from 'node:crypto';
import type { AddressInfo } from 'node:net';

export interface MockIdentity {
  sub: string;
  email: string;
  name?: string;
  emailVerified?: boolean;
}

interface Pending {
  identity: MockIdentity;
  redirectUri: string;
  challenge: string;
  method: string;
  clientId: string;
  used: boolean;
}

export interface OidcMock {
  url: string;
  clientId: string;
  clientSecret: string;
  /** Who "signs in" at the next authorize request. */
  setNextIdentity(identity: MockIdentity): void;
  /** Every token request PocketBase made (for asserting PKCE and redirect_uri). */
  tokenRequests: Array<Record<string, string>>;
  close(): Promise<void>;
}

export async function startOidcMock(): Promise<OidcMock> {
  const clientId = 'devora-test-client';
  const clientSecret = crypto.randomBytes(16).toString('hex');
  const codes = new Map<string, Pending>();
  const accessTokens = new Map<string, MockIdentity>();
  const tokenRequests: Array<Record<string, string>> = [];
  let next: MockIdentity | null = null;

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://idp');
    if (req.method === 'GET' && url.pathname === '/authorize') {
      const q = url.searchParams;
      if (q.get('client_id') !== clientId || q.get('response_type') !== 'code' || !q.get('redirect_uri') || !next) {
        res.writeHead(400).end('bad authorize request');
        return;
      }
      const code = crypto.randomBytes(16).toString('hex');
      codes.set(code, { identity: next, redirectUri: q.get('redirect_uri')!, challenge: q.get('code_challenge') ?? '', method: q.get('code_challenge_method') ?? '', clientId, used: false });
      const back = new URL(q.get('redirect_uri')!);
      back.searchParams.set('code', code);
      if (q.get('state')) back.searchParams.set('state', q.get('state')!);
      res.writeHead(302, { location: back.toString() }).end();
      return;
    }
    if (req.method === 'POST' && url.pathname === '/token') {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const form = Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString('utf8')));
      // PocketBase may send the client credentials in the body or as HTTP Basic auth.
      const basic = /^Basic (.+)$/.exec(req.headers.authorization ?? '');
      if (basic) {
        const [id, secret] = Buffer.from(basic[1], 'base64').toString('utf8').split(':').map(decodeURIComponent);
        form.client_id ??= id;
        form.client_secret ??= secret;
      }
      tokenRequests.push(form);
      const p = codes.get(form.code ?? '');
      const verifierOk = p && p.method === 'S256' && crypto.createHash('sha256').update(form.code_verifier ?? '').digest('base64url') === p.challenge;
      if (!p || p.used || form.client_id !== clientId || form.client_secret !== clientSecret || form.redirect_uri !== p.redirectUri || !verifierOk) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'invalid_grant' }));
        return;
      }
      p.used = true;
      const at = crypto.randomBytes(16).toString('hex');
      accessTokens.set(at, p.identity);
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ access_token: at, token_type: 'Bearer', expires_in: 300 }));
      return;
    }
    if (req.method === 'GET' && url.pathname === '/userinfo') {
      const id = accessTokens.get((req.headers.authorization ?? '').replace(/^Bearer\s+/i, ''));
      if (!id) {
        res.writeHead(401).end();
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' }).end(
        JSON.stringify({ sub: id.sub, email: id.email, name: id.name ?? '', email_verified: id.emailVerified ?? true }),
      );
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    url,
    clientId,
    clientSecret,
    tokenRequests,
    setNextIdentity: (i) => (next = i),
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}
