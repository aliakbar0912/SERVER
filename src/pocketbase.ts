// The server's PocketBase client. PocketBase owns Devora user identities (email/password, Google, GitHub, email
// verification). This server only ever:
//   - verifies a user token a desktop hands over (auth-refresh, then re-reads the record as superuser),
//   - finishes a browser OAuth2 sign-in with the authorization code PocketBase's provider sent to our callback,
//   - re-checks that a user still exists and is verified, lists users for the owner, and deletes an account on request.
// The superuser credentials come from the environment and never leave this process; nothing here is logged.
import type { PocketBaseConfig } from './config.ts';

export interface PbUser {
  id: string;
  email: string;
  name: string;
  verified: boolean;
  created: string;
  avatar: string;
}

export interface PbProvider {
  name: string;
  displayName: string;
  state: string;
  authURL: string;
  codeVerifier: string;
  codeChallengeMethod: string;
}

export interface PbExternalAuth {
  id: string;
  provider: string;
  created: string;
}

/** A PocketBase answer that is not a success. `status` 0 means PocketBase could not be reached. */
export class PbError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'PbError';
    this.status = status;
  }
}

const TIMEOUT_MS = 10_000;
const ID = /^[A-Za-z0-9_]{1,64}$/;

function jwtExp(token: string): number {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8'));
    return typeof payload.exp === 'number' ? payload.exp * 1000 : 0;
  } catch {
    return 0;
  }
}

/** Escapes a value for a single-quoted PocketBase filter literal. */
export function pbLiteral(v: string): string {
  return `'${v.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}

export class PocketBase {
  private superToken: { token: string; until: number } | null = null;
  private superPending: Promise<string> | null = null;
  readonly cfg: PocketBaseConfig;
  private readonly fetchFn: typeof fetch;
  constructor(cfg: PocketBaseConfig, fetchFn: typeof fetch) {
    this.cfg = cfg;
    this.fetchFn = fetchFn;
  }

  private col(): string {
    return encodeURIComponent(this.cfg.usersCollection);
  }

  private async call(method: string, path: string, opts: { body?: unknown; auth?: string } = {}): Promise<{ status: number; body: any }> {
    let res: Response;
    try {
      res = await this.fetchFn(this.cfg.url + path, {
        method,
        headers: { accept: 'application/json', ...(opts.body !== undefined ? { 'content-type': 'application/json' } : {}), ...(opts.auth ? { authorization: opts.auth } : {}) },
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
        redirect: 'error',
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch {
      throw new PbError(0, 'the account service cannot be reached');
    }
    const text = await res.text().catch(() => '');
    let body: any = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = null;
    }
    return { status: res.status, body };
  }

  private async superuser(force = false): Promise<string> {
    if (!force && this.superToken && this.superToken.until > Date.now()) return this.superToken.token;
    if (!this.superPending) {
      this.superPending = (async () => {
        const r = await this.call('POST', '/api/collections/_superusers/auth-with-password', { body: { identity: this.cfg.adminEmail, password: this.cfg.adminPassword } });
        if (r.status !== 200 || typeof r.body?.token !== 'string') throw new PbError(r.status === 0 ? 0 : 502, 'the server could not sign in to the account service');
        const token = r.body.token as string;
        // Renew a minute before PocketBase's own expiry, and at least every 30 minutes.
        const exp = jwtExp(token);
        this.superToken = { token, until: Math.min(exp ? exp - 60_000 : Date.now() + 600_000, Date.now() + 30 * 60_000) };
        return token;
      })().finally(() => (this.superPending = null));
    }
    return this.superPending;
  }

  /** A superuser request, signing in again once if the token was rejected (rotated password, restarted PocketBase). */
  private async admin(method: string, path: string, body?: unknown): Promise<{ status: number; body: any }> {
    let r = await this.call(method, path, { body, auth: await this.superuser() });
    if (r.status === 401 || r.status === 403) r = await this.call(method, path, { body, auth: await this.superuser(true) });
    return r;
  }

  /** Validates a users-collection record and keeps only the fields Devora uses. */
  private user(rec: any): PbUser {
    if (!rec || typeof rec.id !== 'string' || !ID.test(rec.id)) throw new PbError(502, 'the account service returned an unexpected answer');
    if (rec.collectionName !== undefined && rec.collectionName !== this.cfg.usersCollection) throw new PbError(401, 'this account is not a Devora user account');
    return {
      id: rec.id,
      email: typeof rec.email === 'string' ? rec.email : '',
      name: typeof rec.name === 'string' ? rec.name.slice(0, 120) : '',
      verified: rec.verified === true,
      created: typeof rec.created === 'string' ? rec.created : '',
      avatar: typeof rec.avatar === 'string' ? rec.avatar : '',
    };
  }

  /** OAuth2 providers enabled on the users collection, each with a fresh state and PKCE verifier from PocketBase. */
  async providers(): Promise<PbProvider[]> {
    const r = await this.call('GET', `/api/collections/${this.col()}/auth-methods`);
    if (r.status !== 200) throw new PbError(r.status || 0, 'the account service is unavailable');
    const list = r.body?.oauth2?.enabled ? r.body.oauth2.providers : [];
    if (!Array.isArray(list)) return [];
    return list
      .filter((p: any) => p && typeof p.name === 'string' && typeof p.authURL === 'string' && typeof p.state === 'string' && typeof p.codeVerifier === 'string')
      .map((p: any) => ({ name: p.name, displayName: String(p.displayName ?? p.name).slice(0, 60), state: p.state, authURL: p.authURL, codeVerifier: p.codeVerifier, codeChallengeMethod: String(p.codeChallengeMethod ?? '') }));
  }

  /**
   * Finishes an OAuth2 sign-in: PocketBase exchanges the code with the provider (it holds the client secret), checks PKCE
   * and the exact redirect URI, and returns the user. With `userToken` the provider is linked to that signed-in user.
   * The provider's own access/refresh tokens in PocketBase's answer are dropped here.
   */
  async finishOAuth(input: { provider: string; code: string; codeVerifier: string; redirectUrl: string; userToken?: string }): Promise<{ user: PbUser; token: string }> {
    const r = await this.call('POST', `/api/collections/${this.col()}/auth-with-oauth2`, {
      body: { provider: input.provider, code: input.code, codeVerifier: input.codeVerifier, redirectURL: input.redirectUrl },
      auth: input.userToken,
    });
    if (r.status !== 200 || typeof r.body?.token !== 'string') throw new PbError(r.status === 0 ? 0 : 401, 'the sign-in could not be completed');
    return { user: this.user(r.body.record), token: r.body.token as string };
  }

  /** Checks a user token by asking PocketBase to refresh it (signature, expiry, tokenKey). The new token is discarded. */
  async verifyUserToken(token: string): Promise<PbUser> {
    if (!/^[A-Za-z0-9._-]{20,4096}$/.test(token)) throw new PbError(401, 'the sign-in is not valid');
    const r = await this.call('POST', `/api/collections/${this.col()}/auth-refresh`, { auth: token });
    if (r.status !== 200) throw new PbError(r.status === 0 ? 0 : 401, 'the sign-in is not valid or has expired');
    return this.user(r.body?.record);
  }

  /** Checks a password for an existing user (re-authentication before account deletion). */
  async checkPassword(email: string, password: string): Promise<PbUser> {
    const r = await this.call('POST', `/api/collections/${this.col()}/auth-with-password`, { body: { identity: email, password } });
    if (r.status !== 200) throw new PbError(r.status === 0 ? 0 : 401, 'the password is not correct');
    return this.user(r.body?.record);
  }

  /** Checks an email one-time code (PocketBase OTP) for re-authentication. The OTP is single use. */
  async checkOtp(otpId: string, code: string): Promise<PbUser> {
    if (!/^[A-Za-z0-9]{1,64}$/.test(otpId) || !/^[0-9]{4,12}$/.test(code)) throw new PbError(401, 'the code is not correct');
    const r = await this.call('POST', `/api/collections/${this.col()}/auth-with-otp`, { body: { otpId, password: code } });
    // PocketBase limits wrong guesses itself (429 "Too many attempts"): keep that answer, it means "ask for a new code".
    if (r.status === 429) throw new PbError(429, 'too many attempts; request a new code');
    if (r.status !== 200) throw new PbError(r.status === 0 ? 0 : 401, 'the code is not correct');
    return this.user(r.body?.record);
  }

  /** Sets a new password (superuser). PocketBase also renews the user's tokenKey, so every existing user token stops working. */
  async setPassword(id: string, password: string): Promise<void> {
    if (!ID.test(id)) throw new PbError(400, 'invalid user id');
    const r = await this.admin('PATCH', `/api/collections/${this.col()}/records/${encodeURIComponent(id)}`, { password, passwordConfirm: password });
    if (r.status === 400) throw new PbError(400, 'the password was not accepted; use at least 8 characters');
    if (r.status !== 200) throw new PbError(r.status || 0, 'the account service is unavailable');
  }

  /** The user's current record, read as superuser. Null when the account no longer exists. */
  async getUser(id: string): Promise<PbUser | null> {
    if (!ID.test(id)) return null;
    const r = await this.admin('GET', `/api/collections/${this.col()}/records/${encodeURIComponent(id)}`);
    if (r.status === 404) return null;
    if (r.status !== 200) throw new PbError(r.status || 0, 'the account service is unavailable');
    return this.user(r.body);
  }

  async listUsers(opts: { page: number; perPage: number; search: string }): Promise<{ items: PbUser[]; total: number }> {
    const q = new URLSearchParams({ page: String(opts.page), perPage: String(opts.perPage), sort: '-created' });
    const s = opts.search.trim().slice(0, 100);
    if (s) q.set('filter', `(email ~ ${pbLiteral(s)} || name ~ ${pbLiteral(s)} || id = ${pbLiteral(s)})`);
    const r = await this.admin('GET', `/api/collections/${this.col()}/records?${q}`);
    if (r.status !== 200 || !Array.isArray(r.body?.items)) throw new PbError(r.status || 0, 'the account service is unavailable');
    return { items: r.body.items.map((x: any) => this.user(x)), total: Number(r.body.totalItems ?? r.body.items.length) };
  }

  /** Google/GitHub identities linked to the user (PocketBase's own _externalAuths records). */
  async externalAuths(userId: string): Promise<PbExternalAuth[]> {
    if (!ID.test(userId)) return [];
    const filter = `(recordRef = ${pbLiteral(userId)} && collectionRef = ${pbLiteral(await this.collectionId())})`;
    const r = await this.admin('GET', `/api/collections/_externalAuths/records?perPage=50&filter=${encodeURIComponent(filter)}`);
    if (r.status !== 200 || !Array.isArray(r.body?.items)) throw new PbError(r.status || 0, 'the account service is unavailable');
    return r.body.items.map((x: any) => ({ id: String(x.id), provider: String(x.provider), created: String(x.created ?? '') }));
  }

  private usersCollectionId: string | null = null;
  private async collectionId(): Promise<string> {
    if (this.usersCollectionId) return this.usersCollectionId;
    const r = await this.admin('GET', `/api/collections/${this.col()}`);
    if (r.status !== 200 || typeof r.body?.id !== 'string' || r.body.type !== 'auth') throw new PbError(r.status || 0, 'the users collection is not available');
    this.usersCollectionId = r.body.id as string;
    return this.usersCollectionId;
  }

  /** Deletes the user. PocketBase removes its linked _externalAuths records with it. True also when it was already gone. */
  async deleteUser(id: string): Promise<true> {
    if (!ID.test(id)) throw new PbError(400, 'invalid user id');
    const r = await this.admin('DELETE', `/api/collections/${this.col()}/records/${encodeURIComponent(id)}`);
    if (r.status !== 204 && r.status !== 200 && r.status !== 404) throw new PbError(r.status || 0, 'the account could not be deleted in the account service');
    return true;
  }
}
