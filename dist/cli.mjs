#!/usr/bin/env node

// src/pocketbase.ts
var PbError = class extends Error {
  status;
  constructor(status, message) {
    super(message);
    this.name = "PbError";
    this.status = status;
  }
};
var TIMEOUT_MS = 1e4;
var ID = /^[A-Za-z0-9_]{1,64}$/;
function jwtExp(token) {
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"));
    return typeof payload.exp === "number" ? payload.exp * 1e3 : 0;
  } catch {
    return 0;
  }
}
function pbLiteral(v) {
  return `'${v.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;
}
var PocketBase = class {
  superToken = null;
  superPending = null;
  cfg;
  fetchFn;
  constructor(cfg, fetchFn) {
    this.cfg = cfg;
    this.fetchFn = fetchFn;
  }
  col() {
    return encodeURIComponent(this.cfg.usersCollection);
  }
  async call(method, path2, opts = {}) {
    let res;
    try {
      res = await this.fetchFn(this.cfg.url + path2, {
        method,
        headers: { accept: "application/json", ...opts.body !== void 0 ? { "content-type": "application/json" } : {}, ...opts.auth ? { authorization: opts.auth } : {} },
        body: opts.body === void 0 ? void 0 : JSON.stringify(opts.body),
        redirect: "error",
        signal: AbortSignal.timeout(TIMEOUT_MS)
      });
    } catch {
      throw new PbError(0, "the account service cannot be reached");
    }
    const text = await res.text().catch(() => "");
    let body = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = null;
    }
    return { status: res.status, body };
  }
  async superuser(force = false) {
    if (!force && this.superToken && this.superToken.until > Date.now()) return this.superToken.token;
    if (!this.superPending) {
      this.superPending = (async () => {
        const r = await this.call("POST", "/api/collections/_superusers/auth-with-password", { body: { identity: this.cfg.adminEmail, password: this.cfg.adminPassword } });
        if (r.status !== 200 || typeof r.body?.token !== "string") throw new PbError(r.status === 0 ? 0 : 502, "the server could not sign in to the account service");
        const token = r.body.token;
        const exp = jwtExp(token);
        this.superToken = { token, until: Math.min(exp ? exp - 6e4 : Date.now() + 6e5, Date.now() + 30 * 6e4) };
        return token;
      })().finally(() => this.superPending = null);
    }
    return this.superPending;
  }
  /** A superuser request, signing in again once if the token was rejected (rotated password, restarted PocketBase). */
  async admin(method, path2, body) {
    let r = await this.call(method, path2, { body, auth: await this.superuser() });
    if (r.status === 401 || r.status === 403) r = await this.call(method, path2, { body, auth: await this.superuser(true) });
    return r;
  }
  /** Validates a users-collection record and keeps only the fields Devora uses. */
  user(rec) {
    if (!rec || typeof rec.id !== "string" || !ID.test(rec.id)) throw new PbError(502, "the account service returned an unexpected answer");
    if (rec.collectionName !== void 0 && rec.collectionName !== this.cfg.usersCollection) throw new PbError(401, "this account is not a Devora user account");
    return {
      id: rec.id,
      email: typeof rec.email === "string" ? rec.email : "",
      name: typeof rec.name === "string" ? rec.name.slice(0, 120) : "",
      verified: rec.verified === true,
      created: typeof rec.created === "string" ? rec.created : "",
      avatar: typeof rec.avatar === "string" ? rec.avatar : ""
    };
  }
  /** OAuth2 providers enabled on the users collection, each with a fresh state and PKCE verifier from PocketBase. */
  async providers() {
    const r = await this.call("GET", `/api/collections/${this.col()}/auth-methods`);
    if (r.status !== 200) throw new PbError(r.status || 0, "the account service is unavailable");
    const list = r.body?.oauth2?.enabled ? r.body.oauth2.providers : [];
    if (!Array.isArray(list)) return [];
    return list.filter((p) => p && typeof p.name === "string" && typeof p.authURL === "string" && typeof p.state === "string" && typeof p.codeVerifier === "string").map((p) => ({ name: p.name, displayName: String(p.displayName ?? p.name).slice(0, 60), state: p.state, authURL: p.authURL, codeVerifier: p.codeVerifier, codeChallengeMethod: String(p.codeChallengeMethod ?? "") }));
  }
  /**
   * Finishes an OAuth2 sign-in: PocketBase exchanges the code with the provider (it holds the client secret), checks PKCE
   * and the exact redirect URI, and returns the user. With `userToken` the provider is linked to that signed-in user.
   * The provider's own access/refresh tokens in PocketBase's answer are dropped here.
   */
  async finishOAuth(input) {
    const r = await this.call("POST", `/api/collections/${this.col()}/auth-with-oauth2`, {
      body: { provider: input.provider, code: input.code, codeVerifier: input.codeVerifier, redirectURL: input.redirectUrl },
      auth: input.userToken
    });
    if (r.status !== 200 || typeof r.body?.token !== "string") throw new PbError(r.status === 0 ? 0 : 401, "the sign-in could not be completed");
    return { user: this.user(r.body.record), token: r.body.token };
  }
  /** Checks a user token by asking PocketBase to refresh it (signature, expiry, tokenKey). The new token is discarded. */
  async verifyUserToken(token) {
    if (!/^[A-Za-z0-9._-]{20,4096}$/.test(token)) throw new PbError(401, "the sign-in is not valid");
    const r = await this.call("POST", `/api/collections/${this.col()}/auth-refresh`, { auth: token });
    if (r.status !== 200) throw new PbError(r.status === 0 ? 0 : 401, "the sign-in is not valid or has expired");
    return this.user(r.body?.record);
  }
  /** Checks a password for an existing user (re-authentication before account deletion). */
  async checkPassword(email, password) {
    const r = await this.call("POST", `/api/collections/${this.col()}/auth-with-password`, { body: { identity: email, password } });
    if (r.status !== 200) throw new PbError(r.status === 0 ? 0 : 401, "the password is not correct");
    return this.user(r.body?.record);
  }
  /** Checks an email one-time code (PocketBase OTP) for re-authentication. The OTP is single use. */
  async checkOtp(otpId, code) {
    if (!/^[A-Za-z0-9]{1,64}$/.test(otpId) || !/^[0-9]{4,12}$/.test(code)) throw new PbError(401, "the code is not correct");
    const r = await this.call("POST", `/api/collections/${this.col()}/auth-with-otp`, { body: { otpId, password: code } });
    if (r.status === 429) throw new PbError(429, "too many attempts; request a new code");
    if (r.status !== 200) throw new PbError(r.status === 0 ? 0 : 401, "the code is not correct");
    return this.user(r.body?.record);
  }
  /** Sets a new password (superuser). PocketBase also renews the user's tokenKey, so every existing user token stops working. */
  async setPassword(id, password) {
    if (!ID.test(id)) throw new PbError(400, "invalid user id");
    const r = await this.admin("PATCH", `/api/collections/${this.col()}/records/${encodeURIComponent(id)}`, { password, passwordConfirm: password });
    if (r.status === 400) throw new PbError(400, "the password was not accepted; use at least 8 characters");
    if (r.status !== 200) throw new PbError(r.status || 0, "the account service is unavailable");
  }
  /** The user's current record, read as superuser. Null when the account no longer exists. */
  async getUser(id) {
    if (!ID.test(id)) return null;
    const r = await this.admin("GET", `/api/collections/${this.col()}/records/${encodeURIComponent(id)}`);
    if (r.status === 404) return null;
    if (r.status !== 200) throw new PbError(r.status || 0, "the account service is unavailable");
    return this.user(r.body);
  }
  async listUsers(opts) {
    const q = new URLSearchParams({ page: String(opts.page), perPage: String(opts.perPage), sort: "-created" });
    const s = opts.search.trim().slice(0, 100);
    if (s) q.set("filter", `(email ~ ${pbLiteral(s)} || name ~ ${pbLiteral(s)} || id = ${pbLiteral(s)})`);
    const r = await this.admin("GET", `/api/collections/${this.col()}/records?${q}`);
    if (r.status !== 200 || !Array.isArray(r.body?.items)) throw new PbError(r.status || 0, "the account service is unavailable");
    return { items: r.body.items.map((x) => this.user(x)), total: Number(r.body.totalItems ?? r.body.items.length) };
  }
  /** Google/GitHub identities linked to the user (PocketBase's own _externalAuths records). */
  async externalAuths(userId) {
    if (!ID.test(userId)) return [];
    const filter = `(recordRef = ${pbLiteral(userId)} && collectionRef = ${pbLiteral(await this.collectionId())})`;
    const r = await this.admin("GET", `/api/collections/_externalAuths/records?perPage=50&filter=${encodeURIComponent(filter)}`);
    if (r.status !== 200 || !Array.isArray(r.body?.items)) throw new PbError(r.status || 0, "the account service is unavailable");
    return r.body.items.map((x) => ({ id: String(x.id), provider: String(x.provider), created: String(x.created ?? "") }));
  }
  usersCollectionId = null;
  async collectionId() {
    if (this.usersCollectionId) return this.usersCollectionId;
    const r = await this.admin("GET", `/api/collections/${this.col()}`);
    if (r.status !== 200 || typeof r.body?.id !== "string" || r.body.type !== "auth") throw new PbError(r.status || 0, "the users collection is not available");
    this.usersCollectionId = r.body.id;
    return this.usersCollectionId;
  }
  /** Deletes the user. PocketBase removes its linked _externalAuths records with it. True also when it was already gone. */
  async deleteUser(id) {
    if (!ID.test(id)) throw new PbError(400, "invalid user id");
    const r = await this.admin("DELETE", `/api/collections/${this.col()}/records/${encodeURIComponent(id)}`);
    if (r.status !== 204 && r.status !== 200 && r.status !== 404) throw new PbError(r.status || 0, "the account could not be deleted in the account service");
    return true;
  }
};

// src/crypto.ts
import crypto from "node:crypto";
import { promisify } from "node:util";
var scryptAsync = promisify(crypto.scrypt);
var SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };
async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scryptAsync(password, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString("base64")}$${key.toString("base64")}`;
}
async function verifyPassword(password, stored) {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const [N, r, p] = parts.slice(1, 4).map(Number);
  const salt = Buffer.from(parts[4], "base64");
  const expected = Buffer.from(parts[5], "base64");
  const key = await scryptAsync(password, salt, expected.length, { N, r, p, maxmem: 64 * 1024 * 1024 });
  return key.length === expected.length && crypto.timingSafeEqual(key, expected);
}
var dummyHash = null;
function burnPasswordTime(password) {
  dummyHash ??= hashPassword("devora-dummy-password-for-timing");
  return dummyHash.then((h) => verifyPassword(password, h));
}
function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}
function sha256Hex(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}
function parseKeyring(spec, active) {
  const keys = /* @__PURE__ */ new Map();
  for (const entry of spec.split(",").map((s) => s.trim()).filter(Boolean)) {
    const eq = entry.indexOf("=");
    const id = Number(entry.slice(0, eq));
    const key = Buffer.from(entry.slice(eq + 1), "base64");
    if (eq < 1 || !Number.isInteger(id) || id < 1 || id > 999999) throw new Error("DEVORA_SECRET_KEYS entries must look like 1=<base64>");
    if (key.length !== 32) throw new Error(`key ${id} must decode to 32 bytes`);
    if (keys.has(id)) throw new Error(`key ${id} appears twice`);
    keys.set(id, key);
  }
  if (keys.size === 0) return { size: 0, activeId: 0, keys };
  const activeId = Number(active);
  if (!Number.isInteger(activeId) || !keys.has(activeId)) throw new Error("DEVORA_SECRET_ACTIVE_KEY must name one of the ids in DEVORA_SECRET_KEYS");
  return { size: keys.size, activeId, keys };
}
function sealSecret(keyring, plaintext, aad) {
  const key = keyring.keys.get(keyring.activeId);
  if (!key) throw new Error("no encryption key is configured; set DEVORA_SECRET_KEYS and DEVORA_SECRET_ACTIVE_KEY");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return { keyVersion: keyring.activeId, iv, ciphertext, tag: cipher.getAuthTag() };
}
function openSecret(keyring, sealed, aad) {
  const key = keyring.keys.get(sealed.keyVersion);
  if (!key) throw new Error(`encryption key ${sealed.keyVersion} is not configured; restore it before reading this secret`);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, sealed.iv);
  decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(sealed.tag);
  return Buffer.concat([decipher.update(sealed.ciphertext), decipher.final()]).toString("utf8");
}

// src/http/util.ts
var HttpError = class extends Error {
  status;
  code;
  headers;
  constructor(status, code, message, headers = {}) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.code = code;
    this.headers = headers;
  }
};
function fail(status, code, message, headers) {
  throw new HttpError(status, code, message, headers);
}
function sendJson(res, status, body, headers = {}) {
  const payload = status === 204 ? "" : JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    ...headers
  });
  res.end(payload);
}
function sendError(res, err) {
  sendJson(res, err.status, { error: { code: err.code, message: err.message } }, err.headers);
}
function sendOpenAiError(res, status, code, message, headers = {}) {
  const type = status >= 500 ? "server_error" : status === 429 ? "rate_limit_error" : status === 401 || status === 403 ? "authentication_error" : "invalid_request_error";
  sendJson(res, status, { error: { message, type, code } }, headers);
}
async function readJson(req, limit2) {
  const declared = Number(req.headers["content-length"] ?? 0);
  if (declared > limit2) fail(413, "payload_too_large", "the request body is too large");
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit2) {
      req.destroy();
      fail(413, "payload_too_large", "the request body is too large");
    }
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  if (!text.trim()) return {};
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail(400, "invalid_json", "the request body is not valid JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(400, "invalid_request", "the request body must be a JSON object");
  return value;
}
function setCookie(name, value, opts) {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${opts.maxAgeSeconds}${opts.secure ? "; Secure" : ""}`;
}
function clearCookie(name, secure) {
  return `${name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? "; Secure" : ""}`;
}
function clientAddress(req, trustProxy) {
  if (trustProxy) {
    const xff = req.headers["x-forwarded-for"];
    const last = (Array.isArray(xff) ? xff.join(",") : xff ?? "").split(",").map((s) => s.trim()).filter(Boolean).pop();
    if (last) return last.slice(0, 64);
  }
  return (req.socket.remoteAddress ?? "unknown").slice(0, 64);
}
function userAgent(req) {
  const ua = req.headers["user-agent"];
  return (Array.isArray(ua) ? ua[0] : ua ?? "").slice(0, 300);
}
function requireObject(v, what = "body") {
  if (!v || typeof v !== "object" || Array.isArray(v)) fail(400, "invalid_request", `${what} must be an object`);
  return v;
}
function rejectUnknown(body, allowed) {
  for (const k of Object.keys(body)) if (!allowed.includes(k)) fail(400, "invalid_request", `unknown field "${k}"`);
}
function str(body, key, opts) {
  const raw = body[key];
  if (raw === void 0 || raw === null) {
    if (opts.optional) return void 0;
    fail(400, "invalid_request", `${key} is required`);
  }
  if (typeof raw !== "string") fail(400, "invalid_request", `${key} must be a string`);
  const value = opts.trim === false ? raw : raw.trim();
  if (value.length < (opts.min ?? 0)) fail(400, "invalid_request", `${key} is too short`);
  if (value.length > opts.max) fail(400, "invalid_request", `${key} is longer than ${opts.max} characters`);
  if (opts.pattern && value && !opts.pattern.test(value)) fail(400, "invalid_request", `${key} has an invalid format`);
  return value;
}
function int(body, key, opts) {
  const raw = body[key];
  if (raw === void 0 || raw === null) {
    if (opts.optional) return void 0;
    fail(400, "invalid_request", `${key} is required`);
  }
  if (typeof raw !== "number" || !Number.isInteger(raw) || raw < opts.min || raw > opts.max) {
    fail(400, "invalid_request", `${key} must be an integer from ${opts.min} to ${opts.max}`);
  }
  return raw;
}
function bool(body, key, opts = {}) {
  const raw = body[key];
  if (raw === void 0 || raw === null) {
    if (opts.optional || opts.def !== void 0) return opts.def;
    fail(400, "invalid_request", `${key} is required`);
  }
  if (typeof raw !== "boolean") fail(400, "invalid_request", `${key} must be true or false`);
  return raw;
}
var UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function uuidParam(value) {
  if (!value || !UUID.test(value)) fail(404, "not_found", "not found");
  return value;
}
var SENSITIVE_KEYS = /authorization|cookie|apikey|api_key|password|token|secret|content|messages|prompt/i;
function log(level, msg, fields = {}) {
  const safe = {};
  for (const [k, v] of Object.entries(fields)) safe[k] = SENSITIVE_KEYS.test(k) ? "[redacted]" : v;
  const line = JSON.stringify({ time: (/* @__PURE__ */ new Date()).toISOString(), level, msg, ...safe });
  (level === "error" ? process.stderr : process.stdout).write(line + "\n");
}

// src/modules/auth.ts
import crypto2 from "node:crypto";
var SESSION_COOKIE = "devora_admin";
var SESSION_HOURS = 12;
var REAUTH_MINUTES = 5;
var LOCK_FAILURES = 5;
var LOCK_MINUTES = 15;
var LOGIN_PER_IP = 20;
var LOGIN_WINDOW_SECONDS = 15 * 60;
var INVALID = "invalid email or password";
async function login(ctx) {
  const { db, config, limits } = ctx.deps;
  const ipKey = `login:ip:${ctx.ip}`;
  const ipLimit = await limits.hit(ipKey, LOGIN_PER_IP, LOGIN_WINDOW_SECONDS);
  if (!ipLimit.allowed) fail(429, "rate_limited", "too many login attempts; try again later", { "retry-after": String(ipLimit.retryAfterSeconds) });
  const body = requireObject(await readJson(ctx.req, 8 * 1024));
  rejectUnknown(body, ["email", "password"]);
  const email = str(body, "email", { min: 3, max: 254 }).toLowerCase();
  const password = str(body, "password", { min: 1, max: 256, trim: false });
  const { rows } = await db.query("SELECT id, email, password_hash, locked_until FROM owners WHERE email = $1", [email]);
  const owner = rows[0];
  const now = await dbNow(db);
  if (!owner) {
    await burnPasswordTime(password);
    fail(401, "invalid_credentials", INVALID);
  }
  if (owner.locked_until && new Date(owner.locked_until) > now) fail(401, "invalid_credentials", INVALID);
  const ok = await verifyPassword(password, owner.password_hash);
  if (!ok) {
    await db.query(
      `UPDATE owners SET
         failed_logins = CASE WHEN failed_logins + 1 >= $2 THEN 0 ELSE failed_logins + 1 END,
         locked_until = CASE WHEN failed_logins + 1 >= $2 THEN now() + make_interval(mins => $3) ELSE locked_until END
       WHERE id = $1`,
      [owner.id, LOCK_FAILURES, LOCK_MINUTES]
    );
    fail(401, "invalid_credentials", INVALID);
  }
  await limits.clear(ipKey);
  await db.query("UPDATE owners SET failed_logins = 0, locked_until = NULL WHERE id = $1", [owner.id]);
  const token = randomToken(32);
  const csrf = randomToken(32);
  await db.query(
    `INSERT INTO admin_sessions (owner_id, token_hash, csrf_token, expires_at, ip, user_agent)
     VALUES ($1, $2, $3, now() + make_interval(hours => $4), $5, $6)`,
    [owner.id, sha256Hex(token), csrf, SESSION_HOURS, clientAddress(ctx.req, config.trustProxy), userAgent(ctx.req)]
  );
  sendJson(
    ctx.res,
    200,
    { csrfToken: csrf, owner: { email: owner.email } },
    { "set-cookie": setCookie(SESSION_COOKIE, token, { maxAgeSeconds: SESSION_HOURS * 3600, secure: config.cookieSecure }) }
  );
}
async function dbNow(db) {
  const { rows } = await db.query("SELECT now() AS t");
  return new Date(rows[0].t);
}
async function ownerSession(ctx) {
  const token = cookieValue(ctx.req.headers.cookie, SESSION_COOKIE);
  if (!token) fail(401, "unauthenticated", "sign in required");
  const { rows } = await ctx.deps.db.query(
    `SELECT s.id, s.owner_id, s.csrf_token, s.expires_at, s.reauth_until, s.revoked_at, o.email, now() AS db_now
       FROM admin_sessions s JOIN owners o ON o.id = s.owner_id
      WHERE s.token_hash = $1`,
    [sha256Hex(token)]
  );
  const row = rows[0];
  const now = row ? new Date(row.db_now) : /* @__PURE__ */ new Date();
  if (!row || row.revoked_at || new Date(row.expires_at) <= now) fail(401, "unauthenticated", "sign in required");
  await ctx.deps.db.query("UPDATE admin_sessions SET last_seen_at = now() WHERE id = $1 AND last_seen_at < now() - interval '1 minute'", [row.id]);
  return {
    sessionId: row.id,
    ownerId: row.owner_id,
    email: row.email,
    csrfToken: row.csrf_token,
    reauthUntil: row.reauth_until ? new Date(row.reauth_until) : null,
    dbNow: now
  };
}
function requireCsrf(ctx, session) {
  const sent = ctx.req.headers["x-csrf-token"];
  const value = Array.isArray(sent) ? sent[0] : sent ?? "";
  const a = Buffer.from(value, "utf8");
  const b = Buffer.from(session.csrfToken, "utf8");
  if (a.length === 0 || a.length !== b.length || !crypto2.timingSafeEqual(a, b)) {
    fail(403, "csrf_failed", "the request could not be verified; reload the page and try again");
  }
}
function requireReauth(session) {
  if (!session.reauthUntil || session.reauthUntil <= session.dbNow) {
    fail(403, "reauth_required", "confirm your password to make this change");
  }
}
async function sessionInfo(ctx) {
  const s = await ownerSession(ctx);
  sendJson(ctx.res, 200, {
    csrfToken: s.csrfToken,
    owner: { email: s.email },
    reauthUntil: s.reauthUntil && s.reauthUntil > s.dbNow ? s.reauthUntil.toISOString() : null
  });
}
async function logout(ctx) {
  const s = await ownerSession(ctx);
  requireCsrf(ctx, s);
  await ctx.deps.db.query("UPDATE admin_sessions SET revoked_at = now() WHERE id = $1", [s.sessionId]);
  ctx.res.setHeader("set-cookie", clearCookie(SESSION_COOKIE, ctx.deps.config.cookieSecure));
  ctx.res.writeHead(204);
  ctx.res.end();
}
async function reauth(ctx) {
  const s = await ownerSession(ctx);
  requireCsrf(ctx, s);
  const ipKey = `reauth:ip:${ctx.ip}`;
  const limit2 = await ctx.deps.limits.hit(ipKey, LOGIN_PER_IP, LOGIN_WINDOW_SECONDS);
  if (!limit2.allowed) fail(429, "rate_limited", "too many attempts; try again later", { "retry-after": String(limit2.retryAfterSeconds) });
  const body = requireObject(await readJson(ctx.req, 8 * 1024));
  rejectUnknown(body, ["password"]);
  const password = str(body, "password", { min: 1, max: 256, trim: false });
  const { rows } = await ctx.deps.db.query("SELECT password_hash FROM owners WHERE id = $1", [s.ownerId]);
  if (!rows[0] || !await verifyPassword(password, rows[0].password_hash)) {
    fail(401, "invalid_credentials", "the password is not correct");
  }
  await ctx.deps.limits.clear(ipKey);
  const { rows: up } = await ctx.deps.db.query(
    `UPDATE admin_sessions SET reauth_until = now() + make_interval(mins => $2) WHERE id = $1 RETURNING reauth_until`,
    [s.sessionId, REAUTH_MINUTES]
  );
  sendJson(ctx.res, 200, { reauthUntil: new Date(up[0].reauth_until).toISOString() });
}
async function guardOwner(ctx, opts) {
  const s = await ownerSession(ctx);
  if (opts.write) requireCsrf(ctx, s);
  if (opts.sensitive) requireReauth(s);
  return s;
}
function cookieValue(header, name) {
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0 && part.slice(0, eq).trim() === name) return decodeURIComponent(part.slice(eq + 1).trim());
  }
  return null;
}

// src/modules/upstream.ts
var UpstreamError = class extends Error {
  kind;
  status;
  constructor(kind, message, status) {
    super(message);
    this.name = "UpstreamError";
    this.kind = kind;
    this.status = status;
  }
};
var LOOPBACK = /* @__PURE__ */ new Set(["localhost", "127.0.0.1", "[::1]"]);
var BLOCKED_HOSTS = /* @__PURE__ */ new Set(["169.254.169.254", "100.100.100.200", "metadata.google.internal", "metadata"]);
function normalizeBaseUrl(input) {
  let u;
  try {
    u = new URL(input.trim());
  } catch {
    fail(400, "invalid_request", "baseUrl must be a full URL such as https://api.example.com/v1");
  }
  if (u.protocol !== "https:" && !(u.protocol === "http:" && LOOPBACK.has(u.hostname))) {
    fail(400, "invalid_request", "baseUrl must use https (plain http is allowed only for localhost)");
  }
  if (u.username || u.password) fail(400, "invalid_request", "baseUrl must not contain a username or password");
  if (u.search || u.hash) fail(400, "invalid_request", "baseUrl must not contain a query string or fragment");
  if (BLOCKED_HOSTS.has(u.hostname) || /^169\.254\./.test(u.hostname)) fail(400, "invalid_request", "this address is not allowed as a provider");
  const path2 = u.pathname.replace(/\/+$/, "");
  return `${u.protocol}//${u.host}${path2}`;
}
async function listUpstreamModels(f, baseUrl, apiKey, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    res = await f(`${baseUrl}/models`, {
      method: "GET",
      headers: apiKey ? { authorization: `Bearer ${apiKey}`, accept: "application/json" } : { accept: "application/json" },
      signal: controller.signal
    });
  } catch (e) {
    if (e.name === "AbortError") throw new UpstreamError("timeout", `the provider did not answer within ${Math.round(timeoutMs / 1e3)} seconds`);
    throw new UpstreamError("unreachable", "the provider could not be reached; check the base URL and the network");
  } finally {
    clearTimeout(timer);
  }
  if (res.status === 401 || res.status === 403) {
    await res.body?.cancel().catch(() => void 0);
    throw new UpstreamError("auth", `the provider rejected the API key (HTTP ${res.status})`, res.status);
  }
  if (res.status === 404) {
    await res.body?.cancel().catch(() => void 0);
    throw new UpstreamError("rejected", "the base URL did not answer like an OpenAI-compatible API (HTTP 404); check that it ends with the API version, such as /v1", 404);
  }
  if (res.status === 429) {
    await res.body?.cancel().catch(() => void 0);
    throw new UpstreamError("rate_limited", "the provider is rate limiting requests (HTTP 429)", 429);
  }
  if (res.status >= 500) {
    await res.body?.cancel().catch(() => void 0);
    throw new UpstreamError("server", `the provider returned a server error (HTTP ${res.status})`, res.status);
  }
  if (!res.ok) {
    await res.body?.cancel().catch(() => void 0);
    throw new UpstreamError("rejected", `the provider refused the request (HTTP ${res.status})`, res.status);
  }
  let json;
  try {
    json = await res.json();
  } catch {
    throw new UpstreamError("bad_response", "the provider did not return a model list in the expected format");
  }
  if (!json || !Array.isArray(json.data)) throw new UpstreamError("bad_response", "the provider did not return a model list in the expected format");
  return json.data.map((m) => m?.id).filter((id) => typeof id === "string" && id.length > 0 && id.length <= 200);
}
function describeFailure(e) {
  if (e instanceof UpstreamError) return { ok: false, message: e.message, kind: e.kind };
  return { ok: false, message: "the provider test failed unexpectedly", kind: "internal" };
}

// src/modules/providers.ts
var KEY_PATTERN = /^[\x21-\x7E]{8,512}$/;
function toProvider(r, modelCount = 0) {
  return {
    id: r.id,
    name: r.name,
    adapter: r.adapter,
    baseUrl: r.base_url,
    authScheme: r.auth_scheme,
    enabled: r.enabled,
    timeoutMs: r.timeout_ms,
    maxRetries: r.max_retries,
    hasApiKey: r.has_key === true,
    keyVersion: r.key_version ?? null,
    modelCount,
    lastTest: r.last_test_at ? { ok: r.last_test_ok, at: new Date(r.last_test_at).toISOString(), latencyMs: r.last_test_latency_ms, message: r.last_test_message, kind: r.last_test_kind ?? null } : null,
    discovery: r.discovery_at ? { ok: r.discovery_ok, supported: r.discovery_supported, at: new Date(r.discovery_at).toISOString(), message: r.discovery_message } : null,
    createdAt: r.created_at,
    updatedAt: r.updated_at
  };
}
var SELECT_PROVIDER = `
  SELECT p.*, (s.provider_id IS NOT NULL) AS has_key, s.key_version,
         (SELECT count(*)::int FROM models m WHERE m.provider_id = p.id) AS model_count
    FROM providers p LEFT JOIN provider_secrets s ON s.provider_id = p.id`;
async function listProviders(ctx) {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query(`${SELECT_PROVIDER} ORDER BY p.name`);
  sendJson(ctx.res, 200, { providers: rows.map((r) => toProvider(r, r.model_count)) });
}
async function loadProvider(q, id) {
  const { rows } = await q.query(`${SELECT_PROVIDER} WHERE p.id = $1`, [id]);
  if (!rows[0]) fail(404, "not_found", "provider not found");
  return rows[0];
}
async function createProvider(ctx) {
  await guardOwner(ctx, { write: true });
  const body = requireObject(await readJson(ctx.req, 16 * 1024));
  rejectUnknown(body, ["name", "adapter", "baseUrl", "authScheme", "enabled", "timeoutMs", "maxRetries"]);
  const name = str(body, "name", { min: 1, max: 80 });
  const adapter = str(body, "adapter", { max: 40, optional: true }) ?? "openai-compatible";
  if (adapter !== "openai-compatible") fail(400, "invalid_request", "adapter must be openai-compatible");
  const baseUrl = normalizeBaseUrl(str(body, "baseUrl", { min: 8, max: 2048 }));
  const authScheme = str(body, "authScheme", { max: 10, optional: true }) ?? "bearer";
  if (authScheme !== "bearer" && authScheme !== "none") fail(400, "invalid_request", "authScheme must be bearer or none");
  const enabled = bool(body, "enabled", { def: true });
  const timeoutMs = int(body, "timeoutMs", { min: 1e3, max: 6e5, optional: true }) ?? 12e4;
  const maxRetries = int(body, "maxRetries", { min: 0, max: 3, optional: true }) ?? 0;
  const created = await ctx.deps.db.transaction(async (q) => {
    const { rows } = await q.query(
      `INSERT INTO providers (name, adapter, base_url, auth_scheme, enabled, timeout_ms, max_retries)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [name, adapter, baseUrl, authScheme, enabled, timeoutMs, maxRetries]
    );
    await bumpCatalogue(q);
    return rows[0].id;
  }).catch((e) => {
    if (e?.code === "23505") fail(409, "duplicate", "a provider with this name already exists");
    throw e;
  });
  sendJson(ctx.res, 201, toProvider(await loadProvider(ctx.deps.db, created)));
}
async function updateProvider(ctx) {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 16 * 1024));
  rejectUnknown(body, ["name", "baseUrl", "authScheme", "enabled", "timeoutMs", "maxRetries"]);
  const current = await loadProvider(ctx.deps.db, id);
  const name = str(body, "name", { min: 1, max: 80, optional: true }) ?? current.name;
  const baseUrl = body.baseUrl === void 0 ? current.base_url : normalizeBaseUrl(str(body, "baseUrl", { min: 8, max: 2048 }));
  const authScheme = str(body, "authScheme", { max: 10, optional: true }) ?? current.auth_scheme;
  if (authScheme !== "bearer" && authScheme !== "none") fail(400, "invalid_request", "authScheme must be bearer or none");
  const enabled = bool(body, "enabled", { optional: true }) ?? current.enabled;
  const timeoutMs = int(body, "timeoutMs", { min: 1e3, max: 6e5, optional: true }) ?? current.timeout_ms;
  const maxRetries = int(body, "maxRetries", { min: 0, max: 3, optional: true }) ?? current.max_retries;
  const endpointChanged = baseUrl !== current.base_url || authScheme !== current.auth_scheme;
  await ctx.deps.db.transaction(async (q) => {
    await q.query(
      `UPDATE providers SET name = $2, base_url = $3, auth_scheme = $4, enabled = $5, timeout_ms = $6, max_retries = $7,
              last_test_ok = CASE WHEN $8 THEN NULL ELSE last_test_ok END,
              last_test_at = CASE WHEN $8 THEN NULL ELSE last_test_at END,
              updated_at = now()
        WHERE id = $1`,
      [id, name, baseUrl, authScheme, enabled, timeoutMs, maxRetries, endpointChanged]
    );
    if (!enabled) await q.query("UPDATE models SET is_default = false WHERE provider_id = $1", [id]);
    await bumpCatalogue(q);
  }).catch((e) => {
    if (e?.code === "23505") fail(409, "duplicate", "a provider with this name already exists");
    throw e;
  });
  sendJson(ctx.res, 200, toProvider(await loadProvider(ctx.deps.db, id)));
}
async function deleteProvider(ctx) {
  await guardOwner(ctx, { write: true, sensitive: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ["confirmName"]);
  const current = await loadProvider(ctx.deps.db, id);
  if (str(body, "confirmName", { max: 80, optional: true }) !== current.name) fail(400, "confirmation_mismatch", "type the provider name exactly to delete it");
  await ctx.deps.db.transaction(async (q) => {
    await q.query("DELETE FROM providers WHERE id = $1", [id]);
    await bumpCatalogue(q);
  });
  sendJson(ctx.res, 200, { deleted: true });
}
var keyAad = (providerId) => `provider:${providerId}`;
async function providerApiKey(deps, providerId) {
  const { rows } = await deps.db.query("SELECT key_version, iv, ciphertext, tag FROM provider_secrets WHERE provider_id = $1", [providerId]);
  if (!rows[0]) return null;
  return openSecret(
    deps.config.keyring,
    { keyVersion: rows[0].key_version, iv: rows[0].iv, ciphertext: rows[0].ciphertext, tag: rows[0].tag },
    keyAad(providerId)
  );
}
async function setProviderKey(ctx) {
  await guardOwner(ctx, { write: true, sensitive: true });
  const id = uuidParam(ctx.params.id);
  await loadProvider(ctx.deps.db, id);
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ["apiKey"]);
  const apiKey = str(body, "apiKey", { min: 8, max: 512, trim: false });
  if (!KEY_PATTERN.test(apiKey)) fail(400, "invalid_request", "the API key contains spaces or unsupported characters");
  const sealed = sealSecret(ctx.deps.config.keyring, apiKey, keyAad(id));
  await ctx.deps.db.query(
    `INSERT INTO provider_secrets (provider_id, key_version, iv, ciphertext, tag, updated_at)
     VALUES ($1, $2, $3, $4, $5, now())
     ON CONFLICT (provider_id) DO UPDATE SET key_version = EXCLUDED.key_version, iv = EXCLUDED.iv,
       ciphertext = EXCLUDED.ciphertext, tag = EXCLUDED.tag, updated_at = now()`,
    [id, sealed.keyVersion, sealed.iv, sealed.ciphertext, sealed.tag]
  );
  await ctx.deps.db.query("UPDATE providers SET last_test_ok = NULL, last_test_at = NULL, last_test_message = NULL WHERE id = $1", [id]);
  sendJson(ctx.res, 200, { hasApiKey: true, keyVersion: sealed.keyVersion });
}
async function clearProviderKey(ctx) {
  await guardOwner(ctx, { write: true, sensitive: true });
  const id = uuidParam(ctx.params.id);
  await loadProvider(ctx.deps.db, id);
  await ctx.deps.db.query("DELETE FROM provider_secrets WHERE provider_id = $1", [id]);
  sendJson(ctx.res, 200, { hasApiKey: false, keyVersion: null });
}
async function runProbe(ctx, providerId) {
  const p = await loadProvider(ctx.deps.db, providerId);
  const key = p.auth_scheme === "bearer" ? await providerApiKey(ctx.deps, providerId) : null;
  if (p.auth_scheme === "bearer" && !key) return { ok: false, message: "no API key is stored for this provider", status: 0, models: [], latencyMs: 0, kind: "auth" };
  const started = Date.now();
  try {
    const models = await listUpstreamModels(ctx.deps.fetch, p.base_url, key, Math.min(p.timeout_ms, 2e4));
    return { ok: true, message: `reachable; ${models.length} model${models.length === 1 ? "" : "s"} listed`, status: 200, models, latencyMs: Date.now() - started, kind: null };
  } catch (e) {
    const d = describeFailure(e);
    return { ok: false, message: d.message, status: 0, models: [], latencyMs: Date.now() - started, kind: d.kind };
  }
}
async function testProvider(ctx) {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const r = await runProbe(ctx, id);
  await ctx.deps.db.query(
    "UPDATE providers SET last_test_ok = $2, last_test_at = now(), last_test_latency_ms = $3, last_test_message = $4, last_test_kind = $5 WHERE id = $1",
    [id, r.ok, r.latencyMs, r.message, r.kind]
  );
  await ctx.deps.limits.cacheSet("provider-health", null, 1).catch(() => void 0);
  sendJson(ctx.res, 200, { ok: r.ok, message: r.message, latencyMs: r.latencyMs });
}
async function discoverModels(ctx) {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  await loadProvider(ctx.deps.db, id);
  const r = await discoverProvider(ctx.deps, id);
  if (r.skipped) fail(409, "refresh_in_progress", r.message);
  if (!r.ok && r.supported !== false) fail(502, "upstream_failed", r.message);
  sendJson(ctx.res, 200, { found: r.found, added: r.added, supported: r.supported, message: r.message });
}

// src/modules/registry.ts
async function allowedModelIds(db, deviceId, access) {
  if (access === "all") return null;
  if (!deviceId) return /* @__PURE__ */ new Set();
  const { rows } = await db.query("SELECT model_id FROM device_models WHERE device_id = $1", [deviceId]);
  return new Set(rows.map((r) => r.model_id));
}
function isAllowed(allowed, modelId) {
  return allowed === null || allowed.has(modelId);
}
var RECENT_MINUTES = 30;
var TEST_FRESH_DAYS = 7;
var PROVIDER_FAILURE_CODES = ["upstream_auth_failed", "upstream_timeout", "upstream_unreachable", "upstream_error", "upstream_rate_limited"];
var HARD_TEST_FAILURES = ["auth", "timeout", "unreachable", "server"];
async function providerHealth(db) {
  const { rows } = await db.query(
    `SELECT p.id, p.last_test_ok, p.last_test_kind, p.last_test_at,
            (p.last_test_at > now() - make_interval(days => $2)) AS test_fresh,
            recent.outcomes
       FROM providers p
       LEFT JOIN LATERAL (
         SELECT json_agg(CASE WHEN l.status = 'ok' THEN 'ok' WHEN l.error_code IN (SELECT jsonb_array_elements_text($3::jsonb)) THEN 'fail' ELSE 'other' END ORDER BY l.created_at DESC) AS outcomes
           FROM (SELECT status, error_code, created_at FROM request_logs
                  WHERE provider_id = p.id AND created_at > now() - make_interval(mins => $1) AND status <> 'cancelled'
                  ORDER BY created_at DESC LIMIT 5) l
       ) recent ON true`,
    [RECENT_MINUTES, TEST_FRESH_DAYS, PROVIDER_FAILURE_CODES]
  );
  const out = /* @__PURE__ */ new Map();
  for (const r of rows) {
    const outcomes = (r.outcomes ?? []).filter((o) => o !== "other");
    let h;
    if (outcomes[0] === "ok") h = { availability: "available", reason: "answering requests" };
    else if (outcomes.length >= 3 && outcomes.slice(0, 3).every((o) => o === "fail")) h = { availability: "degraded", reason: "recent requests failed" };
    else if (r.last_test_ok === true && r.test_fresh) h = { availability: "available", reason: "connectivity test passed" };
    else if (r.last_test_ok === false && r.test_fresh && HARD_TEST_FAILURES.includes(r.last_test_kind)) h = { availability: "degraded", reason: "connectivity test failed" };
    else h = { availability: "unknown", reason: "not checked recently" };
    out.set(r.id, h);
  }
  return out;
}
async function discoverProvider(deps, providerId) {
  const run = async () => {
    const { rows } = await deps.db.query("SELECT id, base_url, auth_scheme, timeout_ms, enabled FROM providers WHERE id = $1", [providerId]);
    const p = rows[0];
    if (!p) return { ok: false, supported: null, found: 0, added: 0, message: "provider not found" };
    const key = p.auth_scheme === "bearer" ? await providerApiKey(deps, providerId) : null;
    if (p.auth_scheme === "bearer" && !key) {
      return record(deps.db, providerId, { ok: false, supported: null, found: 0, added: 0, message: "no API key is stored for this provider" });
    }
    let ids;
    try {
      ids = await listUpstreamModels(deps.fetch, p.base_url, key, Math.min(p.timeout_ms, 2e4));
    } catch (e) {
      const unsupported = e instanceof UpstreamError && (e.kind === "bad_response" || e.kind === "rejected" && e.status === 404);
      const message = unsupported ? "this provider does not offer a model list; add models by their exact id" : describeFailure(e).message;
      return record(deps.db, providerId, { ok: false, supported: unsupported ? false : null, found: 0, added: 0, message });
    }
    let added = 0;
    await deps.db.transaction(async (q) => {
      for (const upstreamId of ids) {
        const res = await q.query(
          `INSERT INTO models (provider_id, upstream_model_id, display_name, enabled, capabilities, source, last_listed_at)
           VALUES ($1, $2, $2, false, $3, 'discovered', now())
           ON CONFLICT (provider_id, upstream_model_id) DO UPDATE SET last_listed_at = now()
           RETURNING (xmax = 0) AS inserted`,
          [providerId, upstreamId, unknownCapabilities()]
        );
        if (res.rows[0]?.inserted) added += 1;
      }
    });
    return record(deps.db, providerId, {
      ok: true,
      supported: true,
      found: ids.length,
      added,
      message: `${ids.length} model${ids.length === 1 ? "" : "s"} listed, ${added} new`
    });
  };
  const result = await withProviderLock(deps, providerId, run);
  return result ?? { ok: false, supported: null, found: 0, added: 0, message: "a refresh of this provider is already running", skipped: true };
}
async function withProviderLock(deps, providerId, fn) {
  if (deps.limits.kind === "redis") return deps.limits.withLock(`discover:${providerId}`, 6e4, fn);
  return deps.db.transaction(async (q) => {
    const { rows } = await q.query("SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0)) AS got", [`discover:${providerId}`]);
    if (!rows[0].got) return null;
    return fn();
  });
}
async function record(db, providerId, r) {
  await db.query(
    `UPDATE providers SET discovery_at = now(), discovery_ok = $2, discovery_message = $3,
            discovery_supported = COALESCE($4, discovery_supported)
      WHERE id = $1`,
    [providerId, r.ok, r.message.slice(0, 300), r.supported]
  );
  return r;
}
async function scheduledDiscovery(deps) {
  const { rows } = await deps.db.query(
    `SELECT p.id, p.name FROM providers p
      WHERE p.enabled AND (p.discovery_supported IS DISTINCT FROM false)
        AND (p.auth_scheme = 'none' OR EXISTS (SELECT 1 FROM provider_secrets s WHERE s.provider_id = p.id))`
  );
  for (const p of rows) {
    try {
      const r = await discoverProvider(deps, p.id);
      if (!r.skipped) log(r.ok ? "info" : "warn", "model discovery", { provider: p.name, ok: r.ok, found: r.found, added: r.added });
    } catch (e) {
      log("error", "model discovery failed", { provider: p.name, error: e instanceof Error ? e.name : "unknown" });
    }
  }
}
async function setDeviceAccess(db, deviceId, access, modelIds) {
  await db.transaction(async (q) => {
    await q.query("UPDATE devices SET model_access = $2 WHERE id = $1", [deviceId, access]);
    await q.query("DELETE FROM device_models WHERE device_id = $1", [deviceId]);
    if (access === "selected" && modelIds.length) {
      await q.query("INSERT INTO device_models (device_id, model_id) SELECT $1, (jsonb_array_elements_text($2::jsonb))::uuid ON CONFLICT DO NOTHING", [deviceId, modelIds]);
    }
    await bumpCatalogue(q);
  });
}

// src/modules/devices.ts
var REGISTER_PER_IP = 10;
var REGISTER_WINDOW_SECONDS = 15 * 60;
var DEVICE_TOUCH_SECONDS = 60;
var INSTALL_ID = /^[A-Za-z0-9_-]{16,64}$/;
async function registerDevice(ctx) {
  const { db, config } = ctx.deps;
  const ip = clientAddress(ctx.req, config.trustProxy);
  const limit2 = await ctx.deps.limits.hit(`register:ip:${ip}`, REGISTER_PER_IP, REGISTER_WINDOW_SECONDS);
  if (!limit2.allowed) fail(429, "rate_limited", "too many registrations from this network; try again later", { "retry-after": String(limit2.retryAfterSeconds) });
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ["installId", "deviceName"]);
  const installId = str(body, "installId", { min: 16, max: 64 });
  if (!INSTALL_ID.test(installId)) fail(400, "invalid_request", "installId must be 16 to 64 letters, digits, _ or -");
  const deviceName = str(body, "deviceName", { min: 1, max: 80 });
  const token = randomToken(32);
  const result = await db.transaction(async (q) => {
    const { rows } = await q.query("SELECT id, status, user_id FROM devices WHERE install_id = $1 FOR UPDATE", [installId]);
    const existing = rows[0];
    if (existing) {
      if (existing.status !== "active") return { blocked: true };
      if (existing.user_id) return { account: true };
      await q.query("UPDATE devices SET token_hash = $2, name = $3, last_seen_at = now() WHERE id = $1", [existing.id, sha256Hex(token), deviceName]);
      return { id: existing.id, created: false };
    }
    const settings = await readSettings(q);
    if (settings.allow_auto_registration === false) return { closed: true };
    const dev = await q.query(
      `INSERT INTO devices (name, token_hash, install_id, registered_via, last_seen_at) VALUES ($1, $2, $3, 'auto', now()) RETURNING id`,
      [deviceName, sha256Hex(token), installId]
    );
    return { id: dev.rows[0].id, created: true };
  });
  if ("blocked" in result) fail(403, "device_blocked", "the owner has blocked this computer");
  if ("account" in result) fail(409, "account_device", "this computer is signed in to a Devora account; sign in again to continue");
  if ("closed" in result) fail(403, "registration_closed", "the owner is not accepting new computers right now");
  sendJson(ctx.res, result.created ? 201 : 200, { deviceId: result.id, token, catalogueVersion: await catalogueVersion(db) });
}
function bearerToken(ctx) {
  const m = /^Bearer\s+([A-Za-z0-9_-]{20,128})$/.exec(ctx.req.headers.authorization ?? "");
  return m ? m[1] : null;
}
async function authenticateDevice(ctx, opts = {}) {
  const central = opts.central !== false;
  const token = bearerToken(ctx);
  if (!token) fail(401, "unauthenticated", "a device token is required");
  const hash = sha256Hex(token);
  const { rows } = await ctx.deps.db.query(
    `SELECT d.id, d.name, d.status, d.model_access, d.app_version, d.user_id, d.token_expires_at,
            (d.token_hash = $1) AS current,
            (d.prev_token_grace_until IS NOT NULL AND d.prev_token_grace_until > now()) AS in_grace,
            (d.token_expires_at IS NOT NULL AND d.token_expires_at <= now()) AS expired,
            (d.user_checked_at IS NULL OR d.user_checked_at < now() - make_interval(secs => $3)) AS recheck,
            (d.user_checked_at IS NOT NULL AND d.user_checked_at > now() - make_interval(secs => $4)) AS recently_checked,
            u.status AS user_status,
            (d.last_seen_at IS NULL OR d.last_seen_at < now() - make_interval(secs => $2)) AS touch
       FROM devices d LEFT JOIN app_users u ON u.user_id = d.user_id
      WHERE d.token_hash = $1 OR d.prev_token_hash = $1`,
    [hash, DEVICE_TOUCH_SECONDS, RECHECK_SECONDS, OFFLINE_GRACE_SECONDS]
  );
  const row = rows[0];
  if (!row || row.status !== "active") fail(401, "device_revoked", "this device is not allowed to use the service");
  if (!row.current && !row.in_grace) {
    await endSession(ctx.deps.db, row.id, "token_reuse");
    log("warn", "rotated device token reused; session ended", { deviceId: row.id });
    fail(401, "session_revoked", "this sign-in was ended for security reasons; sign in again");
  }
  if (row.expired) fail(401, "token_expired", "this sign-in has expired; sign in again");
  if (row.user_id) {
    if (row.user_status === "blocked") fail(403, "account_blocked", "this account has been blocked by the administrator");
    if (row.user_status === "deleting" || row.user_status === "deleted") fail(401, "account_deleted", "this account has been deleted");
    if (row.recheck) {
      const r = await recheckUser(ctx.deps, row.user_id);
      if (r === "deleted") fail(401, "account_deleted", "this account has been deleted");
      if (r === "unverified") fail(403, "email_not_verified", "verify your email address to use Devora AI");
      if (r === "unavailable" && !row.recently_checked) {
        fail(503, "accounts_unavailable", "the account service is temporarily unavailable; local features keep working", { "retry-after": "30" });
      }
    }
  } else if (central && await requireLoginForCentralAi(ctx.deps.db)) {
    fail(403, "login_required", "sign in to your Devora account to use Devora AI");
  }
  const reported = String(ctx.req.headers["x-devora-version"] ?? "");
  const version2 = /^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]{1,30})?$/.test(reported) ? reported : null;
  if (version2 && version2 !== row.app_version) await ctx.deps.db.query("UPDATE devices SET last_seen_at = now(), app_version = $2 WHERE id = $1", [row.id, version2]);
  else if (row.touch) await ctx.deps.db.query("UPDATE devices SET last_seen_at = now() WHERE id = $1", [row.id]);
  return {
    deviceId: row.id,
    name: row.name,
    modelAccess: row.model_access,
    userId: row.user_id ?? null,
    tokenHash: hash,
    tokenExpiresAt: row.token_expires_at ? new Date(row.token_expires_at).toISOString() : null
  };
}
async function listDevices(ctx) {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query(
    `SELECT d.id, d.name, d.status, d.created_at, d.last_seen_at, d.revoked_at, d.model_access, d.registered_via, d.app_version,
            d.user_id, d.signed_out_at, d.token_expires_at,
            (SELECT count(*)::int FROM device_models dm WHERE dm.device_id = d.id) AS granted,
            (SELECT count(*)::int FROM memory_entries me WHERE me.device_id = d.id AND me.deleted = false) AS memories
       FROM devices d ORDER BY d.created_at DESC LIMIT 500`
  );
  sendJson(ctx.res, 200, {
    devices: rows.map((r) => ({
      id: r.id,
      name: r.name,
      status: r.status,
      createdAt: r.created_at,
      lastSeenAt: r.last_seen_at,
      revokedAt: r.revoked_at,
      modelAccess: r.model_access,
      registeredVia: r.registered_via,
      grantedModels: r.granted,
      memories: r.memories,
      appVersion: r.app_version ?? null,
      userId: r.user_id ?? null,
      signedIn: !!r.user_id && !r.signed_out_at
    }))
  });
}
async function revokeDevice(ctx) {
  await guardOwner(ctx, { write: true, sensitive: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ["confirmName"]);
  const confirm = str(body, "confirmName", { max: 80, optional: true });
  const { rows } = await ctx.deps.db.query("SELECT name, status FROM devices WHERE id = $1", [id]);
  if (!rows[0]) fail(404, "not_found", "device not found");
  if (confirm !== rows[0].name) fail(400, "confirmation_mismatch", "type the device name exactly to block it");
  if (rows[0].status === "revoked") fail(409, "already_revoked", "this device is already blocked");
  await ctx.deps.db.query("UPDATE devices SET status = 'revoked', revoked_at = now() WHERE id = $1", [id]);
  sendJson(ctx.res, 200, { id, status: "revoked" });
}
async function unblockDevice(ctx) {
  await guardOwner(ctx, { write: true, sensitive: true });
  const id = uuidParam(ctx.params.id);
  const { rows } = await ctx.deps.db.query("SELECT status FROM devices WHERE id = $1", [id]);
  if (!rows[0]) fail(404, "not_found", "device not found");
  if (rows[0].status === "active") fail(409, "not_blocked", "this device is not blocked");
  await ctx.deps.db.query("UPDATE devices SET status = 'active', revoked_at = NULL, token_hash = $2 WHERE id = $1", [id, sha256Hex(randomToken(32))]);
  sendJson(ctx.res, 200, { id, status: "active" });
}
async function getDeviceModels(ctx) {
  await guardOwner(ctx, { write: false });
  const id = uuidParam(ctx.params.id);
  const { rows } = await ctx.deps.db.query("SELECT model_access FROM devices WHERE id = $1", [id]);
  if (!rows[0]) fail(404, "not_found", "device not found");
  const granted = await ctx.deps.db.query("SELECT model_id FROM device_models WHERE device_id = $1 ORDER BY created_at", [id]);
  sendJson(ctx.res, 200, { modelAccess: rows[0].model_access, modelIds: granted.rows.map((r) => r.model_id) });
}
async function putDeviceModels(ctx) {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 64 * 1024));
  rejectUnknown(body, ["modelAccess", "modelIds"]);
  const access = body.modelAccess;
  if (access !== "all" && access !== "selected") fail(400, "invalid_request", "modelAccess must be all or selected");
  const raw = body.modelIds ?? [];
  if (!Array.isArray(raw) || raw.length > 1e3) fail(400, "invalid_request", "modelIds must be a list of model ids");
  const modelIds = [...new Set(raw.map((v) => uuidParam(typeof v === "string" ? v : "")))];
  const { rows } = await ctx.deps.db.query("SELECT status FROM devices WHERE id = $1", [id]);
  if (!rows[0]) fail(404, "not_found", "device not found");
  if (modelIds.length) {
    const found = await ctx.deps.db.query("SELECT count(*)::int AS n FROM models WHERE id IN (SELECT (jsonb_array_elements_text($1::jsonb))::uuid)", [modelIds]);
    if (found.rows[0].n !== modelIds.length) fail(400, "invalid_request", "one or more models do not exist");
  }
  await setDeviceAccess(ctx.deps.db, id, access, access === "selected" ? modelIds : []);
  sendJson(ctx.res, 200, { modelAccess: access, modelIds: access === "selected" ? modelIds : [] });
}

// src/modules/api-keys.ts
import crypto3 from "node:crypto";
var KEY_PREFIX = "dvk_";
var KEY_SCOPES = ["chat", "models"];
var MAX_KEYS = 200;
function view(r) {
  return {
    id: r.id,
    name: r.name,
    keyPrefix: r.key_prefix,
    last4: r.last4,
    scopes: (r.scopes ?? []).filter((s) => KEY_SCOPES.includes(s)),
    enabled: r.enabled,
    expiresAt: r.expires_at,
    lastUsedAt: r.last_used_at,
    requestCount: Number(r.request_count ?? 0),
    createdAt: r.created_at,
    updatedAt: r.updated_at
  };
}
function readScopes(v) {
  const list = Array.isArray(v) ? v : typeof v === "string" ? v.split(",") : v === void 0 ? ["chat"] : null;
  if (!list) fail(400, "invalid_request", "scopes must be a list or a comma-separated string");
  const out = [...new Set(list.map((s) => String(s).trim()).filter(Boolean))];
  if (out.length === 0) fail(400, "invalid_request", "at least one scope is required");
  for (const s of out) {
    if (!KEY_SCOPES.includes(s)) fail(400, "invalid_request", `unknown scope "${s}"; known scopes: ${KEY_SCOPES.join(", ")}`);
  }
  return out;
}
function readExpiry(v) {
  if (v === void 0 || v === null || v === "" || v === "never") return null;
  const t = Date.parse(String(v));
  if (!Number.isFinite(t)) fail(400, "invalid_request", 'expiresAt must be an ISO date or "never"');
  const d = new Date(t);
  if (d.getTime() < Date.now()) fail(400, "invalid_request", "expiresAt must be in the future");
  if (d.getTime() > Date.now() + 10 * 365 * 24 * 3600 * 1e3) fail(400, "invalid_request", "expiresAt may be at most 10 years ahead");
  return d.toISOString();
}
async function listApiKeys(ctx) {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query("SELECT * FROM api_keys ORDER BY created_at DESC");
  sendJson(ctx.res, 200, { keys: rows.map(view), scopes: KEY_SCOPES });
}
async function createApiKey(ctx) {
  await guardOwner(ctx, { write: true });
  const body = requireObject(await readJson(ctx.req, 16 * 1024));
  rejectUnknown(body, ["name", "scopes", "expiresAt"]);
  const name = str(body, "name", { min: 1, max: 80 });
  if (/[\r\n]/.test(name)) fail(400, "invalid_request", "the name must be a single line");
  const scopes = readScopes(body.scopes);
  const expiresAt = readExpiry(body.expiresAt);
  const secret = KEY_PREFIX + crypto3.randomBytes(24).toString("hex");
  const hash = sha256Hex(secret);
  const id = await ctx.deps.db.transaction(async (q) => {
    const n = await q.query("SELECT count(*)::int AS n FROM api_keys");
    if (n.rows[0].n >= MAX_KEYS) fail(409, "too_many_keys", `there are already ${MAX_KEYS} API keys; delete one first`);
    const { rows: rows2 } = await q.query(
      `INSERT INTO api_keys (name, key_hash, key_prefix, last4, scopes, enabled, expires_at) VALUES ($1, $2, $3, $4, $5, true, $6) RETURNING id`,
      [name, hash, secret.slice(0, 8), secret.slice(-4), JSON.stringify(scopes), expiresAt]
    );
    return rows2[0].id;
  });
  log("info", "api key created", { keyId: id });
  const { rows } = await ctx.deps.db.query("SELECT * FROM api_keys WHERE id = $1", [id]);
  sendJson(ctx.res, 201, {
    key: view(rows[0]),
    secret,
    authorizationHeader: `Bearer ${secret}`,
    note: "Store this secret now. It is not stored in plain text and cannot be shown again."
  });
}
async function updateApiKey(ctx) {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 16 * 1024));
  rejectUnknown(body, ["name", "scopes", "enabled", "expiresAt"]);
  const sets = [];
  const vals = [id];
  const add = (col, v) => {
    vals.push(v);
    sets.push(`${col} = $${vals.length}`);
  };
  const name = str(body, "name", { min: 1, max: 80, optional: true });
  if (name !== void 0) {
    if (/[\r\n]/.test(name)) fail(400, "invalid_request", "the name must be a single line");
    add("name", name);
  }
  if (body.scopes !== void 0) add("scopes", JSON.stringify(readScopes(body.scopes)));
  if (body.enabled !== void 0) {
    if (typeof body.enabled !== "boolean") fail(400, "invalid_request", "enabled must be true or false");
    add("enabled", body.enabled);
  }
  if (body.expiresAt !== void 0) add("expires_at", readExpiry(body.expiresAt));
  if (!sets.length) fail(400, "invalid_request", "nothing to change");
  const { rowCount } = await ctx.deps.db.query(`UPDATE api_keys SET ${sets.join(", ")}, updated_at = now() WHERE id = $1`, vals);
  if (!rowCount) fail(404, "not_found", "key not found");
  const { rows } = await ctx.deps.db.query("SELECT * FROM api_keys WHERE id = $1", [id]);
  sendJson(ctx.res, 200, { key: view(rows[0]) });
}
async function deleteApiKey(ctx) {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const { rowCount } = await ctx.deps.db.query("DELETE FROM api_keys WHERE id = $1", [id]);
  if (!rowCount) fail(404, "not_found", "key not found");
  sendJson(ctx.res, 200, { deleted: true });
}
async function authenticateApiKey(ctx, requiredScope) {
  const m = /^Bearer\s+(\S{20,128})$/.exec(ctx.req.headers.authorization ?? "");
  const token = m?.[1] ?? "";
  if (!token.startsWith(KEY_PREFIX)) return null;
  const hash = sha256Hex(token);
  const { rows } = await ctx.deps.db.query(
    `SELECT id, name, scopes, enabled, (expires_at IS NOT NULL AND expires_at <= now()) AS expired,
            (last_used_at IS NULL OR last_used_at < now() - interval '60 seconds') AS touch
       FROM api_keys WHERE key_hash = $1`,
    [hash]
  );
  const row = rows[0];
  if (!row) fail(401, "invalid_api_key", "this API key is not valid; it may have been deleted");
  if (!row.enabled) fail(403, "api_key_disabled", "this API key has been turned off by the owner");
  if (row.expired) fail(403, "api_key_expired", "this API key has expired; ask the owner for a new one");
  const scopes = Array.isArray(row.scopes) ? row.scopes : [];
  if (!scopes.includes(requiredScope)) {
    fail(403, "missing_scope", `this API key is not allowed to use "${requiredScope}"; the owner must add that scope`);
  }
  try {
    await ctx.deps.db.query(
      `UPDATE api_keys SET request_count = request_count + 1${row.touch ? ", last_used_at = now()" : ""} WHERE id = $1`,
      [row.id]
    );
  } catch (e) {
    log("warn", "could not record API key usage", { error: e instanceof Error ? e.message : String(e) });
  }
  return { keyId: row.id, name: row.name, scopes };
}
async function apiKeyRateLimit(db) {
  try {
    const { rows } = await db.query("SELECT (value)::text::int AS v FROM settings WHERE key = 'api_key_rate_limit_per_minute'");
    const v = Number(rows[0]?.v ?? 30);
    return Number.isInteger(v) && v >= 1 && v <= 600 ? v : 30;
  } catch {
    return 30;
  }
}

// src/modules/catalogue.ts
var CAPABILITY_NAMES = ["streaming", "tools", "vision", "reasoning"];
var CAPABILITY_SOURCES = ["unknown", "admin", "provider_reported", "test"];
var REASONING_LEVELS = ["low", "medium", "high"];
function unknownCapabilities() {
  const unknown = { supported: null, source: "unknown" };
  return { streaming: { ...unknown }, tools: { ...unknown }, vision: { ...unknown }, reasoning: { ...unknown } };
}
function normalizeCapabilities(input) {
  const out = unknownCapabilities();
  if (!input || typeof input !== "object") return out;
  for (const name of CAPABILITY_NAMES) {
    const raw = input[name];
    if (!raw || typeof raw !== "object") continue;
    const supported = raw.supported === true || raw.supported === false ? raw.supported : null;
    const source = CAPABILITY_SOURCES.includes(raw.source) ? raw.source : "unknown";
    const cap = { supported, source };
    if (name === "reasoning" && Array.isArray(raw.levels)) {
      cap.levels = raw.levels.filter((l) => REASONING_LEVELS.includes(l));
    }
    out[name] = cap;
  }
  return out;
}
async function catalogueVersion(db) {
  const { rows } = await db.query("SELECT (value)::text::int AS v FROM settings WHERE key = 'catalogue_version'");
  return rows[0]?.v ?? 1;
}
async function bumpCatalogue(q) {
  const { rows } = await q.query(
    "UPDATE settings SET value = to_jsonb((value::text::int) + 1), updated_at = now() WHERE key = 'catalogue_version' RETURNING value::text::int AS v"
  );
  return rows[0].v;
}
async function readSettings(db) {
  const { rows } = await db.query("SELECT key, value FROM settings");
  return Object.fromEntries(rows.map((r) => [r.key, r.value]));
}
async function orgSkillsVersion(db) {
  try {
    const { rows } = await db.query("SELECT (value)::text::int AS v FROM settings WHERE key = 'skills_version'");
    return rows[0]?.v ?? 0;
  } catch {
    return 0;
  }
}
async function orgAgentsVersion(db) {
  try {
    const { rows } = await db.query("SELECT (value)::text::int AS v FROM settings WHERE key = 'agents_version'");
    return rows[0]?.v ?? 0;
  } catch {
    return 0;
  }
}
async function webSearchReady(db) {
  try {
    const { rows } = await db.query(
      `SELECT 1 FROM search_providers p LEFT JOIN search_provider_secrets s ON s.provider_id = p.id
        WHERE p.enabled AND ((p.kind = 'searxng' AND p.base_url IS NOT NULL) OR (p.kind <> 'searxng' AND s.provider_id IS NOT NULL)
          AND (p.kind <> 'google_cse' OR coalesce(p.options->>'cx', '') <> '')) LIMIT 1`
    );
    return rows.length > 0;
  } catch {
    return false;
  }
}
async function buildCatalogue(db) {
  const settings = await readSettings(db);
  const { rows } = await db.query(
    `SELECT m.id, m.provider_id, m.display_name, m.description, m.context_window, m.is_default, m.capabilities, p.name AS provider_name
       FROM models m JOIN providers p ON p.id = m.provider_id
      WHERE m.enabled AND p.enabled
      ORDER BY m.is_default DESC, m.display_name ASC`
  );
  return {
    version: Number(settings.catalogue_version ?? 1),
    generatedAt: (/* @__PURE__ */ new Date()).toISOString(),
    models: rows.map((r) => ({
      id: r.id,
      providerId: r.provider_id,
      displayName: r.display_name,
      description: r.description,
      providerName: r.provider_name,
      contextWindow: r.context_window,
      isDefault: r.is_default,
      capabilities: normalizeCapabilities(r.capabilities)
    })),
    policy: {
      allowDirectProvider: settings.allow_direct_provider === true,
      maxOutputTokens: Number(settings.max_output_tokens ?? 8192),
      // At least one web search provider is ready (desktops offer the agent's web_search tool only then).
      webSearch: await webSearchReady(db),
      // Organization skills: desktops download /v1/skills again when this changes.
      skillsVersion: await orgSkillsVersion(db),
      // Organization agents: desktops download /v1/agents again when this changes.
      agentsVersion: await orgAgentsVersion(db)
    }
  };
}
var CATALOGUE_CACHE_SECONDS = 300;
async function cachedCatalogue(ctx) {
  const { db, limits } = ctx.deps;
  if (limits.kind !== "redis") return buildCatalogue(db);
  const version2 = await catalogueVersion(db);
  const key = `catalogue:v${version2}`;
  const hit = await limits.cacheGet(key);
  if (hit && hit.version === version2) return hit;
  const cat = await buildCatalogue(db);
  if (cat.version === version2) await limits.cacheSet(key, cat, CATALOGUE_CACHE_SECONDS);
  return cat;
}
async function catalogueRoute(ctx) {
  const device = await authenticateDevice(ctx);
  const full = await cachedCatalogue(ctx);
  const cat = await forDevice(ctx, full, device.deviceId, device.modelAccess);
  const etag = `"${cat.version}"`;
  if (ctx.req.headers["if-none-match"] === etag) {
    ctx.res.writeHead(304, { etag, "cache-control": "no-store" });
    ctx.res.end();
    return;
  }
  sendJson(ctx.res, 200, cat, { etag, "cache-control": "no-store" });
}
async function deviceRoute(ctx) {
  const d = await authenticateDevice(ctx, { central: false });
  sendJson(ctx.res, 200, {
    deviceId: d.deviceId,
    name: d.name,
    status: "active",
    catalogueVersion: await catalogueVersion(ctx.deps.db),
    signedIn: !!d.userId,
    tokenExpiresAt: d.tokenExpiresAt,
    loginRequired: await requireLoginForCentralAi(ctx.deps.db)
  });
}
async function forDevice(ctx, cat, deviceId, access) {
  const allowed = await allowedModelIds(ctx.deps.db, deviceId, access);
  const models = cat.models.filter((m) => isAllowed(allowed, m.id)).map(({ providerId: _p, ...m }) => m);
  return { ...cat, models };
}
var HEALTH_CACHE_SECONDS = 30;
async function catalogueStatusRoute(ctx) {
  const device = await authenticateDevice(ctx);
  const { db, limits } = ctx.deps;
  const cat = await cachedCatalogue(ctx);
  const allowed = await allowedModelIds(db, device.deviceId, device.modelAccess);
  let health = await limits.cacheGet("provider-health");
  if (!health) {
    health = Object.fromEntries(await providerHealth(db));
    await limits.cacheSet("provider-health", health, HEALTH_CACHE_SECONDS);
  }
  const models = cat.models.filter((m) => isAllowed(allowed, m.id)).map((m) => ({ id: m.id, ...health[m.providerId ?? ""] ?? { availability: "unknown", reason: "not checked recently" } }));
  sendJson(ctx.res, 200, { version: cat.version, checkedAt: (/* @__PURE__ */ new Date()).toISOString(), models }, { "cache-control": "no-store" });
}
async function modelRoute(ctx) {
  const device = await authenticateDevice(ctx);
  const id = uuidParam(ctx.params.id);
  const cat = await forDevice(ctx, await cachedCatalogue(ctx), device.deviceId, device.modelAccess);
  const m = cat.models.find((x) => x.id === id);
  if (!m) fail(404, "model_not_found", "this model is not available to this computer");
  sendJson(ctx.res, 200, { ...m, catalogueVersion: cat.version });
}
async function deviceUsageRoute(ctx) {
  const device = await authenticateDevice(ctx);
  const days = Math.min(90, Math.max(1, Number(ctx.url.searchParams.get("days") ?? 30) || 30));
  const { rows } = await ctx.deps.db.query(
    `SELECT model_id, model_name,
            count(*)::int AS requests,
            count(*) FILTER (WHERE status = 'ok')::int AS ok,
            count(*) FILTER (WHERE status = 'error')::int AS failed,
            coalesce(sum(prompt_tokens), 0)::int AS prompt_tokens,
            coalesce(sum(completion_tokens), 0)::int AS completion_tokens
       FROM request_logs
      WHERE device_id = $1 AND created_at > now() - make_interval(days => $2)
      GROUP BY model_id, model_name ORDER BY requests DESC LIMIT 100`,
    [device.deviceId, days]
  );
  sendJson(ctx.res, 200, {
    days,
    models: rows.map((r) => ({ modelId: r.model_id, modelName: r.model_name, requests: r.requests, ok: r.ok, failed: r.failed, promptTokens: r.prompt_tokens, completionTokens: r.completion_tokens }))
  });
}
async function apiModelsRoute(ctx) {
  const key = await authenticateApiKey(ctx, "models");
  if (!key) fail(401, "unauthenticated", "an API key with the models scope is required (Authorization: Bearer dvk_...)");
  const cat = await cachedCatalogue(ctx);
  const created = Math.floor(Date.parse(cat.generatedAt) / 1e3) || 0;
  sendJson(ctx.res, 200, {
    object: "list",
    data: cat.models.map((m) => ({
      id: m.id,
      object: "model",
      created,
      owned_by: m.providerName,
      display_name: m.displayName,
      description: m.description,
      context_window: m.contextWindow,
      is_default: m.isDefault
    }))
  });
}

// src/modules/sessions.ts
var TOKEN_TTL_DAYS = 30;
var ROTATE_GRACE_SECONDS = 120;
var RECHECK_SECONDS = 15 * 60;
var OFFLINE_GRACE_SECONDS = 24 * 3600;
async function issueToken(q, deviceId) {
  const token = randomToken(32);
  const { rows } = await q.query(
    `UPDATE devices SET token_hash = $2, token_issued_at = now(), token_expires_at = now() + make_interval(days => $3),
            prev_token_hash = NULL, prev_token_grace_until = NULL, signed_out_at = NULL, signed_out_reason = NULL,
            user_checked_at = now(), last_seen_at = now()
      WHERE id = $1 RETURNING token_expires_at`,
    [deviceId, sha256Hex(token), TOKEN_TTL_DAYS]
  );
  return { token, expiresAt: new Date(rows[0].token_expires_at).toISOString() };
}
async function rotateToken(q, deviceId, currentHash) {
  const token = randomToken(32);
  const { rows } = await q.query(
    `UPDATE devices SET token_hash = $2, prev_token_hash = $3, prev_token_grace_until = now() + make_interval(secs => $4),
            token_issued_at = now(), token_expires_at = now() + make_interval(days => $5)
      WHERE id = $1 AND token_hash = $3 RETURNING token_expires_at`,
    [deviceId, sha256Hex(token), currentHash, ROTATE_GRACE_SECONDS, TOKEN_TTL_DAYS]
  );
  if (!rows[0]) fail(409, "token_changed", "this sign-in changed; sign in again");
  return { token, expiresAt: new Date(rows[0].token_expires_at).toISOString() };
}
async function endSession(q, deviceId, reason) {
  await q.query(
    `UPDATE devices SET token_hash = $2, prev_token_hash = NULL, prev_token_grace_until = NULL, signed_out_at = now(),
            signed_out_reason = $3, install_id = NULL, token_expires_at = NULL
      WHERE id = $1`,
    [deviceId, sha256Hex(randomToken(32)), reason.slice(0, 40)]
  );
}
async function endUserSessions(q, userId, reason) {
  const { rows } = await q.query("SELECT id FROM devices WHERE user_id = $1 AND signed_out_at IS NULL", [userId]);
  for (const r of rows) await endSession(q, r.id, reason);
  return rows.length;
}
var loginCache = /* @__PURE__ */ new WeakMap();
async function requireLoginForCentralAi(db) {
  const hit = loginCache.get(db);
  if (hit && Date.now() - hit.at < 5e3) return hit.value;
  const s = await readSettings(db);
  const value = s.require_login_for_central_ai === true;
  loginCache.set(db, { value, at: Date.now() });
  return value;
}
function forgetLoginSetting(db) {
  loginCache.delete(db);
}
async function bindDevice(db, input) {
  return db.transaction(async (q) => {
    const u = await q.query(
      `INSERT INTO app_users (user_id, last_login_at) VALUES ($1, now())
       ON CONFLICT (user_id) DO UPDATE SET last_login_at = now() RETURNING status`,
      [input.userId]
    );
    const status = u.rows[0].status;
    if (status === "blocked") fail(403, "account_blocked", "this account has been blocked by the administrator");
    if (status !== "active") fail(403, "account_deleted", "this account has been deleted");
    const { rows } = await q.query("SELECT id, status, user_id, token_hash FROM devices WHERE install_id = $1 FOR UPDATE", [input.installId]);
    const row = rows[0];
    const proven = !!row && !!input.proofHash && row.token_hash === input.proofHash;
    if (row && row.status !== "active") fail(403, "device_blocked", "the owner has blocked this computer");
    let deviceId;
    let claimed;
    if (row && row.user_id === input.userId) {
      deviceId = row.id;
      claimed = "same_user";
    } else if (row && row.user_id === null) {
      if (!proven) fail(409, "device_proof_required", "this computer is registered already; sign in again from the Devora app on it");
      deviceId = row.id;
      claimed = "legacy";
    } else if (row) {
      if (!proven) fail(409, "device_proof_required", "this computer is signed in to another account; sign out there first");
      await endSession(q, row.id, "switched_account");
      deviceId = await newDevice(q, input);
      claimed = "switched";
    } else {
      deviceId = await newDevice(q, input);
      claimed = "new";
    }
    await q.query("UPDATE devices SET user_id = $2, name = $3, install_id = $4 WHERE id = $1", [deviceId, input.userId, input.deviceName, input.installId]);
    const t = await issueToken(q, deviceId);
    return { deviceId, ...t, claimed };
  });
}
async function newDevice(q, input) {
  const { rows } = await q.query(
    `INSERT INTO devices (name, token_hash, registered_via, last_seen_at) VALUES ($1, $2, 'auto', now()) RETURNING id`,
    [input.deviceName, sha256Hex(randomToken(32))]
  );
  return rows[0].id;
}
var inflight = /* @__PURE__ */ new Map();
function recheckUser(deps, userId) {
  const running = inflight.get(userId);
  if (running) return running;
  const p = (async () => {
    if (!deps.pocketbase) return "unavailable";
    try {
      const user = await deps.pocketbase.getUser(userId);
      if (!user) {
        await markDeleted(deps.db, userId, "data");
        void runDeletion(deps, userId).catch(() => void 0);
        return "deleted";
      }
      if (!user.verified) return "unverified";
      await deps.db.query("UPDATE devices SET user_checked_at = now() WHERE user_id = $1 AND signed_out_at IS NULL", [userId]);
      return "ok";
    } catch (e) {
      log("warn", "account check failed", { reason: e instanceof PbError ? e.status : "error" });
      return "unavailable";
    }
  })().finally(() => inflight.delete(userId));
  inflight.set(userId, p);
  return p;
}
async function markDeleted(db, userId, firstStep) {
  await db.transaction(async (q) => {
    await q.query(
      `INSERT INTO app_users (user_id, status, deletion_requested_at, deletion_step) VALUES ($1, 'deleting', now(), $2)
       ON CONFLICT (user_id) DO UPDATE SET status = 'deleting', deletion_requested_at = coalesce(app_users.deletion_requested_at, now()),
         deletion_step = CASE WHEN app_users.status = 'deleting' THEN app_users.deletion_step ELSE EXCLUDED.deletion_step END
       WHERE app_users.status <> 'deleted'`,
      [userId, firstStep]
    );
    await endUserSessions(q, userId, "account_deleted");
  });
}
async function runDeletion(deps, userId) {
  for (let i = 0; i < 5; i++) {
    const { rows } = await deps.db.query("SELECT status, deletion_step FROM app_users WHERE user_id = $1", [userId]);
    const row = rows[0];
    if (!row || row.status === "deleted") return "done";
    if (row.status !== "deleting") return "pending";
    try {
      if (row.deletion_step === "devices") {
        await deps.db.transaction(async (q) => {
          await endUserSessions(q, userId, "account_deleted");
          await q.query("UPDATE app_users SET deletion_step = 'data', deletion_error = NULL WHERE user_id = $1", [userId]);
        });
      } else if (row.deletion_step === "data") {
        await deps.db.transaction(async (q) => {
          await endUserSessions(q, userId, "account_deleted");
          await q.query("DELETE FROM memory_entries WHERE device_id IN (SELECT id FROM devices WHERE user_id = $1)", [userId]);
          await q.query("DELETE FROM auth_handoffs WHERE user_id = $1 OR expected_user_id = $1", [userId]);
          await q.query("UPDATE devices SET user_id = NULL, name = 'Deleted account' WHERE user_id = $1", [userId]);
          await q.query("UPDATE app_users SET deletion_step = 'identity', deletion_error = NULL WHERE user_id = $1", [userId]);
        });
      } else if (row.deletion_step === "identity") {
        if (!deps.pocketbase) throw new PbError(0, "accounts are not configured on this server");
        await deps.pocketbase.deleteUser(userId);
        await deps.db.query("UPDATE app_users SET deletion_step = 'done', status = 'deleted', deleted_at = now(), deletion_error = NULL WHERE user_id = $1", [userId]);
        return "done";
      } else {
        await deps.db.query("UPDATE app_users SET status = 'deleted', deleted_at = coalesce(deleted_at, now()) WHERE user_id = $1", [userId]);
        return "done";
      }
    } catch (e) {
      const msg = e instanceof PbError ? e.message : "the deletion step failed";
      await deps.db.query("UPDATE app_users SET deletion_error = $2 WHERE user_id = $1", [userId, msg.slice(0, 200)]).catch(() => void 0);
      log("warn", "account deletion step failed", { step: row.deletion_step });
      return "pending";
    }
  }
  return "pending";
}
async function accountMaintenance(deps) {
  await deps.db.query("DELETE FROM auth_handoffs WHERE expires_at < now() - interval '1 hour'");
  const { rows } = await deps.db.query("SELECT user_id FROM app_users WHERE status = 'deleting' ORDER BY deletion_requested_at LIMIT 20");
  for (const r of rows) await runDeletion(deps, r.user_id);
}

// src/cli.ts
import http2 from "node:http";

// src/app.ts
import http from "node:http";
import crypto8 from "node:crypto";

// src/db/migrate.ts
import crypto4 from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
var LOCK_KEY = 727001001;
function defaultMigrationsDir() {
  if (process.env.DEVORA_MIGRATIONS_DIR) return path.resolve(process.env.DEVORA_MIGRATIONS_DIR);
  const here = path.dirname(fileURLToPath(import.meta.url));
  for (const c of [path.join(here, "..", "migrations"), path.join(here, "..", "..", "migrations")]) {
    if (fs.existsSync(c)) return c;
  }
  throw new Error("migrations directory not found; set DEVORA_MIGRATIONS_DIR");
}
function loadMigrations(dir = defaultMigrationsDir()) {
  const files = fs.readdirSync(dir).filter((f) => /^\d{4}_[a-z0-9_]+\.sql$/.test(f)).sort();
  const seen = /* @__PURE__ */ new Set();
  return files.map((file) => {
    const m = /^(\d{4})_([a-z0-9_]+)\.sql$/.exec(file);
    const version2 = Number(m[1]);
    if (seen.has(version2)) throw new Error(`duplicate migration version ${version2}`);
    seen.add(version2);
    const text = fs.readFileSync(path.join(dir, file), "utf8");
    const upIdx = text.indexOf("-- migrate:up");
    const downIdx = text.indexOf("-- migrate:down");
    if (upIdx < 0 || downIdx < 0 || downIdx < upIdx) throw new Error(`${file} must contain "-- migrate:up" followed by "-- migrate:down"`);
    return {
      version: version2,
      name: m[2],
      file,
      checksum: crypto4.createHash("sha256").update(text).digest("hex"),
      up: text.slice(upIdx + "-- migrate:up".length, downIdx).trim(),
      down: text.slice(downIdx + "-- migrate:down".length).trim()
    };
  });
}
async function ensureTable(c) {
  await c.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
    version integer PRIMARY KEY,
    name text NOT NULL,
    checksum text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
  )`);
}
async function withLock(db, fn) {
  return db.withConnection(async (c) => {
    await c.query("SELECT pg_advisory_lock($1)", [LOCK_KEY]);
    try {
      await ensureTable(c);
      return await fn(c);
    } finally {
      await c.query("SELECT pg_advisory_unlock($1)", [LOCK_KEY]).catch(() => void 0);
    }
  });
}
function verify(files, applied) {
  const byVersion = new Map(files.map((f) => [f.version, f]));
  for (const row of applied) {
    const f = byVersion.get(row.version);
    if (!f) throw new Error(`database has migration ${row.version} (${row.name}) that this server build does not contain; do not start an older build against a newer schema`);
    if (f.checksum !== row.checksum) throw new Error(`migration ${f.file} was changed after it was applied; create a new migration instead`);
  }
}
async function migrationStatus(db, files = loadMigrations()) {
  return withLock(db, async (c) => {
    const { rows } = await c.query("SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version");
    verify(files, rows);
    const appliedSet = new Set(rows.map((r) => r.version));
    return {
      applied: rows.map((r) => ({ version: r.version, name: r.name, appliedAt: r.applied_at.toISOString() })),
      pending: files.filter((f) => !appliedSet.has(f.version)).map((f) => ({ version: f.version, name: f.name })),
      currentVersion: rows.length ? Math.max(...rows.map((r) => r.version)) : 0,
      latestVersion: files.length ? files[files.length - 1].version : 0
    };
  });
}
async function migrateUp(db, files = loadMigrations()) {
  return withLock(db, async (c) => {
    const { rows } = await c.query("SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version");
    verify(files, rows);
    const appliedSet = new Set(rows.map((r) => r.version));
    const done = [];
    for (const f of files) {
      if (appliedSet.has(f.version)) continue;
      await c.exec("BEGIN");
      try {
        await c.exec(f.up);
        await c.query("INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)", [f.version, f.name, f.checksum]);
        await c.exec("COMMIT");
      } catch (e) {
        await c.exec("ROLLBACK").catch(() => void 0);
        throw new Error(`migration ${f.file} failed and was rolled back: ${e.message}`);
      }
      done.push(f.file);
    }
    return done;
  });
}
async function migrateDown(db, steps, files = loadMigrations()) {
  if (!Number.isInteger(steps) || steps < 1) throw new Error("steps must be a positive integer");
  return withLock(db, async (c) => {
    const { rows } = await c.query("SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version DESC");
    verify(files, rows);
    const reverted = [];
    for (const row of rows.slice(0, steps)) {
      const f = files.find((x) => x.version === row.version);
      await c.exec("BEGIN");
      try {
        await c.exec(f.down);
        await c.query("DELETE FROM schema_migrations WHERE version = $1", [f.version]);
        await c.exec("COMMIT");
      } catch (e) {
        await c.exec("ROLLBACK").catch(() => void 0);
        throw new Error(`reverting ${f.file} failed and was rolled back: ${e.message}`);
      }
      reverted.push(f.file);
    }
    return reverted;
  });
}

// src/limits.ts
import crypto5 from "node:crypto";

// src/persistent-limits.ts
async function hitRate(q, key, limit2, windowSeconds) {
  const { rows } = await q.query(
    `INSERT INTO rate_counters (key, bucket, count)
     VALUES ($1, (floor(extract(epoch FROM now()) / $2) * $2)::bigint, 1)
     ON CONFLICT (key, bucket) DO UPDATE SET count = rate_counters.count + 1
     RETURNING count::int AS count,
               greatest(1, ceil(bucket + $2 - extract(epoch FROM now())))::int AS retry_after`,
    [key, windowSeconds]
  );
  const r = rows[0];
  if (r.count > limit2) return { allowed: false, retryAfterSeconds: r.retry_after };
  return { allowed: true, retryAfterSeconds: 0 };
}
async function clearRate(q, key) {
  await q.query("DELETE FROM rate_counters WHERE key = $1", [key]);
}
async function pruneRates(q) {
  const { rowCount } = await q.query("DELETE FROM rate_counters WHERE bucket < extract(epoch FROM now())::bigint - 3600");
  return rowCount;
}
async function acquireSlot(db, r) {
  const ownerCol = r.apiKeyId ? "api_key_id" : "device_id";
  const ownerId = r.apiKeyId ?? r.deviceId;
  return db.transaction(async (q) => {
    await q.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [r.apiKeyId ? `key-slot:${r.apiKeyId}` : `device-slot:${r.deviceId}`]);
    await q.query(`DELETE FROM device_request_leases WHERE ${ownerCol} = $1 AND expires_at <= now()`, [ownerId]);
    if (r.clientRequestId) {
      const seen = await q.query(
        `SELECT 1 FROM device_request_leases WHERE ${ownerCol} = $1 AND client_request_id = $2
         UNION ALL
         SELECT 1 FROM request_logs WHERE ${ownerCol} = $1 AND client_request_id = $2
         LIMIT 1`,
        [ownerId, r.clientRequestId]
      );
      if (seen.rows.length) return "duplicate";
    }
    const { rows } = await q.query(`SELECT count(*)::int AS n FROM device_request_leases WHERE ${ownerCol} = $1`, [ownerId]);
    if (rows[0].n >= r.maxConcurrent) return "busy";
    await q.query(
      `INSERT INTO device_request_leases (${ownerCol}, request_id, client_request_id, expires_at)
       VALUES ($1, $2, $3, now() + make_interval(secs => $4))`,
      [ownerId, r.requestId, r.clientRequestId, r.leaseSeconds]
    );
    return "ok";
  });
}
async function releaseSlot(q, requestId) {
  await q.query("DELETE FROM device_request_leases WHERE request_id = $1", [requestId]);
}
async function activeLeaseCount(q) {
  const { rows } = await q.query("SELECT count(*)::int AS n FROM device_request_leases WHERE expires_at > now()");
  return rows[0].n;
}

// src/limits.ts
var HIT_SCRIPT = `local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then redis.call('PEXPIRE', KEYS[1], ARGV[1]); ttl = tonumber(ARGV[1]) end
return {n, ttl}`;
var UNLOCK_SCRIPT = `if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end`;
var RedisLimitStore = class {
  constructor(redis, prefix = "devora") {
    this.redis = redis;
    this.prefix = prefix;
  }
  redis;
  prefix;
  kind = "redis";
  k(kind, key) {
    return `${this.prefix}:${kind}:${key}`;
  }
  async hit(key, limit2, windowSeconds) {
    const r = await this.redis.command("EVAL", HIT_SCRIPT, 1, this.k("rl", key), windowSeconds * 1e3);
    const [count, ttlMs] = r;
    if (count > limit2) return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil(ttlMs / 1e3)) };
    return { allowed: true, retryAfterSeconds: 0 };
  }
  async clear(key) {
    await this.redis.command("DEL", this.k("rl", key));
  }
  async cacheGet(key) {
    const v = await this.redis.command("GET", this.k("cache", key));
    if (typeof v !== "string") return null;
    try {
      return JSON.parse(v);
    } catch {
      return null;
    }
  }
  async cacheSet(key, value, ttlSeconds) {
    await this.redis.command("SET", this.k("cache", key), JSON.stringify(value), "EX", ttlSeconds);
  }
  async withLock(name, ttlMs, fn) {
    const key = this.k("lock", name);
    const token = crypto5.randomUUID();
    const got = await this.redis.command("SET", key, token, "NX", "PX", ttlMs);
    if (got !== "OK") return null;
    try {
      return await fn();
    } finally {
      await this.redis.command("EVAL", UNLOCK_SCRIPT, 1, key, token).catch(() => {
      });
    }
  }
};
var DatabaseLimitStore = class {
  constructor(db) {
    this.db = db;
  }
  db;
  kind = "database";
  hit(key, limit2, windowSeconds) {
    return hitRate(this.db, key, limit2, windowSeconds);
  }
  clear(key) {
    return clearRate(this.db, key);
  }
  async cacheGet() {
    return null;
  }
  async cacheSet() {
  }
  async withLock(_name, _ttlMs, fn) {
    return fn();
  }
};

// src/redis.ts
import net from "node:net";
import tls from "node:tls";
import fs2 from "node:fs";
var RedisUnavailableError = class extends Error {
  code;
  constructor(code, message) {
    super(message);
    this.name = "RedisUnavailableError";
    this.code = code;
  }
};
var RedisReplyError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "RedisReplyError";
  }
};
function parseRedisUrl(raw, env = {}) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    throw new Error("REDIS_URL must look like redis://default:PASSWORD@host:6379/0");
  }
  if (u.protocol !== "redis:" && u.protocol !== "rediss:") throw new Error("REDIS_URL must start with redis:// or rediss://");
  if (!u.hostname) throw new Error("REDIS_URL has no host");
  const db = u.pathname && u.pathname !== "/" ? Number(u.pathname.slice(1)) : 0;
  if (!Number.isInteger(db) || db < 0 || db > 15) throw new Error("REDIS_URL database number must be 0 to 15");
  const port = u.port ? Number(u.port) : 6379;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("REDIS_URL port is invalid");
  const num = (v, def, name) => {
    if (v === void 0 || v === "") return def;
    const n = Number(v);
    if (!Number.isInteger(n) || n < 100 || n > 6e4) throw new Error(`${name} must be an integer from 100 to 60000`);
    return n;
  };
  const cfg = {
    host: u.hostname.replace(/^\[|\]$/g, ""),
    port,
    username: u.username ? decodeURIComponent(u.username) : null,
    password: u.password ? decodeURIComponent(u.password) : null,
    db,
    tls: u.protocol === "rediss:",
    connectTimeoutMs: num(env.REDIS_CONNECT_TIMEOUT_MS, 5e3, "REDIS_CONNECT_TIMEOUT_MS"),
    commandTimeoutMs: num(env.REDIS_COMMAND_TIMEOUT_MS, 2e3, "REDIS_COMMAND_TIMEOUT_MS")
  };
  if (env.REDIS_TLS_CA_FILE) {
    if (!cfg.tls) throw new Error("REDIS_TLS_CA_FILE needs a rediss:// URL");
    if (!fs2.existsSync(env.REDIS_TLS_CA_FILE)) throw new Error("REDIS_TLS_CA_FILE does not exist");
    cfg.caFile = env.REDIS_TLS_CA_FILE;
  }
  return cfg;
}
var ReplyParser = class {
  buf = Buffer.alloc(0);
  push(chunk) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
  }
  /** Returns [value] for one complete reply, or null when more bytes are needed. Error replies come back as RedisReplyError values. */
  next() {
    const r = this.read(0);
    if (!r) return null;
    this.buf = this.buf.subarray(r[1]);
    return [r[0]];
  }
  line(at) {
    const end = this.buf.indexOf("\r\n", at);
    if (end < 0) return null;
    return [this.buf.toString("utf8", at, end), end + 2];
  }
  read(at) {
    if (at >= this.buf.length) return null;
    const type = String.fromCharCode(this.buf[at]);
    const l = this.line(at + 1);
    if (!l) return null;
    const [text, after] = l;
    switch (type) {
      case "+":
        return [text, after];
      case "-":
        return [new RedisReplyError(text), after];
      case ":":
        return [Number(text), after];
      case "$": {
        const len = Number(text);
        if (len < 0) return [null, after];
        if (this.buf.length < after + len + 2) return null;
        return [this.buf.toString("utf8", after, after + len), after + len + 2];
      }
      case "*": {
        const n = Number(text);
        if (n < 0) return [null, after];
        const out = [];
        let pos = after;
        for (let i = 0; i < n; i++) {
          const item = this.read(pos);
          if (!item) return null;
          out.push(item[0] instanceof RedisReplyError ? item[0].message : item[0]);
          pos = item[1];
        }
        return [out, pos];
      }
      default:
        throw new RedisUnavailableError("redis_protocol", `unexpected reply type from Redis`);
    }
  }
};
function encode(args) {
  const parts = [Buffer.from(`*${args.length}\r
`)];
  for (const a of args) {
    const b = Buffer.from(String(a), "utf8");
    parts.push(Buffer.from(`$${b.length}\r
`), b, Buffer.from("\r\n"));
  }
  return Buffer.concat(parts);
}
var BACKOFF_MIN_MS = 250;
var BACKOFF_MAX_MS = 3e4;
var Redis = class {
  constructor(cfg, onEvent = () => {
  }) {
    this.cfg = cfg;
    this.onEvent = onEvent;
  }
  cfg;
  onEvent;
  socket = null;
  connecting = null;
  /** Each connection has its own reply queue and parser, so a dying old connection never touches a new one. */
  conns = /* @__PURE__ */ new Map();
  closed = false;
  failures = 0;
  retryAt = 0;
  lastError = null;
  /** Host and port only, for logs and the health view. Never includes credentials. */
  get target() {
    return `${this.cfg.tls ? "rediss" : "redis"}://${this.cfg.host}:${this.cfg.port}/${this.cfg.db}`;
  }
  get connected() {
    return this.socket !== null && !this.socket.destroyed;
  }
  get lastFailure() {
    return this.lastError;
  }
  /** Sends one command. Connects (or reconnects) first when needed; fails fast during the backoff window. */
  async command(...args) {
    const socket = await this.ensure();
    return this.send(socket, args);
  }
  async ping() {
    const t = Date.now();
    const r = await this.command("PING");
    if (r !== "PONG") throw new RedisUnavailableError("redis_bad_reply", "Redis did not answer PING");
    return Date.now() - t;
  }
  /** Graceful shutdown: QUIT, then close. Pending commands are rejected. */
  async close() {
    this.closed = true;
    const s = this.socket;
    if (!s || s.destroyed) return;
    try {
      await Promise.race([this.send(s, ["QUIT"]), new Promise((r) => setTimeout(r, 1e3).unref())]);
    } catch {
    }
    s.destroy();
    this.socket = null;
  }
  send(socket, args) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.fail(socket, new RedisUnavailableError("redis_timeout", `Redis did not answer within ${this.cfg.commandTimeoutMs} ms`));
      }, this.cfg.commandTimeoutMs);
      timer.unref();
      const conn = this.conns.get(socket);
      if (!conn || socket.destroyed) {
        clearTimeout(timer);
        reject(new RedisUnavailableError("redis_unavailable", "the Redis connection closed"));
        return;
      }
      conn.pending.push({ resolve, reject, timer });
      socket.write(encode(args));
    });
  }
  ensure() {
    if (this.closed) return Promise.reject(new RedisUnavailableError("redis_closed", "the Redis client is shut down"));
    if (this.socket && !this.socket.destroyed) return Promise.resolve(this.socket);
    if (this.connecting) return this.connecting;
    const now = Date.now();
    if (now < this.retryAt) {
      return Promise.reject(new RedisUnavailableError("redis_unavailable", `Redis is unavailable (${this.lastError ?? "connection failed"}); retrying in ${Math.ceil((this.retryAt - now) / 1e3)} s`));
    }
    this.connecting = this.open().then(
      (s) => {
        if (this.failures > 0) this.onEvent("info", "redis reconnected", { target: this.target });
        this.failures = 0;
        this.retryAt = 0;
        this.lastError = null;
        this.connecting = null;
        return s;
      },
      (e) => {
        this.failures += 1;
        const delay = Math.min(BACKOFF_MAX_MS, BACKOFF_MIN_MS * 2 ** (this.failures - 1));
        this.retryAt = Date.now() + delay;
        this.lastError = e.message;
        this.connecting = null;
        this.onEvent("error", "redis connection failed", { target: this.target, reason: e.message, retryInMs: delay });
        throw e instanceof RedisUnavailableError ? e : new RedisUnavailableError("redis_unavailable", e.message);
      }
    );
    return this.connecting;
  }
  open() {
    return new Promise((resolve, reject) => {
      const c = this.cfg;
      const socket = c.tls ? tls.connect({ host: c.host, port: c.port, servername: net.isIP(c.host) ? void 0 : c.host, ca: c.caFile ? fs2.readFileSync(c.caFile) : void 0 }) : net.connect({ host: c.host, port: c.port });
      socket.setNoDelay(true);
      socket.setKeepAlive(true, 3e4);
      let settled = false;
      const timer = setTimeout(() => done(new RedisUnavailableError("redis_timeout", `could not connect to Redis within ${c.connectTimeoutMs} ms`)), c.connectTimeoutMs);
      timer.unref();
      const done = (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (err) {
          socket.destroy();
          reject(err);
        } else resolve(socket);
      };
      this.conns.set(socket, { pending: [], parser: new ReplyParser() });
      socket.on("data", (chunk) => this.onData(socket, chunk));
      socket.on("error", (e) => {
        const err = new RedisUnavailableError("redis_unavailable", e.code ? `network error ${e.code}` : "network error");
        if (!settled) done(err);
        else this.fail(socket, err);
      });
      socket.on("close", () => {
        if (!settled) done(new RedisUnavailableError("redis_unavailable", "the connection closed during setup"));
        else this.fail(socket, new RedisUnavailableError("redis_unavailable", "the Redis connection closed"));
      });
      socket.once(c.tls ? "secureConnect" : "connect", async () => {
        try {
          if (c.password !== null) {
            const args = c.username ? ["AUTH", c.username, c.password] : ["AUTH", c.password];
            await this.send(socket, args).catch((e) => {
              throw authError(e);
            });
          }
          if (c.db)
            await this.send(socket, ["SELECT", c.db]).catch((e) => {
              throw authError(e);
            });
          await this.send(socket, ["PING"]).catch((e) => {
            throw authError(e);
          });
          this.socket = socket;
          done(null);
        } catch (e) {
          done(e instanceof Error ? e : new Error(String(e)));
        }
      });
    });
  }
  onData(socket, chunk) {
    const conn = this.conns.get(socket);
    if (!conn) return;
    conn.parser.push(chunk);
    for (; ; ) {
      let r;
      try {
        r = conn.parser.next();
      } catch (e) {
        this.fail(socket, e);
        return;
      }
      if (!r) return;
      const p = conn.pending.shift();
      if (!p) continue;
      clearTimeout(p.timer);
      if (r[0] instanceof RedisReplyError) p.reject(r[0]);
      else p.resolve(r[0]);
    }
  }
  fail(socket, err) {
    if (this.socket === socket) {
      this.socket = null;
      if (!this.closed) {
        this.lastError = err.message;
        this.onEvent("warn", "redis connection lost", { target: this.target, reason: err.message });
      }
    }
    socket.destroy();
    const pending = this.conns.get(socket)?.pending ?? [];
    this.conns.delete(socket);
    for (const p of pending) {
      clearTimeout(p.timer);
      p.reject(err);
    }
  }
};
function authError(e) {
  const m = e instanceof Error ? e.message : "";
  if (/NOAUTH/i.test(m)) return new RedisUnavailableError("redis_auth_required", "Redis requires a password; put it in REDIS_URL (redis://default:PASSWORD@host:6379/0)");
  if (/WRONGPASS|invalid password|invalid username/i.test(m)) return new RedisUnavailableError("redis_auth_failed", "Redis rejected the username or password in REDIS_URL");
  if (/AUTH.*no password is set|without any password configured/i.test(m)) return new RedisUnavailableError("redis_auth_failed", "REDIS_URL has a password but this Redis server has none set");
  return e instanceof Error ? e : new Error(String(e));
}

// src/modules/accounts.ts
import crypto6 from "node:crypto";
var INSTALL_ID2 = /^[A-Za-z0-9_-]{16,64}$/;
var HANDOFF_SECONDS = 10 * 60;
var RESULT_SECONDS = 60;
var WINDOW = 15 * 60;
function pb(deps) {
  if (!deps.pocketbase) fail(503, "accounts_not_configured", "Devora accounts are not set up on this server");
  return deps.pocketbase;
}
async function limit(ctx, key, max, windowSeconds = WINDOW) {
  const r = await ctx.deps.limits.hit(key, max, windowSeconds);
  if (!r.allowed) fail(429, "rate_limited", "too many attempts; try again later", { "retry-after": String(r.retryAfterSeconds) });
}
function pbFail(e, what = "the sign-in is not valid or has expired") {
  if (e instanceof PbError && e.status === 0) fail(503, "accounts_unavailable", "the account service is temporarily unavailable; try again shortly", { "retry-after": "15" });
  if (e instanceof PbError && e.status >= 500) fail(503, "accounts_unavailable", "the account service is temporarily unavailable; try again shortly", { "retry-after": "15" });
  if (e instanceof PbError && e.status === 429) fail(429, "too_many_attempts", "too many wrong codes; request a new code and try again in a few minutes");
  if (e instanceof PbError) fail(401, "invalid_credentials", what);
  throw e;
}
function publicUser(u) {
  return { id: u.id, email: u.email, name: u.name, verified: u.verified };
}
async function signIn(ctx, user, installId, deviceName) {
  if (!user.verified) fail(403, "email_not_verified", "verify your email address first: open the link PocketBase emailed to you");
  const proof = bearerToken(ctx);
  const bound = await bindDevice(ctx.deps.db, { userId: user.id, installId, deviceName, proofHash: proof ? sha256Hex(proof) : null });
  log("info", "device signed in", { deviceId: bound.deviceId, claimed: bound.claimed });
  return { deviceId: bound.deviceId, token: bound.token, tokenExpiresAt: bound.expiresAt, claimed: bound.claimed, user: publicUser(user) };
}
async function authConfig(ctx) {
  const p = ctx.deps.pocketbase;
  const loginRequired = await requireLoginForCentralAi(ctx.deps.db);
  if (!p) {
    sendJson(ctx.res, 200, { enabled: false, loginRequired, pocketbaseUrl: null, usersCollection: null, providers: [] });
    return;
  }
  let providers = [];
  let available = true;
  try {
    if (ctx.deps.config.publicApiOrigin) providers = (await p.providers()).map((x) => ({ name: x.name, displayName: x.displayName }));
  } catch {
    available = false;
  }
  sendJson(ctx.res, 200, { enabled: true, available, loginRequired, pocketbaseUrl: p.cfg.url, usersCollection: p.cfg.usersCollection, providers });
}
async function createSession(ctx) {
  const p = pb(ctx.deps);
  await limit(ctx, `auth:session:ip:${ctx.ip}`, 30);
  const body = requireObject(await readJson(ctx.req, 16 * 1024));
  rejectUnknown(body, ["pbToken", "installId", "deviceName"]);
  const pbToken = str(body, "pbToken", { min: 20, max: 4096 });
  const installId = str(body, "installId", { min: 16, max: 64 });
  if (!INSTALL_ID2.test(installId)) fail(400, "invalid_request", "installId must be 16 to 64 letters, digits, _ or -");
  const deviceName = str(body, "deviceName", { min: 1, max: 80 });
  let user;
  try {
    const fromToken = await p.verifyUserToken(pbToken);
    const current = await p.getUser(fromToken.id);
    if (!current) fail(401, "invalid_credentials", "the sign-in is not valid or has expired");
    user = current;
  } catch (e) {
    pbFail(e);
  }
  sendJson(ctx.res, 200, await signIn(ctx, user, installId, deviceName));
}
async function resetPassword(ctx) {
  const p = pb(ctx.deps);
  await limit(ctx, `auth:reset:ip:${ctx.ip}`, 10);
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ["otpId", "otpCode", "password"]);
  const otpId = str(body, "otpId", { min: 1, max: 64 });
  const otpCode = str(body, "otpCode", { min: 4, max: 12 });
  const password = str(body, "password", { min: 8, max: 200, trim: false });
  let user;
  try {
    user = await p.checkOtp(otpId, otpCode);
    await p.setPassword(user.id, password);
  } catch (e) {
    if (e instanceof PbError && e.status === 400) fail(400, "weak_password", "use a password of at least 8 characters");
    pbFail(e, "the code is not correct or has expired");
  }
  await ctx.deps.db.transaction((q) => endUserSessions(q, user.id, "password_reset"));
  log("info", "password reset with email code", {});
  sendJson(ctx.res, 200, { reset: true });
}
async function oauthStart(ctx) {
  const deps = ctx.deps;
  const p = pb(deps);
  await limit(ctx, `auth:oauth:start:ip:${ctx.ip}`, 30);
  if (!deps.config.publicApiOrigin) fail(503, "oauth_not_configured", "browser sign-in needs PUBLIC_API_ORIGIN on the server");
  if (deps.config.keyring.size === 0) fail(503, "oauth_not_configured", "browser sign-in needs DEVORA_SECRET_KEYS on the server");
  const body = requireObject(await readJson(ctx.req, 16 * 1024));
  rejectUnknown(body, ["provider", "purpose", "loopbackPort", "loopbackNonce", "pbToken"]);
  const providerName = str(body, "provider", { min: 1, max: 40, pattern: /^[a-z0-9_]+$/ });
  const purpose = body.purpose ?? "login";
  if (purpose !== "login" && purpose !== "link" && purpose !== "reauth") fail(400, "invalid_request", "purpose must be login, link or reauth");
  const loopbackPort = int(body, "loopbackPort", { min: 1024, max: 65535 });
  const loopbackNonce = str(body, "loopbackNonce", { min: 16, max: 64, pattern: /^[A-Za-z0-9_-]+$/ });
  let deviceId = null;
  let expectedUserId = null;
  let userToken = null;
  if (purpose !== "login") {
    const device = await authenticateDevice(ctx, { central: false });
    if (!device.userId) fail(403, "not_signed_in", "sign in first");
    deviceId = device.deviceId;
    expectedUserId = device.userId;
    if (purpose === "link") {
      userToken = str(body, "pbToken", { min: 20, max: 4096 });
      try {
        const u = await p.verifyUserToken(userToken);
        if (u.id !== expectedUserId) fail(403, "account_mismatch", "this sign-in belongs to a different account");
      } catch (e) {
        pbFail(e);
      }
    }
  } else if (body.pbToken !== void 0) fail(400, "invalid_request", "pbToken is only used for linking");
  let providers;
  try {
    providers = await p.providers();
  } catch (e) {
    pbFail(e);
  }
  const provider = providers.find((x) => x.name === providerName);
  if (!provider) fail(404, "provider_not_enabled", "this sign-in method is not enabled");
  if (provider.codeChallengeMethod && provider.codeChallengeMethod !== "S256") fail(503, "oauth_not_configured", "this provider is not configured for PKCE S256");
  if (!provider.authURL.endsWith("redirect_uri=")) fail(502, "oauth_not_configured", "the account service returned an unexpected sign-in address");
  const authUrlBase = new URL(provider.authURL);
  if (deps.config.env === "production" && authUrlBase.protocol !== "https:") fail(502, "oauth_not_configured", "the provider sign-in address must use https");
  if (authUrlBase.searchParams.get("state") !== provider.state) fail(502, "oauth_not_configured", "the account service returned an inconsistent sign-in state");
  const redirectUri = `${deps.config.publicApiOrigin}/v1/auth/oauth/callback`;
  const id = crypto6.randomUUID();
  const secret = randomToken(32);
  const sealed = userToken ? sealJson(deps, sealSecret(deps.config.keyring, userToken, `auth_handoff:${id}`)) : null;
  await deps.db.query(
    `INSERT INTO auth_handoffs (id, purpose, provider, state_hash, secret_hash, code_verifier, redirect_uri, loopback_port, loopback_nonce,
                                device_id, expected_user_id, user_token_sealed, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now() + make_interval(secs => $13))`,
    [id, purpose, provider.name, sha256Hex(provider.state), sha256Hex(secret), provider.codeVerifier, redirectUri, loopbackPort, loopbackNonce, deviceId, expectedUserId, sealed, HANDOFF_SECONDS]
  );
  sendJson(ctx.res, 200, { authUrl: provider.authURL + encodeURIComponent(redirectUri), handoffSecret: secret, expiresIn: HANDOFF_SECONDS, provider: provider.name });
}
function sealJson(_deps, s) {
  return { k: s.keyVersion, iv: s.iv.toString("base64"), c: s.ciphertext.toString("base64"), t: s.tag.toString("base64") };
}
function openJson(deps, v, id) {
  return openSecret(deps.config.keyring, { keyVersion: v.k, iv: Buffer.from(v.iv, "base64"), ciphertext: Buffer.from(v.c, "base64"), tag: Buffer.from(v.t, "base64") }, `auth_handoff:${id}`);
}
var PAGE_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
function page(ctx, status, title, text) {
  const esc = (s) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
  const html = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#000;color:#fff;font:15px/1.5 system-ui,sans-serif}main{max-width:420px;padding:24px;text-align:center}h1{font-size:20px;margin:0 0 8px}p{color:#a1a1aa;margin:0}</style>
<main><h1>${esc(title)}</h1><p>${esc(text)}</p></main>`;
  ctx.res.writeHead(status, { "content-type": "text/html; charset=utf-8", "content-security-policy": PAGE_CSP, "cache-control": "no-store" });
  ctx.res.end(html);
}
async function oauthCallback(ctx) {
  const deps = ctx.deps;
  await limit(ctx, `auth:oauth:callback:ip:${ctx.ip}`, 60);
  const q = ctx.url.searchParams;
  const state = q.get("state") ?? "";
  if (!/^[A-Za-z0-9_.~-]{8,200}$/.test(state)) return page(ctx, 400, "Sign-in failed", "This sign-in link is not valid. Start again from the Devora app.");
  const { rows } = await deps.db.query(
    `UPDATE auth_handoffs SET status = 'failed', error_code = 'in_progress'
      WHERE state_hash = $1 AND status = 'pending' AND expires_at > now()
      RETURNING id, purpose, provider, code_verifier, redirect_uri, loopback_port, loopback_nonce, expected_user_id, user_token_sealed`,
    [sha256Hex(state)]
  );
  const h = rows[0];
  if (!h) return page(ctx, 400, "Sign-in expired", "This sign-in was already used or has expired. Start again from the Devora app.");
  const back = (params) => {
    const u = new URL(`http://127.0.0.1:${h.loopback_port}/devora-auth`);
    u.searchParams.set("nonce", h.loopback_nonce);
    for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
    ctx.res.writeHead(302, { location: u.toString(), "cache-control": "no-store", "referrer-policy": "no-referrer" });
    ctx.res.end();
  };
  const failWith = async (code2) => {
    await deps.db.query("UPDATE auth_handoffs SET status = 'failed', error_code = $2, user_token_sealed = NULL WHERE id = $1", [h.id, code2]);
    back({ error: code2 });
  };
  const code = q.get("code") ?? "";
  if (q.get("error") || !code || code.length > 2048) return failWith(q.get("error") === "access_denied" ? "cancelled" : "provider_error");
  let userToken;
  try {
    if (h.user_token_sealed) userToken = openJson(deps, h.user_token_sealed, h.id);
  } catch {
    return failWith("server_error");
  }
  let user;
  let pbToken;
  try {
    const r = await pb(deps).finishOAuth({ provider: h.provider, code, codeVerifier: h.code_verifier, redirectUrl: h.redirect_uri, userToken });
    user = r.user;
    pbToken = r.token;
    const current = await pb(deps).getUser(user.id);
    if (!current) return failWith("invalid_account");
    user = current;
  } catch (e) {
    log("warn", "oauth sign-in failed", { reason: e instanceof PbError ? e.status : "error" });
    return failWith(e instanceof PbError && e.status === 0 ? "accounts_unavailable" : "sign_in_failed");
  }
  if (h.expected_user_id && user.id !== h.expected_user_id) return failWith(h.purpose === "link" ? "identity_in_use" : "account_mismatch");
  if (h.purpose === "login" && !user.verified) return failWith("email_not_verified");
  const resultCode = randomToken(32);
  const sealed = h.purpose === "login" ? sealJson(deps, sealSecret(deps.config.keyring, pbToken, `auth_handoff:${h.id}`)) : null;
  await deps.db.query(
    `UPDATE auth_handoffs SET status = 'completed', error_code = NULL, user_id = $2, result_code_hash = $3,
            result_expires_at = now() + make_interval(secs => $4), user_token_sealed = $5
      WHERE id = $1`,
    [h.id, user.id, sha256Hex(resultCode), RESULT_SECONDS, sealed]
  );
  back({ code: resultCode });
}
async function consumeHandoff(ctx, code, secret, purpose) {
  const { rows } = await ctx.deps.db.query(
    `UPDATE auth_handoffs h SET status = 'consumed', consumed_at = now(), user_token_sealed = NULL
       FROM (SELECT id, user_token_sealed FROM auth_handoffs WHERE result_code_hash = $1 FOR UPDATE) old
      WHERE h.id = old.id AND h.status = 'completed' AND h.result_expires_at > now()
      RETURNING h.id, h.purpose, h.provider, h.secret_hash, h.user_id, h.device_id, old.user_token_sealed AS sealed_before`,
    [sha256Hex(code)]
  );
  const h = rows[0];
  if (!h || h.secret_hash !== sha256Hex(secret) || h.purpose !== purpose) fail(400, "invalid_code", "this sign-in code is not valid or has expired; start again");
  return h;
}
async function exchange(ctx) {
  const deps = ctx.deps;
  pb(deps);
  await limit(ctx, `auth:exchange:ip:${ctx.ip}`, 30);
  const body = requireObject(await readJson(ctx.req, 8 * 1024));
  rejectUnknown(body, ["code", "handoffSecret", "installId", "deviceName"]);
  const code = str(body, "code", { min: 20, max: 128 });
  const secret = str(body, "handoffSecret", { min: 20, max: 128 });
  const kind = await deps.db.query("SELECT purpose FROM auth_handoffs WHERE result_code_hash = $1 AND status = 'completed'", [sha256Hex(code)]);
  const purpose = kind.rows[0]?.purpose;
  if (purpose === "link") {
    const device = await authenticateDevice(ctx, { central: false });
    const h2 = await consumeHandoff(ctx, code, secret, "link");
    if (h2.device_id !== device.deviceId || h2.user_id !== device.userId) fail(400, "invalid_code", "this sign-in code is not valid or has expired; start again");
    sendJson(ctx.res, 200, { linked: true, provider: h2.provider });
    return;
  }
  const installId = str(body, "installId", { min: 16, max: 64 });
  if (!INSTALL_ID2.test(installId)) fail(400, "invalid_request", "installId must be 16 to 64 letters, digits, _ or -");
  const deviceName = str(body, "deviceName", { min: 1, max: 80 });
  const h = await consumeHandoff(ctx, code, secret, "login");
  let pbToken = null;
  try {
    pbToken = h.sealed_before ? openJson(deps, h.sealed_before, h.id) : null;
  } catch {
    pbToken = null;
  }
  let user;
  try {
    user = await pb(deps).getUser(h.user_id);
  } catch (e) {
    pbFail(e);
  }
  if (!user) fail(401, "invalid_credentials", "the sign-in is not valid or has expired");
  sendJson(ctx.res, 200, { ...await signIn(ctx, user, installId, deviceName), pbToken });
}
async function signedIn(ctx) {
  const device = await authenticateDevice(ctx, { central: false });
  if (!device.userId) fail(403, "not_signed_in", "this computer is not signed in to a Devora account");
  return device;
}
async function refresh(ctx) {
  const device = await signedIn(ctx);
  await limit(ctx, `auth:refresh:dev:${device.deviceId}`, 30, 3600);
  const t = await rotateToken(ctx.deps.db, device.deviceId, device.tokenHash);
  sendJson(ctx.res, 200, { token: t.token, tokenExpiresAt: t.expiresAt });
}
async function logout2(ctx) {
  const token = bearerToken(ctx);
  if (!token) fail(401, "unauthenticated", "a device token is required");
  const { rows } = await ctx.deps.db.query("SELECT id, user_id FROM devices WHERE token_hash = $1 OR prev_token_hash = $1", [sha256Hex(token)]);
  if (rows[0]?.user_id) await endSession(ctx.deps.db, rows[0].id, "logout");
  sendJson(ctx.res, 200, { signedOut: true });
}
async function account(ctx) {
  const device = await signedIn(ctx);
  const p = pb(ctx.deps);
  let user;
  let identities;
  try {
    [user, identities] = await Promise.all([p.getUser(device.userId), p.externalAuths(device.userId)]);
  } catch (e) {
    pbFail(e);
  }
  if (!user) fail(401, "account_deleted", "this account has been deleted");
  const { rows } = await ctx.deps.db.query(
    `SELECT id, name, created_at, last_seen_at, app_version, signed_out_at FROM devices
      WHERE user_id = $1 ORDER BY (signed_out_at IS NULL) DESC, last_seen_at DESC NULLS LAST LIMIT 50`,
    [device.userId]
  );
  sendJson(ctx.res, 200, {
    user: { ...publicUser(user), created: user.created, hasAvatar: !!user.avatar },
    identities,
    tokenExpiresAt: device.tokenExpiresAt,
    devices: rows.map((r) => ({ id: r.id, name: r.name, createdAt: r.created_at, lastSeenAt: r.last_seen_at, appVersion: r.app_version, signedIn: !r.signed_out_at, current: r.id === device.deviceId }))
  });
}
async function signOutDevice(ctx) {
  const device = await signedIn(ctx);
  const id = uuidParam(ctx.params.id);
  const { rows } = await ctx.deps.db.query("SELECT user_id, signed_out_at FROM devices WHERE id = $1", [id]);
  if (!rows[0] || rows[0].user_id !== device.userId) fail(404, "not_found", "device not found");
  if (!rows[0].signed_out_at) await endSession(ctx.deps.db, id, "signed_out_remotely");
  sendJson(ctx.res, 200, { id, signedIn: false });
}
async function deleteAccount(ctx) {
  const deps = ctx.deps;
  const device = await signedIn(ctx);
  const p = pb(deps);
  await limit(ctx, `account:delete:dev:${device.deviceId}`, 5, 3600);
  const body = requireObject(await readJson(ctx.req, 8 * 1024));
  rejectUnknown(body, ["password", "code", "handoffSecret", "otpId", "otpCode"]);
  if (typeof body.otpId === "string") {
    const otpId = str(body, "otpId", { min: 1, max: 64 });
    const otpCode = str(body, "otpCode", { min: 4, max: 12 });
    try {
      const checked = await p.checkOtp(otpId, otpCode);
      if (checked.id !== device.userId) fail(401, "invalid_credentials", "the code is not correct");
    } catch (e) {
      pbFail(e, "the code is not correct");
    }
  } else if (typeof body.password === "string") {
    const password = str(body, "password", { min: 1, max: 200, trim: false });
    try {
      const u = await p.getUser(device.userId);
      if (!u) fail(401, "account_deleted", "this account has been deleted");
      const checked = await p.checkPassword(u.email, password);
      if (checked.id !== device.userId) fail(401, "invalid_credentials", "the password is not correct");
    } catch (e) {
      pbFail(e, "the password is not correct");
    }
  } else {
    const code = str(body, "code", { min: 20, max: 128 });
    const secret = str(body, "handoffSecret", { min: 20, max: 128 });
    const h = await consumeHandoff(ctx, code, secret, "reauth");
    if (h.user_id !== device.userId || h.device_id !== device.deviceId) fail(400, "invalid_code", "this sign-in code is not valid or has expired; start again");
  }
  await markDeleted(deps.db, device.userId, "devices");
  const status = await runDeletion(deps, device.userId);
  log("info", "account deletion requested", { status });
  sendJson(ctx.res, status === "done" ? 200 : 202, { status });
}
var USER_ID = /^[A-Za-z0-9_]{1,64}$/;
function userParam(v) {
  if (!v || !USER_ID.test(v)) fail(400, "invalid_request", "invalid user id");
  return v;
}
async function adminListUsers(ctx) {
  await guardOwner(ctx, { write: false });
  const p = ctx.deps.pocketbase;
  if (!p) {
    sendJson(ctx.res, 200, { configured: false, users: [], total: 0, page: 1, perPage: 50 });
    return;
  }
  const page2 = Math.max(1, Math.min(1e3, Number(ctx.url.searchParams.get("page") ?? 1) || 1));
  const search2 = (ctx.url.searchParams.get("search") ?? "").slice(0, 100);
  let list;
  try {
    list = await p.listUsers({ page: page2, perPage: 50, search: search2 });
  } catch (e) {
    pbFail(e);
  }
  const ids = list.items.map((u) => u.id);
  const state = ids.length ? await ctx.deps.db.query(
    `SELECT u.user_id, u.status, u.last_login_at, u.deletion_step, u.deletion_error,
                (SELECT count(*)::int FROM devices d WHERE d.user_id = u.user_id AND d.signed_out_at IS NULL) AS devices
           FROM app_users u WHERE u.user_id IN (SELECT jsonb_array_elements_text($1::jsonb))`,
    [ids]
  ) : { rows: [] };
  const byId = new Map(state.rows.map((r) => [r.user_id, r]));
  sendJson(ctx.res, 200, {
    configured: true,
    page: page2,
    perPage: 50,
    total: list.total,
    users: list.items.map((u) => {
      const s = byId.get(u.id);
      return {
        id: u.id,
        email: u.email,
        name: u.name,
        verified: u.verified,
        createdAt: u.created,
        status: s?.status ?? "active",
        lastLoginAt: s?.last_login_at ?? null,
        signedInDevices: s?.devices ?? 0,
        deletionError: s?.deletion_error ?? null
      };
    })
  });
}
async function adminGetUser(ctx) {
  await guardOwner(ctx, { write: false });
  const id = userParam(ctx.params.id);
  const p = pb(ctx.deps);
  let user;
  let identities;
  try {
    user = await p.getUser(id);
    identities = user ? await p.externalAuths(id) : [];
  } catch (e) {
    pbFail(e);
  }
  const s = await ctx.deps.db.query("SELECT status, first_seen_at, last_login_at, deletion_step, deletion_error, deleted_at FROM app_users WHERE user_id = $1", [id]);
  if (!user && !s.rows[0]) fail(404, "not_found", "user not found");
  const devices = await ctx.deps.db.query(
    `SELECT id, name, status, created_at, last_seen_at, app_version, signed_out_at, signed_out_reason FROM devices WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100`,
    [id]
  );
  sendJson(ctx.res, 200, {
    user: user ? { id: user.id, email: user.email, name: user.name, verified: user.verified, createdAt: user.created } : null,
    state: s.rows[0] ?? null,
    identities,
    devices: devices.rows.map((r) => ({ id: r.id, name: r.name, status: r.status, createdAt: r.created_at, lastSeenAt: r.last_seen_at, appVersion: r.app_version, signedIn: !r.signed_out_at, signedOutReason: r.signed_out_reason }))
  });
}
async function adminUserAction(ctx) {
  const action = ctx.params.action;
  if (!["block", "unblock", "sign-out", "delete"].includes(action)) fail(404, "not_found", "not found");
  const sensitive = action !== "sign-out";
  await guardOwner(ctx, { write: true, sensitive });
  const id = userParam(ctx.params.id);
  const db = ctx.deps.db;
  if (action === "sign-out") {
    const n = await db.transaction((q) => endUserSessions(q, id, "signed_out_by_owner"));
    sendJson(ctx.res, 200, { signedOutDevices: n });
    return;
  }
  if (action === "block" || action === "unblock") {
    const n = await db.transaction(async (q) => {
      const r = await q.query(
        `INSERT INTO app_users (user_id, status, blocked_at) VALUES ($1, $2, CASE WHEN $2 = 'blocked' THEN now() END)
         ON CONFLICT (user_id) DO UPDATE SET status = EXCLUDED.status, blocked_at = EXCLUDED.blocked_at
         WHERE app_users.status IN ('active', 'blocked') RETURNING status`,
        [id, action === "block" ? "blocked" : "active"]
      );
      if (!r.rows[0]) fail(409, "account_deleted", "this account is being deleted");
      return action === "block" ? endUserSessions(q, id, "blocked_by_owner") : 0;
    });
    sendJson(ctx.res, 200, { status: action === "block" ? "blocked" : "active", signedOutDevices: n });
    return;
  }
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ["confirmEmail"]);
  const confirm = str(body, "confirmEmail", { max: 320, optional: true }) ?? "";
  let user = null;
  try {
    user = ctx.deps.pocketbase ? await ctx.deps.pocketbase.getUser(id) : null;
  } catch (e) {
    pbFail(e);
  }
  const existing = await db.query("SELECT status FROM app_users WHERE user_id = $1", [id]);
  if (!user && !existing.rows[0]) fail(404, "not_found", "user not found");
  if (user && confirm.toLowerCase() !== user.email.toLowerCase()) fail(400, "confirmation_mismatch", "type the user's email exactly to delete the account");
  await markDeleted(db, id, "devices");
  const status = await runDeletion(ctx.deps, id);
  sendJson(ctx.res, status === "done" ? 200 : 202, { status });
}
async function adminUserActivity(ctx) {
  await guardOwner(ctx, { write: false });
  const id = userParam(ctx.params.id);
  const days = Math.min(90, Math.max(1, Number(ctx.url.searchParams.get("days") ?? 30) || 30));
  const db = ctx.deps.db;
  const devices = `(SELECT id FROM devices WHERE user_id = $1)`;
  const [byModel, recent, totals, memories, searches] = await Promise.all([
    db.query(
      `SELECT model_name, count(*)::int AS requests, count(*) FILTER (WHERE status = 'error')::int AS failed,
              coalesce(sum(prompt_tokens), 0)::int AS prompt_tokens, coalesce(sum(completion_tokens), 0)::int AS completion_tokens,
              coalesce(round(avg(latency_ms)), 0)::int AS avg_ms
         FROM request_logs WHERE device_id IN ${devices} AND created_at > now() - make_interval(days => $2)
        GROUP BY model_name ORDER BY requests DESC LIMIT 50`,
      [id, days]
    ),
    db.query(
      `SELECT l.created_at, l.model_name, l.provider_name, l.status, l.http_status, l.error_code, l.latency_ms, l.prompt_tokens, l.completion_tokens, d.name AS device_name
         FROM request_logs l LEFT JOIN devices d ON d.id = l.device_id
        WHERE l.device_id IN ${devices} ORDER BY l.created_at DESC LIMIT 50`,
      [id]
    ),
    db.query(
      `SELECT count(*)::int AS requests, count(*) FILTER (WHERE status = 'error')::int AS failed,
              coalesce(sum(prompt_tokens), 0)::int AS prompt_tokens, coalesce(sum(completion_tokens), 0)::int AS completion_tokens
         FROM request_logs WHERE device_id IN ${devices} AND created_at > now() - make_interval(days => $2)`,
      [id, days]
    ),
    db.query(
      `SELECT count(*) FILTER (WHERE NOT deleted)::int AS active,
              coalesce(json_agg(json_build_object('id', id, 'kind', kind, 'scope', scope, 'content', content, 'pinned', pinned, 'updatedAt', updated_at) ORDER BY updated_at DESC) FILTER (WHERE NOT deleted), '[]') AS items
         FROM (SELECT * FROM memory_entries WHERE device_id IN ${devices} ORDER BY updated_at DESC LIMIT 500) m`,
      [id]
    ),
    db.query(`SELECT count(*)::int AS n FROM search_logs WHERE device_id IN ${devices} AND created_at > now() - make_interval(days => $2)`, [id, days]).catch(() => ({ rows: [{ n: 0 }] }))
  ]);
  sendJson(ctx.res, 200, {
    days,
    totals: { ...totals.rows[0], searches: searches.rows[0]?.n ?? 0 },
    byModel: byModel.rows.map((r) => ({ model: r.model_name, requests: r.requests, failed: r.failed, promptTokens: r.prompt_tokens, completionTokens: r.completion_tokens, avgMs: r.avg_ms })),
    recent: recent.rows.map((r) => ({ at: r.created_at, model: r.model_name, provider: r.provider_name, status: r.status, httpStatus: r.http_status, error: r.error_code, latencyMs: r.latency_ms, promptTokens: r.prompt_tokens, completionTokens: r.completion_tokens, device: r.device_name })),
    brain: { active: memories.rows[0]?.active ?? 0, latest: (memories.rows[0]?.items ?? []).slice(0, 30) }
  });
}

// src/modules/desktop-config.ts
var STATUS_MESSAGE_MAX = 200;
var VERSION = /^\d+\.\d+\.\d+$/;
async function readDesktopConfig(db) {
  try {
    const s = await readSettings(db);
    return {
      statusMessage: typeof s.desktop_status_message === "string" ? s.desktop_status_message : "",
      minVersion: typeof s.desktop_min_version === "string" && VERSION.test(s.desktop_min_version) ? s.desktop_min_version : "",
      downloadUrl: typeof s.desktop_download_url === "string" ? s.desktop_download_url : "",
      maintenance: s.desktop_maintenance === true
    };
  } catch {
    return { statusMessage: "", minVersion: "", downloadUrl: "", maintenance: false };
  }
}
var configCache = null;
var DESKTOP_CONFIG_CACHE_MS = 1e4;
function forgetDesktopConfigCache() {
  configCache = null;
}
async function readDesktopConfigCached(db) {
  if (configCache && Date.now() - configCache.at < DESKTOP_CONFIG_CACHE_MS) return configCache.value;
  const value = await readDesktopConfig(db);
  configCache = { at: Date.now(), value };
  return value;
}
function checkDownloadUrl(v) {
  if (!v) return "";
  let u;
  try {
    u = new URL(v);
  } catch {
    fail(400, "invalid_request", "downloadUrl must be an https URL");
  }
  if (u.protocol !== "https:" || u.username || u.password) fail(400, "invalid_request", "downloadUrl must be an https URL without credentials");
  return u.toString();
}
async function getDesktopConfig(ctx) {
  await guardOwner(ctx, { write: false });
  const cfg = await readDesktopConfig(ctx.deps.db);
  sendJson(ctx.res, 200, {
    ...cfg,
    environment: {
      minVersion: ctx.deps.config.desktop.minVersion,
      latestVersion: ctx.deps.config.desktop.latestVersion,
      downloadUrl: ctx.deps.config.desktop.downloadUrl,
      statusMessage: ctx.deps.config.desktop.statusMessage
    }
  });
}
async function patchDesktopConfig(ctx) {
  const session = await guardOwner(ctx, { write: true });
  const body = requireObject(await readJson(ctx.req, 16 * 1024));
  rejectUnknown(body, ["statusMessage", "minVersion", "downloadUrl", "maintenance"]);
  const changes = [];
  if (body.statusMessage !== void 0) {
    const msg = str(body, "statusMessage", { min: 0, max: STATUS_MESSAGE_MAX, optional: true }) ?? "";
    if (/[\u0000-\u001f]/.test(msg)) fail(400, "invalid_request", "the status message may not contain control characters");
    changes.push(["desktop_status_message", msg.trim()]);
  }
  if (body.minVersion !== void 0) {
    const v = str(body, "minVersion", { min: 0, max: 20, optional: true }) ?? "";
    if (v && !VERSION.test(v)) fail(400, "invalid_request", "minVersion must look like 1.2.3, or be empty to clear it");
    if (v) requireReauth(session);
    changes.push(["desktop_min_version", v]);
  }
  if (body.downloadUrl !== void 0) {
    const v = str(body, "downloadUrl", { min: 0, max: 2048, optional: true }) ?? "";
    changes.push(["desktop_download_url", checkDownloadUrl(v)]);
  }
  if (body.maintenance !== void 0) {
    const m = bool(body, "maintenance", { optional: true });
    if (m !== void 0) changes.push(["desktop_maintenance", m]);
  }
  if (!changes.length) fail(400, "invalid_request", "no settings were given");
  await ctx.deps.db.transaction(async (q) => {
    for (const [k, v] of changes) {
      await q.query(
        "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
        [k, JSON.stringify(v)]
      );
    }
  });
  forgetDesktopConfigCache();
  sendJson(ctx.res, 200, await readDesktopConfig(ctx.deps.db));
}

// src/modules/search.ts
var SEARCH_KINDS = ["tavily", "brave", "serper", "exa", "google_cse", "searxng"];
var KIND_INFO = {
  tavily: { label: "Tavily", needsKey: true, needsBaseUrl: false, options: [], signup: "tavily.com" },
  brave: { label: "Brave Search API", needsKey: true, needsBaseUrl: false, options: [], signup: "brave.com/search/api" },
  serper: { label: "Serper (Google results)", needsKey: true, needsBaseUrl: false, options: [], signup: "serper.dev" },
  exa: { label: "Exa", needsKey: true, needsBaseUrl: false, options: [], signup: "exa.ai" },
  google_cse: { label: "Google Programmable Search", needsKey: true, needsBaseUrl: false, options: ["cx"], signup: "programmablesearchengine.google.com" },
  searxng: { label: "SearXNG (self-hosted)", needsKey: false, needsBaseUrl: true, options: [], signup: "docs.searxng.org" }
};
var KEY_PATTERN2 = /^[\x21-\x7e]{8,512}$/;
var TIMEOUT_MS2 = 15e3;
var CACHE_SECONDS = 10 * 60;
var SearchError = class extends Error {
  kind;
  constructor(kind, message) {
    super(message);
    this.name = "SearchError";
    this.kind = kind;
  }
};
var clean = (s, max) => String(s ?? "").replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim().slice(0, max);
function httpUrl(u) {
  try {
    const x = new URL(String(u));
    return x.protocol === "https:" || x.protocol === "http:" ? x.toString() : null;
  } catch {
    return null;
  }
}
function normalize(items, count) {
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  for (const it of items) {
    const url = httpUrl(it.url);
    if (!url || seen.has(url)) continue;
    seen.add(url);
    out.push({ title: clean(it.title, 300) || url, url, snippet: clean(it.snippet, 1e3), published: it.published ? clean(it.published, 40) : null });
    if (out.length >= count) break;
  }
  return out;
}
async function call(f, url, init) {
  let res;
  try {
    res = await f(url, { ...init, redirect: "error", signal: AbortSignal.timeout(TIMEOUT_MS2) });
  } catch (e) {
    if (e.name === "TimeoutError" || e.name === "AbortError") throw new SearchError("timeout", "the search provider did not answer in time");
    throw new SearchError("unreachable", "the search provider could not be reached");
  }
  if (res.status === 401 || res.status === 403) throw new SearchError("auth", "the search provider refused the API key");
  if (res.status === 429) throw new SearchError("rate_limited", "the search provider rate limit or quota was reached");
  if (!res.ok) throw new SearchError(res.status >= 500 ? "unreachable" : "rejected", `the search provider answered with HTTP ${res.status}`);
  try {
    return await res.json();
  } catch {
    throw new SearchError("bad_response", "the search provider sent an unexpected answer");
  }
}
async function runSearch(f, p, key, query, count) {
  const json = (body) => JSON.stringify(body);
  switch (p.kind) {
    case "tavily": {
      const r = await call(f, "https://api.tavily.com/search", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
        body: json({ query, max_results: count, search_depth: "basic", include_answer: false })
      });
      return normalize((r?.results ?? []).map((x) => ({ title: x.title, url: x.url, snippet: x.content, published: x.published_date })), count);
    }
    case "brave": {
      const q = new URLSearchParams({ q: query, count: String(count) });
      const r = await call(f, `https://api.search.brave.com/res/v1/web/search?${q}`, { headers: { accept: "application/json", "x-subscription-token": key ?? "" } });
      return normalize((r?.web?.results ?? []).map((x) => ({ title: x.title, url: x.url, snippet: x.description, published: x.page_age ?? x.age })), count);
    }
    case "serper": {
      const r = await call(f, "https://google.serper.dev/search", { method: "POST", headers: { "content-type": "application/json", "x-api-key": key ?? "" }, body: json({ q: query, num: count }) });
      return normalize((r?.organic ?? []).map((x) => ({ title: x.title, url: x.link, snippet: x.snippet, published: x.date })), count);
    }
    case "exa": {
      const r = await call(f, "https://api.exa.ai/search", {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": key ?? "" },
        body: json({ query, numResults: count, type: "auto", contents: { text: { maxCharacters: 600 } } })
      });
      return normalize((r?.results ?? []).map((x) => ({ title: x.title, url: x.url, snippet: x.text ?? (Array.isArray(x.highlights) ? x.highlights.join(" ") : ""), published: x.publishedDate })), count);
    }
    case "google_cse": {
      const cx = String(p.options?.cx ?? "");
      if (!cx) throw new SearchError("config", "set the search engine id (cx) for Google Programmable Search");
      const q = new URLSearchParams({ key: key ?? "", cx, q: query, num: String(Math.min(count, 10)) });
      const r = await call(f, `https://www.googleapis.com/customsearch/v1?${q}`, { headers: { accept: "application/json" } });
      return normalize((r?.items ?? []).map((x) => ({ title: x.title, url: x.link, snippet: x.snippet })), count);
    }
    case "searxng": {
      if (!p.base_url) throw new SearchError("config", "set the SearXNG address");
      const q = new URLSearchParams({ q: query, format: "json" });
      const r = await call(f, `${p.base_url}/search?${q}`, { headers: { accept: "application/json", ...key ? { authorization: `Bearer ${key}` } : {} } });
      return normalize((r?.results ?? []).map((x) => ({ title: x.title, url: x.url, snippet: x.content, published: x.publishedDate })), count);
    }
  }
}
var keyAad2 = (id) => `search_provider:${id}`;
async function providerKey(deps, id) {
  const { rows } = await deps.db.query("SELECT key_version, iv, ciphertext, tag FROM search_provider_secrets WHERE provider_id = $1", [id]);
  if (!rows[0]) return null;
  return openSecret(deps.config.keyring, { keyVersion: rows[0].key_version, iv: rows[0].iv, ciphertext: rows[0].ciphertext, tag: rows[0].tag }, keyAad2(id));
}
var SELECT = `SELECT p.id, p.name, p.kind, p.base_url, p.options, p.enabled, p.is_default, p.priority, p.last_test_ok, p.last_test_at,
                       p.last_test_latency_ms, p.last_test_message, p.created_at, (s.provider_id IS NOT NULL) AS has_key
                  FROM search_providers p LEFT JOIN search_provider_secrets s ON s.provider_id = p.id`;
function usable(p) {
  return p.enabled && (!KIND_INFO[p.kind].needsKey || p.has_key) && (!KIND_INFO[p.kind].needsBaseUrl || !!p.base_url);
}
function view2(r) {
  const info = KIND_INFO[r.kind];
  return {
    id: r.id,
    name: r.name,
    kind: r.kind,
    kindLabel: info.label,
    baseUrl: r.base_url,
    options: r.options ?? {},
    enabled: r.enabled,
    isDefault: r.is_default,
    priority: r.priority,
    hasApiKey: r.has_key,
    needsApiKey: info.needsKey,
    ready: usable(r),
    lastTest: r.last_test_at ? { ok: r.last_test_ok, at: r.last_test_at, latencyMs: r.last_test_latency_ms, message: r.last_test_message } : null
  };
}
async function load(db, id) {
  const { rows } = await db.query(`${SELECT} WHERE p.id = $1`, [id]);
  if (!rows[0]) fail(404, "not_found", "search provider not found");
  return rows[0];
}
function readOptions(kind, body) {
  const raw = body.options;
  if (raw === void 0) return {};
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) fail(400, "invalid_request", "options must be an object");
  const out = {};
  for (const k of KIND_INFO[kind].options) {
    const v = raw[k];
    if (v === void 0 || v === "") continue;
    if (typeof v !== "string" || !/^[A-Za-z0-9:_-]{1,200}$/.test(v)) fail(400, "invalid_request", `${k} contains unsupported characters`);
    out[k] = v;
  }
  return out;
}
async function listSearchProviders(ctx) {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query(`${SELECT} ORDER BY p.is_default DESC, p.priority, p.created_at`);
  const stats = await ctx.deps.db.query(
    `SELECT count(*)::int AS total, count(*) FILTER (WHERE status = 'error')::int AS failed, count(*) FILTER (WHERE status = 'cached')::int AS cached,
            coalesce(round(avg(latency_ms) FILTER (WHERE status = 'ok')), 0)::int AS avg_ms
       FROM search_logs WHERE created_at > now() - interval '7 days'`
  );
  const settings = await ctx.deps.db.query("SELECT (value)::text::int AS v FROM settings WHERE key = 'search_per_minute'");
  sendJson(ctx.res, 200, {
    providers: rows.map(view2),
    kinds: SEARCH_KINDS.map((k) => ({ kind: k, ...KIND_INFO[k] })),
    last7Days: stats.rows[0],
    perMinute: settings.rows[0]?.v ?? 20
  });
}
async function createSearchProvider(ctx) {
  await guardOwner(ctx, { write: true });
  const body = requireObject(await readJson(ctx.req, 8 * 1024));
  rejectUnknown(body, ["name", "kind", "baseUrl", "options", "enabled"]);
  const kind = body.kind;
  if (!SEARCH_KINDS.includes(kind)) fail(400, "invalid_request", `kind must be one of ${SEARCH_KINDS.join(", ")}`);
  const name = str(body, "name", { min: 1, max: 80 });
  const baseUrl = KIND_INFO[kind].needsBaseUrl ? normalizeBaseUrl(str(body, "baseUrl", { min: 8, max: 2048 })) : null;
  const options = readOptions(kind, body);
  const enabled = bool(body, "enabled", { optional: true, def: true }) ?? true;
  const created = await ctx.deps.db.transaction(async (q) => {
    const dup = await q.query("SELECT 1 FROM search_providers WHERE name = $1", [name]);
    if (dup.rows[0]) fail(409, "name_taken", "a search provider with this name exists");
    const any = await q.query("SELECT count(*)::int AS n FROM search_providers");
    const { rows } = await q.query(
      `INSERT INTO search_providers (name, kind, base_url, options, enabled, is_default, priority)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [name, kind, baseUrl, JSON.stringify(options), enabled, any.rows[0].n === 0, (any.rows[0].n + 1) * 10]
    );
    await bumpCatalogue(q);
    return rows[0].id;
  });
  sendJson(ctx.res, 201, { provider: view2(await load(ctx.deps.db, created)) });
}
async function updateSearchProvider(ctx) {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const current = await load(ctx.deps.db, id);
  const body = requireObject(await readJson(ctx.req, 8 * 1024));
  rejectUnknown(body, ["name", "baseUrl", "options", "enabled", "isDefault", "priority"]);
  const sets = [];
  const vals = [id];
  const add = (col, v) => {
    vals.push(v);
    sets.push(`${col} = $${vals.length}`);
  };
  const name = str(body, "name", { min: 1, max: 80, optional: true });
  if (name !== void 0) add("name", name);
  if (body.baseUrl !== void 0) {
    if (!KIND_INFO[current.kind].needsBaseUrl) fail(400, "invalid_request", "this provider has a fixed address");
    add("base_url", normalizeBaseUrl(str(body, "baseUrl", { min: 8, max: 2048 })));
  }
  if (body.options !== void 0) add("options", JSON.stringify(readOptions(current.kind, body)));
  const enabled = bool(body, "enabled", { optional: true });
  if (enabled !== void 0) add("enabled", enabled);
  const priority = int(body, "priority", { min: 0, max: 1e3, optional: true });
  if (priority !== void 0) add("priority", priority);
  const isDefault = bool(body, "isDefault", { optional: true });
  if (!sets.length && isDefault === void 0) fail(400, "invalid_request", "nothing to change");
  await ctx.deps.db.transaction(async (q) => {
    if (isDefault) await q.query("UPDATE search_providers SET is_default = false WHERE is_default AND id <> $1", [id]);
    if (isDefault !== void 0) add("is_default", isDefault);
    sets.push("updated_at = now()");
    if (body.baseUrl !== void 0 || body.options !== void 0) sets.push("last_test_ok = NULL, last_test_at = NULL, last_test_message = NULL");
    try {
      await q.query(`UPDATE search_providers SET ${sets.join(", ")} WHERE id = $1`, vals);
    } catch (e) {
      if (/unique/i.test(String(e.message))) fail(409, "name_taken", "a search provider with this name exists");
      throw e;
    }
    await bumpCatalogue(q);
  });
  sendJson(ctx.res, 200, { provider: view2(await load(ctx.deps.db, id)) });
}
async function deleteSearchProvider(ctx) {
  await guardOwner(ctx, { write: true, sensitive: true });
  const id = uuidParam(ctx.params.id);
  await load(ctx.deps.db, id);
  await ctx.deps.db.transaction(async (q) => {
    await q.query("DELETE FROM search_providers WHERE id = $1", [id]);
    await bumpCatalogue(q);
  });
  sendJson(ctx.res, 200, { deleted: true });
}
async function setSearchProviderKey(ctx) {
  await guardOwner(ctx, { write: true, sensitive: true });
  const id = uuidParam(ctx.params.id);
  await load(ctx.deps.db, id);
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ["apiKey"]);
  const apiKey = str(body, "apiKey", { min: 8, max: 512, trim: false });
  if (!KEY_PATTERN2.test(apiKey)) fail(400, "invalid_request", "the API key contains spaces or unsupported characters");
  const sealed = sealSecret(ctx.deps.config.keyring, apiKey, keyAad2(id));
  await ctx.deps.db.transaction(async (q) => {
    await q.query(
      `INSERT INTO search_provider_secrets (provider_id, key_version, iv, ciphertext, tag, updated_at) VALUES ($1, $2, $3, $4, $5, now())
       ON CONFLICT (provider_id) DO UPDATE SET key_version = EXCLUDED.key_version, iv = EXCLUDED.iv, ciphertext = EXCLUDED.ciphertext, tag = EXCLUDED.tag, updated_at = now()`,
      [id, sealed.keyVersion, sealed.iv, sealed.ciphertext, sealed.tag]
    );
    await q.query("UPDATE search_providers SET last_test_ok = NULL, last_test_at = NULL, last_test_message = NULL WHERE id = $1", [id]);
    await bumpCatalogue(q);
  });
  sendJson(ctx.res, 200, { hasApiKey: true });
}
async function clearSearchProviderKey(ctx) {
  await guardOwner(ctx, { write: true, sensitive: true });
  const id = uuidParam(ctx.params.id);
  await load(ctx.deps.db, id);
  await ctx.deps.db.transaction(async (q) => {
    await q.query("DELETE FROM search_provider_secrets WHERE provider_id = $1", [id]);
    await bumpCatalogue(q);
  });
  sendJson(ctx.res, 200, { hasApiKey: false });
}
async function testSearchProvider(ctx) {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const p = await load(ctx.deps.db, id);
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ["query"]);
  const query = str(body, "query", { min: 1, max: 200, optional: true }) ?? "Node.js release schedule";
  const key = await providerKey(ctx.deps, id);
  const started = Date.now();
  let ok = false;
  let message = "";
  let results = [];
  if (KIND_INFO[p.kind].needsKey && !key) message = "no API key is stored for this provider";
  else {
    try {
      results = await runSearch(ctx.deps.fetch, p, key, query, 5);
      ok = results.length > 0;
      message = ok ? `working; ${results.length} result${results.length === 1 ? "" : "s"}` : "the provider answered but returned no results";
    } catch (e) {
      message = e instanceof SearchError ? e.message : "the search failed";
    }
  }
  const latencyMs = Date.now() - started;
  await ctx.deps.db.query("UPDATE search_providers SET last_test_ok = $2, last_test_at = now(), last_test_latency_ms = $3, last_test_message = $4 WHERE id = $1", [id, ok, latencyMs, message.slice(0, 300)]);
  sendJson(ctx.res, 200, { ok, message, latencyMs, results });
}
async function perMinute(db) {
  const { rows } = await db.query("SELECT (value)::text::int AS v FROM settings WHERE key = 'search_per_minute'");
  return rows[0]?.v ?? 20;
}
async function search(ctx) {
  if ((await readDesktopConfigCached(ctx.deps.db)).maintenance) {
    fail(503, "maintenance", "web search is briefly under maintenance; try again soon", { "retry-after": "60" });
  }
  const device = await authenticateDevice(ctx);
  const { db, limits } = ctx.deps;
  const rl = await limits.hit(`search:dev:${device.deviceId}`, await perMinute(db), 60);
  if (!rl.allowed) fail(429, "rate_limited", "too many web searches; wait a moment", { "retry-after": String(rl.retryAfterSeconds) });
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ["query", "count"]);
  const query = str(body, "query", { min: 1, max: 400 });
  const count = int(body, "count", { min: 1, max: 10, optional: true }) ?? 5;
  const { rows } = await db.query(`${SELECT} WHERE p.enabled ORDER BY p.is_default DESC, p.priority, p.created_at`);
  const providers = rows.filter(usable);
  if (!providers.length) fail(503, "search_not_configured", "web search is not set up on this server yet");
  const cacheKey = `search:${sha256Hex(`${count}
${query.toLowerCase()}`)}`;
  const cached = await limits.cacheGet(cacheKey).catch(() => null);
  if (cached) {
    await db.query("INSERT INTO search_logs (device_id, provider_name, status, results) VALUES ($1, $2, 'cached', $3)", [device.deviceId, cached.provider, cached.results.length]);
    sendJson(ctx.res, 200, { provider: cached.provider, cached: true, results: cached.results });
    return;
  }
  const errors = [];
  for (const p of providers) {
    const started = Date.now();
    try {
      const key = await providerKey(ctx.deps, p.id);
      const results = await runSearch(ctx.deps.fetch, p, key, query, count);
      await db.query("INSERT INTO search_logs (device_id, provider_id, provider_name, status, results, latency_ms) VALUES ($1, $2, $3, 'ok', $4, $5)", [device.deviceId, p.id, p.name, results.length, Date.now() - started]);
      await limits.cacheSet(cacheKey, { provider: p.name, results }, CACHE_SECONDS).catch(() => void 0);
      sendJson(ctx.res, 200, { provider: p.name, cached: false, results });
      return;
    } catch (e) {
      const kind = e instanceof SearchError ? e.kind : "error";
      errors.push(`${p.name}: ${e instanceof SearchError ? e.message : "failed"}`);
      log("warn", "search provider failed", { provider: p.name, kind });
      await db.query("INSERT INTO search_logs (device_id, provider_id, provider_name, status, error_code, latency_ms) VALUES ($1, $2, $3, 'error', $4, $5)", [device.deviceId, p.id, p.name, kind, Date.now() - started]);
    }
  }
  fail(502, "search_failed", `web search failed with every provider (${errors.join("; ").slice(0, 400)})`);
}
async function pruneSearchLogs(db, days) {
  const { rowCount } = await db.query("DELETE FROM search_logs WHERE created_at < now() - make_interval(days => $1)", [days]);
  return rowCount;
}

// src/modules/skills.ts
var LIMITS = { name: 80, description: 1024, trigger: 40, triggers: 20, instructions: 12e3, examples: 8e3 };
function slugify(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "skill";
}
function readTriggers(v) {
  const list = Array.isArray(v) ? v : typeof v === "string" ? v.split(",") : v === void 0 ? [] : null;
  if (!list) fail(400, "invalid_request", "triggers must be a list of words or a comma-separated string");
  const out = [...new Set(list.map((t) => String(t).trim().toLowerCase()).filter(Boolean))];
  if (out.length > LIMITS.triggers) fail(400, "invalid_request", `at most ${LIMITS.triggers} triggers`);
  if (out.some((t) => t.length > LIMITS.trigger || /[\r\n]/.test(t))) fail(400, "invalid_request", `each trigger is one line of at most ${LIMITS.trigger} characters`);
  return out;
}
function view3(r) {
  return {
    id: r.id,
    slug: r.slug,
    name: r.name,
    description: r.description,
    triggers: r.triggers ?? [],
    instructions: r.instructions,
    examples: r.examples,
    enabled: r.enabled,
    revision: r.revision,
    createdAt: r.created_at,
    updatedAt: r.updated_at
  };
}
async function bumpSkills(q) {
  await q.query("UPDATE settings SET value = to_jsonb((value::text::int) + 1), updated_at = now() WHERE key = 'skills_version'");
  await bumpCatalogue(q);
}
async function skillsVersion(db) {
  try {
    const { rows } = await db.query("SELECT (value)::text::int AS v FROM settings WHERE key = 'skills_version'");
    return rows[0]?.v ?? 0;
  } catch {
    return 0;
  }
}
function readSkill(body, partial) {
  const name = str(body, "name", { min: 1, max: LIMITS.name, optional: partial });
  if (name !== void 0 && /[\r\n]/.test(name)) fail(400, "invalid_request", "the name must be a single line");
  const description = str(body, "description", { min: 1, max: LIMITS.description, optional: partial });
  const instructions = str(body, "instructions", { min: 1, max: LIMITS.instructions, optional: partial, trim: false });
  const examples = str(body, "examples", { max: LIMITS.examples, optional: true, trim: false });
  const triggers = body.triggers === void 0 ? void 0 : readTriggers(body.triggers);
  const enabled = bool(body, "enabled", { optional: true });
  return { name, description, instructions: instructions?.trim(), examples: examples?.trim(), triggers, enabled };
}
async function listOrgSkills(ctx) {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query("SELECT * FROM org_skills ORDER BY name");
  sendJson(ctx.res, 200, { skills: rows.map(view3), version: await skillsVersion(ctx.deps.db), limits: LIMITS });
}
async function createOrgSkill(ctx) {
  await guardOwner(ctx, { write: true });
  const body = requireObject(await readJson(ctx.req, 64 * 1024));
  rejectUnknown(body, ["name", "description", "triggers", "instructions", "examples", "enabled"]);
  const s = readSkill(body, false);
  const id = await ctx.deps.db.transaction(async (q) => {
    let slug = slugify(s.name);
    for (let i = 2; (await q.query("SELECT 1 FROM org_skills WHERE slug = $1", [slug])).rows.length; i++) slug = `${slugify(s.name).slice(0, 55)}-${i}`;
    const { rows: rows2 } = await q.query(
      `INSERT INTO org_skills (slug, name, description, triggers, instructions, examples, enabled) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [slug, s.name, s.description, JSON.stringify(s.triggers ?? []), s.instructions, s.examples ?? "", s.enabled ?? true]
    );
    await bumpSkills(q);
    return rows2[0].id;
  });
  const { rows } = await ctx.deps.db.query("SELECT * FROM org_skills WHERE id = $1", [id]);
  sendJson(ctx.res, 201, { skill: view3(rows[0]) });
}
async function updateOrgSkill(ctx) {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 64 * 1024));
  rejectUnknown(body, ["name", "description", "triggers", "instructions", "examples", "enabled"]);
  const s = readSkill(body, true);
  const sets = [];
  const vals = [id];
  const add = (col, v) => {
    vals.push(v);
    sets.push(`${col} = $${vals.length}`);
  };
  if (s.name !== void 0) add("name", s.name);
  if (s.description !== void 0) add("description", s.description);
  if (s.instructions !== void 0) add("instructions", s.instructions);
  if (s.examples !== void 0) add("examples", s.examples);
  if (s.triggers !== void 0) add("triggers", JSON.stringify(s.triggers));
  if (s.enabled !== void 0) add("enabled", s.enabled);
  if (!sets.length) fail(400, "invalid_request", "nothing to change");
  await ctx.deps.db.transaction(async (q) => {
    const { rowCount } = await q.query(`UPDATE org_skills SET ${sets.join(", ")}, revision = revision + 1, updated_at = now() WHERE id = $1`, vals);
    if (!rowCount) fail(404, "not_found", "skill not found");
    await bumpSkills(q);
  });
  const { rows } = await ctx.deps.db.query("SELECT * FROM org_skills WHERE id = $1", [id]);
  sendJson(ctx.res, 200, { skill: view3(rows[0]) });
}
async function deleteOrgSkill(ctx) {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  await ctx.deps.db.transaction(async (q) => {
    const { rowCount } = await q.query("DELETE FROM org_skills WHERE id = $1", [id]);
    if (!rowCount) fail(404, "not_found", "skill not found");
    await bumpSkills(q);
  });
  sendJson(ctx.res, 200, { deleted: true });
}
async function desktopSkills(ctx) {
  await authenticateDevice(ctx);
  const version2 = await skillsVersion(ctx.deps.db);
  const etag = `"skills-${version2}"`;
  if (ctx.req.headers["if-none-match"] === etag) {
    ctx.res.writeHead(304, { etag, "cache-control": "no-store" });
    ctx.res.end();
    return;
  }
  const { rows } = await ctx.deps.db.query("SELECT slug, name, description, triggers, instructions, examples, revision, updated_at FROM org_skills WHERE enabled ORDER BY name");
  sendJson(
    ctx.res,
    200,
    { version: version2, skills: rows.map((r) => ({ slug: r.slug, name: r.name, description: r.description, triggers: r.triggers ?? [], instructions: r.instructions, examples: r.examples, revision: r.revision, updatedAt: r.updated_at })) },
    { etag }
  );
}

// src/modules/models.ts
function toModel(r) {
  return {
    id: r.id,
    providerId: r.provider_id,
    providerName: r.provider_name,
    providerEnabled: r.provider_enabled,
    upstreamModelId: r.upstream_model_id,
    displayName: r.display_name,
    description: r.description,
    enabled: r.enabled,
    isDefault: r.is_default,
    contextWindow: r.context_window,
    capabilities: normalizeCapabilities(r.capabilities),
    fallbackModelId: r.fallback_model_id ?? null,
    source: r.source ?? "manual",
    lastListedAt: r.last_listed_at ?? null,
    updatedAt: r.updated_at
  };
}
var SELECT_MODEL = `
  SELECT m.*, p.name AS provider_name, p.enabled AS provider_enabled
    FROM models m JOIN providers p ON p.id = m.provider_id`;
async function listModels(ctx) {
  await guardOwner(ctx, { write: false });
  const q = ctx.url.searchParams;
  const where = [];
  const params = [];
  if (q.get("providerId")) {
    params.push(uuidParam(q.get("providerId")));
    where.push(`m.provider_id = $${params.length}`);
  }
  if (q.get("enabled") === "true" || q.get("enabled") === "false") {
    params.push(q.get("enabled") === "true");
    where.push(`m.enabled = $${params.length}`);
  }
  if (q.get("q")) {
    params.push(`%${q.get("q").slice(0, 80).replace(/[%_\\]/g, "\\$&")}%`);
    where.push(`(m.display_name ILIKE $${params.length} OR m.upstream_model_id ILIKE $${params.length})`);
  }
  const sql = `${SELECT_MODEL}${where.length ? ` WHERE ${where.join(" AND ")}` : ""} ORDER BY p.name, m.display_name LIMIT 500`;
  const { rows } = await ctx.deps.db.query(sql, params);
  sendJson(ctx.res, 200, { models: rows.map(toModel) });
}
async function loadModel(db, id) {
  const { rows } = await db.query(`${SELECT_MODEL} WHERE m.id = $1`, [id]);
  if (!rows[0]) fail(404, "not_found", "model not found");
  return rows[0];
}
function parseCapabilities(body, fallback) {
  if (body.capabilities === void 0) return fallback;
  const raw = requireObject(body.capabilities, "capabilities");
  const allowed = ["streaming", "tools", "vision", "reasoning"];
  for (const k of Object.keys(raw)) if (!allowed.includes(k)) fail(400, "invalid_request", `unknown capability "${k}"`);
  for (const [k, v] of Object.entries(raw)) {
    const c = requireObject(v, `capabilities.${k}`);
    rejectUnknown(c, k === "reasoning" ? ["supported", "source", "levels"] : ["supported", "source"]);
    if (c.supported !== void 0 && c.supported !== null && typeof c.supported !== "boolean") fail(400, "invalid_request", `capabilities.${k}.supported must be true, false or null`);
    if (c.source !== void 0 && !["unknown", "admin", "provider_reported", "test"].includes(c.source)) fail(400, "invalid_request", `capabilities.${k}.source is not valid`);
  }
  return normalizeCapabilities({ ...fallback, ...raw });
}
async function createModel(ctx) {
  await guardOwner(ctx, { write: true });
  const body = requireObject(await readJson(ctx.req, 16 * 1024));
  rejectUnknown(body, ["providerId", "upstreamModelId", "displayName", "description", "contextWindow", "capabilities", "enabled"]);
  const providerId = uuidParam(str(body, "providerId", { min: 36, max: 36 }));
  const upstreamModelId = str(body, "upstreamModelId", { min: 1, max: 200, trim: false });
  const displayName = str(body, "displayName", { min: 1, max: 120 });
  const description = str(body, "description", { max: 500, optional: true }) ?? "";
  const contextWindow = int(body, "contextWindow", { min: 1, max: 1e7, optional: true }) ?? null;
  const enabled = bool(body, "enabled", { def: false });
  const capabilities = parseCapabilities(body, unknownCapabilities());
  const { rows: p } = await ctx.deps.db.query("SELECT enabled FROM providers WHERE id = $1", [providerId]);
  if (!p[0]) fail(404, "not_found", "provider not found");
  if (enabled && !p[0].enabled) fail(409, "provider_disabled", "enable the provider before enabling its models");
  const id = await ctx.deps.db.transaction(async (q) => {
    const { rows } = await q.query(
      `INSERT INTO models (provider_id, upstream_model_id, display_name, description, enabled, context_window, capabilities)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [providerId, upstreamModelId, displayName, description, enabled, contextWindow, capabilities]
    );
    if (enabled) await bumpCatalogue(q);
    return rows[0].id;
  }).catch((e) => {
    if (e?.code === "23505") fail(409, "duplicate", "this provider already has that model");
    throw e;
  });
  sendJson(ctx.res, 201, toModel(await loadModel(ctx.deps.db, id)));
}
async function updateModel(ctx) {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 16 * 1024));
  rejectUnknown(body, ["enabled", "displayName", "description", "contextWindow", "capabilities", "fallbackModelId"]);
  const current = await loadModel(ctx.deps.db, id);
  const enabled = bool(body, "enabled", { optional: true }) ?? current.enabled;
  const displayName = str(body, "displayName", { min: 1, max: 120, optional: true }) ?? current.display_name;
  const description = str(body, "description", { max: 500, optional: true }) ?? current.description;
  const contextWindow = body.contextWindow === void 0 ? current.context_window : body.contextWindow === null ? null : int(body, "contextWindow", { min: 1, max: 1e7 });
  const capabilities = parseCapabilities(body, normalizeCapabilities(current.capabilities));
  let fallbackModelId = current.fallback_model_id ?? null;
  if (body.fallbackModelId !== void 0) {
    fallbackModelId = body.fallbackModelId === null ? null : uuidParam(typeof body.fallbackModelId === "string" ? body.fallbackModelId : "");
    if (fallbackModelId === id) fail(400, "invalid_request", "a model cannot be its own fallback");
    if (fallbackModelId) {
      const fb = await ctx.deps.db.query("SELECT 1 FROM models WHERE id = $1", [fallbackModelId]);
      if (!fb.rows[0]) fail(400, "invalid_request", "the fallback model does not exist");
    }
  }
  if (enabled && !current.provider_enabled) fail(409, "provider_disabled", "enable the provider before enabling its models");
  await ctx.deps.db.transaction(async (q) => {
    await q.query(
      `UPDATE models SET enabled = $2, display_name = $3, description = $4, context_window = $5, capabilities = $6,
              fallback_model_id = $7, is_default = CASE WHEN $2 THEN is_default ELSE false END, updated_at = now()
        WHERE id = $1`,
      [id, enabled, displayName, description, contextWindow, capabilities, fallbackModelId]
    );
    await bumpCatalogue(q);
  });
  sendJson(ctx.res, 200, toModel(await loadModel(ctx.deps.db, id)));
}
async function setDefaultModel(ctx) {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const current = await loadModel(ctx.deps.db, id);
  if (!current.enabled || !current.provider_enabled) fail(409, "model_disabled", "only an enabled model with an enabled provider can be the default");
  await ctx.deps.db.transaction(async (q) => {
    await q.query("UPDATE models SET is_default = false WHERE is_default");
    await q.query("UPDATE models SET is_default = true, updated_at = now() WHERE id = $1", [id]);
    await bumpCatalogue(q);
  });
  sendJson(ctx.res, 200, toModel(await loadModel(ctx.deps.db, id)));
}
async function deleteModel(ctx) {
  await guardOwner(ctx, { write: true, sensitive: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ["confirmName"]);
  const current = await loadModel(ctx.deps.db, id);
  if (str(body, "confirmName", { max: 120, optional: true }) !== current.display_name) fail(400, "confirmation_mismatch", "type the model name exactly to delete it");
  await ctx.deps.db.transaction(async (q) => {
    await q.query("DELETE FROM models WHERE id = $1", [id]);
    await bumpCatalogue(q);
  });
  sendJson(ctx.res, 200, { deleted: true });
}

// src/modules/chat.ts
var BODY_LIMIT = 4 * 1024 * 1024;
var MAX_MESSAGES = 400;
var MAX_TEXT_CHARS = 15e5;
var MAX_TOOLS = 128;
var UPSTREAM_BODY_LIMIT = 16 * 1024 * 1024;
var TOP_LEVEL = ["model", "messages", "tools", "tool_choice", "temperature", "top_p", "max_tokens", "reasoning_effort", "stream", "stream_options"];
var ROLES = ["system", "user", "assistant", "tool"];
var oa = (code, message, status = 400, headers = {}) => new HttpError(status, code, message, headers);
function parseChatRequest(body, maxOutputTokens) {
  for (const k of Object.keys(body)) if (!TOP_LEVEL.includes(k)) throw oa("unsupported_parameter", `the parameter "${k}" is not supported`);
  if (typeof body.model !== "string" || !UUID.test(body.model)) throw oa("invalid_request", "model must be a model id from the catalogue");
  if (!Array.isArray(body.messages) || body.messages.length < 1 || body.messages.length > MAX_MESSAGES) {
    throw oa("invalid_request", `messages must be a list of 1 to ${MAX_MESSAGES} items`);
  }
  let textChars = 0;
  let hasImages = false;
  const messages = body.messages.map((raw, i) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw oa("invalid_request", `messages[${i}] must be an object`);
    const m = raw;
    if (!ROLES.includes(m.role)) throw oa("invalid_request", `messages[${i}].role is not valid`);
    const out = { role: m.role };
    if (typeof m.content === "string") {
      textChars += m.content.length;
      out.content = m.content;
    } else if (Array.isArray(m.content)) {
      out.content = m.content.map((p) => {
        if (p?.type === "text" && typeof p.text === "string") {
          textChars += p.text.length;
          return { type: "text", text: p.text };
        }
        if (p?.type === "image_url" && typeof p.image_url?.url === "string" && p.image_url.url.length <= 8e6) {
          hasImages = true;
          return { type: "image_url", image_url: { url: p.image_url.url, ...p.image_url.detail ? { detail: String(p.image_url.detail).slice(0, 10) } : {} } };
        }
        throw oa("invalid_request", `messages[${i}].content has an unsupported part`);
      });
    } else if (m.content === null && m.role === "assistant") {
      out.content = null;
    } else {
      throw oa("invalid_request", `messages[${i}].content must be text or a list of parts`);
    }
    if (m.name !== void 0) {
      if (typeof m.name !== "string" || m.name.length > 64) throw oa("invalid_request", `messages[${i}].name is not valid`);
      out.name = m.name;
    }
    if (m.tool_call_id !== void 0) {
      if (typeof m.tool_call_id !== "string" || m.tool_call_id.length > 200) throw oa("invalid_request", `messages[${i}].tool_call_id is not valid`);
      out.tool_call_id = m.tool_call_id;
    }
    if (m.tool_calls !== void 0) {
      if (!Array.isArray(m.tool_calls) || m.tool_calls.length > 64) throw oa("invalid_request", `messages[${i}].tool_calls is not valid`);
      out.tool_calls = m.tool_calls.map((t) => {
        if (typeof t?.id !== "string" || typeof t?.function?.name !== "string" || typeof t?.function?.arguments !== "string") {
          throw oa("invalid_request", `messages[${i}].tool_calls has an invalid entry`);
        }
        textChars += t.function.arguments.length;
        return { id: t.id.slice(0, 200), type: "function", function: { name: t.function.name.slice(0, 200), arguments: t.function.arguments } };
      });
    }
    return out;
  });
  if (textChars > MAX_TEXT_CHARS) throw oa("invalid_request", "the conversation is too large for one request");
  let tools;
  if (body.tools !== void 0) {
    if (!Array.isArray(body.tools) || body.tools.length > MAX_TOOLS) throw oa("invalid_request", `tools must be a list of at most ${MAX_TOOLS} functions`);
    tools = body.tools.map((t) => {
      if (t?.type !== "function" || typeof t.function?.name !== "string" || !/^[a-zA-Z0-9_-]{1,64}$/.test(t.function.name)) {
        throw oa("invalid_request", "each tool must be a function with a valid name");
      }
      return { type: "function", function: { name: t.function.name, description: typeof t.function.description === "string" ? t.function.description.slice(0, 4e3) : void 0, parameters: t.function.parameters ?? { type: "object", properties: {} } } };
    });
  }
  let toolChoice;
  if (body.tool_choice !== void 0) {
    if (["auto", "none", "required"].includes(body.tool_choice)) toolChoice = body.tool_choice;
    else if (body.tool_choice?.type === "function" && typeof body.tool_choice.function?.name === "string") toolChoice = { type: "function", function: { name: body.tool_choice.function.name } };
    else throw oa("invalid_request", "tool_choice is not valid");
  }
  const num = (k, min, max) => {
    const v = body[k];
    if (v === void 0 || v === null) return void 0;
    if (typeof v !== "number" || !Number.isFinite(v) || v < min || v > max) throw oa("invalid_request", `${k} must be a number from ${min} to ${max}`);
    return v;
  };
  const temperature = num("temperature", 0, 2);
  const topP = num("top_p", 0, 1);
  let maxTokens;
  if (body.max_tokens !== void 0 && body.max_tokens !== null) {
    maxTokens = int({ max_tokens: body.max_tokens }, "max_tokens", { min: 1, max: maxOutputTokens });
  }
  let reasoning;
  if (body.reasoning_effort !== void 0 && body.reasoning_effort !== null) {
    if (!REASONING_LEVELS.includes(body.reasoning_effort)) throw oa("invalid_request", "reasoning_effort must be low, medium or high");
    reasoning = body.reasoning_effort;
  }
  const stream = body.stream === void 0 ? false : body.stream === true;
  if (body.stream !== void 0 && typeof body.stream !== "boolean") throw oa("invalid_request", "stream must be true or false");
  let includeUsage = false;
  if (body.stream_options !== void 0) {
    if (!stream) throw oa("invalid_request", "stream_options requires stream: true");
    const so = body.stream_options;
    if (!so || typeof so !== "object" || Object.keys(so).some((k) => k !== "include_usage") || so.include_usage !== void 0 && typeof so.include_usage !== "boolean") {
      throw oa("invalid_request", "stream_options may only contain include_usage");
    }
    includeUsage = so.include_usage === true;
  }
  return {
    model: body.model,
    messages,
    tools,
    tool_choice: toolChoice,
    temperature,
    top_p: topP,
    max_tokens: maxTokens,
    reasoning_effort: reasoning,
    stream,
    include_usage: includeUsage,
    hasImages
  };
}
function buildUpstreamBody(req, upstreamModelId, reasoningLevelsAllowed) {
  const out = { model: upstreamModelId, messages: req.messages, stream: req.stream };
  if (req.stream && req.include_usage) out.stream_options = { include_usage: true };
  if (req.tools) out.tools = req.tools;
  if (req.tool_choice !== void 0) out.tool_choice = req.tool_choice;
  if (req.temperature !== void 0) out.temperature = req.temperature;
  if (req.top_p !== void 0) out.top_p = req.top_p;
  if (req.max_tokens !== void 0) out.max_tokens = req.max_tokens;
  if (req.reasoning_effort && reasoningLevelsAllowed) out.reasoning_effort = req.reasoning_effort;
  return out;
}
var LEASE_SECONDS = 900;
var IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,64}$/;
function idempotencyKey(req) {
  const raw = req.headers["idempotency-key"];
  if (raw === void 0) return null;
  if (typeof raw !== "string" || !IDEMPOTENCY_KEY.test(raw)) {
    fail(400, "invalid_request", "Idempotency-Key must be 8 to 64 letters, digits, dots, colons, underscores or hyphens");
  }
  return raw;
}
function callerDevice(c) {
  return c.kind === "device" ? c.deviceId : null;
}
function callerKey(c) {
  return c.kind === "key" ? c.keyId : null;
}
async function policyNumber(deps, key, fallback) {
  const { rows } = await deps.db.query("SELECT (value)::text::int AS v FROM settings WHERE key = $1", [key]);
  return rows[0]?.v ?? fallback;
}
async function chatCompletions(ctx) {
  const { res, deps } = ctx;
  let deviceId = null;
  try {
    if ((await readDesktopConfigCached(deps.db)).maintenance) {
      fail(503, "maintenance", "the service is briefly under maintenance; try again soon", { "retry-after": "60" });
    }
    const asKey = await authenticateApiKey(ctx, "chat");
    let caller;
    if (asKey) {
      caller = { kind: "key", keyId: asKey.keyId, keyName: asKey.name };
    } else {
      const device = await authenticateDevice(ctx);
      deviceId = device.deviceId;
      caller = { kind: "device", deviceId: device.deviceId, modelAccess: device.modelAccess };
    }
    const clientRequestId = idempotencyKey(ctx.req);
    const rateKey = caller.kind === "key" ? `chat:key:${caller.keyId}` : `chat:dev:${caller.deviceId}`;
    const perMinute2 = caller.kind === "key" ? await apiKeyRateLimit(deps.db) : await policyNumber(deps, "rate_limit_per_minute", 60);
    const rl = await deps.limits.hit(rateKey, perMinute2, 60);
    if (!rl.allowed) fail(429, "rate_limited", "too many requests; wait and try again", { "retry-after": String(rl.retryAfterSeconds) });
    const maxConcurrent = await policyNumber(deps, "max_concurrent_per_device", 2);
    const slot = await acquireSlot(deps.db, {
      deviceId: callerDevice(caller),
      apiKeyId: callerKey(caller),
      requestId: ctx.requestId,
      clientRequestId,
      maxConcurrent,
      leaseSeconds: LEASE_SECONDS
    });
    if (slot === "duplicate") fail(409, "duplicate_request", "this request was already received; send a new Idempotency-Key for a new request");
    if (slot === "busy") fail(429, "too_many_requests", "this device already has requests running; wait for one to finish");
    try {
      await handle(ctx, caller, clientRequestId);
    } finally {
      await releaseSlot(deps.db, ctx.requestId).catch((e) => log("error", "could not release request slot", { requestId: ctx.requestId, error: errText(e) }));
    }
  } catch (e) {
    if (res.headersSent) {
      if (!res.writableEnded) res.end();
      if (!(e instanceof HttpError)) log("error", "chat failed after the stream started", { error: errText(e), deviceId });
      return;
    }
    if (e instanceof HttpError) {
      sendOpenAiError(res, e.status, e.code, e.message, e.headers);
      return;
    }
    if (e instanceof UpstreamError) {
      sendOpenAiError(res, 502, "upstream_error", "the provider failed to answer");
      return;
    }
    log("error", "chat route failed", { error: errText(e), deviceId });
    sendOpenAiError(res, 500, "internal_error", "the request could not be completed");
  }
}
function errText(e) {
  return e instanceof Error ? e.name + ": " + e.message.slice(0, 300) : "unknown error";
}
async function handle(ctx, caller, clientRequestId) {
  const { deps, req } = ctx;
  const deviceId = callerDevice(caller);
  const body = await readJson(req, BODY_LIMIT);
  const policy = await deps.db.query("SELECT (value)::text::int AS v FROM settings WHERE key = 'max_output_tokens'");
  const parsed = parseChatRequest(body, policy.rows[0]?.v ?? 8192);
  const allowed = await allowedModelIds(deps.db, deviceId, caller.kind === "device" ? caller.modelAccess : "all");
  const m = await loadRoute(deps, parsed.model);
  if (!m || !isAllowed(allowed, m.id)) throw oa("model_not_found", "this model is not in the catalogue for this computer; refresh the model list", 404);
  if (!m.model_enabled || !m.provider_enabled) throw oa("model_disabled", "this model is currently disabled; choose another model", 403);
  checkCompatible(m, parsed, true);
  const chain = [m];
  if (m.fallback_model_id) {
    const fb = await loadRoute(deps, m.fallback_model_id);
    if (fb && fb.model_enabled && fb.provider_enabled && isAllowed(allowed, fb.id) && checkCompatible(fb, parsed, false)) chain.push(fb);
  }
  for (let i = 0; i < chain.length; i++) {
    const done = await attempt(ctx, caller, clientRequestId, parsed, chain[i], { requested: m, canFallBack: i < chain.length - 1 });
    if (done) return;
  }
}
async function loadRoute(deps, modelId) {
  const { rows } = await deps.db.query(
    `SELECT m.id, m.upstream_model_id, m.display_name, m.enabled AS model_enabled, m.capabilities, m.fallback_model_id,
            p.id AS provider_id, p.name AS provider_name, p.enabled AS provider_enabled, p.base_url, p.auth_scheme, p.timeout_ms, p.max_retries
       FROM models m JOIN providers p ON p.id = m.provider_id WHERE m.id = $1`,
    [modelId]
  );
  return rows[0] ?? null;
}
function checkCompatible(m, parsed, raise) {
  const caps = normalizeCapabilities(m.capabilities);
  const no = (msg) => {
    if (raise) throw oa("unsupported_parameter", msg);
    return false;
  };
  const ok = (c) => raise ? c.supported !== false : c.supported === true;
  if (parsed.tools && !ok(caps.tools)) return no("this model does not support tools");
  if (parsed.hasImages && !ok(caps.vision)) return no("this model does not accept images");
  if (parsed.reasoning_effort) {
    const levels = caps.reasoning.levels ?? [];
    if (caps.reasoning.supported !== true || levels.length && !levels.includes(parsed.reasoning_effort)) return no("this model does not support that reasoning level");
  }
  return true;
}
function shouldFallBack(e) {
  return e instanceof UpstreamError && ["auth", "rate_limited", "timeout", "unreachable", "server"].includes(e.kind);
}
async function attempt(ctx, caller, clientRequestId, parsed, m, route) {
  const { deps, res } = ctx;
  const deviceId = callerDevice(caller);
  const apiKeyId = callerKey(caller);
  const isFallback = m.id !== route.requested.id;
  let key = null;
  if (m.auth_scheme === "bearer") {
    key = await providerApiKey(deps, m.provider_id);
    if (!key) {
      if (route.canFallBack) {
        log("warn", "model has no provider key; using its fallback", { requestId: ctx.requestId, model: m.id });
        return false;
      }
      throw oa("upstream_auth_failed", "the provider has no API key configured; the owner must add it", 502);
    }
  }
  const upstreamBody = buildUpstreamBody(parsed, m.upstream_model_id, true);
  const url = `${m.base_url}/chat/completions`;
  const started = Date.now();
  const controller = new AbortController();
  let finished = false;
  let movedOn = false;
  let outcome = {
    status: "error",
    http: 500,
    code: "internal_error",
    ttft: null,
    usage: { p: null, c: null }
  };
  const onClose = () => {
    if (!finished) controller.abort();
  };
  res.on("close", onClose);
  const routingHeaders = isFallback ? { "x-devora-model": m.id, "x-devora-fallback-from": route.requested.id } : { "x-devora-model": m.id };
  try {
    const upstream = await callUpstream(deps, url, upstreamBody, key, m.timeout_ms, m.max_retries > 0 ? 1 : 0, parsed.stream, controller);
    if (!parsed.stream) {
      const text = await readLimited(upstream, UPSTREAM_BODY_LIMIT);
      let json;
      try {
        json = JSON.parse(text);
      } catch {
        throw new UpstreamError("bad_response", "malformed response");
      }
      if (!json || !Array.isArray(json.choices)) throw new UpstreamError("bad_response", "malformed response");
      json.model = m.id;
      const usage3 = usageOf(json.usage);
      outcome = { status: "ok", http: 200, code: null, ttft: Date.now() - started, usage: usage3 };
      res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...routingHeaders });
      res.end(JSON.stringify(json));
    } else {
      for (const [k, v] of Object.entries(routingHeaders)) res.setHeader(k, v);
      outcome = await pipeStream(upstream, res, started, controller);
    }
  } catch (e) {
    if (controller.signal.aborted && !timeoutFlag.get(controller) && !res.headersSent) {
      outcome = { status: "cancelled", http: 499, code: "client_disconnected", ttft: null, usage: { p: null, c: null } };
    } else {
      const mapped = mapUpstreamError(e);
      outcome = { status: "error", http: mapped.status, code: mapped.code, ttft: null, usage: { p: null, c: null } };
      if (!res.headersSent && route.canFallBack && shouldFallBack(e)) {
        movedOn = true;
        log("warn", "upstream failed; using the configured fallback", { requestId: ctx.requestId, model: m.id, code: mapped.code });
      } else if (!res.headersSent) sendOpenAiError(res, mapped.status, mapped.code, mapped.message, mapped.headers);
      else if (!res.writableEnded) res.end();
    }
  } finally {
    finished = true;
    res.off("close", onClose);
    await writeLog(deps, {
      requestId: ctx.requestId,
      // The idempotency key belongs to the request, so only the attempt that answers carries it (the column is unique).
      clientRequestId: movedOn ? null : clientRequestId,
      deviceId,
      apiKeyId,
      modelId: m.id,
      modelName: m.display_name,
      providerId: m.provider_id,
      providerName: m.provider_name,
      stream: parsed.stream,
      latencyMs: Date.now() - started,
      ...outcome
    });
  }
  return !movedOn;
}
function usageOf(u) {
  return {
    p: Number.isInteger(u?.prompt_tokens) ? u.prompt_tokens : null,
    c: Number.isInteger(u?.completion_tokens) ? u.completion_tokens : null
  };
}
function mapUpstreamError(e) {
  if (e instanceof HttpError) return { status: e.status, code: e.code, message: e.message, headers: e.headers };
  if (e instanceof UpstreamError) {
    switch (e.kind) {
      case "auth":
        return { status: 502, code: "upstream_auth_failed", message: "the provider rejected the stored API key; the owner must update it" };
      case "rate_limited":
        return { status: 429, code: "upstream_rate_limited", message: "the provider is rate limiting requests; try again shortly", headers: { "retry-after": "20" } };
      case "timeout":
        return { status: 504, code: "upstream_timeout", message: "the provider did not answer in time" };
      case "unreachable":
        return { status: 502, code: "upstream_unreachable", message: "the provider could not be reached" };
      case "rejected":
        return { status: 400, code: "upstream_rejected", message: "the provider rejected this request; try a shorter conversation or another model" };
      default:
        return { status: 502, code: "upstream_error", message: "the provider failed to answer" };
    }
  }
  return { status: 500, code: "internal_error", message: "the request could not be completed" };
}
async function callUpstream(deps, url, body, key, timeoutMs, retries, stream, controller) {
  const headers = {
    "content-type": "application/json",
    accept: stream ? "text/event-stream" : "application/json"
  };
  if (key) headers.authorization = `Bearer ${key}`;
  const payload = JSON.stringify(body);
  let attempt2 = 0;
  for (; ; ) {
    const timer = setTimeout(() => {
      timeoutFlag.set(controller, true);
      controller.abort();
    }, timeoutMs);
    try {
      const res = await deps.fetch(url, { method: "POST", headers, body: payload, signal: controller.signal });
      clearTimeout(timer);
      if (res.status === 401 || res.status === 403) {
        await res.body?.cancel().catch(() => void 0);
        throw new UpstreamError("auth", "auth", res.status);
      }
      if (res.status === 429) {
        await res.body?.cancel().catch(() => void 0);
        throw new UpstreamError("rate_limited", "rate limited", 429);
      }
      if (res.status >= 500) {
        await res.body?.cancel().catch(() => void 0);
        throw new UpstreamError("server", "server error", res.status);
      }
      if (!res.ok) {
        await res.body?.cancel().catch(() => void 0);
        throw new UpstreamError("rejected", "rejected", res.status);
      }
      return res;
    } catch (e) {
      clearTimeout(timer);
      if (e instanceof UpstreamError) throw e;
      if (controller.signal.aborted) {
        if (timeoutFlag.get(controller)) throw new UpstreamError("timeout", "timeout");
        throw e;
      }
      if (attempt2 < retries) {
        attempt2++;
        continue;
      }
      throw new UpstreamError("unreachable", "unreachable");
    }
  }
}
var timeoutFlag = /* @__PURE__ */ new WeakMap();
async function readLimited(res, limit2) {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const chunks = [];
  let size = 0;
  for (; ; ) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit2) {
      await reader.cancel().catch(() => void 0);
      throw new UpstreamError("bad_response", "response too large");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}
async function pipeStream(upstream, res, started, controller) {
  const reader = upstream.body?.getReader();
  if (!reader) throw new UpstreamError("bad_response", "no stream");
  const idleMs = 12e4;
  let idle;
  const armIdle = () => {
    clearTimeout(idle);
    idle = setTimeout(() => {
      timeoutFlag.set(controller, true);
      controller.abort();
    }, idleMs);
  };
  armIdle();
  let ttft = null;
  let usage3 = { p: null, c: null };
  let tail = "";
  let started200 = false;
  try {
    for (; ; ) {
      const { done, value } = await reader.read();
      if (done) break;
      armIdle();
      if (ttft === null) ttft = Date.now() - started;
      if (!started200) {
        res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store", "x-accel-buffering": "no" });
        started200 = true;
      }
      if (!res.writableEnded && !res.destroyed) res.write(value);
      tail += Buffer.from(value).toString("utf8");
      let nl;
      while ((nl = tail.indexOf("\n")) >= 0) {
        const line = tail.slice(0, nl).trim();
        tail = tail.slice(nl + 1);
        if (line.startsWith("data:") && line.includes('"usage"')) {
          try {
            const u = usageOf(JSON.parse(line.slice(5)).usage);
            if (u.p !== null || u.c !== null) usage3 = u;
          } catch {
          }
        }
      }
      if (tail.length > 262144) tail = tail.slice(-65536);
    }
    clearTimeout(idle);
    if (!started200) {
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store" });
    }
    res.end();
    return { status: "ok", http: 200, code: null, ttft, usage: usage3 };
  } catch {
    clearTimeout(idle);
    await reader.cancel().catch(() => void 0);
    if (controller.signal.aborted && !timeoutFlag.get(controller)) {
      if (!res.writableEnded) res.end();
      return { status: "cancelled", http: 499, code: "client_disconnected", ttft, usage: usage3 };
    }
    const timed = timeoutFlag.get(controller) === true;
    if (started200) {
      const err = timed ? { code: "upstream_timeout", message: "the provider stopped sending data" } : { code: "upstream_error", message: "the provider stream was interrupted" };
      if (!res.writableEnded) {
        res.write(`data: ${JSON.stringify({ error: { message: err.message, type: "server_error", code: err.code } })}

`);
        res.write("data: [DONE]\n\n");
        res.end();
      }
      return { status: "error", http: 200, code: err.code, ttft, usage: usage3 };
    }
    throw timed ? new UpstreamError("timeout", "timeout") : new UpstreamError("unreachable", "interrupted");
  }
}
async function writeLog(deps, r) {
  const reported = r.usage.p !== null || r.usage.c !== null;
  const params = [
    r.deviceId,
    r.apiKeyId,
    r.modelId,
    r.modelName,
    r.providerId,
    r.providerName,
    r.status,
    r.http,
    r.code,
    r.stream,
    Math.max(0, Math.round(r.latencyMs)),
    r.ttft,
    r.usage.p,
    r.usage.c,
    reported ? "provider_reported" : "none",
    r.requestId,
    r.clientRequestId
  ];
  const sql = `INSERT INTO request_logs (device_id, api_key_id, model_id, model_name, provider_id, provider_name, status, http_status, error_code, stream, latency_ms, ttft_ms, prompt_tokens, completion_tokens, usage_source, request_id, client_request_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
       ON CONFLICT DO NOTHING`;
  for (let attempt2 = 1; attempt2 <= 3; attempt2++) {
    try {
      await deps.db.query(sql, params);
      return;
    } catch (e) {
      if (attempt2 === 3) {
        log("error", "could not write request log", { requestId: r.requestId, attempts: attempt2, error: errText(e) });
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 150 * attempt2));
    }
  }
}

// src/modules/memory.ts
var SYNC_PER_DEVICE = 40;
var SYNC_WINDOW_SECONDS = 5 * 60;
var MAX_CHANGES = 200;
var MAX_PULL = 800;
var BODY_LIMIT2 = 512 * 1024;
var KINDS = /* @__PURE__ */ new Set(["fact", "preference", "lesson", "decision"]);
var SOURCES = /* @__PURE__ */ new Set(["user", "agent", "system"]);
var CLIENT_KEY = /^[A-Za-z0-9_-]{16,128}$/;
var SECRET_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:sk|ghp|xox[baprs])-?[A-Za-z0-9_-]{16,}|\bAKIA[0-9A-Z]{16}\b|\b(?:api[_-]?key|secret|token|password|passwd|bearer)\b\s*[:=]\s*\S{12,}/i;
var SECRET_SKIP = /(your[_-]|example|placeholder|changeme|xxxx|\$\{|process\.env|os\.environ|getenv|<[^>]+>)/i;
function parseChange(raw, index) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) fail(400, "invalid_request", `changes[${index}] must be an object`);
  const c = requireObject(raw, `changes[${index}]`);
  rejectUnknown(c, ["clientKey", "scope", "projectKey", "kind", "content", "tags", "source", "confidence", "verified", "pinned", "hits", "deleted", "updatedAt"]);
  const clientKey = str(c, "clientKey", { min: 16, max: 128, pattern: CLIENT_KEY });
  if (!clientKey) fail(400, "invalid_request", `changes[${index}].clientKey is required`);
  const scope = str(c, "scope", { min: 6, max: 7 });
  if (scope !== "global" && scope !== "project") fail(400, "invalid_request", `changes[${index}].scope must be global or project`);
  const projectKey = str(c, "projectKey", { max: 120 }) ?? "";
  if (scope === "global" && projectKey) fail(400, "invalid_request", `changes[${index}].projectKey must be empty for global memories`);
  if (scope === "project" && !projectKey) fail(400, "invalid_request", `changes[${index}].projectKey is required for project memories`);
  const kind = str(c, "kind", { min: 4, max: 10 });
  if (!kind || !KINDS.has(kind)) fail(400, "invalid_request", `changes[${index}].kind must be fact, preference, lesson or decision`);
  const content = str(c, "content", { min: 4, max: 600 });
  if (!content) fail(400, "invalid_request", `changes[${index}].content is required`);
  if (SECRET_RE.test(content) && !SECRET_SKIP.test(content)) {
    fail(422, "content_refused", `changes[${index}].content looks like a secret; memories never store keys, tokens or passwords`);
  }
  const source = str(c, "source", { min: 4, max: 6 }) ?? "agent";
  if (!SOURCES.has(source)) fail(400, "invalid_request", `changes[${index}].source must be user, agent or system`);
  const confidenceRaw = c.confidence;
  if (typeof confidenceRaw !== "number" || !Number.isFinite(confidenceRaw) || confidenceRaw < 0 || confidenceRaw > 1) {
    fail(400, "invalid_request", `changes[${index}].confidence must be a number from 0 to 1`);
  }
  const tagsRaw = c.tags ?? [];
  if (!Array.isArray(tagsRaw) || tagsRaw.length > 12) fail(400, "invalid_request", `changes[${index}].tags must be an array of at most 12 items`);
  const tags = tagsRaw.map((t) => String(t).toLowerCase().trim().slice(0, 40)).filter((t) => t.length >= 2);
  const clientUpdatedAt = int(c, "updatedAt", { min: 0, max: 8999999999999 });
  if (clientUpdatedAt === void 0) fail(400, "invalid_request", `changes[${index}].updatedAt is required`);
  return {
    clientKey,
    scope,
    projectKey,
    kind,
    content,
    tags,
    source,
    confidence: confidenceRaw,
    verified: bool(c, "verified", { def: false }) ?? false,
    pinned: bool(c, "pinned", { def: false }) ?? false,
    hits: int(c, "hits", { min: 0, max: 1e6, optional: true }) ?? 0,
    deleted: bool(c, "deleted", { def: false }) ?? false,
    clientUpdatedAt
  };
}
async function syncMemories(ctx) {
  const auth = await authenticateDevice(ctx);
  const limit2 = await ctx.deps.limits.hit(`memory:sync:${auth.deviceId}`, SYNC_PER_DEVICE, SYNC_WINDOW_SECONDS);
  if (!limit2.allowed) fail(429, "rate_limited", "too many memory syncs; try again shortly", { "retry-after": String(limit2.retryAfterSeconds) });
  const body = requireObject(await readJson(ctx.req, BODY_LIMIT2));
  rejectUnknown(body, ["changes", "since"]);
  const rawChanges = body.changes ?? [];
  if (!Array.isArray(rawChanges)) fail(400, "invalid_request", "changes must be an array");
  if (rawChanges.length > MAX_CHANGES) fail(413, "payload_too_large", `at most ${MAX_CHANGES} memories per sync`);
  const changes = rawChanges.map(parseChange);
  const since = int(body, "since", { min: 0, max: 8999999999999, optional: true }) ?? 0;
  const applied = await pushChanges(ctx, auth.deviceId, changes);
  const pull = await pullChanges(ctx, auth.deviceId, since);
  sendJson(ctx.res, 200, { ...pull, applied });
}
async function pushChanges(ctx, deviceId, changes) {
  let applied = 0;
  for (const ch of changes) {
    const { rows } = await ctx.deps.db.query(
      `INSERT INTO memory_entries
         (device_id, client_key, scope, project_key, kind, content, tags, source, confidence, verified, pinned, hits, deleted, client_updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12,$13,$14)
       ON CONFLICT (device_id, client_key) DO UPDATE SET
         scope = EXCLUDED.scope,
         project_key = EXCLUDED.project_key,
         kind = EXCLUDED.kind,
         content = EXCLUDED.content,
         tags = EXCLUDED.tags,
         source = EXCLUDED.source,
         confidence = EXCLUDED.confidence,
         verified = EXCLUDED.verified,
         pinned = EXCLUDED.pinned,
         hits = EXCLUDED.hits,
         deleted = EXCLUDED.deleted,
         client_updated_at = EXCLUDED.client_updated_at,
         updated_at = now()
       WHERE memory_entries.client_updated_at <= EXCLUDED.client_updated_at
       RETURNING id`,
      [
        deviceId,
        ch.clientKey,
        ch.scope,
        ch.projectKey,
        ch.kind,
        ch.content,
        JSON.stringify(ch.tags),
        ch.source,
        ch.confidence,
        ch.verified,
        ch.pinned,
        ch.hits,
        ch.deleted,
        ch.clientUpdatedAt
      ]
    );
    applied += rows.length;
  }
  return applied;
}
async function pullChanges(ctx, deviceId, since) {
  const { rows } = await ctx.deps.db.query(
    `SELECT client_key, scope, project_key, kind, content, tags, source, confidence, verified, pinned, hits, deleted,
            extract(epoch from updated_at) * 1000 AS updated_ms
       FROM memory_entries
      WHERE device_id = $1 AND updated_at > to_timestamp($2 / 1000.0)
      ORDER BY updated_at ASC
      LIMIT $3`,
    [deviceId, since, MAX_PULL + 1]
  );
  const truncated = rows.length > MAX_PULL;
  const kept = truncated ? rows.slice(0, MAX_PULL) : rows;
  const entries = kept.map((r) => ({
    clientKey: r.client_key,
    scope: r.scope,
    projectKey: r.project_key,
    kind: r.kind,
    content: r.content,
    tags: Array.isArray(r.tags) ? r.tags : [],
    source: r.source,
    confidence: Number(r.confidence),
    verified: r.verified === true,
    pinned: r.pinned === true,
    hits: Number(r.hits) || 0,
    deleted: r.deleted === true,
    updatedAt: Math.round(Number(r.updated_ms))
  }));
  const serverTime = truncated && entries.length ? entries[entries.length - 1].updatedAt : Date.now();
  return { serverTime, truncated, entries };
}
var ADMIN_LIMIT = 500;
function memoryFilter(ctx) {
  const sp = ctx.url.searchParams;
  const where = [];
  const params = [];
  const q = (sp.get("q") ?? "").trim().slice(0, 120);
  if (q) {
    params.push(`%${q.replace(/[\\%_]/g, (m) => `\\${m}`)}%`);
    where.push(`m.content ILIKE $${params.length}`);
  }
  const scope = sp.get("scope") ?? "";
  if (scope === "global" || scope === "project") {
    params.push(scope);
    where.push(`m.scope = $${params.length}`);
  }
  const kind = sp.get("kind") ?? "";
  if (["fact", "preference", "lesson", "decision"].includes(kind)) {
    params.push(kind);
    where.push(`m.kind = $${params.length}`);
  }
  const deviceId = sp.get("deviceId") ?? "";
  if (UUID.test(deviceId)) {
    params.push(deviceId);
    where.push(`m.device_id = $${params.length}`);
  }
  const userId = sp.get("userId") ?? "";
  if (/^[A-Za-z0-9_]{1,64}$/.test(userId)) {
    params.push(userId);
    where.push(`m.device_id IN (SELECT id FROM devices WHERE user_id = $${params.length})`);
  }
  return { where: where.length ? `WHERE ${where.join(" AND ")}` : "", params };
}
async function adminListMemory(ctx) {
  await guardOwner(ctx, { write: false });
  const limitRaw = Number(ctx.url.searchParams.get("limit") ?? 100);
  const limit2 = Number.isInteger(limitRaw) && limitRaw >= 1 && limitRaw <= ADMIN_LIMIT ? limitRaw : 100;
  const offsetRaw = Number(ctx.url.searchParams.get("offset") ?? 0);
  const offset = Number.isInteger(offsetRaw) && offsetRaw >= 0 && offsetRaw <= 1e6 ? offsetRaw : 0;
  const f = memoryFilter(ctx);
  const { rows: counted } = await ctx.deps.db.query(
    `SELECT count(*)::int AS total, count(*) FILTER (WHERE m.deleted = false)::int AS active FROM memory_entries m ${f.where}`,
    f.params
  );
  const listParams = [...f.params, limit2, offset];
  const { rows } = await ctx.deps.db.query(
    `SELECT m.id, m.device_id, m.scope, m.project_key, m.kind, m.content, m.tags, m.source, m.confidence,
            m.verified, m.pinned, m.hits, m.deleted, m.created_at, m.updated_at, d.name AS device_name
       FROM memory_entries m LEFT JOIN devices d ON d.id = m.device_id
       ${f.where} ORDER BY m.updated_at DESC LIMIT $${listParams.length - 1} OFFSET $${listParams.length}`,
    listParams
  );
  sendJson(ctx.res, 200, {
    total: counted[0]?.total ?? 0,
    active: counted[0]?.active ?? 0,
    memories: rows.map((r) => ({
      id: r.id,
      deviceId: r.device_id,
      deviceName: r.device_name ?? null,
      scope: r.scope,
      projectKey: r.project_key,
      kind: r.kind,
      content: r.content,
      tags: Array.isArray(r.tags) ? r.tags : [],
      source: r.source,
      confidence: Number(r.confidence),
      verified: r.verified === true,
      pinned: r.pinned === true,
      hits: Number(r.hits) || 0,
      deleted: r.deleted === true,
      createdAt: r.created_at,
      updatedAt: r.updated_at
    }))
  });
}
async function clearMemories(ctx, deviceId) {
  await guardOwner(ctx, { write: true, sensitive: true });
  const { rows } = deviceId ? await ctx.deps.db.query("WITH gone AS (DELETE FROM memory_entries WHERE device_id = $1 RETURNING 1) SELECT count(*)::int AS n FROM gone", [deviceId]) : await ctx.deps.db.query("WITH gone AS (DELETE FROM memory_entries RETURNING 1) SELECT count(*)::int AS n FROM gone");
  sendJson(ctx.res, 200, { cleared: rows[0]?.n ?? 0 });
}
async function adminClearDeviceMemory(ctx) {
  await clearMemories(ctx, uuidParam(ctx.params.id));
}
async function adminClearAllMemory(ctx) {
  await clearMemories(ctx, null);
}

// src/modules/admin-data.ts
async function overview(ctx) {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query(`
    SELECT
      (SELECT count(*)::int FROM providers WHERE enabled) AS providers_enabled,
      (SELECT count(*)::int FROM providers) AS providers_total,
      (SELECT count(*)::int FROM models WHERE enabled) AS models_enabled,
      (SELECT count(*)::int FROM devices WHERE status = 'active') AS devices_active,
      (SELECT count(*)::int FROM request_logs WHERE created_at > now() - interval '24 hours') AS requests_24h,
      (SELECT count(*)::int FROM request_logs WHERE created_at > now() - interval '24 hours' AND status <> 'ok') AS failed_24h,
      (SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms) FROM request_logs WHERE created_at > now() - interval '24 hours' AND status = 'ok')::int AS p50_ms,
      (SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) FROM request_logs WHERE created_at > now() - interval '24 hours' AND status = 'ok')::int AS p95_ms,
      (SELECT count(*)::int FROM api_keys WHERE enabled) AS api_keys_enabled,
      (SELECT count(*)::int FROM org_agents WHERE enabled) AS org_agents_enabled`);
  const providers = await ctx.deps.db.query("SELECT name, enabled, last_test_ok, last_test_at, last_test_message FROM providers ORDER BY name");
  sendJson(ctx.res, 200, {
    ...toCamel(rows[0]),
    providers: providers.rows.map((p) => ({
      name: p.name,
      enabled: p.enabled,
      lastTestOk: p.last_test_ok,
      lastTestAt: p.last_test_at,
      lastTestMessage: p.last_test_message
    }))
  });
}
function toCamel(r) {
  return Object.fromEntries(Object.entries(r).map(([k, v]) => [k.replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase()), v]));
}
async function usage(ctx) {
  await guardOwner(ctx, { write: false });
  const window = ctx.url.searchParams.get("window") ?? "24h";
  if (window !== "24h" && window !== "7d") fail(400, "invalid_request", "window must be 24h or 7d");
  const interval = window === "24h" ? "24 hours" : "7 days";
  const bucket = window === "24h" ? "hour" : "day";
  const q = ctx.deps.db;
  const totals = await q.query(
    `SELECT count(*)::int AS requests,
            count(*) FILTER (WHERE status = 'ok')::int AS ok,
            count(*) FILTER (WHERE status = 'error')::int AS errors,
            count(*) FILTER (WHERE status = 'cancelled')::int AS cancelled,
            coalesce(sum(prompt_tokens) FILTER (WHERE usage_source = 'provider_reported'), 0)::bigint AS prompt_tokens,
            coalesce(sum(completion_tokens) FILTER (WHERE usage_source = 'provider_reported'), 0)::bigint AS completion_tokens,
            count(*) FILTER (WHERE usage_source = 'none')::int AS without_usage
       FROM request_logs WHERE created_at > now() - interval '${interval}'`
  );
  const byModel = await q.query(
    `SELECT model_name, count(*)::int AS requests, count(*) FILTER (WHERE status <> 'ok')::int AS failed
       FROM request_logs WHERE created_at > now() - interval '${interval}'
      GROUP BY model_name ORDER BY requests DESC LIMIT 50`
  );
  const byError = await q.query(
    `SELECT error_code AS code, count(*)::int AS count FROM request_logs
      WHERE created_at > now() - interval '${interval}' AND error_code IS NOT NULL
      GROUP BY error_code ORDER BY count DESC LIMIT 50`
  );
  const series = await q.query(
    `SELECT date_trunc('${bucket}', created_at) AS bucket, count(*)::int AS requests, count(*) FILTER (WHERE status <> 'ok')::int AS failed
       FROM request_logs WHERE created_at > now() - interval '${interval}'
      GROUP BY 1 ORDER BY 1`
  );
  sendJson(ctx.res, 200, {
    window,
    totals: toCamel(totals.rows[0]),
    byModel: byModel.rows.map((r) => ({ modelName: r.model_name, requests: r.requests, failed: r.failed })),
    errorCodes: byError.rows,
    series: series.rows.map((r) => ({ at: r.bucket, requests: r.requests, failed: r.failed })),
    note: "Token counts include only responses where the provider reported usage. Other requests are counted in withoutUsage."
  });
}
async function logs(ctx) {
  await guardOwner(ctx, { write: false });
  const q = ctx.url.searchParams;
  const limit2 = Math.min(200, Math.max(1, Number(q.get("limit") ?? 50) || 50));
  const where = [];
  const params = [];
  if (q.get("status") && ["ok", "error", "cancelled"].includes(q.get("status"))) {
    params.push(q.get("status"));
    where.push(`r.status = $${params.length}`);
  }
  if (q.get("model")) {
    params.push(q.get("model").slice(0, 120));
    where.push(`r.model_name = $${params.length}`);
  }
  if (q.get("cursor")) {
    const c = Number(q.get("cursor"));
    if (!Number.isInteger(c) || c < 1) fail(400, "invalid_request", "cursor is not valid");
    params.push(c);
    where.push(`r.id < $${params.length}`);
  }
  params.push(limit2 + 1);
  const sql = `SELECT r.id, r.created_at, d.name AS device_name, k.name AS api_key_name, r.model_name, r.provider_name, r.status, r.http_status, r.error_code,
                      r.stream, r.latency_ms, r.ttft_ms, r.prompt_tokens, r.completion_tokens, r.usage_source
                 FROM request_logs r LEFT JOIN devices d ON d.id = r.device_id LEFT JOIN api_keys k ON k.id = r.api_key_id
                ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
                ORDER BY r.id DESC LIMIT $${params.length}`;
  const { rows } = await ctx.deps.db.query(sql, params);
  const page2 = rows.slice(0, limit2);
  sendJson(ctx.res, 200, {
    logs: page2.map((r) => ({
      id: Number(r.id),
      createdAt: r.created_at,
      deviceName: r.device_name ?? null,
      apiKeyName: r.api_key_name ?? null,
      modelName: r.model_name,
      providerName: r.provider_name,
      status: r.status,
      httpStatus: r.http_status,
      errorCode: r.error_code,
      stream: r.stream,
      latencyMs: r.latency_ms,
      ttftMs: r.ttft_ms,
      promptTokens: r.prompt_tokens,
      completionTokens: r.completion_tokens,
      usageSource: r.usage_source
    })),
    nextCursor: rows.length > limit2 ? String(page2[page2.length - 1].id) : null
  });
}
async function getSettings(ctx) {
  await guardOwner(ctx, { write: false });
  sendJson(ctx.res, 200, { ...await currentSettings(ctx.deps.db), accountsConfigured: !!ctx.deps.pocketbase });
}
async function currentSettings(db) {
  const s = await readSettings(db);
  return {
    rateLimitPerMinute: Number(s.rate_limit_per_minute ?? 60),
    maxConcurrentPerDevice: Number(s.max_concurrent_per_device ?? 2),
    maxOutputTokens: Number(s.max_output_tokens ?? 8192),
    allowDirectProvider: s.allow_direct_provider === true,
    allowAutoRegistration: s.allow_auto_registration !== false,
    requireLoginForCentralAi: s.require_login_for_central_ai === true,
    searchPerMinute: Number(s.search_per_minute ?? 20),
    apiKeyRateLimitPerMinute: Number(s.api_key_rate_limit_per_minute ?? 30)
  };
}
var SETTING_KEYS = {
  rateLimitPerMinute: "rate_limit_per_minute",
  maxConcurrentPerDevice: "max_concurrent_per_device",
  maxOutputTokens: "max_output_tokens",
  allowDirectProvider: "allow_direct_provider",
  allowAutoRegistration: "allow_auto_registration",
  requireLoginForCentralAi: "require_login_for_central_ai",
  searchPerMinute: "search_per_minute",
  apiKeyRateLimitPerMinute: "api_key_rate_limit_per_minute"
};
async function patchSettings(ctx) {
  const session = await guardOwner(ctx, { write: true });
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, Object.keys(SETTING_KEYS));
  const changes = [];
  const rate = int(body, "rateLimitPerMinute", { min: 1, max: 600, optional: true });
  if (rate !== void 0) changes.push(["rate_limit_per_minute", rate]);
  const conc = int(body, "maxConcurrentPerDevice", { min: 1, max: 16, optional: true });
  if (conc !== void 0) changes.push(["max_concurrent_per_device", conc]);
  const maxOut = int(body, "maxOutputTokens", { min: 1, max: 32768, optional: true });
  if (maxOut !== void 0) changes.push(["max_output_tokens", maxOut]);
  const direct = bool(body, "allowDirectProvider", { optional: true });
  if (direct !== void 0) {
    requireReauth(session);
    changes.push(["allow_direct_provider", direct]);
  }
  const autoReg = bool(body, "allowAutoRegistration", { optional: true });
  if (autoReg !== void 0) changes.push(["allow_auto_registration", autoReg]);
  const searchRate = int(body, "searchPerMinute", { min: 1, max: 120, optional: true });
  if (searchRate !== void 0) changes.push(["search_per_minute", searchRate]);
  const apiKeyRate = int(body, "apiKeyRateLimitPerMinute", { min: 1, max: 600, optional: true });
  if (apiKeyRate !== void 0) changes.push(["api_key_rate_limit_per_minute", apiKeyRate]);
  const requireLogin = bool(body, "requireLoginForCentralAi", { optional: true });
  if (requireLogin !== void 0) {
    requireReauth(session);
    if (requireLogin && !ctx.deps.pocketbase) fail(409, "accounts_not_configured", "set POCKETBASE_URL and the PocketBase superuser on the server first");
    changes.push(["require_login_for_central_ai", requireLogin]);
  }
  if (changes.length === 0) fail(400, "invalid_request", "no settings were given");
  await ctx.deps.db.transaction(async (q) => {
    for (const [k, v] of changes) {
      await q.query(
        "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
        [k, JSON.stringify(v)]
      );
    }
    if (changes.some(([k]) => k === "max_output_tokens" || k === "allow_direct_provider")) await bumpCatalogue(q);
  });
  forgetLoginSetting(ctx.deps.db);
  sendJson(ctx.res, 200, { ...await currentSettings(ctx.deps.db), accountsConfigured: !!ctx.deps.pocketbase });
}
async function pruneLogs(db, days) {
  const { rowCount } = await db.query("DELETE FROM request_logs WHERE created_at < now() - make_interval(days => $1)", [days]);
  return rowCount;
}

// src/modules/health.ts
var STALE_TEST_HOURS = 24 * 7;
async function adminHealth(ctx) {
  await guardOwner(ctx, { write: false });
  const { db, config } = ctx.deps;
  const checkedAt = (/* @__PURE__ */ new Date()).toISOString();
  const dbStart = Date.now();
  let database;
  try {
    await db.query("SELECT 1");
    const latencyMs = Date.now() - dbStart;
    const s = await migrationStatus(db);
    database = { ok: s.pending.length === 0, latencyMs, schemaVersion: s.currentVersion, pendingMigrations: s.pending.length, reason: s.pending.length ? "migrations are pending" : null };
  } catch {
    database = { ok: false, latencyMs: null, schemaVersion: null, pendingMigrations: null, reason: "the database is unreachable" };
  }
  const providers = database.ok ? (await db.query(
    `SELECT count(*) FILTER (WHERE enabled)::int AS enabled,
                  count(*) FILTER (WHERE enabled AND last_test_ok IS NULL)::int AS untested,
                  count(*) FILTER (WHERE enabled AND last_test_ok IS FALSE)::int AS failing,
                  count(*) FILTER (WHERE enabled AND last_test_at < now() - make_interval(hours => $1))::int AS stale
             FROM providers`,
    [STALE_TEST_HOURS]
  )).rows[0] : null;
  const activeLeases = database.ok ? await activeLeaseCount(db) : null;
  let redis;
  if (!ctx.deps.redis) redis = { configured: false, ok: null, latencyMs: null, target: null, reason: null };
  else {
    try {
      const latencyMs = await ctx.deps.redis.ping();
      redis = { configured: true, ok: true, latencyMs, target: ctx.deps.redis.target, reason: null };
    } catch (e) {
      redis = { configured: true, ok: false, latencyMs: null, target: ctx.deps.redis.target, reason: e instanceof Error ? e.message : "unavailable" };
    }
  }
  const limitsUp = ctx.deps.limits.kind === "redis" ? redis.ok === true : database.ok;
  const providerProblems = providers ? providers.failing + providers.untested : 0;
  const status = !database.ok || redis.ok === false ? "down" : providerProblems > 0 || (providers?.stale ?? 0) > 0 ? "degraded" : "ok";
  sendJson(ctx.res, 200, {
    status,
    checkedAt,
    api: { status: "ok", uptimeSeconds: Math.round(process.uptime()), environment: config.env },
    database,
    redis,
    providers: providers ? { enabled: providers.enabled, untested: providers.untested, failing: providers.failing, staleAfterHours: STALE_TEST_HOURS, stale: providers.stale } : null,
    activity: { activeRequests: activeLeases, rateLimitStore: limitsUp ? ctx.deps.limits.kind : "unavailable" },
    configuration: {
      cookieSecure: config.cookieSecure,
      trustProxy: config.trustProxy,
      adminOriginConfigured: config.adminOrigin !== null,
      publicApiOriginConfigured: config.publicApiOrigin !== null,
      secretKeyringConfigured: config.keyring.size > 0,
      databaseTls: config.database.ssl === "require",
      redisTls: config.redis ? config.redis.tls : null
    }
  });
}

// src/modules/releases.ts
import crypto7 from "node:crypto";
var CHUNK_BYTES = 4 * 1024 * 1024;
var MAX_RELEASE_BYTES = 600 * 1024 * 1024;
var MAX_CHUNKS = Math.ceil(MAX_RELEASE_BYTES / CHUNK_BYTES);
var CHECKS_PER_HOUR = 60;
var DOWNLOADS_PER_HOUR = 6;
var VERSION2 = /^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$/;
var SHA256 = /^[0-9a-f]{64}$/;
var FILE_NAME = /^[A-Za-z0-9 ._()+-]{1,200}$/;
function compareVersions(a, b) {
  const parse = (v) => {
    const [core, pre = ""] = v.split(/[-+]/, 2);
    return { nums: core.split(".").map((n) => Number(n) || 0), pre: v.includes("-") ? pre : "" };
  };
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < 3; i++) if ((x.nums[i] ?? 0) !== (y.nums[i] ?? 0)) return (x.nums[i] ?? 0) < (y.nums[i] ?? 0) ? -1 : 1;
  if (x.pre === y.pre) return 0;
  if (!x.pre) return 1;
  if (!y.pre) return -1;
  return x.pre < y.pre ? -1 : 1;
}
function view4(r) {
  return {
    id: r.id,
    version: r.version,
    notes: r.notes,
    mandatory: r.mandatory,
    status: r.status,
    source: r.source,
    externalUrl: r.external_url,
    fileName: r.file_name,
    fileSize: Number(r.file_size),
    sha256: r.sha256,
    uploadComplete: r.upload_complete,
    uploadedBytes: Number(r.uploaded_bytes ?? 0),
    downloads: r.downloads,
    createdAt: r.created_at,
    publishedAt: r.published_at
  };
}
var SELECT2 = `SELECT r.*, coalesce((SELECT sum(length(c.data)) FROM desktop_release_chunks c WHERE c.release_id = r.id), 0)::bigint AS uploaded_bytes
                  FROM desktop_releases r`;
async function getRelease(q, id) {
  const { rows } = await q.query(`${SELECT2} WHERE r.id = $1`, [id]);
  if (!rows[0]) fail(404, "not_found", "release not found");
  return rows[0];
}
async function latestPublished(q, current) {
  const { rows } = await q.query("SELECT * FROM desktop_releases WHERE status = 'published' AND upload_complete");
  const list = rows.sort((a, b) => compareVersions(b.version, a.version));
  const latest = list[0] ?? null;
  const mandatoryList = list.filter((r) => r.mandatory);
  const minVersion = mandatoryList[0]?.version ?? null;
  const mandatory = !!current && mandatoryList.some((r) => compareVersions(r.version, current) > 0);
  return { latest, mandatory, minVersion };
}
async function listReleases(ctx) {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query(`${SELECT2} ORDER BY r.created_at DESC LIMIT 200`);
  const adoption = await ctx.deps.db.query(
    `SELECT coalesce(app_version, 'unknown') AS version, count(*)::int AS devices
       FROM devices WHERE status = 'active' GROUP BY 1 ORDER BY 2 DESC LIMIT 50`
  );
  const list = rows.map(view4).sort((a, b) => compareVersions(b.version, a.version));
  sendJson(ctx.res, 200, {
    releases: list,
    adoption: adoption.rows,
    chunkBytes: CHUNK_BYTES,
    maxBytes: MAX_RELEASE_BYTES
  });
}
async function createRelease(ctx) {
  await guardOwner(ctx, { write: true });
  const body = requireObject(await readJson(ctx.req, 32 * 1024));
  rejectUnknown(body, ["version", "notes", "mandatory", "externalUrl", "sha256", "fileName", "fileSize"]);
  const version2 = str(body, "version", { min: 5, max: 40, pattern: VERSION2 });
  const notes = str(body, "notes", { max: 1e4, optional: true }) ?? "";
  const mandatory = bool(body, "mandatory", { def: false });
  const externalUrl = str(body, "externalUrl", { max: 2e3, optional: true }) || null;
  let sha256 = (str(body, "sha256", { max: 64, optional: true }) || "").toLowerCase() || null;
  const fileName = str(body, "fileName", { max: 200, optional: true }) || `Devora-Setup-${version2}.exe`;
  if (!FILE_NAME.test(fileName)) fail(400, "invalid_request", "fileName may contain letters, digits, spaces and . _ ( ) + -");
  const fileSize = typeof body.fileSize === "number" && Number.isInteger(body.fileSize) && body.fileSize > 0 ? body.fileSize : 0;
  if (fileSize > MAX_RELEASE_BYTES) fail(413, "payload_too_large", `the installer may be at most ${MAX_RELEASE_BYTES / 1024 / 1024} MB`);
  if (externalUrl) {
    let u;
    try {
      u = new URL(externalUrl);
    } catch {
      fail(400, "invalid_request", "externalUrl is not a URL");
    }
    if (u.protocol !== "https:" || u.username || u.password) fail(400, "invalid_request", "externalUrl must be an https address without credentials");
    if (!sha256 || !SHA256.test(sha256)) fail(400, "invalid_request", "give the SHA-256 of the installer at externalUrl, so desktops can verify the download");
  } else sha256 = null;
  try {
    const { rows } = await ctx.deps.db.query(
      `INSERT INTO desktop_releases (version, notes, mandatory, source, external_url, sha256, file_name, file_size, upload_complete)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
      [version2, notes, mandatory, externalUrl ? "url" : "upload", externalUrl, sha256, fileName, fileSize, !!externalUrl]
    );
    sendJson(ctx.res, 201, { release: view4(await getRelease(ctx.deps.db, rows[0].id)), chunkBytes: CHUNK_BYTES });
  } catch (e) {
    if (/duplicate key|unique/i.test(e.message)) fail(409, "version_exists", `version ${version2} already exists`);
    throw e;
  }
}
async function uploadChunk(ctx) {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const seq = Number(ctx.params.seq);
  if (!Number.isInteger(seq) || seq < 0 || seq >= MAX_CHUNKS) fail(400, "invalid_request", "chunk number is out of range");
  const r = await getRelease(ctx.deps.db, id);
  if (r.source !== "upload") fail(409, "not_upload", "this release downloads from an external address");
  if (r.status === "published" || r.upload_complete) fail(409, "upload_closed", "the upload of this release is finished; create a new version to change the installer");
  const declared = Number(ctx.req.headers["content-length"] ?? 0);
  if (declared > CHUNK_BYTES) fail(413, "payload_too_large", `each piece may be at most ${CHUNK_BYTES} bytes`);
  const parts = [];
  let size = 0;
  for await (const c of ctx.req) {
    size += c.length;
    if (size > CHUNK_BYTES) {
      ctx.req.destroy();
      fail(413, "payload_too_large", `each piece may be at most ${CHUNK_BYTES} bytes`);
    }
    parts.push(c);
  }
  if (!size) fail(400, "invalid_request", "the piece is empty");
  await ctx.deps.db.query(
    `INSERT INTO desktop_release_chunks (release_id, seq, data) VALUES ($1, $2, $3)
     ON CONFLICT (release_id, seq) DO UPDATE SET data = EXCLUDED.data`,
    [id, seq, Buffer.concat(parts)]
  );
  sendJson(ctx.res, 200, { seq, bytes: size });
}
async function completeUpload(ctx) {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ["sha256"]);
  const expected = (str(body, "sha256", { max: 64, optional: true }) || "").toLowerCase();
  const r = await getRelease(ctx.deps.db, id);
  if (r.source !== "upload") fail(409, "not_upload", "this release downloads from an external address");
  const { rows } = await ctx.deps.db.query("SELECT seq, length(data)::int AS n FROM desktop_release_chunks WHERE release_id = $1 ORDER BY seq", [id]);
  if (!rows.length) fail(400, "upload_incomplete", "no installer was uploaded");
  rows.forEach((c, i) => {
    if (c.seq !== i) fail(400, "upload_incomplete", `piece ${i} is missing; upload it again`);
  });
  const hash = crypto7.createHash("sha256");
  let total = 0;
  for (const c of rows) {
    const part = await ctx.deps.db.query("SELECT data FROM desktop_release_chunks WHERE release_id = $1 AND seq = $2", [id, c.seq]);
    const buf = part.rows[0].data;
    total += buf.length;
    hash.update(buf);
  }
  const sha256 = hash.digest("hex");
  if (expected && expected !== sha256) fail(400, "checksum_mismatch", "the uploaded installer does not match the file you chose; upload it again");
  if (total > MAX_RELEASE_BYTES) fail(413, "payload_too_large", "the installer is too large");
  const head = await ctx.deps.db.query("SELECT substring(data from 1 for 2) AS h FROM desktop_release_chunks WHERE release_id = $1 AND seq = 0", [id]);
  const magic = head.rows[0]?.h?.toString("latin1") ?? "";
  if (magic !== "MZ") fail(400, "not_an_installer", "this file is not a Windows installer (.exe)");
  await ctx.deps.db.query("UPDATE desktop_releases SET sha256 = $2, file_size = $3, upload_complete = true WHERE id = $1", [id, sha256, total]);
  sendJson(ctx.res, 200, { release: view4(await getRelease(ctx.deps.db, id)) });
}
async function updateRelease(ctx) {
  const session = await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 32 * 1024));
  rejectUnknown(body, ["notes", "mandatory", "status"]);
  const r = await getRelease(ctx.deps.db, id);
  const notes = str(body, "notes", { max: 1e4, optional: true });
  const mandatory = bool(body, "mandatory", { optional: true });
  const status = str(body, "status", { max: 20, optional: true, pattern: /^(draft|published)$/ });
  if (status === "published" && r.status !== "published") {
    if (!r.upload_complete || !r.sha256) fail(409, "upload_incomplete", "upload the installer before publishing");
    requireReauth(session);
  }
  if (mandatory === true && !r.mandatory && (status ?? r.status) === "published") requireReauth(session);
  await ctx.deps.db.query(
    `UPDATE desktop_releases SET notes = coalesce($2, notes), mandatory = coalesce($3, mandatory), status = coalesce($4, status),
            published_at = CASE WHEN $4 = 'published' AND status <> 'published' THEN now() WHEN $4 = 'draft' THEN NULL ELSE published_at END
      WHERE id = $1`,
    [id, notes ?? null, mandatory ?? null, status ?? null]
  );
  forgetPublishedVersions();
  sendJson(ctx.res, 200, { release: view4(await getRelease(ctx.deps.db, id)) });
}
async function deleteRelease(ctx) {
  const session = await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const r = await getRelease(ctx.deps.db, id);
  if (r.status === "published") requireReauth(session);
  await ctx.deps.db.query("DELETE FROM desktop_releases WHERE id = $1", [id]);
  forgetPublishedVersions();
  sendJson(ctx.res, 200, { deleted: true });
}
async function checkForUpdate(ctx) {
  const device = await authenticateDevice(ctx, { central: false });
  const rl = await ctx.deps.limits.hit(`updates:check:${device.deviceId}`, CHECKS_PER_HOUR, 3600);
  if (!rl.allowed) fail(429, "rate_limited", "too many update checks; try again later", { "retry-after": String(rl.retryAfterSeconds) });
  const current = ctx.url.searchParams.get("current") ?? "";
  if (!VERSION2.test(current)) fail(400, "invalid_request", "current must be the installed version, for example 1.2.3");
  const { latest, mandatory } = await latestPublished(ctx.deps.db, current);
  if (!latest || compareVersions(latest.version, current) <= 0) {
    sendJson(ctx.res, 200, { update: null });
    return;
  }
  sendJson(ctx.res, 200, {
    update: {
      id: latest.id,
      version: latest.version,
      notes: latest.notes,
      mandatory,
      fileName: latest.file_name,
      size: Number(latest.file_size),
      sha256: latest.sha256,
      publishedAt: latest.published_at,
      download: latest.source === "url" ? latest.external_url : `/v1/updates/${latest.id}/download`
    }
  });
}
async function downloadUpdate(ctx) {
  const device = await authenticateDevice(ctx, { central: false });
  const rl = await ctx.deps.limits.hit(`updates:download:${device.deviceId}`, DOWNLOADS_PER_HOUR, 3600);
  if (!rl.allowed) fail(429, "rate_limited", "too many update downloads from this computer; try again later", { "retry-after": String(rl.retryAfterSeconds) });
  const id = uuidParam(ctx.params.id);
  const r = await getRelease(ctx.deps.db, id);
  if (r.status !== "published" || !r.upload_complete) fail(404, "not_found", "release not found");
  if (r.source !== "upload") fail(409, "external_download", "this release downloads from its external address");
  const { rows } = await ctx.deps.db.query("SELECT seq FROM desktop_release_chunks WHERE release_id = $1 ORDER BY seq", [id]);
  await ctx.deps.db.query("UPDATE desktop_releases SET downloads = downloads + 1 WHERE id = $1", [id]);
  ctx.res.writeHead(200, {
    "content-type": "application/octet-stream",
    "content-length": String(Number(r.file_size)),
    "content-disposition": `attachment; filename="${r.file_name.replace(/"/g, "")}"`,
    "x-content-sha256": r.sha256 ?? ""
  });
  for (const c of rows) {
    if (ctx.res.destroyed) return;
    const part = await ctx.deps.db.query("SELECT data FROM desktop_release_chunks WHERE release_id = $1 AND seq = $2", [id, c.seq]);
    const buf = part.rows[0]?.data;
    if (!buf) {
      ctx.res.destroy();
      return;
    }
    if (!ctx.res.write(buf)) await new Promise((resolve) => ctx.res.once("drain", () => resolve()));
  }
  ctx.res.end();
}

// src/modules/client-config.ts
var CLIENT_CONFIG_SCHEMA = 1;
var CLIENT_CONFIG_MAX_AGE_SECONDS = 7 * 24 * 3600;
var newest = (a, b) => !a ? b : !b ? a : compareVersions(a, b) >= 0 ? a : b;
function clientConfigBody(config, published = { latestVersion: null, minVersion: null }, overrides = { statusMessage: "", minVersion: "", downloadUrl: "", maintenance: false }) {
  return {
    schema: CLIENT_CONFIG_SCHEMA,
    instanceId: config.instanceId,
    apiOrigin: config.publicApiOrigin,
    apiVersions: ["v1"],
    desktop: {
      // The admin site's overrides win over both the environment and the published releases.
      minVersion: newest(config.desktop.minVersion, newest(published.minVersion, overrides.minVersion || null)),
      latestVersion: newest(config.desktop.latestVersion, published.latestVersion),
      downloadUrl: overrides.downloadUrl || config.desktop.downloadUrl
    },
    status: {
      // The admin site's notice replaces the environment notice (a non-empty override wins; both empty = none).
      message: overrides.statusMessage || config.desktop.statusMessage
    },
    features: {
      // Understood by desktops since the admin-features update: a short maintenance notice in the app.
      maintenance: overrides.maintenance === true
    },
    maxAgeSeconds: CLIENT_CONFIG_MAX_AGE_SECONDS
  };
}
async function clientConfigRoute(ctx) {
  ctx.res.setHeader("cache-control", "public, max-age=300");
  sendJson(
    ctx.res,
    200,
    clientConfigBody(ctx.deps.config, await publishedVersions(ctx.deps.db), await readDesktopConfig(ctx.deps.db))
  );
}
var cache = null;
async function publishedVersions(db) {
  if (cache && Date.now() - cache.at < 3e4) return cache.value;
  try {
    const p = await latestPublished(db);
    cache = { at: Date.now(), value: { latestVersion: p.latest?.version ?? null, minVersion: p.minVersion } };
  } catch {
    return cache?.value ?? { latestVersion: null, minVersion: null };
  }
  return cache.value;
}
function forgetPublishedVersions() {
  cache = null;
}

// src/modules/agents.ts
var LIMITS2 = { name: 80, description: 1024, instructions: 8e3, suggestedModel: 200 };
var ACCESS_LEVELS = ["read", "commands", "docs", "write", "write_commands"];
function slugify2(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "agent";
}
function view5(r) {
  return {
    id: r.id,
    slug: r.slug,
    name: r.name,
    description: r.description,
    instructions: r.instructions,
    access: r.access,
    suggestedModel: r.suggested_model,
    enabled: r.enabled,
    revision: r.revision,
    createdAt: r.created_at,
    updatedAt: r.updated_at
  };
}
async function bumpAgents(q) {
  await q.query("UPDATE settings SET value = to_jsonb((value::text::int) + 1), updated_at = now() WHERE key = 'agents_version'");
  await bumpCatalogue(q);
}
async function agentsVersion(db) {
  try {
    const { rows } = await db.query("SELECT (value)::text::int AS v FROM settings WHERE key = 'agents_version'");
    return rows[0]?.v ?? 0;
  } catch {
    return 0;
  }
}
function readAgent(body, partial) {
  const name = str(body, "name", { min: 1, max: LIMITS2.name, optional: partial });
  if (name !== void 0 && /[\r\n]/.test(name)) fail(400, "invalid_request", "the name must be a single line");
  const description = str(body, "description", { min: 1, max: LIMITS2.description, optional: partial });
  const instructions = str(body, "instructions", { min: 1, max: LIMITS2.instructions, optional: partial, trim: false });
  const access = body.access === void 0 ? void 0 : readAccess(body.access);
  let suggestedModel;
  if (body.suggestedModel !== void 0) {
    if (body.suggestedModel === null || body.suggestedModel === "") suggestedModel = null;
    else suggestedModel = str(body, "suggestedModel", { min: 1, max: LIMITS2.suggestedModel });
  }
  const enabled = bool(body, "enabled", { optional: true });
  return { name, description, instructions: instructions?.trim(), access, suggestedModel, enabled };
}
function readAccess(v) {
  if (typeof v !== "string" || !ACCESS_LEVELS.includes(v)) {
    fail(400, "invalid_request", `access must be one of: ${ACCESS_LEVELS.join(", ")}`);
  }
  return v;
}
async function listOrgAgents(ctx) {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query("SELECT * FROM org_agents ORDER BY name");
  sendJson(ctx.res, 200, { agents: rows.map(view5), version: await agentsVersion(ctx.deps.db), limits: LIMITS2, accessLevels: ACCESS_LEVELS });
}
async function createOrgAgent(ctx) {
  await guardOwner(ctx, { write: true });
  const body = requireObject(await readJson(ctx.req, 64 * 1024));
  rejectUnknown(body, ["name", "description", "instructions", "access", "suggestedModel", "enabled"]);
  const a = readAgent(body, false);
  if (a.access === void 0) fail(400, "invalid_request", "access is required");
  const id = await ctx.deps.db.transaction(async (q) => {
    let slug = slugify2(a.name);
    for (let i = 2; (await q.query("SELECT 1 FROM org_agents WHERE slug = $1", [slug])).rows.length; i++) slug = `${slugify2(a.name).slice(0, 55)}-${i}`;
    const { rows: rows2 } = await q.query(
      `INSERT INTO org_agents (slug, name, description, instructions, access, suggested_model, enabled) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [slug, a.name, a.description, a.instructions, a.access, a.suggestedModel ?? null, a.enabled ?? true]
    );
    await bumpAgents(q);
    return rows2[0].id;
  });
  const { rows } = await ctx.deps.db.query("SELECT * FROM org_agents WHERE id = $1", [id]);
  sendJson(ctx.res, 201, { agent: view5(rows[0]) });
}
async function updateOrgAgent(ctx) {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 64 * 1024));
  rejectUnknown(body, ["name", "description", "instructions", "access", "suggestedModel", "enabled"]);
  const a = readAgent(body, true);
  const sets = [];
  const vals = [id];
  const add = (col, v) => {
    vals.push(v);
    sets.push(`${col} = $${vals.length}`);
  };
  if (a.name !== void 0) add("name", a.name);
  if (a.description !== void 0) add("description", a.description);
  if (a.instructions !== void 0) add("instructions", a.instructions);
  if (a.access !== void 0) add("access", a.access);
  if (a.suggestedModel !== void 0) add("suggested_model", a.suggestedModel);
  if (a.enabled !== void 0) add("enabled", a.enabled);
  if (!sets.length) fail(400, "invalid_request", "nothing to change");
  await ctx.deps.db.transaction(async (q) => {
    const { rowCount } = await q.query(`UPDATE org_agents SET ${sets.join(", ")}, revision = revision + 1, updated_at = now() WHERE id = $1`, vals);
    if (!rowCount) fail(404, "not_found", "agent not found");
    await bumpAgents(q);
  });
  const { rows } = await ctx.deps.db.query("SELECT * FROM org_agents WHERE id = $1", [id]);
  sendJson(ctx.res, 200, { agent: view5(rows[0]) });
}
async function deleteOrgAgent(ctx) {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  await ctx.deps.db.transaction(async (q) => {
    const { rowCount } = await q.query("DELETE FROM org_agents WHERE id = $1", [id]);
    if (!rowCount) fail(404, "not_found", "agent not found");
    await bumpAgents(q);
  });
  sendJson(ctx.res, 200, { deleted: true });
}
async function desktopAgents(ctx) {
  await authenticateDevice(ctx);
  const version2 = await agentsVersion(ctx.deps.db);
  const etag = `"agents-${version2}"`;
  if (ctx.req.headers["if-none-match"] === etag) {
    ctx.res.writeHead(304, { etag, "cache-control": "no-store" });
    ctx.res.end();
    return;
  }
  const { rows } = await ctx.deps.db.query(
    "SELECT slug, name, description, instructions, access, suggested_model, revision, updated_at FROM org_agents WHERE enabled ORDER BY name"
  );
  sendJson(
    ctx.res,
    200,
    {
      version: version2,
      agents: rows.map((r) => ({ slug: r.slug, name: r.name, description: r.description, instructions: r.instructions, access: r.access, suggestedModel: r.suggested_model, revision: r.revision, updatedAt: r.updated_at }))
    },
    { etag }
  );
}

// src/app.ts
var R = (method, path2, handler) => ({ method, parts: path2.split("/").filter(Boolean), handler });
var routes = [
  R("GET", "/healthz", async (ctx) => sendJson(ctx.res, 200, { status: "ok" })),
  R("GET", "/readyz", readiness),
  R("GET", "/v1/client-config", clientConfigRoute),
  R("POST", "/v1/devices/register", registerDevice),
  R("GET", "/v1/device", deviceRoute),
  R("GET", "/v1/catalogue", catalogueRoute),
  R("GET", "/v1/catalogue/status", catalogueStatusRoute),
  R("GET", "/v1/models/:id", modelRoute),
  R("GET", "/v1/usage", deviceUsageRoute),
  R("POST", "/v1/chat/completions", chatCompletions),
  R("GET", "/v1/models", apiModelsRoute),
  R("POST", "/v1/memory/sync", syncMemories),
  R("POST", "/v1/search", search),
  R("GET", "/v1/skills", desktopSkills),
  R("GET", "/v1/agents", desktopAgents),
  R("GET", "/v1/updates/check", checkForUpdate),
  R("GET", "/v1/auth/config", authConfig),
  R("POST", "/v1/auth/session", createSession),
  R("POST", "/v1/auth/password-reset", resetPassword),
  R("POST", "/v1/auth/oauth/start", oauthStart),
  R("GET", "/v1/auth/oauth/callback", oauthCallback),
  R("POST", "/v1/auth/exchange", exchange),
  R("POST", "/v1/auth/refresh", refresh),
  R("POST", "/v1/auth/logout", logout2),
  R("GET", "/v1/account", account),
  R("POST", "/v1/account/devices/:id/sign-out", signOutDevice),
  R("POST", "/v1/account/delete", deleteAccount),
  R("GET", "/v1/updates/:id/download", downloadUpdate),
  R("POST", "/admin/api/auth/login", login),
  R("GET", "/admin/api/auth/session", sessionInfo),
  R("POST", "/admin/api/auth/logout", logout),
  R("POST", "/admin/api/auth/reauth", reauth),
  R("GET", "/admin/api/overview", overview),
  R("GET", "/admin/api/health", adminHealth),
  R("GET", "/admin/api/providers", listProviders),
  R("POST", "/admin/api/providers", createProvider),
  R("PATCH", "/admin/api/providers/:id", updateProvider),
  R("DELETE", "/admin/api/providers/:id", deleteProvider),
  R("PUT", "/admin/api/providers/:id/api-key", setProviderKey),
  R("DELETE", "/admin/api/providers/:id/api-key", clearProviderKey),
  R("POST", "/admin/api/providers/:id/test", testProvider),
  R("POST", "/admin/api/providers/:id/discover", discoverModels),
  R("GET", "/admin/api/models", listModels),
  R("POST", "/admin/api/models", createModel),
  R("PATCH", "/admin/api/models/:id", updateModel),
  R("POST", "/admin/api/models/:id/default", setDefaultModel),
  R("DELETE", "/admin/api/models/:id", deleteModel),
  R("GET", "/admin/api/devices", listDevices),
  R("POST", "/admin/api/devices/:id/revoke", revokeDevice),
  R("POST", "/admin/api/devices/:id/unblock", unblockDevice),
  R("GET", "/admin/api/devices/:id/models", getDeviceModels),
  R("PUT", "/admin/api/devices/:id/models", putDeviceModels),
  R("GET", "/admin/api/usage", usage),
  R("GET", "/admin/api/logs", logs),
  R("GET", "/admin/api/memory", adminListMemory),
  R("DELETE", "/admin/api/memory", adminClearAllMemory),
  R("DELETE", "/admin/api/memory/:id", adminClearDeviceMemory),
  R("GET", "/admin/api/releases", listReleases),
  R("POST", "/admin/api/releases", createRelease),
  R("PUT", "/admin/api/releases/:id/chunks/:seq", uploadChunk),
  R("POST", "/admin/api/releases/:id/complete", completeUpload),
  R("PATCH", "/admin/api/releases/:id", updateRelease),
  R("DELETE", "/admin/api/releases/:id", deleteRelease),
  R("GET", "/admin/api/search-providers", listSearchProviders),
  R("POST", "/admin/api/search-providers", createSearchProvider),
  R("PATCH", "/admin/api/search-providers/:id", updateSearchProvider),
  R("DELETE", "/admin/api/search-providers/:id", deleteSearchProvider),
  R("PUT", "/admin/api/search-providers/:id/api-key", setSearchProviderKey),
  R("DELETE", "/admin/api/search-providers/:id/api-key", clearSearchProviderKey),
  R("POST", "/admin/api/search-providers/:id/test", testSearchProvider),
  R("GET", "/admin/api/skills", listOrgSkills),
  R("POST", "/admin/api/skills", createOrgSkill),
  R("PATCH", "/admin/api/skills/:id", updateOrgSkill),
  R("DELETE", "/admin/api/skills/:id", deleteOrgSkill),
  R("GET", "/admin/api/users", adminListUsers),
  R("GET", "/admin/api/users/:id/activity", adminUserActivity),
  R("GET", "/admin/api/users/:id", adminGetUser),
  R("POST", "/admin/api/users/:id/:action", adminUserAction),
  R("GET", "/admin/api/settings", getSettings),
  R("PATCH", "/admin/api/settings", patchSettings),
  R("GET", "/admin/api/api-keys", listApiKeys),
  R("POST", "/admin/api/api-keys", createApiKey),
  R("PATCH", "/admin/api/api-keys/:id", updateApiKey),
  R("DELETE", "/admin/api/api-keys/:id", deleteApiKey),
  R("GET", "/admin/api/agents", listOrgAgents),
  R("POST", "/admin/api/agents", createOrgAgent),
  R("PATCH", "/admin/api/agents/:id", updateOrgAgent),
  R("DELETE", "/admin/api/agents/:id", deleteOrgAgent),
  R("GET", "/admin/api/desktop-config", getDesktopConfig),
  R("PATCH", "/admin/api/desktop-config", patchDesktopConfig)
];
function match(route, pathname) {
  const segs = pathname.split("/").filter(Boolean);
  if (segs.length !== route.parts.length) return null;
  const params = {};
  for (let i = 0; i < segs.length; i++) {
    const p = route.parts[i];
    if (p.startsWith(":")) {
      try {
        params[p.slice(1)] = decodeURIComponent(segs[i]);
      } catch {
        return null;
      }
    } else if (p !== segs[i]) return null;
  }
  return params;
}
async function readiness(ctx) {
  let schemaVersion;
  try {
    await ctx.deps.db.query("SELECT 1");
    const s = await migrationStatus(ctx.deps.db);
    if (s.pending.length) {
      sendJson(ctx.res, 503, { status: "not_ready", reason: "database migrations are pending" });
      return;
    }
    schemaVersion = s.currentVersion;
  } catch {
    sendJson(ctx.res, 503, { status: "not_ready", reason: "database is unavailable" });
    return;
  }
  if (ctx.deps.redis) {
    try {
      await ctx.deps.redis.ping();
    } catch {
      sendJson(ctx.res, 503, { status: "not_ready", reason: "redis is unavailable" });
      return;
    }
  }
  sendJson(ctx.res, 200, { status: "ready", schemaVersion });
}
function applySecurityHeaders(req, res, deps) {
  res.setHeader("x-content-type-options", "nosniff");
  res.setHeader("referrer-policy", "no-referrer");
  res.setHeader("x-frame-options", "DENY");
  if (deps.config.cookieSecure) res.setHeader("strict-transport-security", "max-age=31536000");
  const path2 = (req.url ?? "").split("?")[0];
  if (path2.startsWith("/admin/api") || path2.startsWith("/v1")) res.setHeader("cache-control", "no-store");
}
function applyCors(req, res, deps) {
  const origin2 = req.headers.origin;
  if (!origin2) return true;
  res.setHeader("vary", "Origin");
  if (!deps.config.adminOrigin || origin2 !== deps.config.adminOrigin) return false;
  res.setHeader("access-control-allow-origin", origin2);
  res.setHeader("access-control-allow-credentials", "true");
  if (req.method === "OPTIONS") {
    res.setHeader("access-control-allow-methods", "GET, POST, PUT, PATCH, DELETE");
    res.setHeader("access-control-allow-headers", "content-type, x-csrf-token");
    res.setHeader("access-control-max-age", "600");
  }
  return true;
}
function createHandler(input) {
  const deps = {
    ...input,
    limits: input.limits ?? new DatabaseLimitStore(input.db),
    redis: input.redis ?? null,
    pocketbase: input.pocketbase !== void 0 ? input.pocketbase : input.config.pocketbase ? new PocketBase(input.config.pocketbase, input.fetch) : null
  };
  return async (req, res) => {
    const requestId = crypto8.randomUUID();
    const started = Date.now();
    let routeName = "unmatched";
    res.setHeader("x-request-id", requestId);
    applySecurityHeaders(req, res, deps);
    const corsOk = applyCors(req, res, deps);
    res.on("finish", () => {
      log("info", "request", { requestId, method: req.method ?? "UNKNOWN", route: routeName, status: res.statusCode, latencyMs: Date.now() - started });
    });
    try {
      const url = new URL(req.url ?? "/", "http://internal");
      if (req.method === "OPTIONS") {
        if (!corsOk) sendError(res, new HttpError(403, "forbidden", "origin not allowed"));
        else {
          res.writeHead(204);
          res.end();
        }
        return;
      }
      let matched = null;
      let pathExists = false;
      for (const route of routes) {
        const params = match(route, url.pathname);
        if (!params) continue;
        pathExists = true;
        if (route.method === req.method) {
          matched = { route, params };
          break;
        }
      }
      if (!matched) {
        if (pathExists) throw new HttpError(405, "method_not_allowed", "method not allowed");
        throw new HttpError(404, "not_found", "not found");
      }
      routeName = `${req.method} /${matched.route.parts.join("/")}`;
      if (req.url && req.url.length > 4096) throw new HttpError(414, "uri_too_long", "the address is too long");
      const ip = clientAddress(req, deps.config.trustProxy);
      await matched.route.handler({ req, res, url, params: matched.params, ip, requestId, deps });
    } catch (e) {
      if (res.headersSent) {
        if (!res.writableEnded) res.end();
        return;
      }
      if (e instanceof HttpError) {
        sendError(res, e);
        return;
      }
      if (e instanceof RedisUnavailableError) {
        log("error", "redis unavailable", { requestId, method: req.method, route: routeName, reason: e.code });
        sendError(res, new HttpError(503, "service_unavailable", "a required service is temporarily unavailable; try again shortly", { "retry-after": "5" }));
        return;
      }
      log("error", "request failed", { requestId, method: req.method, route: routeName, error: e instanceof Error ? e.name : "unknown" });
      sendError(res, new HttpError(500, "internal_error", "something went wrong; try again"));
    }
  };
}
function createServer(deps) {
  const server = http.createServer(createHandler(deps));
  server.requestTimeout = deps.config.requestTimeoutMs;
  server.headersTimeout = deps.config.headersTimeoutMs;
  server.keepAliveTimeout = 65e3;
  return server;
}

// src/config.ts
import fs3 from "node:fs";
import crypto9 from "node:crypto";
function bool2(v, fallback) {
  if (v === void 0 || v === "") return fallback;
  if (["1", "true", "yes", "on"].includes(v.toLowerCase())) return true;
  if (["0", "false", "no", "off"].includes(v.toLowerCase())) return false;
  throw new Error(`expected true or false, got "${v}"`);
}
function int2(v, fallback, min, max, name) {
  if (v === void 0 || v === "") return fallback;
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) throw new Error(`${name} must be an integer from ${min} to ${max}`);
  return n;
}
var LOOPBACK2 = /* @__PURE__ */ new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
function origin(v, name, production = false, ignored = []) {
  if (!v) return null;
  let u;
  try {
    u = new URL(v);
  } catch {
    throw new Error(`${name} must be a URL such as https://admin.YOUR_DOMAIN`);
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error(`${name} must start with https://`);
  if (u.username || u.password) throw new Error(`${name} must not contain credentials`);
  if (u.pathname !== "/" || u.search || u.hash) throw new Error(`${name} must be an origin without a path`);
  if (!production && /YOUR_DOMAIN/i.test(u.hostname)) {
    ignored.push(`${name} still contains the YOUR_DOMAIN placeholder and is ignored; set a real address or remove the line`);
    return null;
  }
  if (production) {
    if (u.protocol !== "https:") throw new Error(`${name} must use https in production`);
    if (LOOPBACK2.has(u.hostname) || u.hostname.endsWith(".localhost")) throw new Error(`${name} must not be a local address in production`);
    if (/YOUR_DOMAIN/i.test(u.hostname)) throw new Error(`${name} still contains the YOUR_DOMAIN placeholder`);
  }
  return u.origin;
}
function httpsUrl(v, name) {
  if (!v) return null;
  let u;
  try {
    u = new URL(v);
  } catch {
    throw new Error(`${name} must be an https URL`);
  }
  if (u.protocol !== "https:" || u.username || u.password) throw new Error(`${name} must be an https URL without credentials`);
  return u.toString();
}
function version(v, name) {
  if (!v) return null;
  if (!/^\d+\.\d+\.\d+$/.test(v)) throw new Error(`${name} must look like 1.2.3`);
  return v;
}
function environment(env) {
  const devora = env.DEVORA_ENV;
  if (devora && !["development", "production"].includes(devora)) throw new Error("DEVORA_ENV must be development or production");
  if (devora === "development" && env.NODE_ENV === "production") {
    throw new Error("DEVORA_ENV=development conflicts with NODE_ENV=production; set DEVORA_ENV=production on a server");
  }
  return devora === "production" || env.NODE_ENV === "production" ? "production" : "development";
}
function instanceId(env, keyring) {
  const explicit = env.DEVORA_INSTANCE_ID;
  if (explicit) {
    if (!/^[A-Za-z0-9_-]{8,64}$/.test(explicit)) throw new Error("DEVORA_INSTANCE_ID must be 8 to 64 letters, digits, _ or -");
    return explicit;
  }
  const first = [...keyring.keys.keys()].sort((a, b) => a - b)[0];
  if (first === void 0) return "development";
  return crypto9.createHmac("sha256", keyring.keys.get(first)).update("devora-instance-id").digest("hex").slice(0, 32);
}
function parseDatabase(env, production) {
  const sslDefault = production ? "require" : "disable";
  let cfg;
  if (env.DATABASE_URL) {
    const u = new URL(env.DATABASE_URL);
    if (u.protocol !== "postgres:" && u.protocol !== "postgresql:") throw new Error("DATABASE_URL must start with postgres://");
    cfg = {
      host: decodeURIComponent(u.hostname),
      port: u.port ? Number(u.port) : 5432,
      user: decodeURIComponent(u.username),
      password: decodeURIComponent(u.password),
      database: decodeURIComponent(u.pathname.replace(/^\//, "")),
      ssl: sslDefault
    };
    const mode = u.searchParams.get("sslmode");
    if (mode) {
      if (mode === "disable") cfg.ssl = "disable";
      else if (["require", "verify-ca", "verify-full"].includes(mode)) cfg.ssl = "require";
      else throw new Error(`sslmode=${mode} is not supported; use disable or require`);
    }
  } else {
    cfg = {
      host: env.DATABASE_HOST ?? "",
      port: Number(env.DATABASE_PORT ?? 5432),
      user: env.DATABASE_USER ?? "",
      password: env.DATABASE_PASSWORD ?? "",
      database: env.DATABASE_NAME ?? "",
      ssl: sslDefault
    };
  }
  if (env.DATABASE_SSL) {
    if (env.DATABASE_SSL !== "disable" && env.DATABASE_SSL !== "require") throw new Error("DATABASE_SSL must be disable or require");
    cfg.ssl = env.DATABASE_SSL;
  }
  if (!cfg.host || !cfg.user || !cfg.database) throw new Error("set DATABASE_URL, or DATABASE_HOST, DATABASE_USER, DATABASE_NAME and DATABASE_PASSWORD");
  if (!Number.isInteger(cfg.port) || cfg.port < 1 || cfg.port > 65535) throw new Error("database port is invalid");
  if (env.DATABASE_CA_FILE) {
    if (!fs3.existsSync(env.DATABASE_CA_FILE)) throw new Error("DATABASE_CA_FILE does not exist");
    cfg.caFile = env.DATABASE_CA_FILE;
  }
  if (production && cfg.ssl === "disable" && !env.DATABASE_ALLOW_PLAINTEXT_NETWORK) {
    throw new Error("production requires DATABASE_SSL=require, or DATABASE_ALLOW_PLAINTEXT_NETWORK=true when the database is on a private network only");
  }
  return cfg;
}
function pocketbase(env, production) {
  const raw = (env.POCKETBASE_URL ?? "").trim();
  const email = (env.POCKETBASE_ADMIN_EMAIL ?? "").trim();
  const password = env.POCKETBASE_ADMIN_PASSWORD ?? "";
  if (!raw) {
    if (email || password) throw new Error("POCKETBASE_ADMIN_EMAIL/POCKETBASE_ADMIN_PASSWORD are set but POCKETBASE_URL is not");
    return null;
  }
  let u;
  try {
    u = new URL(raw);
  } catch {
    throw new Error("POCKETBASE_URL must be a URL such as https://pocketbase.YOUR_DOMAIN");
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("POCKETBASE_URL must start with https://");
  if (u.username || u.password || u.search || u.hash) throw new Error("POCKETBASE_URL must not contain credentials, a query or a fragment");
  if (production && u.protocol !== "https:") throw new Error("POCKETBASE_URL must use https in production");
  if (!email || !password) throw new Error("POCKETBASE_URL needs POCKETBASE_ADMIN_EMAIL and POCKETBASE_ADMIN_PASSWORD (a superuser dedicated to this server)");
  if (production && password.length < 12) throw new Error("POCKETBASE_ADMIN_PASSWORD is too short for production");
  const usersCollection = (env.POCKETBASE_USERS_COLLECTION ?? "").trim() || "users";
  if (!/^[A-Za-z0-9_]{1,64}$/.test(usersCollection)) throw new Error("POCKETBASE_USERS_COLLECTION must be a collection name");
  return { url: u.toString().replace(/\/+$/, ""), usersCollection, adminEmail: email, adminPassword: password };
}
function redisPrefix(v) {
  if (v === void 0 || v === "") return "devora";
  if (!/^[A-Za-z0-9_.-]{1,40}$/.test(v)) throw new Error("REDIS_KEY_PREFIX may contain only letters, digits, _ . - (up to 40)");
  return v;
}
function loadConfig(env = process.env) {
  const production = environment(env) === "production";
  const cookieSecure = bool2(env.COOKIE_SECURE, production);
  if (production && !cookieSecure) throw new Error("COOKIE_SECURE must be true in production");
  const keyring = parseKeyring(env.DEVORA_SECRET_KEYS ?? "", env.DEVORA_SECRET_ACTIVE_KEY ?? "");
  if (production && keyring.size === 0) throw new Error("DEVORA_SECRET_KEYS is required in production");
  const ignoredSettings = [];
  const adminOrigin = origin(env.ADMIN_ORIGIN, "ADMIN_ORIGIN", production, ignoredSettings);
  if (production && !adminOrigin) throw new Error("ADMIN_ORIGIN is required in production (the https address of the admin website)");
  const statusMessage = (env.DEVORA_STATUS_MESSAGE ?? "").trim();
  if (statusMessage.length > 200) throw new Error("DEVORA_STATUS_MESSAGE may be at most 200 characters");
  const headersTimeoutMs = int2(env.HEADERS_TIMEOUT_MS, 3e4, 1e3, 12e4, "HEADERS_TIMEOUT_MS");
  const requestTimeoutMs = int2(env.REQUEST_TIMEOUT_MS, 3e5, 1e4, 36e5, "REQUEST_TIMEOUT_MS");
  if (requestTimeoutMs <= headersTimeoutMs) throw new Error("REQUEST_TIMEOUT_MS must be larger than HEADERS_TIMEOUT_MS");
  return {
    env: production ? "production" : "development",
    host: env.HOST || "0.0.0.0",
    port: int2(env.PORT, 8080, 1, 65535, "PORT"),
    database: parseDatabase(env, production),
    poolSize: int2(env.DATABASE_POOL_SIZE, 10, 1, 50, "DATABASE_POOL_SIZE"),
    adminOrigin,
    cookieSecure,
    trustProxy: bool2(env.TRUST_PROXY, false),
    keyring,
    logRetentionDays: int2(env.DEVORA_LOG_RETENTION_DAYS, 30, 1, 3650, "DEVORA_LOG_RETENTION_DAYS"),
    publicApiOrigin: origin(env.PUBLIC_API_ORIGIN, "PUBLIC_API_ORIGIN", production, ignoredSettings),
    redis: env.REDIS_URL ? parseRedisUrl(env.REDIS_URL, env) : null,
    redisKeyPrefix: redisPrefix(env.REDIS_KEY_PREFIX),
    discoveryIntervalHours: int2(env.DEVORA_DISCOVERY_INTERVAL_HOURS, 12, 0, 168, "DEVORA_DISCOVERY_INTERVAL_HOURS"),
    ignoredSettings,
    requestTimeoutMs,
    headersTimeoutMs,
    desktop: {
      minVersion: version(env.DEVORA_DESKTOP_MIN_VERSION, "DEVORA_DESKTOP_MIN_VERSION"),
      latestVersion: version(env.DEVORA_DESKTOP_LATEST_VERSION, "DEVORA_DESKTOP_LATEST_VERSION"),
      downloadUrl: httpsUrl(env.DEVORA_DESKTOP_DOWNLOAD_URL, "DEVORA_DESKTOP_DOWNLOAD_URL"),
      statusMessage
    },
    instanceId: instanceId(env, keyring),
    pocketbase: pocketbase(env, production)
  };
}
function configWarnings(c) {
  const out = [...c.ignoredSettings];
  if (c.env === "production" && !c.publicApiOrigin) out.push("PUBLIC_API_ORIGIN is not set: desktop apps cannot be moved to a new API domain automatically");
  if (c.env === "production" && !c.trustProxy) out.push("TRUST_PROXY is false: behind Dokploy/Traefik every request appears to come from the proxy");
  if (c.pocketbase && !c.publicApiOrigin) out.push("PUBLIC_API_ORIGIN is not set: Google/GitHub sign-in is off because it needs the public callback address");
  if (c.env === "production" && !c.redis) out.push("REDIS_URL is not set: rate limits use PostgreSQL and there is no cache");
  return out;
}
function redactedConfig(c) {
  return {
    env: c.env,
    host: c.host,
    port: c.port,
    database: `${c.database.host}:${c.database.port}/${c.database.database} (ssl ${c.database.ssl})`,
    adminOrigin: c.adminOrigin,
    publicApiOrigin: c.publicApiOrigin,
    cookieSecure: c.cookieSecure,
    trustProxy: c.trustProxy,
    encryptionKeys: c.keyring.size,
    redis: c.redis ? `${c.redis.host}:${c.redis.port}/${c.redis.db}${c.redis.tls ? " (tls)" : ""}` : null,
    requestTimeoutMs: c.requestTimeoutMs,
    desktopMinVersion: c.desktop.minVersion,
    pocketbase: c.pocketbase ? `${c.pocketbase.url} (collection ${c.pocketbase.usersCollection})` : null
  };
}

// src/db/pg-wire.ts
import crypto10 from "node:crypto";
import net2 from "node:net";
import tls2 from "node:tls";
import fs4 from "node:fs";
var PgError = class extends Error {
  code;
  detail;
  constructor(message, code = "", detail) {
    super(message);
    this.name = "PgError";
    this.code = code;
    this.detail = detail;
  }
};
var OID = { bool: 16, bytea: 17, int8: 20, int2: 21, int4: 23, json: 114, float4: 700, float8: 701, numeric: 1700, timestamp: 1114, timestamptz: 1184, jsonb: 3802 };
function decodeValue(oid, text) {
  if (text === null) return null;
  switch (oid) {
    case OID.bool:
      return text === "t";
    case OID.int2:
    case OID.int4:
    case OID.int8:
    case OID.float4:
    case OID.float8:
    case OID.numeric:
      return Number(text);
    case OID.json:
    case OID.jsonb:
      return JSON.parse(text);
    case OID.bytea:
      return text.startsWith("\\x") ? Buffer.from(text.slice(2), "hex") : Buffer.from(text);
    case OID.timestamp:
    case OID.timestamptz:
      return parseTimestamp(text);
    default:
      return text;
  }
}
function parseTimestamp(text) {
  let t = text.replace(" ", "T");
  t = t.replace(/(\.\d{3})\d+/, "$1");
  if (/[+-]\d{2}$/.test(t)) t += ":00";
  else if (!/(Z|[+-]\d{2}:\d{2})$/.test(t)) t += "Z";
  return new Date(t);
}
function encodeParam(v) {
  if (v === null || v === void 0) return null;
  if (typeof v === "boolean") return Buffer.from(v ? "true" : "false", "utf8");
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new PgError("non-finite number parameter");
    return Buffer.from(String(v), "utf8");
  }
  if (Buffer.isBuffer(v)) return Buffer.from(`\\x${v.toString("hex")}`, "utf8");
  if (v instanceof Date) return Buffer.from(v.toISOString(), "utf8");
  if (typeof v === "object") return Buffer.from(JSON.stringify(v), "utf8");
  return Buffer.from(String(v), "utf8");
}
function cstr(s) {
  return Buffer.concat([Buffer.from(s, "utf8"), Buffer.of(0)]);
}
function int16(n) {
  const b = Buffer.alloc(2);
  b.writeInt16BE(n, 0);
  return b;
}
function int32(n) {
  const b = Buffer.alloc(4);
  b.writeInt32BE(n, 0);
  return b;
}
function frame(type, body) {
  return Buffer.concat([Buffer.from(type, "ascii"), int32(body.length + 4), body]);
}
function parseError(body) {
  const fields = {};
  let i = 0;
  while (i < body.length && body[i] !== 0) {
    const code = String.fromCharCode(body[i]);
    const end = body.indexOf(0, i + 1);
    fields[code] = body.toString("utf8", i + 1, end);
    i = end + 1;
  }
  return new PgError(fields.M ?? "database error", fields.C ?? "", fields.D);
}
function hmac(key, data) {
  return crypto10.createHmac("sha256", key).update(data).digest();
}
var PgConnection = class _PgConnection {
  socket;
  buf = Buffer.alloc(0);
  inbox = [];
  waiters = [];
  failure = null;
  busy = false;
  /** True once the socket failed; the pool then discards the connection. */
  broken = false;
  static async connect(cfg) {
    const conn = new _PgConnection();
    await conn.open(cfg);
    return conn;
  }
  async open(cfg) {
    const raw = await new Promise((resolve, reject) => {
      const s = net2.connect({ host: cfg.host, port: cfg.port });
      const timer = setTimeout(() => {
        s.destroy();
        reject(new PgError(`connection to database timed out after ${cfg.connectTimeoutMs ?? 1e4} ms`));
      }, cfg.connectTimeoutMs ?? 1e4);
      s.once("connect", () => {
        clearTimeout(timer);
        resolve(s);
      });
      s.once("error", (e) => {
        clearTimeout(timer);
        reject(new PgError(`cannot reach the database: ${e.message}`));
      });
    });
    let sock = raw;
    if (cfg.ssl === "require") {
      raw.write(Buffer.concat([int32(8), int32(80877103)]));
      const answer = await new Promise((resolve, reject) => {
        raw.once("data", (d) => resolve(d.toString("ascii", 0, 1)));
        raw.once("error", reject);
      });
      if (answer !== "S") throw new PgError("the database does not offer TLS, but DATABASE_SSL=require");
      sock = await new Promise((resolve, reject) => {
        const t = tls2.connect({
          socket: raw,
          servername: cfg.host,
          rejectUnauthorized: true,
          ca: cfg.caFile ? fs4.readFileSync(cfg.caFile) : void 0
        });
        t.once("secureConnect", () => resolve(t));
        t.once("error", (e) => reject(new PgError(`TLS to the database failed: ${e.message}`)));
      });
    }
    this.socket = sock;
    this.attach();
    const params = {
      user: cfg.user,
      database: cfg.database,
      application_name: "devora-server",
      timezone: "UTC",
      statement_timeout: String(cfg.statementTimeoutMs ?? 3e4),
      client_encoding: "UTF8"
    };
    const kv = Buffer.concat(Object.entries(params).flatMap(([k, v]) => [cstr(k), cstr(v)]));
    const body = Buffer.concat([int32(196608), kv, Buffer.of(0)]);
    this.socket.write(Buffer.concat([int32(body.length + 4), body]));
    for (; ; ) {
      const m = await this.next();
      if (m.type === "R") {
        const code = m.body.readInt32BE(0);
        if (code === 0) continue;
        if (code === 10) {
          const mechs = m.body.toString("utf8", 4).split("\0").filter(Boolean);
          if (!mechs.includes("SCRAM-SHA-256")) throw new PgError("the database requires an authentication method this server does not support");
          await this.scram(cfg.password);
          continue;
        }
        throw new PgError(`unsupported authentication method (${code}); the server requires SCRAM-SHA-256`);
      }
      if (m.type === "E") throw parseError(m.body);
      if (m.type === "Z") break;
    }
  }
  attach() {
    this.socket.on("data", (d) => {
      this.buf = this.buf.length ? Buffer.concat([this.buf, d]) : d;
      while (this.buf.length >= 5) {
        const len = this.buf.readInt32BE(1);
        if (this.buf.length < len + 1) break;
        const msg = { type: String.fromCharCode(this.buf[0]), body: this.buf.subarray(5, len + 1) };
        this.buf = this.buf.subarray(len + 1);
        const w = this.waiters.shift();
        if (w) w.resolve(msg);
        else this.inbox.push(msg);
      }
    });
    const fail2 = (e) => {
      this.broken = true;
      this.failure = this.failure ?? e;
      for (const w of this.waiters.splice(0)) w.reject(this.failure);
    };
    this.socket.on("error", (e) => fail2(new PgError(`database connection failed: ${e.message}`)));
    this.socket.on("close", () => fail2(new PgError("database connection closed")));
  }
  next() {
    const m = this.inbox.shift();
    if (m) return Promise.resolve(m);
    if (this.failure) return Promise.reject(this.failure);
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
  }
  async scram(password) {
    const nonce = crypto10.randomBytes(18).toString("base64");
    const clientFirstBare = `n=,r=${nonce}`;
    const initial = Buffer.from(`n,,${clientFirstBare}`, "utf8");
    this.socket.write(frame("p", Buffer.concat([cstr("SCRAM-SHA-256"), int32(initial.length), initial])));
    const first = await this.next();
    if (first.type === "E") throw parseError(first.body);
    if (first.type !== "R" || first.body.readInt32BE(0) !== 11) throw new PgError("unexpected reply during authentication");
    const serverFirst = first.body.toString("utf8", 4);
    const attrs = Object.fromEntries(serverFirst.split(",").map((p) => [p[0], p.slice(2)]));
    if (!attrs.r?.startsWith(nonce) || !attrs.s || !attrs.i) throw new PgError("invalid SCRAM challenge from the database");
    const iterations = Number(attrs.i);
    if (!Number.isInteger(iterations) || iterations < 4096 || iterations > 1e6) throw new PgError("unacceptable SCRAM iteration count");
    const salted = await new Promise(
      (resolve, reject) => crypto10.pbkdf2(password, Buffer.from(attrs.s, "base64"), iterations, 32, "sha256", (e, k) => e ? reject(e) : resolve(k))
    );
    const clientKey = hmac(salted, "Client Key");
    const storedKey = crypto10.createHash("sha256").update(clientKey).digest();
    const clientFinalNoProof = `c=biws,r=${attrs.r}`;
    const authMessage = `${clientFirstBare},${serverFirst},${clientFinalNoProof}`;
    const signature = hmac(storedKey, authMessage);
    const proof = Buffer.alloc(clientKey.length);
    for (let i = 0; i < proof.length; i++) proof[i] = clientKey[i] ^ signature[i];
    const clientFinal = Buffer.from(`${clientFinalNoProof},p=${proof.toString("base64")}`, "utf8");
    this.socket.write(frame("p", clientFinal));
    const last = await this.next();
    if (last.type === "E") throw parseError(last.body);
    if (last.type !== "R" || last.body.readInt32BE(0) !== 12) throw new PgError("password authentication failed");
    const serverKey = hmac(salted, "Server Key");
    const expected = hmac(serverKey, authMessage).toString("base64");
    const got = last.body.toString("utf8", 4).replace(/^v=/, "");
    if (got !== expected) throw new PgError("the database failed to prove its identity (SCRAM)");
  }
  async begin() {
    if (this.busy) throw new PgError("connection is already running a query");
    this.busy = true;
  }
  /** Runs one parameterized statement with the extended protocol. Parameters are text values; SQL never contains them. */
  async query(sql, params = []) {
    await this.begin();
    try {
      const values = params.map(encodeParam);
      const bind = [
        cstr(""),
        cstr(""),
        int16(0),
        int16(values.length),
        ...values.flatMap((v) => v === null ? [int32(-1)] : [int32(v.length), v]),
        int16(0)
      ];
      this.socket.write(
        Buffer.concat([
          frame("P", Buffer.concat([cstr(""), cstr(sql), int16(0)])),
          frame("B", Buffer.concat(bind)),
          frame("D", Buffer.concat([Buffer.from("P", "ascii"), cstr("")])),
          frame("E", Buffer.concat([cstr(""), int32(0)])),
          frame("S", Buffer.alloc(0))
        ])
      );
      return await this.readResult();
    } finally {
      this.busy = false;
    }
  }
  /** Runs one or more statements with the simple protocol (no parameters). Used for migrations and transaction control. */
  async exec(sql) {
    await this.begin();
    try {
      this.socket.write(frame("Q", cstr(sql)));
      await this.readResult();
    } finally {
      this.busy = false;
    }
  }
  async readResult() {
    let cols = [];
    const rows = [];
    let rowCount = 0;
    let error = null;
    for (; ; ) {
      const m = await this.next();
      switch (m.type) {
        case "T": {
          const n = m.body.readInt16BE(0);
          cols = [];
          let p = 2;
          for (let i = 0; i < n; i++) {
            const end = m.body.indexOf(0, p);
            const name = m.body.toString("utf8", p, end);
            p = end + 1;
            const oid = m.body.readInt32BE(p + 6);
            p += 18;
            cols.push({ name, oid });
          }
          break;
        }
        case "D": {
          const n = m.body.readInt16BE(0);
          const row = {};
          let p = 2;
          for (let i = 0; i < n; i++) {
            const len = m.body.readInt32BE(p);
            p += 4;
            const text = len === -1 ? null : m.body.toString("utf8", p, p + len);
            if (len !== -1) p += len;
            const col = cols[i];
            row[col.name] = decodeValue(col.oid, text);
          }
          rows.push(row);
          break;
        }
        case "C": {
          const tag = m.body.toString("utf8", 0, m.body.indexOf(0));
          const n = Number(tag.split(" ").pop());
          if (Number.isFinite(n)) rowCount = n;
          break;
        }
        case "E":
          error = parseError(m.body);
          break;
        case "Z":
          if (error) throw error;
          return { rows, rowCount: rowCount || rows.length };
        default:
          break;
      }
    }
  }
  close() {
    try {
      this.socket.end(frame("X", Buffer.alloc(0)));
    } catch {
    }
    this.socket.destroy();
  }
};
var Db = class {
  constructor(cfg, max = 10) {
    this.cfg = cfg;
    this.max = max;
  }
  cfg;
  max;
  idle = [];
  total = 0;
  waiters = [];
  closed = false;
  async acquire() {
    if (this.closed) throw new PgError("database pool is closed");
    const c = this.idle.pop();
    if (c) return c;
    if (this.total < this.max) {
      this.total++;
      try {
        return await PgConnection.connect(this.cfg);
      } catch (e) {
        this.total--;
        throw e;
      }
    }
    return new Promise((resolve) => this.waiters.push(resolve));
  }
  release(c) {
    if (c.broken) {
      this.total--;
      c.close();
      const w2 = this.waiters.shift();
      if (w2) void this.acquire().then(w2);
      return;
    }
    const w = this.waiters.shift();
    if (w) w(c);
    else this.idle.push(c);
  }
  async query(sql, params = []) {
    const c = await this.acquire();
    try {
      return await c.query(sql, params);
    } finally {
      this.release(c);
    }
  }
  async transaction(fn) {
    const c = await this.acquire();
    try {
      await c.exec("BEGIN");
      try {
        const out = await fn(c);
        await c.exec("COMMIT");
        return out;
      } catch (e) {
        if (!c.broken) await c.exec("ROLLBACK").catch(() => void 0);
        throw e;
      }
    } finally {
      this.release(c);
    }
  }
  /** Runs a callback with a dedicated connection and no transaction (used by the migration runner for advisory locks). */
  async withConnection(fn) {
    const c = await this.acquire();
    try {
      return await fn(c);
    } finally {
      this.release(c);
    }
  }
  async close() {
    this.closed = true;
    for (const c of this.idle.splice(0)) {
      c.close();
      this.total--;
    }
  }
};

// src/cli.ts
var HOUR = 36e5;
function usage2() {
  process.stderr.write(
    [
      "usage:",
      "  serve                         start the API (refuses to start if migrations are pending)",
      "  migrate status                list applied and pending migrations",
      "  migrate up                    apply pending migrations",
      "  migrate down [--steps N]      revert the latest N migrations (default 1)",
      "  create-owner                  create the single owner (email and password from the environment)",
      "  create-database               create the configured database if it does not exist yet",
      "  redis-check                   test REDIS_URL: connection, password, round trip",
      "  healthcheck                   query the local /readyz (used by the container health check)",
      ""
    ].join("\n")
  );
  process.exit(2);
}
async function serve() {
  const config = loadConfig();
  log("info", "configuration", redactedConfig(config));
  for (const w of configWarnings(config)) log("warn", w);
  const db = new Db(config.database, config.poolSize);
  const status = await migrationStatus(db);
  if (status.pending.length) {
    log("error", 'database migrations are pending; run "migrate up" before starting the server', { pending: status.pending.map((p) => p.name) });
    await db.close();
    process.exit(1);
  }
  const owners = await db.query("SELECT count(*)::int AS n FROM owners");
  if (owners.rows[0].n === 0) log("warn", "no owner exists yet; run create-owner before using the admin website");
  let redis = null;
  let limits = new DatabaseLimitStore(db);
  if (config.redis) {
    redis = new Redis(config.redis, (level, msg, fields) => log(level, msg, fields));
    try {
      await redis.ping();
    } catch (e) {
      log("error", "redis is configured but unavailable; fix REDIS_URL or the Redis service", { target: redis.target, reason: e instanceof Error ? e.message : "unknown" });
      await redis.close();
      await db.close();
      process.exit(1);
    }
    limits = new RedisLimitStore(redis, config.redisKeyPrefix);
  }
  log("info", "runtime state store", { store: limits.kind, redis: redis?.target ?? null });
  const pocketbase2 = config.pocketbase ? new PocketBase(config.pocketbase, globalThis.fetch) : null;
  const server = createServer({ db, config, limits, redis, fetch: globalThis.fetch, pocketbase: pocketbase2 });
  await new Promise((resolve) => server.listen(config.port, config.host, resolve));
  log("info", "devora backend listening", { port: config.port, env: config.env, schemaVersion: status.currentVersion });
  const prune = async () => {
    try {
      const n = await limits.withLock("prune-logs", 10 * 6e4, async () => await pruneLogs(db, config.logRetentionDays) + await pruneSearchLogs(db, config.logRetentionDays));
      if (n) log("info", "pruned old request logs", { deleted: n, retentionDays: config.logRetentionDays });
    } catch (e) {
      log("error", "log pruning failed", { error: e instanceof Error ? e.name : "unknown" });
    }
  };
  void prune();
  const timer = setInterval(prune, 6 * HOUR);
  timer.unref();
  const pruneCounters = async () => {
    try {
      await limits.withLock("prune-rates", 10 * 6e4, () => pruneRates(db));
    } catch (e) {
      log("error", "rate counter pruning failed", { error: e instanceof Error ? e.name : "unknown" });
    }
  };
  const countersTimer = setInterval(pruneCounters, HOUR);
  countersTimer.unref();
  const deps = { db, config, limits, redis, fetch: globalThis.fetch, pocketbase: pocketbase2 };
  const accountJob = () => limits.withLock("account-maintenance", 5 * 6e4, () => accountMaintenance(deps)).catch((e) => log("error", "account maintenance failed", { error: e instanceof Error ? e.name : "unknown" }));
  const accountTimer = setInterval(accountJob, 10 * 6e4);
  accountTimer.unref();
  setTimeout(accountJob, 3e4).unref();
  const discover = () => scheduledDiscovery(deps).catch((e) => log("error", "scheduled discovery failed", { error: e instanceof Error ? e.name : "unknown" }));
  let discoveryTimer = null;
  let firstDiscovery = null;
  if (config.discoveryIntervalHours > 0) {
    firstDiscovery = setTimeout(discover, 6e4);
    firstDiscovery.unref();
    discoveryTimer = setInterval(discover, config.discoveryIntervalHours * HOUR);
    discoveryTimer.unref();
  }
  const stop = async (signal) => {
    log("info", "shutting down", { signal });
    clearInterval(timer);
    clearInterval(countersTimer);
    clearInterval(accountTimer);
    if (discoveryTimer) clearInterval(discoveryTimer);
    if (firstDiscovery) clearTimeout(firstDiscovery);
    const closed = new Promise((r) => server.close(() => r()));
    const deadline = new Promise((r) => setTimeout(r, 2e4).unref());
    await Promise.race([closed, deadline]);
    server.closeAllConnections?.();
    await redis?.close();
    await db.close();
    process.exit(0);
  };
  process.on("SIGTERM", () => void stop("SIGTERM"));
  process.on("SIGINT", () => void stop("SIGINT"));
}
async function migrate(args) {
  const config = loadConfig();
  const db = new Db(config.database, 2);
  try {
    const [sub, ...rest] = args;
    if (sub === "status") {
      const s = await migrationStatus(db);
      process.stdout.write(JSON.stringify(s, null, 2) + "\n");
    } else if (sub === "up") {
      const done = await migrateUp(db, loadMigrations());
      process.stdout.write(done.length ? `applied: ${done.join(", ")}
` : "database is up to date\n");
    } else if (sub === "down") {
      const i = rest.indexOf("--steps");
      const steps = i >= 0 ? Number(rest[i + 1]) : 1;
      const done = await migrateDown(db, steps, loadMigrations());
      process.stdout.write(done.length ? `reverted: ${done.join(", ")}
` : "nothing to revert\n");
    } else {
      usage2();
    }
  } finally {
    await db.close();
  }
}
async function createOwner() {
  const config = loadConfig();
  const email = (process.env.DEVORA_OWNER_EMAIL ?? "").trim().toLowerCase();
  const password = process.env.DEVORA_OWNER_PASSWORD ?? "";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) throw new Error("set DEVORA_OWNER_EMAIL to a valid email address");
  if (password.length < 12 || password.length > 256) throw new Error("set DEVORA_OWNER_PASSWORD (12 to 256 characters)");
  const db = new Db(config.database, 2);
  try {
    const { rows } = await db.query("SELECT count(*)::int AS n FROM owners");
    if (rows[0].n > 0) throw new Error("an owner already exists; this server supports one owner");
    await db.query("INSERT INTO owners (email, password_hash) VALUES ($1, $2)", [email, await hashPassword(password)]);
    process.stdout.write(`owner created: ${email}
`);
  } finally {
    await db.close();
  }
}
async function createDatabase() {
  const config = loadConfig();
  const name = config.database.database;
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(name)) throw new Error("DATABASE_NAME may contain only letters, digits and underscores");
  const db = new Db({ ...config.database, database: "postgres" }, 1);
  try {
    const { rows } = await db.query("SELECT 1 FROM pg_database WHERE datname = $1", [name]);
    if (rows.length) {
      process.stdout.write(`database "${name}" already exists
`);
      return;
    }
    await db.query(`CREATE DATABASE "${name}"`);
    process.stdout.write(`database "${name}" created
`);
  } finally {
    await db.close();
  }
}
async function redisCheck() {
  const config = loadConfig();
  if (!config.redis) throw new Error("REDIS_URL is not set");
  const redis = new Redis(config.redis);
  try {
    const ms = await redis.ping();
    const info = String(await redis.command("INFO", "server"));
    const version2 = /redis_version:([^\r\n]+)/.exec(info)?.[1] ?? "unknown";
    process.stdout.write(
      `redis ok: ${redis.target}, version ${version2}, round trip ${ms} ms, ${config.redis.password ? "password accepted" : "no password configured and none required"}, ${config.redis.tls ? "TLS" : "no TLS"}
`
    );
  } finally {
    await redis.close();
  }
}
function healthcheck() {
  const port = Number(process.env.PORT ?? 8080);
  return new Promise((resolve, reject) => {
    const req = http2.get({ host: "127.0.0.1", port, path: "/readyz", timeout: 4e3 }, (res) => {
      res.resume();
      if (res.statusCode === 200) resolve();
      else reject(new Error(`readyz returned ${res.statusCode}`));
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
  });
}
async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  switch (cmd) {
    case "serve":
      return serve();
    case "migrate":
      return migrate(args);
    case "create-owner":
      return createOwner();
    case "create-database":
      return createDatabase();
    case "redis-check":
      return redisCheck();
    case "healthcheck":
      return healthcheck();
    default:
      return usage2();
  }
}
main().catch((e) => {
  process.stderr.write(`error: ${e instanceof Error ? e.message : String(e)}
`);
  process.exit(1);
});
//# sourceMappingURL=cli.mjs.map
