// HTTP application: route table, security headers, CORS for the admin origin only, and sanitized error responses.
import http from 'node:http';
import crypto from 'node:crypto';
import type { Ctx, Deps } from './context.ts';
import { clientAddress, HttpError, log, sendError, sendJson } from './http/util.ts';
import { migrationStatus } from './db/migrate.ts';
import { DatabaseLimitStore } from './limits.ts';
import { RedisUnavailableError } from './redis.ts';
import { PocketBase } from './pocketbase.ts';
import * as accounts from './modules/accounts.ts';
import * as search from './modules/search.ts';
import * as skills from './modules/skills.ts';
import * as auth from './modules/auth.ts';
import * as devices from './modules/devices.ts';
import * as catalogue from './modules/catalogue.ts';
import * as providers from './modules/providers.ts';
import * as models from './modules/models.ts';
import * as chat from './modules/chat.ts';
import * as memory from './modules/memory.ts';
import * as data from './modules/admin-data.ts';
import * as health from './modules/health.ts';
import * as clientConfig from './modules/client-config.ts';
import * as releases from './modules/releases.ts';
import * as apiKeys from './modules/api-keys.ts';
import * as agents from './modules/agents.ts';
import * as announcements from './modules/announcements.ts';
import * as desktopConfig from './modules/desktop-config.ts';
import * as brain from './modules/brain.ts';
import * as audit from './modules/audit.ts';

type Handler = (ctx: Ctx) => Promise<void>;
interface Route {
  method: string;
  parts: string[];
  handler: Handler;
}

const R = (method: string, path: string, handler: Handler): Route => ({ method, parts: path.split('/').filter(Boolean), handler });

const routes: Route[] = [
  R('GET', '/healthz', async (ctx) => sendJson(ctx.res, 200, { status: 'ok' })),
  R('GET', '/readyz', readiness),
  R('GET', '/v1/client-config', clientConfig.clientConfigRoute),
  R('POST', '/v1/devices/register', devices.registerDevice),
  R('GET', '/v1/device', catalogue.deviceRoute),
  R('GET', '/v1/catalogue', catalogue.catalogueRoute),
  R('GET', '/v1/catalogue/status', catalogue.catalogueStatusRoute),
  R('GET', '/v1/models/:id', catalogue.modelRoute),
  R('GET', '/v1/usage', catalogue.deviceUsageRoute),
  R('POST', '/v1/chat/completions', chat.chatCompletions),
  R('GET', '/v1/models', catalogue.apiModelsRoute),
  R('POST', '/v1/memory/sync', memory.syncMemories),
  R('POST', '/v1/brain/beat', brain.brainBeat),
  R('GET', '/v1/announcements', announcements.desktopAnnouncements),
  R('POST', '/v1/search', search.search),
  R('GET', '/v1/skills', skills.desktopSkills),
  R('GET', '/v1/agents', agents.desktopAgents),
  R('GET', '/v1/updates/check', releases.checkForUpdate),
  R('GET', '/v1/auth/config', accounts.authConfig),
  R('POST', '/v1/auth/session', accounts.createSession),
  R('POST', '/v1/auth/password-reset', accounts.resetPassword),
  R('POST', '/v1/auth/oauth/start', accounts.oauthStart),
  R('GET', '/v1/auth/oauth/callback', accounts.oauthCallback),
  R('POST', '/v1/auth/exchange', accounts.exchange),
  R('POST', '/v1/auth/refresh', accounts.refresh),
  R('POST', '/v1/auth/logout', accounts.logout),
  R('GET', '/v1/account', accounts.account),
  R('POST', '/v1/account/devices/:id/sign-out', accounts.signOutDevice),
  R('POST', '/v1/account/delete', accounts.deleteAccount),
  R('GET', '/v1/updates/:id/download', releases.downloadUpdate),

  R('POST', '/admin/api/auth/login', auth.login),
  R('GET', '/admin/api/auth/session', auth.sessionInfo),
  R('POST', '/admin/api/auth/logout', auth.logout),
  R('POST', '/admin/api/auth/reauth', auth.reauth),

  R('GET', '/admin/api/overview', data.overview),
  R('GET', '/admin/api/health', health.adminHealth),

  R('GET', '/admin/api/providers', providers.listProviders),
  R('POST', '/admin/api/providers', audit.withAudit('provider.create', providers.createProvider)),
  R('PATCH', '/admin/api/providers/:id', audit.withAudit('provider.update', providers.updateProvider)),
  R('DELETE', '/admin/api/providers/:id', audit.withAudit('provider.delete', providers.deleteProvider)),
  R('PUT', '/admin/api/providers/:id/api-key', audit.withAudit('provider.set_key', providers.setProviderKey)),
  R('DELETE', '/admin/api/providers/:id/api-key', audit.withAudit('provider.clear_key', providers.clearProviderKey)),
  R('POST', '/admin/api/providers/:id/test', audit.withAudit('provider.test', providers.testProvider)),
  R('POST', '/admin/api/providers/:id/discover', audit.withAudit('provider.discover', providers.discoverModels)),

  R('GET', '/admin/api/models', models.listModels),
  R('POST', '/admin/api/models', audit.withAudit('model.create', models.createModel)),
  R('PATCH', '/admin/api/models/:id', audit.withAudit('model.update', models.updateModel)),
  R('POST', '/admin/api/models/:id/default', audit.withAudit('model.set_default', models.setDefaultModel)),
  R('DELETE', '/admin/api/models/:id', audit.withAudit('model.delete', models.deleteModel)),

  R('GET', '/admin/api/devices', devices.listDevices),
  R('POST', '/admin/api/devices/:id/revoke', audit.withAudit('device.revoke', devices.revokeDevice)),
  R('POST', '/admin/api/devices/:id/unblock', audit.withAudit('device.unblock', devices.unblockDevice)),
  R('GET', '/admin/api/devices/:id/models', devices.getDeviceModels),
  R('PUT', '/admin/api/devices/:id/models', audit.withAudit('device.set_models', devices.putDeviceModels)),

  R('GET', '/admin/api/usage', data.usage),
  R('GET', '/admin/api/logs', data.logs),
  R('GET', '/admin/api/brain', brain.adminBrain),
  R('GET', '/admin/api/memory', memory.adminListMemory),
  R('DELETE', '/admin/api/memory', memory.adminClearAllMemory),
  R('DELETE', '/admin/api/memory/:id', memory.adminClearDeviceMemory),
  R('GET', '/admin/api/releases', releases.listReleases),
  R('POST', '/admin/api/releases', audit.withAudit('release.create', releases.createRelease)),
  R('PUT', '/admin/api/releases/:id/chunks/:seq', releases.uploadChunk),
  R('POST', '/admin/api/releases/:id/complete', audit.withAudit('release.complete', releases.completeUpload)),
  R('PATCH', '/admin/api/releases/:id', audit.withAudit('release.update', releases.updateRelease)),
  R('DELETE', '/admin/api/releases/:id', audit.withAudit('release.delete', releases.deleteRelease)),
  R('GET', '/admin/api/search-providers', search.listSearchProviders),
  R('POST', '/admin/api/search-providers', audit.withAudit('search_provider.create', search.createSearchProvider)),
  R('PATCH', '/admin/api/search-providers/:id', audit.withAudit('search_provider.update', search.updateSearchProvider)),
  R('DELETE', '/admin/api/search-providers/:id', audit.withAudit('search_provider.delete', search.deleteSearchProvider)),
  R('PUT', '/admin/api/search-providers/:id/api-key', audit.withAudit('search_provider.set_key', search.setSearchProviderKey)),
  R('DELETE', '/admin/api/search-providers/:id/api-key', audit.withAudit('search_provider.clear_key', search.clearSearchProviderKey)),
  R('POST', '/admin/api/search-providers/:id/test', audit.withAudit('search_provider.test', search.testSearchProvider)),
  R('GET', '/admin/api/skills', skills.listOrgSkills),
  R('POST', '/admin/api/skills', audit.withAudit('skill.create', skills.createOrgSkill)),
  R('PATCH', '/admin/api/skills/:id', audit.withAudit('skill.update', skills.updateOrgSkill)),
  R('DELETE', '/admin/api/skills/:id', audit.withAudit('skill.delete', skills.deleteOrgSkill)),
  R('GET', '/admin/api/users', accounts.adminListUsers),
  R('GET', '/admin/api/users/:id/activity', accounts.adminUserActivity),
  R('GET', '/admin/api/users/:id', accounts.adminGetUser),
  R('POST', '/admin/api/users/:id/:action', audit.withAudit('user.action', accounts.adminUserAction)),
  R('GET', '/admin/api/settings', data.getSettings),
  R('PATCH', '/admin/api/settings', audit.withAudit('settings.update', data.patchSettings)),

  R('GET', '/admin/api/api-keys', apiKeys.listApiKeys),
  R('POST', '/admin/api/api-keys', audit.withAudit('api_key.create', apiKeys.createApiKey)),
  R('PATCH', '/admin/api/api-keys/:id', audit.withAudit('api_key.update', apiKeys.updateApiKey)),
  R('DELETE', '/admin/api/api-keys/:id', audit.withAudit('api_key.delete', apiKeys.deleteApiKey)),

  R('GET', '/admin/api/agents', agents.listOrgAgents),
  R('POST', '/admin/api/agents', audit.withAudit('agent.create', agents.createOrgAgent)),
  R('PATCH', '/admin/api/agents/:id', audit.withAudit('agent.update', agents.updateOrgAgent)),
  R('DELETE', '/admin/api/agents/:id', audit.withAudit('agent.delete', agents.deleteOrgAgent)),

  R('GET', '/admin/api/desktop-config', desktopConfig.getDesktopConfig),
  R('PATCH', '/admin/api/desktop-config', audit.withAudit('desktop_config.update', desktopConfig.patchDesktopConfig)),

  R('GET', '/admin/api/announcements', announcements.listOrgAnnouncements),
  R('POST', '/admin/api/announcements', audit.withAudit('announcement.create', announcements.createOrgAnnouncement)),
  R('PATCH', '/admin/api/announcements/:id', audit.withAudit('announcement.update', announcements.updateOrgAnnouncement)),
  R('DELETE', '/admin/api/announcements/:id', audit.withAudit('announcement.delete', announcements.deleteOrgAnnouncement)),

  R('GET', '/admin/api/audit', audit.listAudit),
  R('GET', '/admin/api/export', data.exportConfig),
];

function match(route: Route, pathname: string): Record<string, string> | null {
  const segs = pathname.split('/').filter(Boolean);
  if (segs.length !== route.parts.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < segs.length; i++) {
    const p = route.parts[i];
    if (p.startsWith(':')) {
      try {
        params[p.slice(1)] = decodeURIComponent(segs[i]);
      } catch {
        return null;
      }
    } else if (p !== segs[i]) return null;
  }
  return params;
}

async function readiness(ctx: Ctx): Promise<void> {
  let schemaVersion: number | null;
  try {
    await ctx.deps.db.query('SELECT 1');
    const s = await migrationStatus(ctx.deps.db);
    if (s.pending.length) {
      sendJson(ctx.res, 503, { status: 'not_ready', reason: 'database migrations are pending' });
      return;
    }
    schemaVersion = s.currentVersion;
  } catch {
    sendJson(ctx.res, 503, { status: 'not_ready', reason: 'database is unavailable' });
    return;
  }
  if (ctx.deps.redis) {
    try {
      await ctx.deps.redis.ping();
    } catch {
      sendJson(ctx.res, 503, { status: 'not_ready', reason: 'redis is unavailable' });
      return;
    }
  }
  sendJson(ctx.res, 200, { status: 'ready', schemaVersion });
}

function applySecurityHeaders(req: http.IncomingMessage, res: http.ServerResponse, deps: Deps): void {
  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader('x-frame-options', 'DENY');
  if (deps.config.cookieSecure) res.setHeader('strict-transport-security', 'max-age=31536000');
  const path = (req.url ?? '').split('?')[0];
  if (path.startsWith('/admin/api') || path.startsWith('/v1')) res.setHeader('cache-control', 'no-store');
}

/** CORS is granted only to the configured admin origin, with credentials. Other origins get no CORS headers. */
function applyCors(req: http.IncomingMessage, res: http.ServerResponse, deps: Deps): boolean {
  const origin = req.headers.origin;
  if (!origin) return true;
  res.setHeader('vary', 'Origin');
  if (!deps.config.adminOrigin || origin !== deps.config.adminOrigin) return false;
  res.setHeader('access-control-allow-origin', origin);
  res.setHeader('access-control-allow-credentials', 'true');
  if (req.method === 'OPTIONS') {
    res.setHeader('access-control-allow-methods', 'GET, POST, PUT, PATCH, DELETE');
    res.setHeader('access-control-allow-headers', 'content-type, x-csrf-token, x-api-key');
    res.setHeader('access-control-max-age', '600');
  }
  return true;
}

/** Paths reachable without the API key: health probes for the load balancer, and the OAuth callback the user's browser opens. */
const KEYLESS_PATHS = new Set(['/healthz', '/readyz', '/v1/auth/oauth/callback']);

/** True when the request carries the configured API access key (or none is configured). Constant-time comparison. */
function hasApiKey(req: http.IncomingMessage, pathname: string, deps: Deps): boolean {
  const expected = deps.config.apiAccessKey;
  if (!expected || KEYLESS_PATHS.has(pathname)) return true;
  const got = req.headers['x-api-key'];
  if (typeof got !== 'string' || !got) return false;
  const a = crypto.createHash('sha256').update(got).digest();
  const b = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

/** Deps as callers build them. `limits` defaults to the PostgreSQL store and `redis` to none. */
export type DepsInput = Omit<Deps, 'limits' | 'redis' | 'pocketbase'> & Partial<Pick<Deps, 'limits' | 'redis' | 'pocketbase'>>;

export function createHandler(input: DepsInput): http.RequestListener {
  const deps: Deps = {
    ...input,
    limits: input.limits ?? new DatabaseLimitStore(input.db),
    redis: input.redis ?? null,
    pocketbase: input.pocketbase !== undefined ? input.pocketbase : input.config.pocketbase ? new PocketBase(input.config.pocketbase, input.fetch) : null,
  };
  return async (req, res) => {
    const requestId = crypto.randomUUID();
    const started = Date.now();
    let routeName = 'unmatched';
    res.setHeader('x-request-id', requestId);
    applySecurityHeaders(req, res, deps);
    const corsOk = applyCors(req, res, deps);
    // One structured line per request: no query string, headers or bodies. Health probes are logged too, at info level.
    res.on('finish', () => {
      log('info', 'request', { requestId, method: req.method ?? 'UNKNOWN', route: routeName, status: res.statusCode, latencyMs: Date.now() - started });
    });
    try {
      const url = new URL(req.url ?? '/', 'http://internal');
      if (req.method === 'OPTIONS') {
        if (!corsOk) sendError(res, new HttpError(403, 'forbidden', 'origin not allowed'));
        else {
          res.writeHead(204);
          res.end();
        }
        return;
      }
      if (!hasApiKey(req, url.pathname, deps)) throw new HttpError(401, 'invalid_api_key', 'a valid API key is required');
      let matched: { route: Route; params: Record<string, string> } | null = null;
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
        if (pathExists) throw new HttpError(405, 'method_not_allowed', 'method not allowed');
        throw new HttpError(404, 'not_found', 'not found');
      }
      routeName = `${req.method} /${matched.route.parts.join('/')}`;
      if (req.url && req.url.length > 4096) throw new HttpError(414, 'uri_too_long', 'the address is too long');
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
        log('error', 'redis unavailable', { requestId, method: req.method, route: routeName, reason: e.code });
        sendError(res, new HttpError(503, 'service_unavailable', 'a required service is temporarily unavailable; try again shortly', { 'retry-after': '5' }));
        return;
      }
      log('error', 'request failed', { requestId, method: req.method, route: routeName, error: e instanceof Error ? e.name : 'unknown' });
      sendError(res, new HttpError(500, 'internal_error', 'something went wrong; try again'));
    }
  };
}

export function createServer(deps: DepsInput): http.Server {
  const server = http.createServer(createHandler(deps));
  server.requestTimeout = deps.config.requestTimeoutMs;
  server.headersTimeout = deps.config.headersTimeoutMs;
  server.keepAliveTimeout = 65_000;
  return server;
}
