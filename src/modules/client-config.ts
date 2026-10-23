// GET /v1/client-config: public, non-secret runtime settings for desktop apps. No authentication. The only database read is
// the newest published release version (cached briefly); when the database is down the environment settings are used.
// The desktop app validates every field and never lets this response weaken security: it cannot disable TLS or
// authentication, and a new API origin is only followed when the desktop already trusts it (see the desktop's
// src/core/central/runtime-config.ts). Nothing here is code; it is plain data.
import type { Ctx } from '../context.ts';
import type { Config } from '../config.ts';
import type { Queryer } from '../db/pg-wire.ts';
import { sendJson } from '../http/util.ts';
import { compareVersions, latestPublished } from './releases.ts';

export const CLIENT_CONFIG_SCHEMA = 1;
/** How long a desktop app may keep using this response when the server cannot be reached. */
export const CLIENT_CONFIG_MAX_AGE_SECONDS = 7 * 24 * 3600;

/** Versions from releases published in the admin site, merged with the DEVORA_DESKTOP_* settings (the newer wins). */
export interface PublishedVersions {
  latestVersion: string | null;
  minVersion: string | null;
}

const newest = (a: string | null, b: string | null) => (!a ? b : !b ? a : compareVersions(a, b) >= 0 ? a : b);

export function clientConfigBody(config: Config, published: PublishedVersions = { latestVersion: null, minVersion: null }): Record<string, unknown> {
  return {
    schema: CLIENT_CONFIG_SCHEMA,
    instanceId: config.instanceId,
    apiOrigin: config.publicApiOrigin,
    apiVersions: ['v1'],
    desktop: {
      minVersion: newest(config.desktop.minVersion, published.minVersion),
      latestVersion: newest(config.desktop.latestVersion, published.latestVersion),
      downloadUrl: config.desktop.downloadUrl,
    },
    status: { message: config.desktop.statusMessage },
    features: {},
    maxAgeSeconds: CLIENT_CONFIG_MAX_AGE_SECONDS,
  };
}

export async function clientConfigRoute(ctx: Ctx): Promise<void> {
  // Short shared caching is fine: the body is the same for everyone and contains no secrets.
  ctx.res.setHeader('cache-control', 'public, max-age=300');
  sendJson(ctx.res, 200, clientConfigBody(ctx.deps.config, await publishedVersions(ctx.deps.db)));
}

let cache: { at: number; value: PublishedVersions } | null = null;
async function publishedVersions(db: Queryer): Promise<PublishedVersions> {
  if (cache && Date.now() - cache.at < 30_000) return cache.value;
  try {
    const p = await latestPublished(db);
    cache = { at: Date.now(), value: { latestVersion: p.latest?.version ?? null, minVersion: p.minVersion } };
  } catch {
    return cache?.value ?? { latestVersion: null, minVersion: null };
  }
  return cache.value;
}

/** Tests and publishing call this so a new release is announced at once. */
export function forgetPublishedVersions(): void {
  cache = null;
}
