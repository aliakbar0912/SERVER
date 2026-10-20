// GET /v1/client-config: public, non-secret runtime settings for desktop apps. No authentication, no database access.
// The desktop app validates every field and never lets this response weaken security: it cannot disable TLS or
// authentication, and a new API origin is only followed when the desktop already trusts it (see the desktop's
// src/core/central/runtime-config.ts). Nothing here is code; it is plain data.
import type { Ctx } from '../context.ts';
import type { Config } from '../config.ts';
import { sendJson } from '../http/util.ts';

export const CLIENT_CONFIG_SCHEMA = 1;
/** How long a desktop app may keep using this response when the server cannot be reached. */
export const CLIENT_CONFIG_MAX_AGE_SECONDS = 7 * 24 * 3600;

export function clientConfigBody(config: Config): Record<string, unknown> {
  return {
    schema: CLIENT_CONFIG_SCHEMA,
    instanceId: config.instanceId,
    apiOrigin: config.publicApiOrigin,
    apiVersions: ['v1'],
    desktop: {
      minVersion: config.desktop.minVersion,
      latestVersion: config.desktop.latestVersion,
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
  sendJson(ctx.res, 200, clientConfigBody(ctx.deps.config));
}
