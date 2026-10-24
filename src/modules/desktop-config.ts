// Desktop announcement settings, edited by the owner in the admin site and served to every desktop through
// GET /v1/client-config. Values stored here override the DEVORA_DESKTOP_* environment settings (the newer write wins);
// an empty value removes the override and falls back to the environment. Raising the minimum version requires a
// password confirmation, because it can lock older desktops out of central AI until they update.
import type { Ctx } from '../context.ts';
import type { Queryer } from '../db/pg-wire.ts';
import { bool, fail, readJson, rejectUnknown, requireObject, sendJson, str } from '../http/util.ts';
import { guardOwner, requireReauth } from './auth.ts';
import { readSettings } from './catalogue.ts';

export const STATUS_MESSAGE_MAX = 200;
const VERSION = /^\d+\.\d+\.\d+$/;

export interface DesktopConfig {
  /** Short notice shown in the desktop app ('' = none). */
  statusMessage: string;
  /** Oldest desktop version the server still supports ('' = no override). */
  minVersion: string;
  /** https page where users download the installer ('' = no override). */
  downloadUrl: string;
  /** Announced in client-config.features.maintenance so desktops can say the service is briefly unavailable. */
  maintenance: boolean;
}

/** Reads the DB-backed overrides; missing rows fall back to safe defaults. Never throws. */
export async function readDesktopConfig(db: Queryer): Promise<DesktopConfig> {
  try {
    const s = await readSettings(db);
    return {
      statusMessage: typeof s.desktop_status_message === 'string' ? s.desktop_status_message : '',
      minVersion: typeof s.desktop_min_version === 'string' && VERSION.test(s.desktop_min_version) ? s.desktop_min_version : '',
      downloadUrl: typeof s.desktop_download_url === 'string' ? s.desktop_download_url : '',
      maintenance: s.desktop_maintenance === true,
    };
  } catch {
    // Before migration 12 (or while the database is down) the environment settings apply unchanged.
    return { statusMessage: '', minVersion: '', downloadUrl: '', maintenance: false };
  }
}

// The per-request maintenance gate (chat, search) uses a very short cache so hot endpoints do not read the
// settings table on every call. The admin site's own routes always read the live values.
let configCache: { at: number; value: DesktopConfig } | null = null;
const DESKTOP_CONFIG_CACHE_MS = 10_000;

/** Tests call this so a saved announcement applies at once. */
export function forgetDesktopConfigCache(): void {
  configCache = null;
}

/** Cached readDesktopConfig for hot per-request checks; at most one settings read every 10 seconds. */
export async function readDesktopConfigCached(db: Queryer): Promise<DesktopConfig> {
  if (configCache && Date.now() - configCache.at < DESKTOP_CONFIG_CACHE_MS) return configCache.value;
  const value = await readDesktopConfig(db);
  configCache = { at: Date.now(), value };
  return value;
}

function checkDownloadUrl(v: string): string {
  if (!v) return '';
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    fail(400, 'invalid_request', 'downloadUrl must be an https URL');
  }
  if (u.protocol !== 'https:' || u.username || u.password) fail(400, 'invalid_request', 'downloadUrl must be an https URL without credentials');
  return u.toString();
}

export async function getDesktopConfig(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const cfg = await readDesktopConfig(ctx.deps.db);
  sendJson(ctx.res, 200, {
    ...cfg,
    environment: {
      minVersion: ctx.deps.config.desktop.minVersion,
      latestVersion: ctx.deps.config.desktop.latestVersion,
      downloadUrl: ctx.deps.config.desktop.downloadUrl,
      statusMessage: ctx.deps.config.desktop.statusMessage,
    },
  });
}

export async function patchDesktopConfig(ctx: Ctx): Promise<void> {
  const session = await guardOwner(ctx, { write: true });
  const body = requireObject(await readJson(ctx.req, 16 * 1024));
  rejectUnknown(body, ['statusMessage', 'minVersion', 'downloadUrl', 'maintenance']);
  const changes: [string, unknown][] = [];
  if (body.statusMessage !== undefined) {
    const msg = str(body, 'statusMessage', { min: 0, max: STATUS_MESSAGE_MAX, optional: true }) ?? '';
    if (/[\u0000-\u001f]/.test(msg)) fail(400, 'invalid_request', 'the status message may not contain control characters');
    changes.push(['desktop_status_message', msg.trim()]);
  }
  if (body.minVersion !== undefined) {
    const v = str(body, 'minVersion', { min: 0, max: 20, optional: true }) ?? '';
    // A wrong version string would be ignored by desktops; an unreachable one locks them out, so it needs confirmation.
    if (v && !VERSION.test(v)) fail(400, 'invalid_request', 'minVersion must look like 1.2.3, or be empty to clear it');
    if (v) requireReauth(session);
    changes.push(['desktop_min_version', v]);
  }
  if (body.downloadUrl !== undefined) {
    const v = str(body, 'downloadUrl', { min: 0, max: 2048, optional: true }) ?? '';
    changes.push(['desktop_download_url', checkDownloadUrl(v)]);
  }
  if (body.maintenance !== undefined) {
    const m = bool(body, 'maintenance', { optional: true });
    if (m !== undefined) changes.push(['desktop_maintenance', m]);
  }
  if (!changes.length) fail(400, 'invalid_request', 'no settings were given');
  await ctx.deps.db.transaction(async (q) => {
    for (const [k, v] of changes) {
      await q.query(
        'INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()',
        [k, JSON.stringify(v)],
      );
    }
  });
  forgetDesktopConfigCache();
  sendJson(ctx.res, 200, await readDesktopConfig(ctx.deps.db));
}
