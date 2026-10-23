// Desktop app updates. The owner creates a release in the admin site, uploads the installer (or gives an https download
// with its SHA-256) and publishes it. Desktop apps ask /v1/updates/check, download the installer, verify its SHA-256 and
// size, and install it. Installers are stored in the database in chunks, so they survive redeploys without a volume.
import crypto from 'node:crypto';
import type { Ctx } from '../context.ts';
import type { Queryer } from '../db/pg-wire.ts';
import { bool, fail, readJson, rejectUnknown, requireObject, sendJson, str, uuidParam } from '../http/util.ts';
import { guardOwner, requireReauth } from './auth.ts';
import { authenticateDevice } from './devices.ts';
import { forgetPublishedVersions } from './client-config.ts';

/** Size of one uploaded piece. Small enough for any reverse proxy body limit and short requests. */
export const CHUNK_BYTES = 4 * 1024 * 1024;
/** Largest installer accepted. */
export const MAX_RELEASE_BYTES = 600 * 1024 * 1024;
const MAX_CHUNKS = Math.ceil(MAX_RELEASE_BYTES / CHUNK_BYTES);
const CHECKS_PER_HOUR = 60;
const DOWNLOADS_PER_HOUR = 6;
const VERSION = /^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$/;
const SHA256 = /^[0-9a-f]{64}$/;
const FILE_NAME = /^[A-Za-z0-9 ._()+-]{1,200}$/;

/** Semantic version order: 1.2.10 > 1.2.9; a pre-release (1.2.0-beta) is older than its release (1.2.0). */
export function compareVersions(a: string, b: string): number {
  const parse = (v: string) => {
    const [core, pre = ''] = v.split(/[-+]/, 2);
    return { nums: core.split('.').map((n) => Number(n) || 0), pre: v.includes('-') ? pre : '' };
  };
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < 3; i++) if ((x.nums[i] ?? 0) !== (y.nums[i] ?? 0)) return (x.nums[i] ?? 0) < (y.nums[i] ?? 0) ? -1 : 1;
  if (x.pre === y.pre) return 0;
  if (!x.pre) return 1;
  if (!y.pre) return -1;
  return x.pre < y.pre ? -1 : 1;
}

interface ReleaseRow {
  id: string;
  version: string;
  notes: string;
  mandatory: boolean;
  status: 'draft' | 'published';
  source: 'upload' | 'url';
  external_url: string | null;
  file_name: string;
  file_size: string | number;
  sha256: string | null;
  upload_complete: boolean;
  downloads: number;
  created_at: Date;
  published_at: Date | null;
  uploaded_bytes?: string | number;
  uploaded_chunks?: number;
}

function view(r: ReleaseRow) {
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
    publishedAt: r.published_at,
  };
}

const SELECT = `SELECT r.*, coalesce((SELECT sum(length(c.data)) FROM desktop_release_chunks c WHERE c.release_id = r.id), 0)::bigint AS uploaded_bytes
                  FROM desktop_releases r`;

async function getRelease(q: Queryer, id: string): Promise<ReleaseRow> {
  const { rows } = await q.query(`${SELECT} WHERE r.id = $1`, [id]);
  if (!rows[0]) fail(404, 'not_found', 'release not found');
  return rows[0] as ReleaseRow;
}

/** The newest published release, and whether any published release newer than `current` is mandatory. */
export async function latestPublished(q: Queryer, current?: string): Promise<{ latest: ReleaseRow | null; mandatory: boolean; minVersion: string | null }> {
  const { rows } = await q.query("SELECT * FROM desktop_releases WHERE status = 'published' AND upload_complete");
  const list = (rows as ReleaseRow[]).sort((a, b) => compareVersions(b.version, a.version));
  const latest = list[0] ?? null;
  const mandatoryList = list.filter((r) => r.mandatory);
  const minVersion = mandatoryList[0]?.version ?? null;
  const mandatory = !!current && mandatoryList.some((r) => compareVersions(r.version, current) > 0);
  return { latest, mandatory, minVersion };
}

// ------------------------------------------------------------------ owner routes

export async function listReleases(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const { rows } = await ctx.deps.db.query(`${SELECT} ORDER BY r.created_at DESC LIMIT 200`);
  const adoption = await ctx.deps.db.query(
    `SELECT coalesce(app_version, 'unknown') AS version, count(*)::int AS devices
       FROM devices WHERE status = 'active' GROUP BY 1 ORDER BY 2 DESC LIMIT 50`,
  );
  const list = (rows as ReleaseRow[]).map(view).sort((a, b) => compareVersions(b.version, a.version));
  sendJson(ctx.res, 200, {
    releases: list,
    adoption: adoption.rows,
    chunkBytes: CHUNK_BYTES,
    maxBytes: MAX_RELEASE_BYTES,
  });
}

export async function createRelease(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const body = requireObject(await readJson(ctx.req, 32 * 1024));
  rejectUnknown(body, ['version', 'notes', 'mandatory', 'externalUrl', 'sha256', 'fileName', 'fileSize']);
  const version = str(body, 'version', { min: 5, max: 40, pattern: VERSION })!;
  const notes = str(body, 'notes', { max: 10_000, optional: true }) ?? '';
  const mandatory = bool(body, 'mandatory', { def: false })!;
  const externalUrl = str(body, 'externalUrl', { max: 2000, optional: true }) || null;
  let sha256 = (str(body, 'sha256', { max: 64, optional: true }) || '').toLowerCase() || null;
  const fileName = str(body, 'fileName', { max: 200, optional: true }) || `Devora-Setup-${version}.exe`;
  if (!FILE_NAME.test(fileName)) fail(400, 'invalid_request', 'fileName may contain letters, digits, spaces and . _ ( ) + -');
  const fileSize = typeof body.fileSize === 'number' && Number.isInteger(body.fileSize) && body.fileSize > 0 ? body.fileSize : 0;
  if (fileSize > MAX_RELEASE_BYTES) fail(413, 'payload_too_large', `the installer may be at most ${MAX_RELEASE_BYTES / 1024 / 1024} MB`);
  if (externalUrl) {
    let u: URL;
    try {
      u = new URL(externalUrl);
    } catch {
      fail(400, 'invalid_request', 'externalUrl is not a URL');
    }
    if (u.protocol !== 'https:' || u.username || u.password) fail(400, 'invalid_request', 'externalUrl must be an https address without credentials');
    if (!sha256 || !SHA256.test(sha256)) fail(400, 'invalid_request', 'give the SHA-256 of the installer at externalUrl, so desktops can verify the download');
  } else sha256 = null;
  try {
    const { rows } = await ctx.deps.db.query(
      `INSERT INTO desktop_releases (version, notes, mandatory, source, external_url, sha256, file_name, file_size, upload_complete)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
      [version, notes, mandatory, externalUrl ? 'url' : 'upload', externalUrl, sha256, fileName, fileSize, !!externalUrl],
    );
    sendJson(ctx.res, 201, { release: view(await getRelease(ctx.deps.db, rows[0].id)), chunkBytes: CHUNK_BYTES });
  } catch (e) {
    if (/duplicate key|unique/i.test((e as Error).message)) fail(409, 'version_exists', `version ${version} already exists`);
    throw e;
  }
}

/** PUT /admin/api/releases/:id/chunks/:seq: one piece of the installer, raw bytes. Re-sending a piece replaces it. */
export async function uploadChunk(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const seq = Number(ctx.params.seq);
  if (!Number.isInteger(seq) || seq < 0 || seq >= MAX_CHUNKS) fail(400, 'invalid_request', 'chunk number is out of range');
  const r = await getRelease(ctx.deps.db, id);
  if (r.source !== 'upload') fail(409, 'not_upload', 'this release downloads from an external address');
  if (r.status === 'published' || r.upload_complete) fail(409, 'upload_closed', 'the upload of this release is finished; create a new version to change the installer');
  const declared = Number(ctx.req.headers['content-length'] ?? 0);
  if (declared > CHUNK_BYTES) fail(413, 'payload_too_large', `each piece may be at most ${CHUNK_BYTES} bytes`);
  const parts: Buffer[] = [];
  let size = 0;
  for await (const c of ctx.req) {
    size += (c as Buffer).length;
    if (size > CHUNK_BYTES) {
      ctx.req.destroy();
      fail(413, 'payload_too_large', `each piece may be at most ${CHUNK_BYTES} bytes`);
    }
    parts.push(c as Buffer);
  }
  if (!size) fail(400, 'invalid_request', 'the piece is empty');
  await ctx.deps.db.query(
    `INSERT INTO desktop_release_chunks (release_id, seq, data) VALUES ($1, $2, $3)
     ON CONFLICT (release_id, seq) DO UPDATE SET data = EXCLUDED.data`,
    [id, seq, Buffer.concat(parts)],
  );
  sendJson(ctx.res, 200, { seq, bytes: size });
}

/** POST /admin/api/releases/:id/complete { sha256? }: checks the pieces are complete and records size and SHA-256. */
export async function completeUpload(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ['sha256']);
  const expected = (str(body, 'sha256', { max: 64, optional: true }) || '').toLowerCase();
  const r = await getRelease(ctx.deps.db, id);
  if (r.source !== 'upload') fail(409, 'not_upload', 'this release downloads from an external address');
  const { rows } = await ctx.deps.db.query('SELECT seq, length(data)::int AS n FROM desktop_release_chunks WHERE release_id = $1 ORDER BY seq', [id]);
  if (!rows.length) fail(400, 'upload_incomplete', 'no installer was uploaded');
  rows.forEach((c, i) => {
    if (c.seq !== i) fail(400, 'upload_incomplete', `piece ${i} is missing; upload it again`);
  });
  const hash = crypto.createHash('sha256');
  let total = 0;
  for (const c of rows) {
    const part = await ctx.deps.db.query('SELECT data FROM desktop_release_chunks WHERE release_id = $1 AND seq = $2', [id, c.seq]);
    const buf = part.rows[0].data as Buffer;
    total += buf.length;
    hash.update(buf);
  }
  const sha256 = hash.digest('hex');
  if (expected && expected !== sha256) fail(400, 'checksum_mismatch', 'the uploaded installer does not match the file you chose; upload it again');
  if (total > MAX_RELEASE_BYTES) fail(413, 'payload_too_large', 'the installer is too large');
  // A Windows installer starts with "MZ". This catches a wrong file before anyone downloads it.
  const head = await ctx.deps.db.query('SELECT substring(data from 1 for 2) AS h FROM desktop_release_chunks WHERE release_id = $1 AND seq = 0', [id]);
  const magic = (head.rows[0]?.h as Buffer | undefined)?.toString('latin1') ?? '';
  if (magic !== 'MZ') fail(400, 'not_an_installer', 'this file is not a Windows installer (.exe)');
  await ctx.deps.db.query('UPDATE desktop_releases SET sha256 = $2, file_size = $3, upload_complete = true WHERE id = $1', [id, sha256, total]);
  sendJson(ctx.res, 200, { release: view(await getRelease(ctx.deps.db, id)) });
}

/** PATCH /admin/api/releases/:id { notes?, mandatory?, status? }. Publishing needs a recent password confirmation. */
export async function updateRelease(ctx: Ctx): Promise<void> {
  const session = await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const body = requireObject(await readJson(ctx.req, 32 * 1024));
  rejectUnknown(body, ['notes', 'mandatory', 'status']);
  const r = await getRelease(ctx.deps.db, id);
  const notes = str(body, 'notes', { max: 10_000, optional: true });
  const mandatory = bool(body, 'mandatory', { optional: true });
  const status = str(body, 'status', { max: 20, optional: true, pattern: /^(draft|published)$/ });
  if (status === 'published' && r.status !== 'published') {
    if (!r.upload_complete || !r.sha256) fail(409, 'upload_incomplete', 'upload the installer before publishing');
    requireReauth(session);
  }
  if (mandatory === true && !r.mandatory && (status ?? r.status) === 'published') requireReauth(session);
  await ctx.deps.db.query(
    `UPDATE desktop_releases SET notes = coalesce($2, notes), mandatory = coalesce($3, mandatory), status = coalesce($4, status),
            published_at = CASE WHEN $4 = 'published' AND status <> 'published' THEN now() WHEN $4 = 'draft' THEN NULL ELSE published_at END
      WHERE id = $1`,
    [id, notes ?? null, mandatory ?? null, status ?? null],
  );
  forgetPublishedVersions();
  sendJson(ctx.res, 200, { release: view(await getRelease(ctx.deps.db, id)) });
}

export async function deleteRelease(ctx: Ctx): Promise<void> {
  const session = await guardOwner(ctx, { write: true });
  const id = uuidParam(ctx.params.id);
  const r = await getRelease(ctx.deps.db, id);
  if (r.status === 'published') requireReauth(session);
  await ctx.deps.db.query('DELETE FROM desktop_releases WHERE id = $1', [id]);
  forgetPublishedVersions();
  sendJson(ctx.res, 200, { deleted: true });
}

// ------------------------------------------------------------------ desktop routes

/** GET /v1/updates/check?current=1.2.3: the newest published release when it is newer than `current`. */
export async function checkForUpdate(ctx: Ctx): Promise<void> {
  const device = await authenticateDevice(ctx, { central: false });
  const rl = await ctx.deps.limits.hit(`updates:check:${device.deviceId}`, CHECKS_PER_HOUR, 3600);
  if (!rl.allowed) fail(429, 'rate_limited', 'too many update checks; try again later', { 'retry-after': String(rl.retryAfterSeconds) });
  const current = ctx.url.searchParams.get('current') ?? '';
  if (!VERSION.test(current)) fail(400, 'invalid_request', 'current must be the installed version, for example 1.2.3');
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
      download: latest.source === 'url' ? latest.external_url : `/v1/updates/${latest.id}/download`,
    },
  });
}

/** GET /v1/updates/:id/download: streams an uploaded, published installer. */
export async function downloadUpdate(ctx: Ctx): Promise<void> {
  const device = await authenticateDevice(ctx, { central: false });
  // Installers are large: a computer may start only a few downloads an hour, so one token cannot drain the server.
  const rl = await ctx.deps.limits.hit(`updates:download:${device.deviceId}`, DOWNLOADS_PER_HOUR, 3600);
  if (!rl.allowed) fail(429, 'rate_limited', 'too many update downloads from this computer; try again later', { 'retry-after': String(rl.retryAfterSeconds) });
  const id = uuidParam(ctx.params.id);
  const r = await getRelease(ctx.deps.db, id);
  if (r.status !== 'published' || !r.upload_complete) fail(404, 'not_found', 'release not found');
  if (r.source !== 'upload') fail(409, 'external_download', 'this release downloads from its external address');
  const { rows } = await ctx.deps.db.query('SELECT seq FROM desktop_release_chunks WHERE release_id = $1 ORDER BY seq', [id]);
  await ctx.deps.db.query('UPDATE desktop_releases SET downloads = downloads + 1 WHERE id = $1', [id]);
  ctx.res.writeHead(200, {
    'content-type': 'application/octet-stream',
    'content-length': String(Number(r.file_size)),
    'content-disposition': `attachment; filename="${r.file_name.replace(/"/g, '')}"`,
    'x-content-sha256': r.sha256 ?? '',
  });
  for (const c of rows) {
    if (ctx.res.destroyed) return;
    const part = await ctx.deps.db.query('SELECT data FROM desktop_release_chunks WHERE release_id = $1 AND seq = $2', [id, c.seq]);
    const buf = part.rows[0]?.data as Buffer | undefined;
    if (!buf) {
      ctx.res.destroy();
      return;
    }
    if (!ctx.res.write(buf)) await new Promise<void>((resolve) => ctx.res.once('drain', () => resolve()));
  }
  ctx.res.end();
}
