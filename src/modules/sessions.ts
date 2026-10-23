// Signed-in devices: binding a device to a PocketBase user, token issue/rotation/expiry, ending sessions, periodic
// re-checks of the account, and the account-deletion journal.
//
// Rules (also in docs/ACCOUNTS.md):
//   - Legacy device (user_id null): works exactly as before with its existing token, unless the owner turns on
//     "Require sign-in for central AI". Its memory and logs stay with the device.
//   - Signing in on a computer binds its installation to the user. An unclaimed legacy device is claimed only when the
//     request also proves it holds that device's current token; otherwise the desktop must use a new installation id.
//   - A device signed in as another user is never moved: with proof of its token the old session is ended and released,
//     and a new device row is created for the new user (old memory stays with the old user).
//   - Once a device belongs to a user, /v1/devices/register never issues it a token again; only a sign-in does.
//   - Signed-in tokens expire after 30 days and are rotated by the desktop. The previous token works for 2 minutes after a
//     rotation (lost response); used after that, the session is ended as a stolen copy.
//   - Logout and account deletion replace the token hash with a random value and release the installation id.
import type { Deps } from '../context.ts';
import type { Queryer } from '../db/pg-wire.ts';
import { randomToken, sha256Hex } from '../crypto.ts';
import { fail, log } from '../http/util.ts';
import { PbError } from '../pocketbase.ts';
import { readSettings } from './catalogue.ts';

export const TOKEN_TTL_DAYS = 30;
export const ROTATE_GRACE_SECONDS = 120;
/** How often a signed-in user's account is re-checked with PocketBase. */
export const RECHECK_SECONDS = 15 * 60;
/** While PocketBase is unreachable, a user checked within this window keeps working. */
export const OFFLINE_GRACE_SECONDS = 24 * 3600;

type Db = Deps['db'];

/** Issues a new signed-in token for the device. The previous one stops working immediately. */
export async function issueToken(q: Queryer, deviceId: string): Promise<{ token: string; expiresAt: string }> {
  const token = randomToken(32);
  const { rows } = await q.query(
    `UPDATE devices SET token_hash = $2, token_issued_at = now(), token_expires_at = now() + make_interval(days => $3),
            prev_token_hash = NULL, prev_token_grace_until = NULL, signed_out_at = NULL, signed_out_reason = NULL,
            user_checked_at = now(), last_seen_at = now()
      WHERE id = $1 RETURNING token_expires_at`,
    [deviceId, sha256Hex(token), TOKEN_TTL_DAYS],
  );
  return { token, expiresAt: new Date(rows[0].token_expires_at).toISOString() };
}

/** Rotation: a new token, the current one kept as `prev` for a short grace period. */
export async function rotateToken(q: Queryer, deviceId: string, currentHash: string): Promise<{ token: string; expiresAt: string }> {
  const token = randomToken(32);
  const { rows } = await q.query(
    `UPDATE devices SET token_hash = $2, prev_token_hash = $3, prev_token_grace_until = now() + make_interval(secs => $4),
            token_issued_at = now(), token_expires_at = now() + make_interval(days => $5)
      WHERE id = $1 AND token_hash = $3 RETURNING token_expires_at`,
    [deviceId, sha256Hex(token), currentHash, ROTATE_GRACE_SECONDS, TOKEN_TTL_DAYS],
  );
  if (!rows[0]) fail(409, 'token_changed', 'this sign-in changed; sign in again');
  return { token, expiresAt: new Date(rows[0].token_expires_at).toISOString() };
}

/** Ends a device's session: its token (and any previous token) stop working, and its installation id is released. */
export async function endSession(q: Queryer, deviceId: string, reason: string): Promise<void> {
  await q.query(
    `UPDATE devices SET token_hash = $2, prev_token_hash = NULL, prev_token_grace_until = NULL, signed_out_at = now(),
            signed_out_reason = $3, install_id = NULL, token_expires_at = NULL
      WHERE id = $1`,
    [deviceId, sha256Hex(randomToken(32)), reason.slice(0, 40)],
  );
}

export async function endUserSessions(q: Queryer, userId: string, reason: string): Promise<number> {
  const { rows } = await q.query('SELECT id FROM devices WHERE user_id = $1 AND signed_out_at IS NULL', [userId]);
  for (const r of rows) await endSession(q, r.id, reason);
  return rows.length;
}

const loginCache = new WeakMap<object, { value: boolean; at: number }>();

/** The owner's "Require sign-in for central AI" setting (cached for 5 seconds per process). Off unless set to true. */
export async function requireLoginForCentralAi(db: Db): Promise<boolean> {
  const hit = loginCache.get(db);
  if (hit && Date.now() - hit.at < 5_000) return hit.value;
  const s = await readSettings(db);
  const value = s.require_login_for_central_ai === true;
  loginCache.set(db, { value, at: Date.now() });
  return value;
}

export function forgetLoginSetting(db: Db): void {
  loginCache.delete(db);
}

/**
 * Binds this installation to `userId` and issues a signed-in token. `proofHash` is the sha256 of the device token the
 * request presented (Authorization header), or null.
 */
export async function bindDevice(
  db: Db,
  input: { userId: string; installId: string; deviceName: string; proofHash: string | null },
): Promise<{ deviceId: string; token: string; expiresAt: string; claimed: 'new' | 'same_user' | 'legacy' | 'switched' }> {
  return db.transaction(async (q) => {
    const u = await q.query(
      `INSERT INTO app_users (user_id, last_login_at) VALUES ($1, now())
       ON CONFLICT (user_id) DO UPDATE SET last_login_at = now() RETURNING status`,
      [input.userId],
    );
    const status = u.rows[0].status as string;
    if (status === 'blocked') fail(403, 'account_blocked', 'this account has been blocked by the administrator');
    if (status !== 'active') fail(403, 'account_deleted', 'this account has been deleted');

    const { rows } = await q.query('SELECT id, status, user_id, token_hash FROM devices WHERE install_id = $1 FOR UPDATE', [input.installId]);
    const row = rows[0];
    const proven = !!row && !!input.proofHash && row.token_hash === input.proofHash;
    if (row && row.status !== 'active') fail(403, 'device_blocked', 'the owner has blocked this computer');
    let deviceId: string;
    let claimed: 'new' | 'same_user' | 'legacy' | 'switched';
    if (row && row.user_id === input.userId) {
      deviceId = row.id;
      claimed = 'same_user';
    } else if (row && row.user_id === null) {
      // Knowing an installation id is not enough to take over a computer (and its memory): prove the current token.
      if (!proven) fail(409, 'device_proof_required', 'this computer is registered already; sign in again from the Devora app on it');
      deviceId = row.id;
      claimed = 'legacy';
    } else if (row) {
      if (!proven) fail(409, 'device_proof_required', 'this computer is signed in to another account; sign out there first');
      await endSession(q, row.id, 'switched_account');
      deviceId = await newDevice(q, input);
      claimed = 'switched';
    } else {
      deviceId = await newDevice(q, input);
      claimed = 'new';
    }
    await q.query('UPDATE devices SET user_id = $2, name = $3, install_id = $4 WHERE id = $1', [deviceId, input.userId, input.deviceName, input.installId]);
    const t = await issueToken(q, deviceId);
    return { deviceId, ...t, claimed };
  });
}

async function newDevice(q: Queryer, input: { installId: string; deviceName: string }): Promise<string> {
  const { rows } = await q.query(
    `INSERT INTO devices (name, token_hash, registered_via, last_seen_at) VALUES ($1, $2, 'auto', now()) RETURNING id`,
    [input.deviceName, sha256Hex(randomToken(32))],
  );
  return rows[0].id;
}

// ------------------------------------------------------------------ account re-checks

const inflight = new Map<string, Promise<'ok' | 'deleted' | 'unverified' | 'unavailable'>>();

/**
 * Re-reads the user from PocketBase (as superuser): the account must still exist and be verified. A deleted account starts
 * the deletion journal (ends every session, removes Devora data). Concurrent checks for one user share one request.
 */
export function recheckUser(deps: Deps, userId: string): Promise<'ok' | 'deleted' | 'unverified' | 'unavailable'> {
  const running = inflight.get(userId);
  if (running) return running;
  const p = (async () => {
    if (!deps.pocketbase) return 'unavailable' as const;
    try {
      const user = await deps.pocketbase.getUser(userId);
      if (!user) {
        await markDeleted(deps.db, userId, 'data');
        void runDeletion(deps, userId).catch(() => undefined);
        return 'deleted' as const;
      }
      if (!user.verified) return 'unverified' as const;
      await deps.db.query('UPDATE devices SET user_checked_at = now() WHERE user_id = $1 AND signed_out_at IS NULL', [userId]);
      return 'ok' as const;
    } catch (e) {
      log('warn', 'account check failed', { reason: e instanceof PbError ? e.status : 'error' });
      return 'unavailable' as const;
    }
  })().finally(() => inflight.delete(userId));
  inflight.set(userId, p);
  return p;
}

// ------------------------------------------------------------------ account deletion journal

/** Marks the account as being deleted and ends every session in one transaction. */
export async function markDeleted(db: Db, userId: string, firstStep: 'devices' | 'data'): Promise<void> {
  await db.transaction(async (q) => {
    await q.query(
      `INSERT INTO app_users (user_id, status, deletion_requested_at, deletion_step) VALUES ($1, 'deleting', now(), $2)
       ON CONFLICT (user_id) DO UPDATE SET status = 'deleting', deletion_requested_at = coalesce(app_users.deletion_requested_at, now()),
         deletion_step = CASE WHEN app_users.status = 'deleting' THEN app_users.deletion_step ELSE EXCLUDED.deletion_step END
       WHERE app_users.status <> 'deleted'`,
      [userId, firstStep],
    );
    await endUserSessions(q, userId, 'account_deleted');
  });
}

/**
 * Runs (or resumes) a deletion. Each step commits with the journal, so a crash or a PocketBase outage leaves a recorded
 * state that the background job finishes:
 *   devices  - every session of the user ends (tokens replaced, installation ids released)
 *   data     - the user's synced memory is deleted, handoffs removed, devices unlinked and renamed. Request logs (no prompt
 *              or response content, only model, status and token counts) stay for usage/audit until log retention.
 *   identity - the PocketBase user is deleted (PocketBase also removes its _externalAuths); already gone counts as done.
 * The app_users row stays as a tombstone (random id and dates only).
 */
export async function runDeletion(deps: Deps, userId: string): Promise<'done' | 'pending'> {
  for (let i = 0; i < 5; i++) {
    const { rows } = await deps.db.query('SELECT status, deletion_step FROM app_users WHERE user_id = $1', [userId]);
    const row = rows[0];
    if (!row || row.status === 'deleted') return 'done';
    if (row.status !== 'deleting') return 'pending';
    try {
      if (row.deletion_step === 'devices') {
        await deps.db.transaction(async (q) => {
          await endUserSessions(q, userId, 'account_deleted');
          await q.query("UPDATE app_users SET deletion_step = 'data', deletion_error = NULL WHERE user_id = $1", [userId]);
        });
      } else if (row.deletion_step === 'data') {
        await deps.db.transaction(async (q) => {
          await endUserSessions(q, userId, 'account_deleted');
          await q.query('DELETE FROM memory_entries WHERE device_id IN (SELECT id FROM devices WHERE user_id = $1)', [userId]);
          await q.query('DELETE FROM auth_handoffs WHERE user_id = $1 OR expected_user_id = $1', [userId]);
          await q.query("UPDATE devices SET user_id = NULL, name = 'Deleted account' WHERE user_id = $1", [userId]);
          await q.query("UPDATE app_users SET deletion_step = 'identity', deletion_error = NULL WHERE user_id = $1", [userId]);
        });
      } else if (row.deletion_step === 'identity') {
        if (!deps.pocketbase) throw new PbError(0, 'accounts are not configured on this server');
        await deps.pocketbase.deleteUser(userId);
        await deps.db.query("UPDATE app_users SET deletion_step = 'done', status = 'deleted', deleted_at = now(), deletion_error = NULL WHERE user_id = $1", [userId]);
        return 'done';
      } else {
        await deps.db.query("UPDATE app_users SET status = 'deleted', deleted_at = coalesce(deleted_at, now()) WHERE user_id = $1", [userId]);
        return 'done';
      }
    } catch (e) {
      const msg = e instanceof PbError ? e.message : 'the deletion step failed';
      await deps.db.query('UPDATE app_users SET deletion_error = $2 WHERE user_id = $1', [userId, msg.slice(0, 200)]).catch(() => undefined);
      log('warn', 'account deletion step failed', { step: row.deletion_step });
      return 'pending';
    }
  }
  return 'pending';
}

/** Background job: finishes interrupted deletions and removes expired sign-in handoffs. */
export async function accountMaintenance(deps: Deps): Promise<void> {
  await deps.db.query("DELETE FROM auth_handoffs WHERE expires_at < now() - interval '1 hour'");
  const { rows } = await deps.db.query("SELECT user_id FROM app_users WHERE status = 'deleting' ORDER BY deletion_requested_at LIMIT 20");
  for (const r of rows) await runDeletion(deps, r.user_id);
}
