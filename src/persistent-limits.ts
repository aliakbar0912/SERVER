// Limits that survive restarts and are shared by every backend process: fixed-window rate counters and per-device
// request leases. Both live in PostgreSQL. Windows use the database clock, so processes agree on the bucket.
import type { Db, Queryer } from './db/pg-wire.ts';

export interface RateResult {
  allowed: boolean;
  retryAfterSeconds: number;
}

/** Counts one hit in the current fixed window. Atomic: one upsert, no read-modify-write race. */
export async function hitRate(q: Queryer, key: string, limit: number, windowSeconds: number): Promise<RateResult> {
  // bucket = epoch second at which the current window started, so windows of different sizes can share the table.
  const { rows } = await q.query(
    `INSERT INTO rate_counters (key, bucket, count)
     VALUES ($1, (floor(extract(epoch FROM now()) / $2) * $2)::bigint, 1)
     ON CONFLICT (key, bucket) DO UPDATE SET count = rate_counters.count + 1
     RETURNING count::int AS count,
               greatest(1, ceil(bucket + $2 - extract(epoch FROM now())))::int AS retry_after`,
    [key, windowSeconds],
  );
  const r = rows[0];
  if (r.count > limit) return { allowed: false, retryAfterSeconds: r.retry_after };
  return { allowed: true, retryAfterSeconds: 0 };
}

/** Clears every window for a key after a success (for example a successful login). */
export async function clearRate(q: Queryer, key: string): Promise<void> {
  await q.query('DELETE FROM rate_counters WHERE key = $1', [key]);
}

/** Drops windows that started more than one hour ago. Every window in use is shorter than that, so no live counter is removed. */
export async function pruneRates(q: Queryer): Promise<number> {
  const { rowCount } = await q.query("DELETE FROM rate_counters WHERE bucket < extract(epoch FROM now())::bigint - 3600");
  return rowCount;
}

export type SlotResult = 'ok' | 'busy' | 'duplicate';

export interface SlotRequest {
  deviceId: string;
  requestId: string;
  clientRequestId: string | null;
  maxConcurrent: number;
  leaseSeconds: number;
}

/**
 * Takes one request slot for a device. A transaction-scoped advisory lock on the device serialises only that device's
 * checks, so devices never wait on each other. Leases past their expiry are removed first, so a crashed request frees its slot.
 * A client request id that already has a lease or a completed log row is reported as 'duplicate' and no upstream call is made.
 */
export async function acquireSlot(db: Db, r: SlotRequest): Promise<SlotResult> {
  return db.transaction(async (q) => {
    await q.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`device-slot:${r.deviceId}`]);
    await q.query('DELETE FROM device_request_leases WHERE device_id = $1 AND expires_at <= now()', [r.deviceId]);
    if (r.clientRequestId) {
      const seen = await q.query(
        `SELECT 1 FROM device_request_leases WHERE device_id = $1 AND client_request_id = $2
         UNION ALL
         SELECT 1 FROM request_logs WHERE device_id = $1 AND client_request_id = $2
         LIMIT 1`,
        [r.deviceId, r.clientRequestId],
      );
      if (seen.rows.length) return 'duplicate';
    }
    const { rows } = await q.query('SELECT count(*)::int AS n FROM device_request_leases WHERE device_id = $1', [r.deviceId]);
    if (rows[0].n >= r.maxConcurrent) return 'busy';
    await q.query(
      `INSERT INTO device_request_leases (device_id, request_id, client_request_id, expires_at)
       VALUES ($1, $2, $3, now() + make_interval(secs => $4))`,
      [r.deviceId, r.requestId, r.clientRequestId, r.leaseSeconds],
    );
    return 'ok';
  });
}

export async function releaseSlot(q: Queryer, requestId: string): Promise<void> {
  await q.query('DELETE FROM device_request_leases WHERE request_id = $1', [requestId]);
}

export async function activeLeaseCount(q: Queryer): Promise<number> {
  const { rows } = await q.query('SELECT count(*)::int AS n FROM device_request_leases WHERE expires_at > now()');
  return rows[0].n;
}
