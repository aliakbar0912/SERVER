-- Devora central platform, schema version 2: persistent rate limits, device concurrency leases, and request idempotency.
-- Additive only. Existing tables, rows and the 0001 schema are unchanged except for two nullable columns on request_logs.
-- Applied by `node dist/cli.mjs migrate up`. Each migration runs in one transaction.

-- migrate:up

-- Fixed-window counters shared by every backend process. Old buckets are pruned by the server.
CREATE TABLE rate_counters (
  key text NOT NULL CHECK (char_length(key) BETWEEN 1 AND 200),
  bucket bigint NOT NULL,
  count integer NOT NULL DEFAULT 0 CHECK (count >= 0),
  PRIMARY KEY (key, bucket)
);
CREATE INDEX rate_counters_bucket_idx ON rate_counters (bucket);

-- One row per in-flight chat request. A row that outlives its lease (for example after a crash) stops counting.
CREATE TABLE device_request_leases (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  request_id text NOT NULL CHECK (char_length(request_id) BETWEEN 1 AND 64),
  client_request_id text CHECK (client_request_id IS NULL OR char_length(client_request_id) BETWEEN 8 AND 64),
  started_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
CREATE INDEX device_request_leases_device_idx ON device_request_leases (device_id, expires_at);
CREATE UNIQUE INDEX device_request_leases_client_idx ON device_request_leases (device_id, client_request_id) WHERE client_request_id IS NOT NULL;

-- Server-generated id for log correlation, and the optional client Idempotency-Key. Both are nullable for old rows.
ALTER TABLE request_logs ADD COLUMN request_id text;
ALTER TABLE request_logs ADD COLUMN client_request_id text CHECK (client_request_id IS NULL OR char_length(client_request_id) BETWEEN 8 AND 64);
CREATE UNIQUE INDEX request_logs_client_request_idx ON request_logs (device_id, client_request_id) WHERE client_request_id IS NOT NULL;

-- migrate:down
DROP INDEX IF EXISTS request_logs_client_request_idx;
ALTER TABLE request_logs DROP COLUMN IF EXISTS client_request_id;
ALTER TABLE request_logs DROP COLUMN IF EXISTS request_id;
DROP TABLE IF EXISTS device_request_leases;
DROP TABLE IF EXISTS rate_counters;
