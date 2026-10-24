-- Devora central platform, schema version 10: API keys for programmatic access to the central platform API.
-- The owner creates keys in the admin site (name, scopes, optional expiry). Only the sha256 hash is stored;
-- the secret is shown once at creation. Keys authenticate POST /v1/chat/completions and GET /v1/models
-- with `Authorization: Bearer dvk_...`, so scripts and integrations can use the platform without a desktop device.

-- migrate:up
CREATE TABLE api_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
  key_hash text NOT NULL UNIQUE CHECK (char_length(key_hash) = 64),
  -- Short, safe-to-show identifier: the key prefix (with dvk_) and its last 4 characters.
  key_prefix text NOT NULL CHECK (char_length(key_prefix) BETWEEN 5 AND 24),
  last4 text NOT NULL CHECK (last4 ~ '^[A-Za-z0-9]{4}$'),
  scopes jsonb NOT NULL DEFAULT '["chat"]'::jsonb CHECK (jsonb_typeof(scopes) = 'array'),
  enabled boolean NOT NULL DEFAULT true,
  expires_at timestamptz,
  last_used_at timestamptz,
  request_count bigint NOT NULL DEFAULT 0 CHECK (request_count >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX api_keys_enabled_idx ON api_keys (enabled);

-- Chat requests authenticated by an API key hold a lease against the key, not a device.
ALTER TABLE device_request_leases ALTER COLUMN device_id DROP NOT NULL;
ALTER TABLE device_request_leases ADD COLUMN api_key_id uuid REFERENCES api_keys(id) ON DELETE CASCADE;
ALTER TABLE device_request_leases ADD CONSTRAINT device_request_leases_owner CHECK ((device_id IS NOT NULL) <> (api_key_id IS NOT NULL));
CREATE INDEX device_request_leases_api_key_idx ON device_request_leases (api_key_id, expires_at);

-- Usage rows record which key made the request (nullable: device requests keep device_id).
ALTER TABLE request_logs ADD COLUMN api_key_id uuid REFERENCES api_keys(id) ON DELETE SET NULL;
CREATE INDEX request_logs_api_key_idx ON request_logs (api_key_id) WHERE api_key_id IS NOT NULL;

-- Per-minute request limit for API keys (the Settings page exposes it).
INSERT INTO settings (key, value) VALUES ('api_key_rate_limit_per_minute', '30') ON CONFLICT (key) DO NOTHING;

-- migrate:down
DROP INDEX IF EXISTS request_logs_api_key_idx;
ALTER TABLE request_logs DROP COLUMN IF EXISTS api_key_id;
DROP INDEX IF EXISTS device_request_leases_api_key_idx;
ALTER TABLE device_request_leases DROP CONSTRAINT IF EXISTS device_request_leases_owner;
ALTER TABLE device_request_leases DROP COLUMN IF EXISTS api_key_id;
ALTER TABLE device_request_leases ALTER COLUMN device_id SET NOT NULL;
DROP TABLE IF EXISTS api_keys;
DELETE FROM settings WHERE key = 'api_key_rate_limit_per_minute';
