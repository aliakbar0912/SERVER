-- Devora central platform, schema version 7: Devora accounts (PocketBase users) linked to desktop devices.
-- Additive only. No existing row is changed: every current device keeps its token, its memory and its request logs, and
-- stays an unclaimed ("legacy") device until someone signs in on that computer and proves they hold its current token.
-- PocketBase stays the source of truth for identities; PostgreSQL only stores the stable PocketBase user id.

-- migrate:up

-- The PocketBase user this device is signed in as. Null = legacy / signed-out device (works as before, unless the owner
-- turns on "Require sign-in for central AI").
ALTER TABLE devices ADD COLUMN user_id text CHECK (user_id IS NULL OR user_id ~ '^[A-Za-z0-9_]{1,64}$');
-- Tokens issued after sign-in expire and rotate. Null = a token issued before version 7 (no expiry, as before).
ALTER TABLE devices ADD COLUMN token_issued_at timestamptz;
ALTER TABLE devices ADD COLUMN token_expires_at timestamptz;
-- The token replaced by the last rotation. Accepted for a short grace period (a lost response); used after that it is
-- treated as a stolen copy and the session is ended.
ALTER TABLE devices ADD COLUMN prev_token_hash text;
ALTER TABLE devices ADD COLUMN prev_token_grace_until timestamptz;
-- When the server last confirmed with PocketBase that the user still exists and is verified.
ALTER TABLE devices ADD COLUMN user_checked_at timestamptz;
-- Set when the session ended (logout, account deleted, token reuse, ...). The token is replaced by a random value then.
ALTER TABLE devices ADD COLUMN signed_out_at timestamptz;
ALTER TABLE devices ADD COLUMN signed_out_reason text CHECK (signed_out_reason IS NULL OR char_length(signed_out_reason) <= 40);
CREATE INDEX devices_user_idx ON devices (user_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX devices_prev_token_idx ON devices (prev_token_hash) WHERE prev_token_hash IS NOT NULL;

-- Devora's operational state for a PocketBase user: blocking by the owner and the account-deletion journal. No email,
-- name or other identity data is copied here; the admin panel reads those from PocketBase.
CREATE TABLE app_users (
  user_id text PRIMARY KEY CHECK (user_id ~ '^[A-Za-z0-9_]{1,64}$'),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'blocked', 'deleting', 'deleted')),
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz,
  blocked_at timestamptz,
  deletion_requested_at timestamptz,
  -- Next step of an interrupted deletion: devices, data, identity, done.
  deletion_step text CHECK (deletion_step IS NULL OR deletion_step IN ('devices', 'data', 'identity', 'done')),
  deletion_error text CHECK (deletion_error IS NULL OR char_length(deletion_error) <= 200),
  deleted_at timestamptz
);
CREATE INDEX app_users_deleting_idx ON app_users (deletion_requested_at) WHERE status = 'deleting';

-- One browser sign-in (Google, GitHub, ...). Only hashes of the OAuth state, the desktop's handoff secret and the 60 second
-- result code are stored. The PKCE verifier is single-use and expires with the row. A PocketBase user token (only for
-- linking a provider to the signed-in account) is stored encrypted and cleared as soon as the callback runs.
CREATE TABLE auth_handoffs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  purpose text NOT NULL CHECK (purpose IN ('login', 'link', 'reauth')),
  provider text NOT NULL CHECK (provider ~ '^[a-z0-9_]{1,40}$'),
  state_hash text NOT NULL UNIQUE,
  secret_hash text NOT NULL,
  code_verifier text NOT NULL CHECK (char_length(code_verifier) BETWEEN 43 AND 128),
  redirect_uri text NOT NULL,
  loopback_port integer NOT NULL CHECK (loopback_port BETWEEN 1024 AND 65535),
  loopback_nonce text NOT NULL CHECK (loopback_nonce ~ '^[A-Za-z0-9_-]{16,64}$'),
  -- link / reauth: the signed-in device and user that started it.
  device_id uuid REFERENCES devices(id) ON DELETE CASCADE,
  expected_user_id text,
  user_token_sealed jsonb,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'failed', 'consumed')),
  error_code text CHECK (error_code IS NULL OR char_length(error_code) <= 40),
  user_id text,
  result_code_hash text UNIQUE,
  result_expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz
);
CREATE INDEX auth_handoffs_expires_idx ON auth_handoffs (expires_at);

-- Off by default: devices without a signed-in user keep using central AI exactly as before.
INSERT INTO settings (key, value) VALUES ('require_login_for_central_ai', 'false') ON CONFLICT (key) DO NOTHING;

-- migrate:down
-- Rolling back forgets which devices are signed in (their tokens keep working as legacy tokens). Devices and their
-- memory and logs are not deleted.
DELETE FROM settings WHERE key = 'require_login_for_central_ai';
DROP TABLE IF EXISTS auth_handoffs;
DROP TABLE IF EXISTS app_users;
DROP INDEX IF EXISTS devices_prev_token_idx;
DROP INDEX IF EXISTS devices_user_idx;
ALTER TABLE devices DROP COLUMN IF EXISTS signed_out_reason;
ALTER TABLE devices DROP COLUMN IF EXISTS signed_out_at;
ALTER TABLE devices DROP COLUMN IF EXISTS user_checked_at;
ALTER TABLE devices DROP COLUMN IF EXISTS prev_token_grace_until;
ALTER TABLE devices DROP COLUMN IF EXISTS prev_token_hash;
ALTER TABLE devices DROP COLUMN IF EXISTS token_expires_at;
ALTER TABLE devices DROP COLUMN IF EXISTS token_issued_at;
ALTER TABLE devices DROP COLUMN IF EXISTS user_id;
