-- Devora central platform, schema version 1.
-- Applied by `node dist/cli.mjs migrate up`. Each migration runs in one transaction.

-- migrate:up
CREATE TABLE owners (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL UNIQUE CHECK (char_length(email) BETWEEN 3 AND 254),
  password_hash text NOT NULL,
  failed_logins integer NOT NULL DEFAULT 0,
  locked_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE admin_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  csrf_token text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  reauth_until timestamptz,
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  ip text,
  user_agent text
);
CREATE INDEX admin_sessions_owner_idx ON admin_sessions (owner_id);

CREATE TABLE providers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 80),
  adapter text NOT NULL CHECK (adapter IN ('openai-compatible')),
  base_url text NOT NULL CHECK (char_length(base_url) BETWEEN 8 AND 2048),
  auth_scheme text NOT NULL CHECK (auth_scheme IN ('bearer', 'none')),
  enabled boolean NOT NULL DEFAULT true,
  timeout_ms integer NOT NULL DEFAULT 120000 CHECK (timeout_ms BETWEEN 1000 AND 600000),
  max_retries integer NOT NULL DEFAULT 0 CHECK (max_retries BETWEEN 0 AND 3),
  last_test_ok boolean,
  last_test_at timestamptz,
  last_test_latency_ms integer,
  last_test_message text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE provider_secrets (
  provider_id uuid PRIMARY KEY REFERENCES providers(id) ON DELETE CASCADE,
  key_version integer NOT NULL,
  iv bytea NOT NULL,
  ciphertext bytea NOT NULL,
  tag bytea NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE models (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id uuid NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
  upstream_model_id text NOT NULL CHECK (char_length(upstream_model_id) BETWEEN 1 AND 200),
  display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 120),
  description text NOT NULL DEFAULT '',
  enabled boolean NOT NULL DEFAULT false,
  is_default boolean NOT NULL DEFAULT false,
  context_window integer CHECK (context_window IS NULL OR context_window > 0),
  capabilities jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider_id, upstream_model_id)
);
CREATE UNIQUE INDEX models_one_default_idx ON models (is_default) WHERE is_default;

CREATE TABLE devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  token_hash text NOT NULL UNIQUE,
  created_by uuid REFERENCES owners(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz,
  revoked_at timestamptz
);

CREATE TABLE enrollment_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code_hash text NOT NULL UNIQUE,
  label text NOT NULL DEFAULT '',
  created_by uuid REFERENCES owners(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  device_id uuid REFERENCES devices(id) ON DELETE SET NULL
);

-- Names are copied into each row so logs stay readable after a provider or model is removed.
CREATE TABLE request_logs (
  id bigserial PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  device_id uuid REFERENCES devices(id) ON DELETE SET NULL,
  model_id uuid REFERENCES models(id) ON DELETE SET NULL,
  model_name text NOT NULL,
  provider_id uuid REFERENCES providers(id) ON DELETE SET NULL,
  provider_name text NOT NULL,
  status text NOT NULL CHECK (status IN ('ok', 'error', 'cancelled')),
  http_status integer NOT NULL,
  error_code text,
  stream boolean NOT NULL DEFAULT false,
  latency_ms integer NOT NULL,
  ttft_ms integer,
  prompt_tokens integer,
  completion_tokens integer,
  usage_source text NOT NULL DEFAULT 'none' CHECK (usage_source IN ('provider_reported', 'none'))
);
CREATE INDEX request_logs_created_idx ON request_logs (created_at DESC);

CREATE TABLE settings (
  key text PRIMARY KEY,
  value jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO settings (key, value) VALUES
  ('catalogue_version', '1'),
  ('rate_limit_per_minute', '60'),
  ('max_concurrent_per_device', '2'),
  ('max_output_tokens', '8192'),
  ('allow_direct_provider', 'false');

-- migrate:down
DROP TABLE IF EXISTS request_logs;
DROP TABLE IF EXISTS enrollment_codes;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS models;
DROP TABLE IF EXISTS provider_secrets;
DROP TABLE IF EXISTS providers;
DROP TABLE IF EXISTS admin_sessions;
DROP TABLE IF EXISTS owners;
DROP TABLE IF EXISTS settings;
