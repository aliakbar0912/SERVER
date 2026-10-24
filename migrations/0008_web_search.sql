-- Devora central platform, schema version 8: web search providers for the agent's web_search tool.
-- Additive only. Search provider API keys are encrypted with DEVORA_SECRET_KEYS like model provider keys and never leave
-- the server: desktops call /v1/search with their device token and get normalized results.

-- migrate:up
CREATE TABLE search_providers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 80),
  kind text NOT NULL CHECK (kind IN ('tavily', 'brave', 'serper', 'exa', 'google_cse', 'searxng')),
  -- Only SearXNG (self-hosted) has a base URL; the others use their fixed public API address.
  base_url text CHECK (base_url IS NULL OR char_length(base_url) BETWEEN 8 AND 2048),
  -- Non-secret options, for example the Google Programmable Search Engine id (cx).
  options jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(options) = 'object'),
  enabled boolean NOT NULL DEFAULT true,
  is_default boolean NOT NULL DEFAULT false,
  -- Fallback order after the default: lower first.
  priority integer NOT NULL DEFAULT 100 CHECK (priority BETWEEN 0 AND 1000),
  last_test_ok boolean,
  last_test_at timestamptz,
  last_test_latency_ms integer,
  last_test_message text CHECK (last_test_message IS NULL OR char_length(last_test_message) <= 300),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX search_providers_one_default ON search_providers (is_default) WHERE is_default;

CREATE TABLE search_provider_secrets (
  provider_id uuid PRIMARY KEY REFERENCES search_providers(id) ON DELETE CASCADE,
  key_version integer NOT NULL,
  iv bytea NOT NULL,
  ciphertext bytea NOT NULL,
  tag bytea NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- One row per search request (no query text is stored: queries can contain private project details).
CREATE TABLE search_logs (
  id bigserial PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  device_id uuid REFERENCES devices(id) ON DELETE SET NULL,
  provider_id uuid REFERENCES search_providers(id) ON DELETE SET NULL,
  provider_name text NOT NULL,
  status text NOT NULL CHECK (status IN ('ok', 'error', 'cached')),
  error_code text CHECK (error_code IS NULL OR char_length(error_code) <= 40),
  results integer NOT NULL DEFAULT 0,
  latency_ms integer NOT NULL DEFAULT 0
);
CREATE INDEX search_logs_created_idx ON search_logs (created_at DESC);

INSERT INTO settings (key, value) VALUES ('search_per_minute', '20') ON CONFLICT (key) DO NOTHING;

-- migrate:down
DELETE FROM settings WHERE key = 'search_per_minute';
DROP TABLE IF EXISTS search_logs;
DROP TABLE IF EXISTS search_provider_secrets;
DROP TABLE IF EXISTS search_providers;
