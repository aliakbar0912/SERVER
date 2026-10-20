-- Devora central platform, schema version 3: per-device model access, server-side fallback, discovery metadata.
-- Additive only. Existing rows keep their behaviour: every device keeps access to all enabled models, no model has a fallback.

-- migrate:up

-- Which models a device may use. 'all' = every enabled model (the previous behaviour). 'selected' = only the rows in device_models.
ALTER TABLE devices ADD COLUMN model_access text NOT NULL DEFAULT 'all' CHECK (model_access IN ('all', 'selected'));

CREATE TABLE device_models (
  device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  model_id uuid NOT NULL REFERENCES models(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, model_id)
);
CREATE INDEX device_models_model_idx ON device_models (model_id);

-- Optional fallback used by the server when the upstream of this model fails before any reply was sent.
ALTER TABLE models ADD COLUMN fallback_model_id uuid REFERENCES models(id) ON DELETE SET NULL;
ALTER TABLE models ADD CONSTRAINT models_fallback_not_self CHECK (fallback_model_id IS NULL OR fallback_model_id <> id);
-- Where the entry came from, and when the provider's model list last contained it (null = never seen in a listing).
ALTER TABLE models ADD COLUMN source text NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'discovered'));
ALTER TABLE models ADD COLUMN last_listed_at timestamptz;

-- Model discovery results, kept apart from the connectivity test so an unsupported model list never marks a provider as failing.
ALTER TABLE providers ADD COLUMN discovery_supported boolean;
ALTER TABLE providers ADD COLUMN discovery_at timestamptz;
ALTER TABLE providers ADD COLUMN discovery_ok boolean;
ALTER TABLE providers ADD COLUMN discovery_message text;
-- The failure kind of the last connectivity test (auth, timeout, unreachable, server, rejected, rate_limited, bad_response).
ALTER TABLE providers ADD COLUMN last_test_kind text;

-- Recent outcomes per provider, for availability.
CREATE INDEX request_logs_provider_created_idx ON request_logs (provider_id, created_at DESC);

-- migrate:down
DROP INDEX IF EXISTS request_logs_provider_created_idx;
ALTER TABLE providers DROP COLUMN IF EXISTS last_test_kind;
ALTER TABLE providers DROP COLUMN IF EXISTS discovery_message;
ALTER TABLE providers DROP COLUMN IF EXISTS discovery_ok;
ALTER TABLE providers DROP COLUMN IF EXISTS discovery_at;
ALTER TABLE providers DROP COLUMN IF EXISTS discovery_supported;
ALTER TABLE models DROP COLUMN IF EXISTS last_listed_at;
ALTER TABLE models DROP COLUMN IF EXISTS source;
ALTER TABLE models DROP CONSTRAINT IF EXISTS models_fallback_not_self;
ALTER TABLE models DROP COLUMN IF EXISTS fallback_model_id;
DROP TABLE IF EXISTS device_models;
ALTER TABLE devices DROP COLUMN IF EXISTS model_access;
