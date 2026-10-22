-- Devora central platform, schema version 5: device memory sync.
-- Long-term agent memory ("brain") mirrored from desktop installs. One row per deterministic client key per device,
-- so the same memory statement is idempotent across pushes. Tombstones (deleted) make forgets propagate.

-- migrate:up
CREATE TABLE memory_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  client_key text NOT NULL CHECK (char_length(client_key) BETWEEN 16 AND 128),
  scope text NOT NULL CHECK (scope IN ('global', 'project')),
  project_key text NOT NULL DEFAULT '' CHECK (char_length(project_key) <= 120),
  kind text NOT NULL CHECK (kind IN ('fact', 'preference', 'lesson', 'decision')),
  content text NOT NULL CHECK (char_length(content) BETWEEN 4 AND 600),
  tags jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(tags) = 'array'),
  source text NOT NULL CHECK (source IN ('user', 'agent', 'system')),
  confidence real NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  verified boolean NOT NULL DEFAULT false,
  pinned boolean NOT NULL DEFAULT false,
  hits integer NOT NULL DEFAULT 0 CHECK (hits >= 0),
  deleted boolean NOT NULL DEFAULT false,
  client_updated_at bigint NOT NULL CHECK (client_updated_at >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (device_id, client_key)
);
CREATE INDEX memory_entries_device_idx ON memory_entries (device_id, updated_at DESC);

-- migrate:down
DROP TABLE IF EXISTS memory_entries;
