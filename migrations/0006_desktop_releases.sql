-- Devora central platform, schema version 6: desktop app updates published from the admin site.
-- The owner uploads an installer (stored in the database in chunks, so it survives redeploys without a volume) or points to
-- an https download with its SHA-256, then publishes it. Desktop apps check, download, verify and install it.
-- Additive only.

-- migrate:up
CREATE TABLE desktop_releases (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  version text NOT NULL UNIQUE CHECK (version ~ '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$'),
  notes text NOT NULL DEFAULT '' CHECK (char_length(notes) <= 10000),
  mandatory boolean NOT NULL DEFAULT false,
  status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published')),
  source text NOT NULL DEFAULT 'upload' CHECK (source IN ('upload', 'url')),
  external_url text CHECK (external_url IS NULL OR external_url ~ '^https://'),
  file_name text NOT NULL DEFAULT '' CHECK (char_length(file_name) <= 200),
  file_size bigint NOT NULL DEFAULT 0 CHECK (file_size >= 0),
  sha256 text CHECK (sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'),
  upload_complete boolean NOT NULL DEFAULT false,
  downloads integer NOT NULL DEFAULT 0 CHECK (downloads >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz
);

-- The uploaded installer, in order. Chunks are written as the admin site uploads them and checked when the upload finishes.
CREATE TABLE desktop_release_chunks (
  release_id uuid NOT NULL REFERENCES desktop_releases(id) ON DELETE CASCADE,
  seq integer NOT NULL CHECK (seq >= 0),
  data bytea NOT NULL,
  PRIMARY KEY (release_id, seq)
);

-- The desktop version each computer last reported, for the update rollout view.
ALTER TABLE devices ADD COLUMN app_version text CHECK (app_version IS NULL OR char_length(app_version) <= 40);

-- migrate:down
ALTER TABLE devices DROP COLUMN IF EXISTS app_version;
DROP TABLE IF EXISTS desktop_release_chunks;
DROP TABLE IF EXISTS desktop_releases;
