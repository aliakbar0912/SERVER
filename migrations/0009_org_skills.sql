-- Devora central platform, schema version 9: skills the owner publishes to every desktop from the admin site.
-- Additive only. Desktops download them with their device token and show them as "Organization" skills (read-only
-- there; users can still turn each one off for themselves).

-- migrate:up
CREATE TABLE org_skills (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,59}$'),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
  description text NOT NULL CHECK (char_length(description) BETWEEN 1 AND 1024),
  triggers jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(triggers) = 'array'),
  instructions text NOT NULL CHECK (char_length(instructions) BETWEEN 1 AND 12000),
  examples text NOT NULL DEFAULT '' CHECK (char_length(examples) <= 8000),
  enabled boolean NOT NULL DEFAULT true,
  revision integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Bumped on every change, so desktops know when to download the list again.
INSERT INTO settings (key, value) VALUES ('skills_version', '1') ON CONFLICT (key) DO NOTHING;

-- migrate:down
DELETE FROM settings WHERE key = 'skills_version';
DROP TABLE IF EXISTS org_skills;
