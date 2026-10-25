-- Devora central platform, schema version 14: announcements the owner publishes to every desktop from the admin site.
-- An announcement is a short notice (title, body and a level: info, warning or critical) shown to users in the desktop
-- app. Desktops download the enabled ones with GET /v1/announcements using their device token; the response carries an
-- `announcements_version` ETag, so a desktop only downloads the list again when something changed.

-- migrate:up
CREATE TABLE org_announcements (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,59}$'),
  title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 120),
  body text NOT NULL CHECK (char_length(body) BETWEEN 1 AND 4000),
  level text NOT NULL DEFAULT 'info' CHECK (level IN ('info', 'warning', 'critical')),
  enabled boolean NOT NULL DEFAULT true,
  revision integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Bumped on every change, so desktops know when to download the list again.
INSERT INTO settings (key, value) VALUES ('announcements_version', '1') ON CONFLICT (key) DO NOTHING;

-- migrate:down
DELETE FROM settings WHERE key = 'announcements_version';
DROP TABLE IF EXISTS org_announcements;
