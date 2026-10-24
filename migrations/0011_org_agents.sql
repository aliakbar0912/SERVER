-- Devora central platform, schema version 11: organization agents the owner publishes to every desktop from the admin site.
-- An agent is a reusable subagent preset: name, description, instructions (its purpose), the access level it runs with
-- (the desktop's own RoleAccess levels) and an optional suggested model id. Desktops download them with
-- GET /v1/agents using their device token; the catalogue policy carries `agentsVersion`, so a desktop only downloads
-- again when something changed. The access level can only narrow what the desktop already allows, never widen it.

-- migrate:up
CREATE TABLE org_agents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,59}$'),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
  description text NOT NULL CHECK (char_length(description) BETWEEN 1 AND 1024),
  instructions text NOT NULL CHECK (char_length(instructions) BETWEEN 1 AND 8000),
  access text NOT NULL CHECK (access IN ('read', 'commands', 'docs', 'write', 'write_commands')),
  suggested_model text CHECK (suggested_model IS NULL OR char_length(suggested_model) BETWEEN 1 AND 200),
  enabled boolean NOT NULL DEFAULT true,
  revision integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Bumped on every change, so desktops know when to download the list again.
INSERT INTO settings (key, value) VALUES ('agents_version', '1') ON CONFLICT (key) DO NOTHING;

-- migrate:down
DELETE FROM settings WHERE key = 'agents_version';
DROP TABLE IF EXISTS org_agents;
