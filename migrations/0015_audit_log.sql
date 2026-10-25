-- Devora central platform, schema version 15: the owner's audit log.
-- Every sensitive change made through the admin site (settings, providers, models, devices, users, releases, agents,
-- skills, API keys, announcements) is recorded here: who made it (the signed-in owner's email), what kind of change
-- (a stable action name), on which target (the route parameter when there is one) and a small JSON detail (route
-- parameters only; never request bodies, so secrets and content stay out of the log). Entries are kept for the same
-- retention window as request logs and pruned by the same maintenance loop.

-- migrate:up
CREATE TABLE audit_log (
  id bigserial PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  actor text NOT NULL DEFAULT '' CHECK (char_length(actor) <= 254),
  action text NOT NULL CHECK (char_length(action) BETWEEN 1 AND 120),
  target text NOT NULL DEFAULT '' CHECK (char_length(target) <= 200),
  detail jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_log_created_idx ON audit_log (created_at DESC);
CREATE INDEX audit_log_action_idx ON audit_log (action, created_at DESC);

-- migrate:down
DROP TABLE IF EXISTS audit_log;
