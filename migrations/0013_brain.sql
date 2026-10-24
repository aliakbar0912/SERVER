-- Devora central platform, schema version 13: the brain dashboard.
-- Desktops send a small heartbeat ("beat") every 30 seconds while they are open: whether the agent is working, the
-- tasks in progress, the last tool step and local memory counts. The latest beat is kept on the device row; notable
-- moments (a task started, finished or failed) are kept as brain_events for 14 days. No code or file contents.

-- migrate:up
ALTER TABLE devices ADD COLUMN beat_at timestamptz;
ALTER TABLE devices ADD COLUMN beat_state text CHECK (beat_state IS NULL OR beat_state IN ('idle', 'running'));
ALTER TABLE devices ADD COLUMN beat jsonb;

CREATE TABLE brain_events (
  id bigserial PRIMARY KEY,
  device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  kind text NOT NULL CHECK (kind IN ('task_started', 'task_completed', 'task_failed', 'task_cancelled', 'online', 'offline')),
  title text NOT NULL DEFAULT '' CHECK (char_length(title) <= 120),
  detail jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX brain_events_created_idx ON brain_events (created_at DESC);
CREATE INDEX brain_events_device_idx ON brain_events (device_id, created_at DESC);

-- migrate:down
DROP TABLE IF EXISTS brain_events;
ALTER TABLE devices DROP COLUMN IF EXISTS beat;
ALTER TABLE devices DROP COLUMN IF EXISTS beat_state;
ALTER TABLE devices DROP COLUMN IF EXISTS beat_at;
