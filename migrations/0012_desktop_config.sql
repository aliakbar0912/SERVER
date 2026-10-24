-- Devora central platform, schema version 12: desktop announcement settings edited in the admin site.
-- These values override the DEVORA_DESKTOP_* environment settings in GET /v1/client-config, so the owner can
-- publish a notice, raise the minimum version or move the download page without a server restart.
-- An empty value removes the override and falls back to the environment.

-- migrate:up
INSERT INTO settings (key, value) VALUES
  ('desktop_status_message', '""'),
  ('desktop_min_version', '""'),
  ('desktop_download_url', '""'),
  ('desktop_maintenance', 'false')
ON CONFLICT (key) DO NOTHING;

-- migrate:down
DELETE FROM settings WHERE key IN ('desktop_status_message', 'desktop_min_version', 'desktop_download_url', 'desktop_maintenance');
