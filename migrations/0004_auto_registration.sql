-- Devora central platform, schema version 4: desktops register themselves (no enrollment codes).
-- Additive only. Existing devices keep working with their current tokens; the enrollment_codes table is kept untouched.

-- migrate:up

-- A random id the desktop app generates once per installation. It lets the same installation get a new token after it lost
-- its old one, and lets a blocked installation stay blocked. Null for devices that enrolled with a code before version 4.
ALTER TABLE devices ADD COLUMN install_id text UNIQUE CHECK (install_id IS NULL OR install_id ~ '^[A-Za-z0-9_-]{16,64}$');
ALTER TABLE devices ADD COLUMN registered_via text NOT NULL DEFAULT 'code' CHECK (registered_via IN ('code', 'auto'));

-- The owner can stop new desktops from registering (for example during abuse) without affecting registered ones.
INSERT INTO settings (key, value) VALUES ('allow_auto_registration', 'true') ON CONFLICT (key) DO NOTHING;

-- migrate:down
DELETE FROM settings WHERE key = 'allow_auto_registration';
ALTER TABLE devices DROP COLUMN IF EXISTS registered_via;
ALTER TABLE devices DROP COLUMN IF EXISTS install_id;
