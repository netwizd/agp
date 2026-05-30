ALTER TABLE resources
    ADD COLUMN IF NOT EXISTS public_path TEXT NOT NULL DEFAULT '';

ALTER TABLE resources
    DROP CONSTRAINT IF EXISTS resources_public_host_key;

CREATE INDEX IF NOT EXISTS idx_resources_public_host ON resources(public_host);

CREATE UNIQUE INDEX IF NOT EXISTS idx_resources_public_route
    ON resources(public_host, public_path)
    WHERE public_path <> '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_resources_public_host_legacy
    ON resources(public_host)
    WHERE public_path = '';
