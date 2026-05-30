ALTER TABLE resources
ADD COLUMN category TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_resources_category ON resources(category);
