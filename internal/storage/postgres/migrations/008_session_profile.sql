ALTER TABLE sessions ADD COLUMN audience TEXT NOT NULL DEFAULT 'legacy' CHECK (audience IN ('legacy', 'management'));
ALTER TABLE sessions ADD COLUMN audience_origin TEXT NOT NULL DEFAULT '';
CREATE TABLE session_profiles (
 id INTEGER PRIMARY KEY CHECK (id = 1),
 fingerprint TEXT NOT NULL,
 portal_host TEXT NOT NULL,
 management_origin TEXT NOT NULL,
 session_cookie_name TEXT NOT NULL,
 csrf_cookie_name TEXT NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
