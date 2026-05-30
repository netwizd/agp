CREATE TABLE resources_v2 (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    icon TEXT NOT NULL DEFAULT '',
    internal_url TEXT NOT NULL,
    public_host TEXT NOT NULL,
    public_path TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO resources_v2(
    id, name, description, category, icon, internal_url, public_host, public_path, enabled, created_at, updated_at
)
SELECT id, name, description, category, icon, internal_url, public_host, '', enabled, created_at, updated_at
FROM resources;

CREATE TABLE resource_groups_v2 (
    resource_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    PRIMARY KEY (resource_id, group_id)
);

INSERT INTO resource_groups_v2(resource_id, group_id)
SELECT resource_id, group_id FROM resource_groups;

CREATE TABLE resource_ip_allowlists_v2 (
    resource_id TEXT NOT NULL,
    cidr TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (resource_id, cidr)
);

INSERT INTO resource_ip_allowlists_v2(resource_id, cidr, created_at)
SELECT resource_id, cidr, created_at FROM resource_ip_allowlists;

CREATE TABLE resource_diagnostics_v2 (
    id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO resource_diagnostics_v2(id, resource_id, outcome, result_json, created_by, created_at)
SELECT id, resource_id, outcome, result_json, created_by, created_at FROM resource_diagnostics;

DROP TABLE resource_diagnostics;
DROP TABLE resource_ip_allowlists;
DROP TABLE resource_groups;
DROP TABLE resources;

ALTER TABLE resources_v2 RENAME TO resources;

CREATE TABLE resource_groups (
    resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (resource_id, group_id)
);

INSERT INTO resource_groups(resource_id, group_id)
SELECT resource_id, group_id FROM resource_groups_v2;

CREATE TABLE resource_ip_allowlists (
    resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    cidr TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (resource_id, cidr)
);

INSERT INTO resource_ip_allowlists(resource_id, cidr, created_at)
SELECT resource_id, cidr, created_at FROM resource_ip_allowlists_v2;

CREATE TABLE resource_diagnostics (
    id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    outcome TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO resource_diagnostics(id, resource_id, outcome, result_json, created_by, created_at)
SELECT id, resource_id, outcome, result_json, created_by, created_at FROM resource_diagnostics_v2;

DROP TABLE resource_diagnostics_v2;
DROP TABLE resource_ip_allowlists_v2;
DROP TABLE resource_groups_v2;

CREATE INDEX IF NOT EXISTS idx_resources_public_host ON resources(public_host);
CREATE UNIQUE INDEX IF NOT EXISTS idx_resources_public_route
    ON resources(public_host, public_path)
    WHERE public_path <> '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_resources_public_host_legacy
    ON resources(public_host)
    WHERE public_path = '';

CREATE INDEX IF NOT EXISTS idx_resource_diagnostics_resource_created_at
    ON resource_diagnostics(resource_id, created_at);
