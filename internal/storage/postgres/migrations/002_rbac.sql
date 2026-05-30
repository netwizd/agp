CREATE TABLE IF NOT EXISTS permissions (
    id TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS group_permissions (
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    permission_id TEXT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, permission_id)
);

INSERT INTO permissions(id, description) VALUES
    ('dashboard.read', 'Read administrative dashboard'),
    ('users.read', 'List and inspect users'),
    ('users.manage', 'Create, update and delete users'),
    ('groups.read', 'List and inspect groups'),
    ('groups.manage', 'Create, update and delete groups'),
    ('resources.read', 'List and inspect resources'),
    ('resources.manage', 'Create, update and delete resources'),
    ('resources.diagnostics', 'Run resource upstream diagnostics'),
    ('nginx.recommendations.read', 'Generate Nginx configuration recommendations'),
    ('sessions.read', 'List active sessions'),
    ('sessions.revoke', 'Revoke active sessions'),
    ('audit.read', 'Read audit events')
ON CONFLICT (id) DO NOTHING;
