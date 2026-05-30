ALTER TABLE public_downloads
    ADD COLUMN IF NOT EXISTS sha256 TEXT NOT NULL DEFAULT '';

INSERT INTO permissions(id, description) VALUES
    ('users.superadmin.manage', 'Grant or revoke global administrator status'),
    ('audit.export', 'Export audit events to files')
ON CONFLICT (id) DO NOTHING;
