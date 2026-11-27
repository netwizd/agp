-- Register execution permission identifiers without granting them to any group.
-- Bootstrap administrators request the complete catalog via authz.AllPermissions.
INSERT INTO permissions(id, description) VALUES
    ('rollouts.create', 'Start an approved rollout'),
    ('rollouts.cancel', 'Cancel an active rollout'),
    ('rollouts.rollback', 'Start an approved rollback')
ON CONFLICT (id) DO NOTHING;
