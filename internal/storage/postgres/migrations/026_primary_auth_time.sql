-- Fresh MFA does not prove a recent primary credential. Historical rows remain
-- NULL and must reauthenticate before contact/security procedures requiring it.
ALTER TABLE identity_flows ADD COLUMN primary_verified_at TIMESTAMP NULL;
ALTER TABLE sessions ADD COLUMN primary_at TIMESTAMP NULL;
