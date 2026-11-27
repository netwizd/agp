ALTER TABLE users ADD COLUMN identity_kind TEXT NOT NULL DEFAULT 'local' CHECK(identity_kind IN ('local','directory'));
CREATE TABLE directory_identities (
 id TEXT PRIMARY KEY,principal_id TEXT NOT NULL UNIQUE,provider_id TEXT NOT NULL REFERENCES directory_providers(id),
 forest_guid TEXT NOT NULL,object_guid TEXT NOT NULL,authenticator_version BIGINT NOT NULL CHECK(authenticator_version>0),
 revoked BOOLEAN NOT NULL DEFAULT FALSE,created_at TIMESTAMPTZ NOT NULL,
 UNIQUE(provider_id,forest_guid,object_guid)
);
ALTER TABLE identity_flows ADD COLUMN directory_identity_id TEXT NOT NULL DEFAULT '';
ALTER TABLE identity_flows ADD COLUMN directory_identity_version BIGINT NOT NULL DEFAULT 0 CHECK(directory_identity_version>=0);
ALTER TABLE identity_flows ADD COLUMN directory_provider_version_id TEXT NOT NULL DEFAULT '';
ALTER TABLE identity_flows ADD COLUMN directory_provider_guard_version BIGINT NOT NULL DEFAULT 0 CHECK(directory_provider_guard_version>=0);
ALTER TABLE sessions ADD COLUMN directory_identity_id TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN directory_identity_version BIGINT NOT NULL DEFAULT 0 CHECK(directory_identity_version>=0);
ALTER TABLE sessions ADD COLUMN directory_provider_version_id TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN directory_provider_guard_version BIGINT NOT NULL DEFAULT 0 CHECK(directory_provider_guard_version>=0);
CREATE TRIGGER directory_identities_keys_immutable BEFORE UPDATE OF id,principal_id,provider_id,forest_guid,object_guid,authenticator_version,created_at OR DELETE ON directory_identities FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
