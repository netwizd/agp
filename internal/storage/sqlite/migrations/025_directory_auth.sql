ALTER TABLE users ADD COLUMN identity_kind TEXT NOT NULL DEFAULT 'local' CHECK(identity_kind IN ('local','directory'));
CREATE TABLE directory_identities (
 id TEXT PRIMARY KEY,principal_id TEXT NOT NULL UNIQUE,provider_id TEXT NOT NULL REFERENCES directory_providers(id),
 forest_guid TEXT NOT NULL,object_guid TEXT NOT NULL,authenticator_version BIGINT NOT NULL CHECK(authenticator_version>0),
 revoked BOOLEAN NOT NULL DEFAULT FALSE,created_at TIMESTAMP NOT NULL,
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
CREATE TRIGGER directory_identities_keys_immutable BEFORE UPDATE OF id,principal_id,provider_id,forest_guid,object_guid,authenticator_version,created_at ON directory_identities BEGIN SELECT RAISE(ABORT,'immutable_directory_identity'); END;
CREATE TRIGGER directory_identities_no_delete BEFORE DELETE ON directory_identities BEGIN SELECT RAISE(ABORT,'immutable_directory_identity'); END;
-- SQLite retained the v1 legacy/management-only CHECK from migration 008.
-- PostgreSQL already widened it in 009; rebuild atomically to preserve all
-- historical sessions and permit the same login/gateway audiences here.
CREATE TABLE sessions_directory_upgrade (
 id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 token_hash TEXT NOT NULL UNIQUE,csrf_hash TEXT NOT NULL,ip TEXT NOT NULL,user_agent TEXT NOT NULL,
 expires_at TIMESTAMP NOT NULL,created_at TIMESTAMP NOT NULL,revoked_at TIMESTAMP NULL,
 audience TEXT NOT NULL DEFAULT 'legacy' CHECK(audience IN ('legacy','management','login','gateway')),
 audience_origin TEXT NOT NULL DEFAULT '',authority_epoch BIGINT NOT NULL DEFAULT 0,
 security_version BIGINT NOT NULL DEFAULT 0,mfa_at TIMESTAMP NULL,last_seen_at TIMESTAMP NULL,
 source_session_id TEXT NOT NULL DEFAULT '',gateway_id TEXT NOT NULL DEFAULT '',node_id TEXT NOT NULL DEFAULT '',
 directory_identity_id TEXT NOT NULL DEFAULT '',directory_identity_version BIGINT NOT NULL DEFAULT 0 CHECK(directory_identity_version>=0),
 directory_provider_version_id TEXT NOT NULL DEFAULT '',directory_provider_guard_version BIGINT NOT NULL DEFAULT 0 CHECK(directory_provider_guard_version>=0)
);
INSERT INTO sessions_directory_upgrade SELECT id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,revoked_at,audience,audience_origin,authority_epoch,security_version,mfa_at,last_seen_at,source_session_id,gateway_id,node_id,directory_identity_id,directory_identity_version,directory_provider_version_id,directory_provider_guard_version FROM sessions;
DROP TABLE sessions;
ALTER TABLE sessions_directory_upgrade RENAME TO sessions;
CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
