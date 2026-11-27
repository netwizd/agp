CREATE TABLE directory_providers (
 id TEXT PRIMARY KEY,name TEXT NOT NULL,forest_guid TEXT NOT NULL,guard_id TEXT NOT NULL UNIQUE,
 row_version BIGINT NOT NULL CHECK(row_version>0),guard_version BIGINT NOT NULL CHECK(guard_version>=0),
 enabled BOOLEAN NOT NULL DEFAULT FALSE,active_version_id TEXT NULL,created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE directory_provider_versions (
 id TEXT PRIMARY KEY,provider_id TEXT NOT NULL REFERENCES directory_providers(id),guard_version BIGINT NOT NULL CHECK(guard_version>0),
 content_digest TEXT NOT NULL,canonical_json TEXT NOT NULL CHECK(length(canonical_json)<=1048576),author_id TEXT NOT NULL,author_fingerprint TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL,
 UNIQUE(provider_id,guard_version)
);
CREATE TABLE directory_provider_tests (
 id TEXT PRIMARY KEY,provider_id TEXT NOT NULL REFERENCES directory_providers(id),version_id TEXT NOT NULL REFERENCES directory_provider_versions(id),
 content_digest TEXT NOT NULL,authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),state TEXT NOT NULL CHECK(state IN ('passed','failed')),
 result_json TEXT NOT NULL CHECK(length(result_json)<=8192),created_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ NOT NULL CHECK(expires_at>created_at)
);
CREATE INDEX directory_provider_tests_current ON directory_provider_tests(provider_id,version_id,created_at DESC);
CREATE TABLE directory_provider_operations (
 id TEXT PRIMARY KEY,provider_id TEXT NOT NULL REFERENCES directory_providers(id),version_id TEXT NOT NULL REFERENCES directory_provider_versions(id),
 request_digest TEXT NOT NULL,intent_json TEXT NOT NULL CHECK(length(intent_json)<=65536),author_id TEXT NOT NULL,author_fingerprint TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','applied','recovery_required')),approval_status TEXT NOT NULL CHECK(approval_status IN ('pending','approved')),
 created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE directory_provider_approvals (
 id TEXT NOT NULL UNIQUE,operation_id TEXT PRIMARY KEY REFERENCES directory_provider_operations(id),request_digest TEXT NOT NULL,reviewer_id TEXT NOT NULL,reviewer_fingerprint TEXT NOT NULL,
 mfa_at TIMESTAMPTZ NOT NULL,created_at TIMESTAMPTZ NOT NULL,reason TEXT NOT NULL
);
CREATE TABLE directory_provider_requests (
 actor_id TEXT NOT NULL,request_key TEXT NOT NULL,fingerprint TEXT NOT NULL,operation_id TEXT NOT NULL REFERENCES directory_provider_operations(id),
 PRIMARY KEY(actor_id,request_key)
);
CREATE TRIGGER directory_provider_versions_immutable BEFORE UPDATE OR DELETE ON directory_provider_versions FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER directory_provider_tests_immutable BEFORE UPDATE OR DELETE ON directory_provider_tests FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER directory_provider_approvals_immutable BEFORE UPDATE OR DELETE ON directory_provider_approvals FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER directory_provider_requests_immutable BEFORE UPDATE OR DELETE ON directory_provider_requests FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER directory_provider_operations_intent_immutable BEFORE UPDATE OF id,provider_id,version_id,request_digest,intent_json,author_id,author_fingerprint,created_at OR DELETE ON directory_provider_operations FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TABLE directory_provider_action_requests (
 actor_id TEXT NOT NULL,action TEXT NOT NULL,request_key TEXT NOT NULL,fingerprint TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY(actor_id,action,request_key)
);
CREATE TRIGGER directory_provider_action_requests_immutable BEFORE UPDATE OR DELETE ON directory_provider_action_requests FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
