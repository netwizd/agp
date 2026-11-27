CREATE TABLE oidc_providers (
 id TEXT PRIMARY KEY,name TEXT NOT NULL,issuer TEXT NOT NULL UNIQUE,guard_id TEXT NOT NULL UNIQUE,
 row_version BIGINT NOT NULL CHECK(row_version>0),guard_version BIGINT NOT NULL CHECK(guard_version>=0),
 enabled BOOLEAN NOT NULL DEFAULT FALSE,active_version_id TEXT NULL,created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE oidc_provider_versions (
 id TEXT PRIMARY KEY,provider_id TEXT NOT NULL REFERENCES oidc_providers(id),guard_version BIGINT NOT NULL CHECK(guard_version>0),
 content_digest TEXT NOT NULL,canonical_json TEXT NOT NULL CHECK(length(canonical_json)<=65536),author_id TEXT NOT NULL,author_fingerprint TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL,
 UNIQUE(provider_id,guard_version)
);
CREATE TABLE oidc_provider_tests (
 id TEXT PRIMARY KEY,provider_id TEXT NOT NULL REFERENCES oidc_providers(id),version_id TEXT NOT NULL REFERENCES oidc_provider_versions(id),
 content_digest TEXT NOT NULL,authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),state TEXT NOT NULL CHECK(state IN ('passed','failed')),
 created_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ NOT NULL CHECK(expires_at>created_at)
);
CREATE INDEX oidc_provider_tests_current ON oidc_provider_tests(provider_id,version_id,created_at DESC);
CREATE TABLE oidc_links (
 id TEXT PRIMARY KEY,provider_id TEXT NOT NULL REFERENCES oidc_providers(id),subject TEXT NOT NULL,guard_id TEXT NOT NULL UNIQUE,
 row_version BIGINT NOT NULL CHECK(row_version>0),guard_version BIGINT NOT NULL CHECK(guard_version>=0),
 enabled BOOLEAN NOT NULL DEFAULT FALSE,active_version_id TEXT NULL,created_at TIMESTAMPTZ NOT NULL,UNIQUE(provider_id,subject)
);
CREATE TABLE oidc_link_versions (
 id TEXT PRIMARY KEY,link_id TEXT NOT NULL REFERENCES oidc_links(id),guard_version BIGINT NOT NULL CHECK(guard_version>0),
 directory_identity_id TEXT NOT NULL REFERENCES directory_identities(id),principal_id TEXT NOT NULL,content_digest TEXT NOT NULL,canonical_json TEXT NOT NULL,
 UNIQUE(link_id,guard_version)
);
CREATE TABLE oidc_operations (
 id TEXT PRIMARY KEY,family TEXT NOT NULL CHECK(family IN ('provider_security_change','oidc_identity_link')),
 provider_id TEXT NOT NULL REFERENCES oidc_providers(id),version_id TEXT NOT NULL,request_digest TEXT NOT NULL,
 intent_json TEXT NOT NULL CHECK(length(intent_json)<=65536),author_id TEXT NOT NULL,author_fingerprint TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','applied','recovery_required')),approval_status TEXT NOT NULL CHECK(approval_status IN ('pending','approved')),created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE oidc_approvals (
 id TEXT NOT NULL UNIQUE,operation_id TEXT PRIMARY KEY REFERENCES oidc_operations(id),request_digest TEXT NOT NULL,
 reviewer_id TEXT NOT NULL,reviewer_fingerprint TEXT NOT NULL,mfa_at TIMESTAMPTZ NOT NULL,primary_at TIMESTAMPTZ NOT NULL,created_at TIMESTAMPTZ NOT NULL,reason TEXT NOT NULL
);
CREATE TABLE oidc_action_requests (
 actor_id TEXT NOT NULL,action TEXT NOT NULL,request_key TEXT NOT NULL,fingerprint TEXT NOT NULL,operation_id TEXT NOT NULL REFERENCES oidc_operations(id),created_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY(actor_id,action,request_key)
);
CREATE TABLE oidc_authorizations (
 id TEXT PRIMARY KEY,state_hash TEXT NOT NULL UNIQUE,flow_id TEXT NOT NULL,binding_hash TEXT NOT NULL,csrf_hash TEXT NOT NULL,
 provider_id TEXT NOT NULL REFERENCES oidc_providers(id),provider_version_id TEXT NOT NULL REFERENCES oidc_provider_versions(id),provider_guard_version BIGINT NOT NULL CHECK(provider_guard_version>0),
 purpose TEXT NOT NULL CHECK(purpose IN ('login','step_up')),audience TEXT NOT NULL,origin TEXT NOT NULL,redirect_uri TEXT NOT NULL,authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),
 key_id TEXT NOT NULL,nonce TEXT NOT NULL,ciphertext TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','exchanging','failed','completed','cancelled')),result_flow_id TEXT NOT NULL DEFAULT '',exchange_started_at TIMESTAMPTZ NULL,
 CHECK((state IN ('pending','exchanging') AND key_id<>'' AND nonce<>'' AND ciphertext<>'') OR (state IN ('failed','completed','cancelled') AND key_id='' AND nonce='' AND ciphertext=''))
);
CREATE INDEX oidc_authorizations_flow ON oidc_authorizations(flow_id,state);
ALTER TABLE sessions ADD COLUMN oidc_authentication BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE identity_flows ADD COLUMN oidc_authentication BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE oidc_contexts (
 entity_kind TEXT NOT NULL CHECK(entity_kind IN ('sessions','identity_flows')),entity_id TEXT NOT NULL,
 provider_id TEXT NOT NULL REFERENCES oidc_providers(id),provider_version_id TEXT NOT NULL REFERENCES oidc_provider_versions(id),provider_guard_version BIGINT NOT NULL CHECK(provider_guard_version>0),
 link_id TEXT NOT NULL REFERENCES oidc_links(id),link_version_id TEXT NOT NULL REFERENCES oidc_link_versions(id),link_guard_version BIGINT NOT NULL CHECK(link_guard_version>0),
 issuer TEXT NOT NULL,subject TEXT NOT NULL,auth_time TIMESTAMPTZ NOT NULL,acr TEXT NOT NULL,amr_json TEXT NOT NULL CHECK(length(amr_json)<=8192),
 PRIMARY KEY(entity_kind,entity_id)
);
CREATE TRIGGER oidc_provider_versions_immutable BEFORE UPDATE OR DELETE ON oidc_provider_versions FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER oidc_provider_tests_immutable BEFORE UPDATE OR DELETE ON oidc_provider_tests FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER oidc_link_versions_immutable BEFORE UPDATE OR DELETE ON oidc_link_versions FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER oidc_approvals_immutable BEFORE UPDATE OR DELETE ON oidc_approvals FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER oidc_action_requests_immutable BEFORE UPDATE OR DELETE ON oidc_action_requests FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER oidc_contexts_immutable BEFORE UPDATE OR DELETE ON oidc_contexts FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER oidc_providers_keys_immutable BEFORE UPDATE OF id,issuer,guard_id,created_at OR DELETE ON oidc_providers FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER oidc_links_keys_immutable BEFORE UPDATE OF id,provider_id,subject,guard_id,created_at OR DELETE ON oidc_links FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER oidc_operations_keys_immutable BEFORE UPDATE OF id,family,provider_id,version_id,request_digest,intent_json,author_id,author_fingerprint,created_at OR DELETE ON oidc_operations FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER oidc_authorizations_keys_immutable BEFORE UPDATE OF id,state_hash,flow_id,binding_hash,csrf_hash,provider_id,provider_version_id,provider_guard_version,purpose,audience,origin,redirect_uri,authority_epoch,created_at,expires_at ON oidc_authorizations FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE FUNCTION agp_oidc_authorization_erasure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='DELETE' THEN IF OLD.state IN ('pending','exchanging') THEN RAISE EXCEPTION 'active_oidc_authorization'; END IF; RETURN OLD; END IF;
 IF ROW(NEW.key_id,NEW.nonce,NEW.ciphertext) IS DISTINCT FROM ROW(OLD.key_id,OLD.nonce,OLD.ciphertext) AND NOT(NEW.state IN ('failed','completed','cancelled') AND NEW.key_id='' AND NEW.nonce='' AND NEW.ciphertext='' AND OLD.key_id<>'') THEN RAISE EXCEPTION 'immutable_oidc_proof'; END IF;
 RETURN NEW; END $$;
CREATE TRIGGER oidc_authorizations_proof_erasure BEFORE UPDATE OF key_id,nonce,ciphertext OR DELETE ON oidc_authorizations FOR EACH ROW EXECUTE FUNCTION agp_oidc_authorization_erasure();
