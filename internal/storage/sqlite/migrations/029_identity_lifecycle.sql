ALTER TABLE users ADD COLUMN lifecycle_state TEXT NOT NULL DEFAULT 'active' CHECK(lifecycle_state IN ('invited','active'));
CREATE TABLE identity_one_time_tokens (
 id TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES users(id),
 purpose TEXT NOT NULL CHECK(purpose IN ('activate','reset_password','recover_mfa')),
 proof_kind TEXT NOT NULL CHECK(proof_kind IN ('email','supervised')),
 token_hash TEXT NOT NULL UNIQUE,
 guard_id TEXT NOT NULL UNIQUE, guard_version BIGINT NOT NULL CHECK(guard_version>0),
 epoch BIGINT NOT NULL CHECK(epoch>0), security_version BIGINT NOT NULL CHECK(security_version>0), password_version BIGINT NOT NULL CHECK(password_version>0),
 policy_digest TEXT NOT NULL, issuer_id TEXT NOT NULL, issuer_fingerprint TEXT NOT NULL,
 contact_id TEXT NOT NULL DEFAULT '', contact_version BIGINT NOT NULL DEFAULT 0 CHECK(contact_version>=0), generation BIGINT NOT NULL CHECK(generation>0),
 authorization_operation_id TEXT NULL UNIQUE, allowed_action TEXT NOT NULL CHECK(allowed_action IN ('activate','replace_mfa','reset_password')),
 created_at TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL CHECK(expires_at>created_at),
 reserved_flow_id TEXT NOT NULL DEFAULT '', reserved_binding_hash TEXT NOT NULL DEFAULT '', reserved_at TIMESTAMP NULL,
 consumed_at TIMESTAMP NULL, revoked_at TIMESTAMP NULL,
 CHECK((purpose='activate' AND proof_kind='email' AND allowed_action='activate' AND issuer_id<>'' AND authorization_operation_id IS NULL) OR (purpose='reset_password' AND proof_kind='email' AND allowed_action='reset_password' AND authorization_operation_id IS NULL) OR (purpose='recover_mfa' AND proof_kind='supervised' AND allowed_action='replace_mfa' AND authorization_operation_id IS NOT NULL AND issuer_id<>'') OR (purpose='reset_password' AND proof_kind='supervised' AND allowed_action='reset_password' AND authorization_operation_id IS NOT NULL AND issuer_id<>'')),
 CHECK((reserved_flow_id='' AND reserved_binding_hash='' AND reserved_at IS NULL) OR (reserved_flow_id<>'' AND reserved_binding_hash<>'' AND reserved_at IS NOT NULL)),
 CHECK(consumed_at IS NULL OR reserved_at IS NOT NULL), CHECK(consumed_at IS NULL OR revoked_at IS NULL),
 CHECK(proof_kind<>'email' OR (contact_id<>'' AND contact_version>0))
);
CREATE INDEX identity_one_time_target ON identity_one_time_tokens(principal_id,purpose,expires_at);
CREATE INDEX identity_one_time_flow ON identity_one_time_tokens(reserved_flow_id);
CREATE TRIGGER identity_one_time_keys_immutable BEFORE UPDATE OF id,principal_id,purpose,proof_kind,token_hash,guard_id,guard_version,epoch,security_version,password_version,policy_digest,issuer_id,issuer_fingerprint,contact_id,contact_version,generation,authorization_operation_id,allowed_action,created_at,expires_at ON identity_one_time_tokens BEGIN SELECT RAISE(ABORT,'immutable_identity_token'); END;
CREATE TRIGGER identity_one_time_terminal BEFORE UPDATE ON identity_one_time_tokens WHEN (OLD.reserved_at IS NOT NULL AND (NEW.reserved_flow_id<>OLD.reserved_flow_id OR NEW.reserved_binding_hash<>OLD.reserved_binding_hash OR NEW.reserved_at IS NULL OR NEW.reserved_at<>OLD.reserved_at)) OR (OLD.consumed_at IS NOT NULL AND (NEW.consumed_at IS NULL OR NEW.consumed_at<>OLD.consumed_at)) OR (OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS NULL OR NEW.revoked_at<>OLD.revoked_at)) BEGIN SELECT RAISE(ABORT,'irreversible_identity_token'); END;
CREATE TRIGGER identity_one_time_live_no_delete BEFORE DELETE ON identity_one_time_tokens WHEN OLD.consumed_at IS NULL AND OLD.revoked_at IS NULL BEGIN SELECT RAISE(ABORT,'live_identity_token'); END;
