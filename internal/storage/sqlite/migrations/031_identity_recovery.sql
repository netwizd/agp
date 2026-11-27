CREATE TABLE identity_recovery_operations (
 id TEXT PRIMARY KEY, target_id TEXT NOT NULL REFERENCES users(id), request_digest TEXT NOT NULL, intent_json TEXT NOT NULL,
 creator_id TEXT NOT NULL REFERENCES users(id), creator_fingerprint TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','applied','recovery_required')), approval_status TEXT NOT NULL CHECK(approval_status IN ('pending','approved')),
 post_security_version BIGINT NOT NULL DEFAULT 0 CHECK(post_security_version>=0), post_password_version BIGINT NOT NULL DEFAULT 0 CHECK(post_password_version>=0), created_at TIMESTAMP NOT NULL
);
CREATE INDEX identity_recovery_target ON identity_recovery_operations(target_id,created_at);
CREATE TABLE identity_recovery_approvals (
 id TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE REFERENCES identity_recovery_operations(id), request_digest TEXT NOT NULL,
 reviewer_id TEXT NOT NULL REFERENCES users(id), reviewer_fingerprint TEXT NOT NULL, mfa_at TIMESTAMP NOT NULL, primary_at TIMESTAMP NOT NULL, created_at TIMESTAMP NOT NULL, reason TEXT NOT NULL
);
CREATE TABLE identity_recovery_requests (
 actor_id TEXT NOT NULL, action TEXT NOT NULL, request_key TEXT NOT NULL, fingerprint TEXT NOT NULL,
 operation_id TEXT NOT NULL REFERENCES identity_recovery_operations(id), created_at TIMESTAMP NOT NULL,
 PRIMARY KEY(actor_id,action,request_key)
);
-- This row is a typed setup capability, not a primary or session credential.
-- Its independent journal guard is spent again at completion or cancellation.
CREATE TABLE identity_recovery_capabilities (
 flow_id TEXT PRIMARY KEY REFERENCES identity_flows(id) ON DELETE CASCADE,
 token_id TEXT NOT NULL DEFAULT '', operation_id TEXT NOT NULL DEFAULT '', principal_id TEXT NOT NULL REFERENCES users(id),
 allowed_action TEXT NOT NULL CHECK(allowed_action IN ('replace_mfa','reset_password')),
 proof_kind TEXT NOT NULL CHECK(proof_kind IN ('email','supervised','recovery_code')),
 guard_id TEXT NOT NULL UNIQUE, bound_guard_version BIGINT NOT NULL CHECK(bound_guard_version>=0),
 epoch BIGINT NOT NULL CHECK(epoch>0), security_version BIGINT NOT NULL CHECK(security_version>0), password_version BIGINT NOT NULL CHECK(password_version>0), policy_digest TEXT NOT NULL, target_fingerprint TEXT NOT NULL,
 totp_verified BOOLEAN NOT NULL DEFAULT FALSE, totp_factor_version BIGINT NOT NULL DEFAULT 0 CHECK(totp_factor_version>=0), password_phc TEXT NOT NULL DEFAULT '',
 state TEXT NOT NULL CHECK(state IN ('pending','completed','cancelled')),
 created_at TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL CHECK(expires_at>created_at),
 CHECK((proof_kind='recovery_code' AND allowed_action='replace_mfa' AND token_id='' AND operation_id='') OR (proof_kind='email' AND allowed_action='reset_password' AND token_id<>'' AND operation_id='') OR (proof_kind='supervised' AND token_id<>'' AND operation_id<>'')),
 CHECK(allowed_action='reset_password' OR password_phc=''), CHECK((totp_verified=FALSE AND totp_factor_version=0) OR (totp_verified=TRUE AND proof_kind='email' AND totp_factor_version>0)), CHECK(state='pending' OR password_phc='')
);
CREATE TRIGGER identity_recovery_operations_immutable BEFORE UPDATE OF id,target_id,request_digest,intent_json,creator_id,creator_fingerprint,created_at ON identity_recovery_operations BEGIN SELECT RAISE(ABORT,'immutable_recovery_authority'); END;
CREATE TRIGGER identity_recovery_approvals_immutable BEFORE UPDATE ON identity_recovery_approvals BEGIN SELECT RAISE(ABORT,'immutable_recovery_authority'); END;
CREATE TRIGGER identity_recovery_requests_immutable BEFORE UPDATE ON identity_recovery_requests BEGIN SELECT RAISE(ABORT,'immutable_recovery_authority'); END;
CREATE TRIGGER identity_recovery_capabilities_immutable BEFORE UPDATE OF flow_id,token_id,operation_id,principal_id,allowed_action,proof_kind,guard_id,bound_guard_version,epoch,security_version,password_version,policy_digest,target_fingerprint,created_at,expires_at ON identity_recovery_capabilities BEGIN SELECT RAISE(ABORT,'immutable_recovery_authority'); END;
CREATE TRIGGER identity_recovery_capability_terminal BEFORE UPDATE ON identity_recovery_capabilities WHEN OLD.state IN ('completed','cancelled') AND (NEW.state<>OLD.state OR NEW.password_phc<>'') BEGIN SELECT RAISE(ABORT,'terminal_recovery_capability'); END;
CREATE TRIGGER identity_recovery_operation_terminal BEFORE UPDATE ON identity_recovery_operations WHEN OLD.state IN ('applied','recovery_required') AND (NEW.state<>OLD.state OR NEW.post_security_version<>OLD.post_security_version OR NEW.post_password_version<>OLD.post_password_version) BEGIN SELECT RAISE(ABORT,'terminal_recovery_operation'); END;
