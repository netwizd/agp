-- Approval metadata is separate from security_operations: pending human
-- review never installs the coordinator's global restrictive-write barrier.
CREATE TABLE role_grant_operations (
 id TEXT PRIMARY KEY, target_id TEXT NOT NULL REFERENCES users(id), request_digest TEXT NOT NULL, intent_json TEXT NOT NULL,
 creator_id TEXT NOT NULL REFERENCES users(id), creator_fingerprint TEXT NOT NULL, creator_token_hash TEXT NOT NULL, creator_origin TEXT NOT NULL,
 creator_primary_at TIMESTAMPTZ NOT NULL, creator_mfa_at TIMESTAMPTZ NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','applied')), approval_status TEXT NOT NULL CHECK(approval_status IN ('pending','approved','not_required')), created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX role_grant_target ON role_grant_operations(target_id,created_at);
CREATE TABLE role_grant_approvals (
 id TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE REFERENCES role_grant_operations(id), request_digest TEXT NOT NULL,
 reviewer_id TEXT NOT NULL REFERENCES users(id), reviewer_fingerprint TEXT NOT NULL, reviewer_token_hash TEXT NOT NULL, reviewer_origin TEXT NOT NULL,
 primary_at TIMESTAMPTZ NOT NULL, mfa_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL, reason TEXT NOT NULL
);
CREATE TABLE role_grant_requests (
 actor_id TEXT NOT NULL REFERENCES users(id), action TEXT NOT NULL, request_key TEXT NOT NULL, fingerprint TEXT NOT NULL,
 operation_id TEXT NOT NULL REFERENCES role_grant_operations(id), created_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY(actor_id,action,request_key)
);
CREATE FUNCTION role_grant_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable_role_authority'; END $$;
CREATE TRIGGER role_grant_operations_immutable BEFORE UPDATE OF id,target_id,request_digest,intent_json,creator_id,creator_fingerprint,creator_token_hash,creator_origin,creator_primary_at,creator_mfa_at,created_at ON role_grant_operations FOR EACH ROW EXECUTE FUNCTION role_grant_immutable();
CREATE TRIGGER role_grant_approvals_immutable BEFORE UPDATE ON role_grant_approvals FOR EACH ROW EXECUTE FUNCTION role_grant_immutable();
CREATE TRIGGER role_grant_requests_immutable BEFORE UPDATE ON role_grant_requests FOR EACH ROW EXECUTE FUNCTION role_grant_immutable();
CREATE FUNCTION role_grant_transition() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF OLD.state='applied' AND (NEW.state<>OLD.state OR NEW.approval_status<>OLD.approval_status) THEN RAISE EXCEPTION 'terminal_role_operation'; END IF;
 IF OLD.approval_status IN ('approved','not_required') AND NEW.approval_status<>OLD.approval_status THEN RAISE EXCEPTION 'terminal_role_approval'; END IF;
 RETURN NEW; END $$;
CREATE TRIGGER role_grant_transition BEFORE UPDATE ON role_grant_operations FOR EACH ROW EXECUTE FUNCTION role_grant_transition();
