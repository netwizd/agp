-- Metadata-only retries. Neither passwords nor invitation plaintext enter this table.
CREATE TABLE identity_invite_requests (
 actor_id TEXT NOT NULL, action TEXT NOT NULL CHECK(action IN ('pending','invite')), request_key TEXT NOT NULL,
 request_digest TEXT NOT NULL, response_json TEXT NOT NULL, created_at TIMESTAMP NOT NULL,
 PRIMARY KEY(actor_id,action,request_key)
);
CREATE TRIGGER identity_invite_requests_immutable BEFORE UPDATE ON identity_invite_requests BEGIN SELECT RAISE(ABORT,'immutable_invitation_request'); END;
CREATE TABLE identity_activation_stages (
 flow_id TEXT PRIMARY KEY REFERENCES identity_flows(id) ON DELETE CASCADE,
 token_id TEXT NOT NULL UNIQUE REFERENCES identity_one_time_tokens(id), target_fingerprint TEXT NOT NULL,
 password_phc TEXT NOT NULL DEFAULT '', email_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
 enrollment_id TEXT NOT NULL DEFAULT '', factor_version BIGINT NOT NULL DEFAULT 0,
 ciphertext TEXT NOT NULL DEFAULT '', key_id TEXT NOT NULL DEFAULT '', nonce TEXT NOT NULL DEFAULT '',
 totp_step BIGINT NOT NULL DEFAULT -1, proof_at TIMESTAMP NULL, code_hashes_json TEXT NOT NULL DEFAULT '[]',
 state TEXT NOT NULL CHECK(state IN ('reserved','password','email','enrollment','ready','completed','aborted')),
 created_at TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL,
 CHECK(state NOT IN ('completed','aborted') OR (password_phc='' AND ciphertext='' AND key_id='' AND nonce='' AND code_hashes_json='[]'))
);
CREATE TRIGGER identity_activation_binding_immutable BEFORE UPDATE OF flow_id,token_id,target_fingerprint,created_at,expires_at ON identity_activation_stages BEGIN SELECT RAISE(ABORT,'immutable_activation_binding'); END;
CREATE TRIGGER identity_activation_terminal BEFORE UPDATE ON identity_activation_stages WHEN OLD.state IN ('completed','aborted') AND (NEW.state<>OLD.state OR NEW.password_phc<>'' OR NEW.ciphertext<>'' OR NEW.key_id<>'' OR NEW.nonce<>'' OR NEW.code_hashes_json<>'[]') BEGIN SELECT RAISE(ABORT,'terminal_activation_stage'); END;
CREATE TABLE identity_invite_outbox (
 id TEXT PRIMARY KEY,token_id TEXT NOT NULL UNIQUE REFERENCES identity_one_time_tokens(id),
 epoch BIGINT NOT NULL,generation BIGINT NOT NULL,key_ref TEXT NOT NULL,nonce TEXT NOT NULL,ciphertext TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('prepared','queued','sending','accepted','failed','unknown','expired','cancelled')),
 claim_id TEXT NOT NULL DEFAULT '',created_at TIMESTAMP NOT NULL,expires_at TIMESTAMP NOT NULL
);
CREATE INDEX identity_invite_outbox_queue ON identity_invite_outbox(state,created_at,id);
CREATE TRIGGER identity_invite_payload_immutable BEFORE UPDATE OF id,token_id,epoch,generation,key_ref,nonce,ciphertext,created_at,expires_at ON identity_invite_outbox BEGIN SELECT RAISE(ABORT,'immutable_invitation_payload'); END;
CREATE TRIGGER identity_invite_outbox_terminal BEFORE UPDATE ON identity_invite_outbox WHEN (OLD.state IN ('accepted','failed','unknown','expired','cancelled') AND NEW.state<>OLD.state) OR (OLD.claim_id<>'' AND NEW.claim_id<>OLD.claim_id) OR (OLD.state='sending' AND NEW.state IN ('prepared','queued')) BEGIN SELECT RAISE(ABORT,'terminal_invitation_delivery'); END;
