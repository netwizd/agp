CREATE TABLE identity_contacts (
 id TEXT PRIMARY KEY,principal_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 authenticator_version BIGINT NOT NULL CHECK(authenticator_version>0),revision BIGINT NOT NULL CHECK(revision>0),
 key_id TEXT NOT NULL,nonce TEXT NOT NULL,ciphertext TEXT NOT NULL,verified BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX identity_contacts_owner ON identity_contacts(principal_id,id);
CREATE TABLE identity_email_challenges (
 id TEXT PRIMARY KEY,flow_id TEXT NOT NULL REFERENCES identity_flows(id) ON DELETE CASCADE,
 purpose TEXT NOT NULL CHECK(purpose IN ('verify_email','invite_confirmation','recovery_confirmation')),
 audience TEXT NOT NULL,principal_id TEXT NOT NULL,contact_id TEXT NOT NULL REFERENCES identity_contacts(id) ON DELETE CASCADE,
 contact_version BIGINT NOT NULL,epoch BIGINT NOT NULL,generation BIGINT NOT NULL CHECK(generation>0),
 pepper_id TEXT NOT NULL,code_mac TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('active','consumed','cancelled','expired')),
 attempts INTEGER NOT NULL DEFAULT 0,issued_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ NOT NULL,resend_after TIMESTAMPTZ NOT NULL,
 UNIQUE(flow_id,generation)
);
CREATE INDEX identity_email_challenge_flow ON identity_email_challenges(flow_id,generation);
CREATE TABLE identity_email_flow_state (
 flow_id TEXT PRIMARY KEY REFERENCES identity_flows(id) ON DELETE CASCADE,
 current_challenge_id TEXT NOT NULL,contact_id TEXT NOT NULL,purpose TEXT NOT NULL,
 generation BIGINT NOT NULL,issue_count INTEGER NOT NULL CHECK(issue_count BETWEEN 1 AND 3),
 source_key TEXT NOT NULL,provider_key TEXT NOT NULL
);
CREATE TABLE identity_email_outbox (
 id TEXT PRIMARY KEY,challenge_id TEXT NOT NULL UNIQUE REFERENCES identity_email_challenges(id) ON DELETE CASCADE,
 flow_id TEXT NOT NULL,epoch BIGINT NOT NULL,generation BIGINT NOT NULL,
 key_ref TEXT NOT NULL,nonce TEXT NOT NULL,ciphertext TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('queued','sending','accepted','failed','unknown','expired','cancelled')),
 claim_id TEXT NOT NULL DEFAULT '',created_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX identity_email_outbox_queue ON identity_email_outbox(state,created_at,id);
CREATE TABLE identity_email_limits (
 bucket TEXT PRIMARY KEY,window_start TIMESTAMPTZ NOT NULL,attempts INTEGER NOT NULL CHECK(attempts>=0)
);
