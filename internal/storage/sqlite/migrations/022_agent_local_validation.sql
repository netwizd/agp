-- Immutable local native syntax probes; never remote task/apply receipts.
CREATE TABLE agent_local_validation_requests (
 id TEXT PRIMARY KEY,node_id TEXT NOT NULL,identity_digest TEXT NOT NULL,
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),request_id TEXT NOT NULL,
 request_fingerprint TEXT NOT NULL,request_json TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL,expires_at TIMESTAMP NOT NULL CHECK(expires_at>created_at),
 UNIQUE(node_id,identity_digest,request_id),CHECK(length(request_json)<=65536)
);
CREATE INDEX agent_local_validation_requests_node_idx ON agent_local_validation_requests(node_id,created_at);
CREATE TABLE agent_local_validation_results (
 id TEXT PRIMARY KEY,request_fact_id TEXT NOT NULL UNIQUE REFERENCES agent_local_validation_requests(id),
 result_json TEXT NOT NULL CHECK(length(result_json)<=65536),recorded_at TIMESTAMP NOT NULL
);
CREATE TRIGGER agent_local_validation_requests_no_update BEFORE UPDATE ON agent_local_validation_requests BEGIN SELECT RAISE(ABORT,'immutable_local_validation_fact'); END;
CREATE TRIGGER agent_local_validation_requests_no_delete BEFORE DELETE ON agent_local_validation_requests BEGIN SELECT RAISE(ABORT,'immutable_local_validation_fact'); END;
CREATE TRIGGER agent_local_validation_results_no_update BEFORE UPDATE ON agent_local_validation_results BEGIN SELECT RAISE(ABORT,'immutable_local_validation_fact'); END;
CREATE TRIGGER agent_local_validation_results_no_delete BEFORE DELETE ON agent_local_validation_results BEGIN SELECT RAISE(ABORT,'immutable_local_validation_fact'); END;
