-- Root-signed observations and immutable materialization inputs are distinct
-- from operator-declared inventory and compiler proposals.
CREATE TABLE execution_baseline_challenges (
 id TEXT PRIMARY KEY, node_id TEXT NOT NULL, anchor_digest TEXT NOT NULL,
 query_json TEXT NOT NULL CHECK(length(CAST(query_json AS BLOB))<=16384),
 head_json TEXT NOT NULL CHECK(length(CAST(head_json AS BLOB))<=16384),
 created_at TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL CHECK(expires_at>created_at),
 capture_digest TEXT NOT NULL DEFAULT ''
);
CREATE INDEX execution_baseline_challenges_node ON execution_baseline_challenges(node_id,created_at);
CREATE TABLE execution_baseline_captures (
 id TEXT PRIMARY KEY REFERENCES execution_baseline_challenges(id), node_id TEXT NOT NULL,
 capture_digest TEXT NOT NULL UNIQUE, capture_json TEXT NOT NULL CHECK(length(CAST(capture_json AS BLOB))<=65536),
 received_at TIMESTAMP NOT NULL
);
CREATE TABLE execution_source_outcomes (
 receipt_id TEXT PRIMARY KEY, node_id TEXT NOT NULL, task_id TEXT NOT NULL UNIQUE,
 receipt_digest TEXT NOT NULL UNIQUE, receipt_json TEXT NOT NULL CHECK(length(CAST(receipt_json AS BLOB))<=65536),
 received_at TIMESTAMP NOT NULL
);
CREATE TABLE execution_source_freezes (
 node_id TEXT PRIMARY KEY, anchor_digest TEXT NOT NULL, challenge_id TEXT NOT NULL REFERENCES execution_baseline_captures(id),
 created_at TIMESTAMP NOT NULL
);
CREATE TABLE execution_verified_baselines (
 node_id TEXT PRIMARY KEY, anchor_digest TEXT NOT NULL, boot_digest TEXT NOT NULL,
 capture_id TEXT NOT NULL REFERENCES execution_baseline_captures(id),
 active_json TEXT NOT NULL CHECK(length(CAST(active_json AS BLOB))<=16384),
 accepted_sequence BIGINT NOT NULL CHECK(accepted_sequence>=0), receipt_sequence BIGINT NOT NULL CHECK(receipt_sequence>=0),
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0), writer_epoch BIGINT NOT NULL CHECK(writer_epoch>0),
 deny_sequence BIGINT NOT NULL CHECK(deny_sequence>=0), frozen BOOLEAN NOT NULL DEFAULT FALSE,
 proof_kind TEXT NOT NULL CHECK(proof_kind IN ('capture','receipt')), proof_id TEXT NOT NULL,
 verified_at TIMESTAMP NOT NULL, row_version BIGINT NOT NULL CHECK(row_version>0)
);
CREATE TRIGGER execution_baseline_challenges_once BEFORE UPDATE ON execution_baseline_challenges WHEN NEW.id<>OLD.id OR NEW.node_id<>OLD.node_id OR NEW.anchor_digest<>OLD.anchor_digest OR NEW.query_json<>OLD.query_json OR NEW.head_json<>OLD.head_json OR NEW.created_at<>OLD.created_at OR NEW.expires_at<>OLD.expires_at OR OLD.capture_digest<>'' OR NEW.capture_digest='' BEGIN SELECT RAISE(ABORT,'immutable_baseline_challenge'); END;
CREATE TRIGGER execution_baseline_challenges_no_delete BEFORE DELETE ON execution_baseline_challenges BEGIN SELECT RAISE(ABORT,'immutable_baseline_challenge'); END;
CREATE TRIGGER execution_baseline_captures_no_update BEFORE UPDATE ON execution_baseline_captures BEGIN SELECT RAISE(ABORT,'immutable_baseline_capture'); END;
CREATE TRIGGER execution_baseline_captures_no_delete BEFORE DELETE ON execution_baseline_captures BEGIN SELECT RAISE(ABORT,'immutable_baseline_capture'); END;
CREATE TRIGGER execution_source_outcomes_no_update BEFORE UPDATE ON execution_source_outcomes BEGIN SELECT RAISE(ABORT,'immutable_source_outcome'); END;
CREATE TRIGGER execution_source_outcomes_no_delete BEFORE DELETE ON execution_source_outcomes BEGIN SELECT RAISE(ABORT,'immutable_source_outcome'); END;
CREATE TRIGGER execution_source_freezes_no_update BEFORE UPDATE ON execution_source_freezes BEGIN SELECT RAISE(ABORT,'immutable_source_freeze'); END;
CREATE TRIGGER execution_source_freezes_no_delete BEFORE DELETE ON execution_source_freezes BEGIN SELECT RAISE(ABORT,'immutable_source_freeze'); END;
CREATE TRIGGER execution_verified_baselines_monotonic BEFORE UPDATE ON execution_verified_baselines WHEN NEW.node_id<>OLD.node_id OR NEW.anchor_digest<>OLD.anchor_digest OR NEW.accepted_sequence<OLD.accepted_sequence OR NEW.receipt_sequence<OLD.receipt_sequence OR NEW.authority_epoch<OLD.authority_epoch OR NEW.writer_epoch<OLD.writer_epoch OR NEW.deny_sequence<OLD.deny_sequence OR NEW.verified_at<OLD.verified_at OR NEW.row_version<>OLD.row_version+1 OR (OLD.frozen=TRUE AND NEW.frozen=FALSE) BEGIN SELECT RAISE(ABORT,'verified_baseline_rollback'); END;
CREATE TRIGGER execution_verified_baselines_no_delete BEFORE DELETE ON execution_verified_baselines BEGIN SELECT RAISE(ABORT,'verified_baseline_rollback'); END;
