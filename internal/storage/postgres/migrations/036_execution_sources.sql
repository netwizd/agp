CREATE TABLE execution_baseline_challenges (
 id TEXT PRIMARY KEY, node_id TEXT NOT NULL, anchor_digest TEXT NOT NULL,
 query_json TEXT NOT NULL CHECK(octet_length(query_json)<=16384),
 head_json TEXT NOT NULL CHECK(octet_length(head_json)<=16384),
 created_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL CHECK(expires_at>created_at),
 capture_digest TEXT NOT NULL DEFAULT ''
);
CREATE INDEX execution_baseline_challenges_node ON execution_baseline_challenges(node_id,created_at);
CREATE TABLE execution_baseline_captures (
 id TEXT PRIMARY KEY REFERENCES execution_baseline_challenges(id), node_id TEXT NOT NULL,
 capture_digest TEXT NOT NULL UNIQUE, capture_json TEXT NOT NULL CHECK(octet_length(capture_json)<=65536),
 received_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE execution_source_outcomes (
 receipt_id TEXT PRIMARY KEY, node_id TEXT NOT NULL, task_id TEXT NOT NULL UNIQUE,
 receipt_digest TEXT NOT NULL UNIQUE, receipt_json TEXT NOT NULL CHECK(octet_length(receipt_json)<=65536),
 received_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE execution_source_freezes (
 node_id TEXT PRIMARY KEY, anchor_digest TEXT NOT NULL, challenge_id TEXT NOT NULL REFERENCES execution_baseline_captures(id),
 created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE execution_verified_baselines (
 node_id TEXT PRIMARY KEY, anchor_digest TEXT NOT NULL, boot_digest TEXT NOT NULL,
 capture_id TEXT NOT NULL REFERENCES execution_baseline_captures(id), active_json TEXT NOT NULL CHECK(octet_length(active_json)<=16384),
 accepted_sequence BIGINT NOT NULL CHECK(accepted_sequence>=0), receipt_sequence BIGINT NOT NULL CHECK(receipt_sequence>=0),
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0), writer_epoch BIGINT NOT NULL CHECK(writer_epoch>0),
 deny_sequence BIGINT NOT NULL CHECK(deny_sequence>=0), frozen BOOLEAN NOT NULL DEFAULT FALSE,
 proof_kind TEXT NOT NULL CHECK(proof_kind IN ('capture','receipt')), proof_id TEXT NOT NULL,
 verified_at TIMESTAMPTZ NOT NULL, row_version BIGINT NOT NULL CHECK(row_version>0)
);
CREATE FUNCTION agp_execution_baseline_challenge_once() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.id<>OLD.id OR NEW.node_id<>OLD.node_id OR NEW.anchor_digest<>OLD.anchor_digest OR NEW.query_json<>OLD.query_json OR NEW.head_json<>OLD.head_json OR NEW.created_at<>OLD.created_at OR NEW.expires_at<>OLD.expires_at OR OLD.capture_digest<>'' OR NEW.capture_digest='' THEN RAISE EXCEPTION 'immutable_baseline_challenge'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER execution_baseline_challenges_once BEFORE UPDATE ON execution_baseline_challenges FOR EACH ROW EXECUTE FUNCTION agp_execution_baseline_challenge_once();
CREATE FUNCTION agp_execution_source_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable_execution_source_fact'; END $$;
CREATE TRIGGER execution_baseline_challenges_no_delete BEFORE DELETE ON execution_baseline_challenges FOR EACH ROW EXECUTE FUNCTION agp_execution_source_immutable();
CREATE TRIGGER execution_baseline_captures_immutable BEFORE UPDATE OR DELETE ON execution_baseline_captures FOR EACH ROW EXECUTE FUNCTION agp_execution_source_immutable();
CREATE TRIGGER execution_source_outcomes_immutable BEFORE UPDATE OR DELETE ON execution_source_outcomes FOR EACH ROW EXECUTE FUNCTION agp_execution_source_immutable();
CREATE TRIGGER execution_source_freezes_immutable BEFORE UPDATE OR DELETE ON execution_source_freezes FOR EACH ROW EXECUTE FUNCTION agp_execution_source_immutable();
CREATE FUNCTION agp_verified_baseline_monotonic() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.node_id<>OLD.node_id OR NEW.anchor_digest<>OLD.anchor_digest OR NEW.accepted_sequence<OLD.accepted_sequence OR NEW.receipt_sequence<OLD.receipt_sequence OR NEW.authority_epoch<OLD.authority_epoch OR NEW.writer_epoch<OLD.writer_epoch OR NEW.deny_sequence<OLD.deny_sequence OR NEW.verified_at<OLD.verified_at OR NEW.row_version<>OLD.row_version+1 OR (OLD.frozen=TRUE AND NEW.frozen=FALSE) THEN RAISE EXCEPTION 'verified_baseline_rollback'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER execution_verified_baselines_monotonic BEFORE UPDATE ON execution_verified_baselines FOR EACH ROW EXECUTE FUNCTION agp_verified_baseline_monotonic();
CREATE TRIGGER execution_verified_baselines_no_delete BEFORE DELETE ON execution_verified_baselines FOR EACH ROW EXECUTE FUNCTION agp_execution_source_immutable();
