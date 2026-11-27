-- Read-only observations; external registry remains outside CP restore.
CREATE TABLE fleet_inventory_challenges (
 id TEXT PRIMARY KEY,node_id TEXT NOT NULL,identity_digest TEXT NOT NULL,
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),token_hash TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL,expires_at TIMESTAMP NOT NULL,consumed_request_id TEXT,
 CHECK(expires_at>created_at)
);
CREATE INDEX fleet_inventory_challenges_node_idx ON fleet_inventory_challenges(node_id,created_at);
CREATE INDEX fleet_inventory_challenges_identity_idx ON fleet_inventory_challenges(identity_digest,expires_at);
CREATE TABLE fleet_capability_snapshots (
 node_id TEXT NOT NULL,digest TEXT NOT NULL,canonical_json TEXT NOT NULL,created_at TIMESTAMP NOT NULL,
 PRIMARY KEY(node_id,digest),CHECK(length(CAST(canonical_json AS BLOB))<=262144)
);
CREATE TABLE fleet_inventory_receipts (
 id TEXT PRIMARY KEY,node_id TEXT NOT NULL,receipt_sequence BIGINT NOT NULL CHECK(receipt_sequence>0),identity_digest TEXT NOT NULL,authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),
 request_id TEXT NOT NULL,request_fingerprint TEXT NOT NULL,capability_digest TEXT NOT NULL,observation_digest TEXT NOT NULL,
 observation_json TEXT NOT NULL,receipt_json TEXT NOT NULL,received_at TIMESTAMP NOT NULL,expires_at TIMESTAMP NOT NULL,
 UNIQUE(node_id,identity_digest,request_id),UNIQUE(node_id,receipt_sequence),FOREIGN KEY(node_id,capability_digest) REFERENCES fleet_capability_snapshots(node_id,digest),
 CHECK(expires_at>received_at),CHECK(length(CAST(observation_json AS BLOB))<=1048576)
);
CREATE INDEX fleet_inventory_receipts_current_idx ON fleet_inventory_receipts(node_id,receipt_sequence DESC);
CREATE TRIGGER fleet_capability_snapshots_no_update BEFORE UPDATE ON fleet_capability_snapshots BEGIN SELECT RAISE(ABORT,'immutable_inventory_fact'); END;
CREATE TRIGGER fleet_capability_snapshots_no_delete BEFORE DELETE ON fleet_capability_snapshots BEGIN SELECT RAISE(ABORT,'immutable_inventory_fact'); END;
CREATE TRIGGER fleet_inventory_receipts_no_update BEFORE UPDATE ON fleet_inventory_receipts BEGIN SELECT RAISE(ABORT,'immutable_inventory_fact'); END;
CREATE TRIGGER fleet_inventory_receipts_no_delete BEFORE DELETE ON fleet_inventory_receipts BEGIN SELECT RAISE(ABORT,'immutable_inventory_fact'); END;
CREATE TRIGGER fleet_inventory_challenges_consume BEFORE UPDATE ON fleet_inventory_challenges WHEN NEW.id<>OLD.id OR NEW.node_id<>OLD.node_id OR NEW.identity_digest<>OLD.identity_digest OR NEW.authority_epoch<>OLD.authority_epoch OR NEW.token_hash<>OLD.token_hash OR NEW.created_at<>OLD.created_at OR NEW.expires_at<>OLD.expires_at OR OLD.consumed_request_id IS NOT NULL OR NEW.consumed_request_id IS NULL BEGIN SELECT RAISE(ABORT,'inventory_challenge_single_use'); END;
