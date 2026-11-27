-- Read-only observations from external role-bound identities. Identity trust
-- remains outside this database and its restore domain.
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
 PRIMARY KEY(node_id,digest),CHECK(octet_length(canonical_json)<=262144)
);
CREATE TABLE fleet_inventory_receipts (
 id TEXT PRIMARY KEY,node_id TEXT NOT NULL,receipt_sequence BIGINT NOT NULL CHECK(receipt_sequence>0),identity_digest TEXT NOT NULL,authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),
 request_id TEXT NOT NULL,request_fingerprint TEXT NOT NULL,capability_digest TEXT NOT NULL,observation_digest TEXT NOT NULL,
 observation_json TEXT NOT NULL,receipt_json TEXT NOT NULL,received_at TIMESTAMP NOT NULL,expires_at TIMESTAMP NOT NULL,
 UNIQUE(node_id,identity_digest,request_id),UNIQUE(node_id,receipt_sequence),FOREIGN KEY(node_id,capability_digest) REFERENCES fleet_capability_snapshots(node_id,digest),
 CHECK(expires_at>received_at),CHECK(octet_length(observation_json)<=1048576)
);
CREATE INDEX fleet_inventory_receipts_current_idx ON fleet_inventory_receipts(node_id,receipt_sequence DESC);
CREATE FUNCTION agp_inventory_fact_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable_inventory_fact'; END $$;
CREATE TRIGGER fleet_capability_snapshots_immutable BEFORE UPDATE OR DELETE ON fleet_capability_snapshots FOR EACH ROW EXECUTE FUNCTION agp_inventory_fact_immutable();
CREATE TRIGGER fleet_inventory_receipts_immutable BEFORE UPDATE OR DELETE ON fleet_inventory_receipts FOR EACH ROW EXECUTE FUNCTION agp_inventory_fact_immutable();
CREATE FUNCTION agp_inventory_challenge_consume() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF (to_jsonb(NEW)-'consumed_request_id')<>(to_jsonb(OLD)-'consumed_request_id') OR OLD.consumed_request_id IS NOT NULL OR NEW.consumed_request_id IS NULL THEN RAISE EXCEPTION 'inventory_challenge_single_use'; END IF; RETURN NEW;
END $$;
CREATE TRIGGER fleet_inventory_challenges_consume BEFORE UPDATE ON fleet_inventory_challenges FOR EACH ROW EXECUTE FUNCTION agp_inventory_challenge_consume();
