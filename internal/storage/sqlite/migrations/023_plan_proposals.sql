-- Planning review artifacts deliberately have no executable Plan or sequence.
CREATE TABLE config_plan_proposals (
 id TEXT PRIMARY KEY,site_id TEXT NOT NULL,revision_id TEXT NOT NULL REFERENCES config_revisions(id),
 proposal_digest TEXT NOT NULL UNIQUE,authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),
 author_id TEXT NOT NULL,author_fingerprint TEXT NOT NULL,
 dependency_digest TEXT NOT NULL,proposal_json TEXT NOT NULL CHECK(length(proposal_json)<=33554432),
 created_at TIMESTAMP NOT NULL,expires_at TIMESTAMP NOT NULL CHECK(expires_at>created_at)
);
CREATE INDEX config_plan_proposals_page ON config_plan_proposals(created_at DESC,id DESC);
CREATE TABLE config_plan_proposal_reviews (
 id TEXT PRIMARY KEY,proposal_id TEXT NOT NULL REFERENCES config_plan_proposals(id),
 reviewer_id TEXT NOT NULL,reviewer_fingerprint TEXT NOT NULL,
 review_digest TEXT NOT NULL,review_json TEXT NOT NULL CHECK(length(review_json)<=65536),
 created_at TIMESTAMP NOT NULL,UNIQUE(proposal_id,reviewer_id)
);
CREATE TABLE config_plan_proposal_signatures (
 id TEXT PRIMARY KEY,review_id TEXT NOT NULL REFERENCES config_plan_proposal_reviews(id),
 key_id TEXT NOT NULL,envelope_digest TEXT NOT NULL,
 envelope_json TEXT NOT NULL CHECK(length(envelope_json)<=33619968),created_at TIMESTAMP NOT NULL,
 UNIQUE(review_id,key_id)
);
CREATE TRIGGER config_plan_proposals_no_update BEFORE UPDATE ON config_plan_proposals BEGIN SELECT RAISE(ABORT,'immutable_plan_proposal'); END;
CREATE TRIGGER config_plan_proposals_no_delete BEFORE DELETE ON config_plan_proposals BEGIN SELECT RAISE(ABORT,'immutable_plan_proposal'); END;
CREATE TRIGGER config_plan_proposal_reviews_no_update BEFORE UPDATE ON config_plan_proposal_reviews BEGIN SELECT RAISE(ABORT,'immutable_plan_proposal'); END;
CREATE TRIGGER config_plan_proposal_reviews_no_delete BEFORE DELETE ON config_plan_proposal_reviews BEGIN SELECT RAISE(ABORT,'immutable_plan_proposal'); END;
CREATE TRIGGER config_plan_proposal_signatures_no_update BEFORE UPDATE ON config_plan_proposal_signatures BEGIN SELECT RAISE(ABORT,'immutable_plan_proposal'); END;
CREATE TRIGGER config_plan_proposal_signatures_no_delete BEFORE DELETE ON config_plan_proposal_signatures BEGIN SELECT RAISE(ABORT,'immutable_plan_proposal'); END;
