CREATE TABLE config_authoring_reviews(
 id TEXT PRIMARY KEY,preview_id TEXT NOT NULL REFERENCES config_zone_previews(id),
 author_id TEXT NOT NULL,reviewer_id TEXT NOT NULL CHECK(reviewer_id<>author_id),
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),author_fingerprint TEXT NOT NULL,reviewer_fingerprint TEXT NOT NULL,
 review_json TEXT NOT NULL,created_at TIMESTAMP NOT NULL,expires_at TIMESTAMP NOT NULL,mfa_at TIMESTAMP NOT NULL,reason TEXT NOT NULL
);
CREATE INDEX config_reviews_preview_idx ON config_authoring_reviews(preview_id,created_at);
CREATE TRIGGER config_reviews_immutable_update BEFORE UPDATE ON config_authoring_reviews BEGIN SELECT RAISE(ABORT,'immutable_authoring_review'); END;
CREATE TRIGGER config_reviews_immutable_delete BEFORE DELETE ON config_authoring_reviews BEGIN SELECT RAISE(ABORT,'immutable_authoring_review'); END;
