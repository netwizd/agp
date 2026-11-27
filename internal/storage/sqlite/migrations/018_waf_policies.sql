-- Immutable WAF policy bodies and independent qualification/approval/publication facts.
CREATE TABLE config_waf_policy_revisions (
 id TEXT PRIMARY KEY,parent_id TEXT REFERENCES config_waf_policy_revisions(id),policy_id TEXT NOT NULL,site_id TEXT NOT NULL,
 revision_number BIGINT NOT NULL CHECK(revision_number>0),content_digest TEXT NOT NULL,canonical_json TEXT NOT NULL,
 created_by TEXT NOT NULL,created_at TIMESTAMP NOT NULL,UNIQUE(policy_id,revision_number),UNIQUE(id,policy_id,site_id),
 CHECK(parent_id IS NULL OR parent_id<>id)
);
CREATE TABLE config_waf_policy_heads (
 policy_id TEXT PRIMARY KEY,site_id TEXT NOT NULL,revision_id TEXT NOT NULL UNIQUE,row_version BIGINT NOT NULL CHECK(row_version>0),
 FOREIGN KEY(revision_id,policy_id,site_id) REFERENCES config_waf_policy_revisions(id,policy_id,site_id)
);
CREATE INDEX config_waf_policy_heads_site_idx ON config_waf_policy_heads(site_id,policy_id);
CREATE TABLE config_waf_policy_validations (
 id TEXT PRIMARY KEY,policy_revision_id TEXT NOT NULL REFERENCES config_waf_policy_revisions(id),
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),author_fingerprint TEXT NOT NULL,
 qualification_digest TEXT NOT NULL,report_json TEXT NOT NULL,created_by TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL,expires_at TIMESTAMP NOT NULL,CHECK(expires_at>created_at)
);
CREATE INDEX config_waf_policy_validations_revision_idx ON config_waf_policy_validations(policy_revision_id,created_at);
CREATE TABLE config_waf_policy_operations (
 id TEXT PRIMARY KEY,validation_id TEXT NOT NULL REFERENCES config_waf_policy_validations(id),state TEXT NOT NULL CHECK(state='succeeded'),created_at TIMESTAMP NOT NULL
);
CREATE TABLE config_waf_policy_approvals (
 id TEXT PRIMARY KEY,policy_revision_id TEXT NOT NULL REFERENCES config_waf_policy_revisions(id),validation_id TEXT NOT NULL REFERENCES config_waf_policy_validations(id),
 content_digest TEXT NOT NULL,qualification_digest TEXT NOT NULL,author_id TEXT NOT NULL,approver_id TEXT NOT NULL CHECK(approver_id<>author_id),
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),author_fingerprint TEXT NOT NULL,approver_fingerprint TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL,expires_at TIMESTAMP NOT NULL,mfa_at TIMESTAMP NOT NULL,reason TEXT NOT NULL,CHECK(expires_at>created_at)
);
CREATE INDEX config_waf_policy_approvals_revision_idx ON config_waf_policy_approvals(policy_revision_id,created_at);
CREATE TABLE config_waf_policy_publications (
 id TEXT PRIMARY KEY,policy_revision_id TEXT NOT NULL UNIQUE REFERENCES config_waf_policy_revisions(id),approval_id TEXT NOT NULL REFERENCES config_waf_policy_approvals(id),
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),content_digest TEXT NOT NULL,qualification_digest TEXT NOT NULL,published_by TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL,mfa_at TIMESTAMP NOT NULL
);
CREATE TRIGGER config_waf_policy_revisions_no_update BEFORE UPDATE ON config_waf_policy_revisions BEGIN SELECT RAISE(ABORT,'immutable_waf_policy_fact'); END;
CREATE TRIGGER config_waf_policy_revisions_no_delete BEFORE DELETE ON config_waf_policy_revisions BEGIN SELECT RAISE(ABORT,'immutable_waf_policy_fact'); END;
CREATE TRIGGER config_waf_policy_validations_no_update BEFORE UPDATE ON config_waf_policy_validations BEGIN SELECT RAISE(ABORT,'immutable_waf_policy_fact'); END;
CREATE TRIGGER config_waf_policy_validations_no_delete BEFORE DELETE ON config_waf_policy_validations BEGIN SELECT RAISE(ABORT,'immutable_waf_policy_fact'); END;
CREATE TRIGGER config_waf_policy_operations_no_update BEFORE UPDATE ON config_waf_policy_operations BEGIN SELECT RAISE(ABORT,'immutable_waf_policy_fact'); END;
CREATE TRIGGER config_waf_policy_operations_no_delete BEFORE DELETE ON config_waf_policy_operations BEGIN SELECT RAISE(ABORT,'immutable_waf_policy_fact'); END;
CREATE TRIGGER config_waf_policy_approvals_no_update BEFORE UPDATE ON config_waf_policy_approvals BEGIN SELECT RAISE(ABORT,'immutable_waf_policy_fact'); END;
CREATE TRIGGER config_waf_policy_approvals_no_delete BEFORE DELETE ON config_waf_policy_approvals BEGIN SELECT RAISE(ABORT,'immutable_waf_policy_fact'); END;
CREATE TRIGGER config_waf_policy_publications_no_update BEFORE UPDATE ON config_waf_policy_publications BEGIN SELECT RAISE(ABORT,'immutable_waf_policy_fact'); END;
CREATE TRIGGER config_waf_policy_publications_no_delete BEFORE DELETE ON config_waf_policy_publications BEGIN SELECT RAISE(ABORT,'immutable_waf_policy_fact'); END;
CREATE TRIGGER config_waf_policy_heads_no_delete BEFORE DELETE ON config_waf_policy_heads BEGIN SELECT RAISE(ABORT,'immutable_policy_identity'); END;
CREATE TRIGGER config_waf_policy_heads_initial BEFORE INSERT ON config_waf_policy_heads WHEN NOT EXISTS(SELECT 1 FROM config_waf_policy_revisions r WHERE r.id=NEW.revision_id AND r.parent_id IS NULL AND r.revision_number=1 AND NEW.row_version=1) BEGIN SELECT RAISE(ABORT,'policy_head_cas_required'); END;
CREATE TRIGGER config_waf_policy_heads_cas BEFORE UPDATE ON config_waf_policy_heads WHEN NEW.policy_id<>OLD.policy_id OR NEW.site_id<>OLD.site_id OR NEW.row_version<>OLD.row_version+1 OR NOT EXISTS(SELECT 1 FROM config_waf_policy_revisions r WHERE r.id=NEW.revision_id AND r.parent_id=OLD.revision_id AND r.revision_number=NEW.row_version) BEGIN SELECT RAISE(ABORT,'policy_head_cas_required'); END;
