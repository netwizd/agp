-- Trusted zone publication facts, frozen resolutions and sealed desired provenance.
CREATE TABLE config_zone_validations (
 id TEXT PRIMARY KEY,zone_revision_id TEXT NOT NULL REFERENCES config_zone_revisions(id),
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),author_fingerprint TEXT NOT NULL,
 dependency_digest TEXT NOT NULL,report_json TEXT NOT NULL,created_by TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL,expires_at TIMESTAMP NOT NULL,CHECK(expires_at>created_at)
);
CREATE INDEX config_zone_validations_revision_idx ON config_zone_validations(zone_revision_id,created_at);
CREATE TABLE config_zone_operations (
 id TEXT PRIMARY KEY,validation_id TEXT NOT NULL REFERENCES config_zone_validations(id),created_at TIMESTAMP NOT NULL
);
CREATE TABLE config_zone_approvals (
 id TEXT PRIMARY KEY,zone_revision_id TEXT NOT NULL REFERENCES config_zone_revisions(id),validation_id TEXT NOT NULL REFERENCES config_zone_validations(id),
 content_digest TEXT NOT NULL,dependency_digest TEXT NOT NULL,author_id TEXT NOT NULL,approver_id TEXT NOT NULL CHECK(approver_id<>author_id),
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),author_fingerprint TEXT NOT NULL,approver_fingerprint TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL,expires_at TIMESTAMP NOT NULL,mfa_at TIMESTAMP NOT NULL,reason TEXT NOT NULL,CHECK(expires_at>created_at)
);
CREATE INDEX config_zone_approvals_revision_idx ON config_zone_approvals(zone_revision_id,created_at);
CREATE TABLE config_zone_publications (
 id TEXT PRIMARY KEY,zone_revision_id TEXT NOT NULL UNIQUE REFERENCES config_zone_revisions(id),approval_id TEXT NOT NULL REFERENCES config_zone_approvals(id),
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),content_digest TEXT NOT NULL,dependency_digest TEXT NOT NULL,published_by TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL,mfa_at TIMESTAMP NOT NULL
);
CREATE TABLE config_zone_resolutions (
 id TEXT PRIMARY KEY,zone_revision_id TEXT NOT NULL REFERENCES config_zone_revisions(id),site_id TEXT NOT NULL,
 base_revision_id TEXT NOT NULL REFERENCES config_revisions(id),authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),
 operation_id TEXT NOT NULL UNIQUE,resolution_digest TEXT NOT NULL,request_json TEXT NOT NULL,report_json TEXT NOT NULL,created_by TEXT NOT NULL,author_fingerprint TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL,expires_at TIMESTAMP NOT NULL,CHECK(expires_at>created_at)
);
CREATE INDEX config_zone_resolutions_site_idx ON config_zone_resolutions(site_id,id);
CREATE TABLE config_zone_changes (
 id TEXT PRIMARY KEY,resolution_id TEXT NOT NULL REFERENCES config_zone_resolutions(id),request_json TEXT NOT NULL,request_digest TEXT NOT NULL,
 result_revision_id TEXT NOT NULL UNIQUE REFERENCES config_revisions(id),operation_id TEXT NOT NULL UNIQUE,created_by TEXT NOT NULL,created_at TIMESTAMP NOT NULL
);
CREATE TABLE config_revision_zone_assignments (
 revision_id TEXT NOT NULL REFERENCES config_revisions(id),gateway_id TEXT NOT NULL,zone_revision_id TEXT NOT NULL REFERENCES config_zone_revisions(id),
 resolution_id TEXT NOT NULL REFERENCES config_zone_resolutions(id),binding_digest TEXT NOT NULL,
 PRIMARY KEY(revision_id,gateway_id),FOREIGN KEY(revision_id,gateway_id) REFERENCES config_gateways(revision_id,id)
);
CREATE TRIGGER config_zone_validations_no_update BEFORE UPDATE ON config_zone_validations BEGIN SELECT RAISE(ABORT,'immutable_zone_fact'); END;
CREATE TRIGGER config_zone_validations_no_delete BEFORE DELETE ON config_zone_validations BEGIN SELECT RAISE(ABORT,'immutable_zone_fact'); END;
CREATE TRIGGER config_zone_operations_no_update BEFORE UPDATE ON config_zone_operations BEGIN SELECT RAISE(ABORT,'immutable_zone_fact'); END;
CREATE TRIGGER config_zone_operations_no_delete BEFORE DELETE ON config_zone_operations BEGIN SELECT RAISE(ABORT,'immutable_zone_fact'); END;
CREATE TRIGGER config_zone_approvals_no_update BEFORE UPDATE ON config_zone_approvals BEGIN SELECT RAISE(ABORT,'immutable_zone_fact'); END;
CREATE TRIGGER config_zone_approvals_no_delete BEFORE DELETE ON config_zone_approvals BEGIN SELECT RAISE(ABORT,'immutable_zone_fact'); END;
CREATE TRIGGER config_zone_publications_no_update BEFORE UPDATE ON config_zone_publications BEGIN SELECT RAISE(ABORT,'immutable_zone_fact'); END;
CREATE TRIGGER config_zone_publications_no_delete BEFORE DELETE ON config_zone_publications BEGIN SELECT RAISE(ABORT,'immutable_zone_fact'); END;
CREATE TRIGGER config_zone_resolutions_no_update BEFORE UPDATE ON config_zone_resolutions BEGIN SELECT RAISE(ABORT,'immutable_zone_fact'); END;
CREATE TRIGGER config_zone_resolutions_no_delete BEFORE DELETE ON config_zone_resolutions BEGIN SELECT RAISE(ABORT,'immutable_zone_fact'); END;
CREATE TRIGGER config_zone_changes_no_update BEFORE UPDATE ON config_zone_changes BEGIN SELECT RAISE(ABORT,'immutable_zone_fact'); END;
CREATE TRIGGER config_zone_changes_no_delete BEFORE DELETE ON config_zone_changes BEGIN SELECT RAISE(ABORT,'immutable_zone_fact'); END;
CREATE TRIGGER config_revision_zone_assignments_no_update BEFORE UPDATE ON config_revision_zone_assignments BEGIN SELECT RAISE(ABORT,'immutable_zone_fact'); END;
CREATE TRIGGER config_revision_zone_assignments_no_delete BEFORE DELETE ON config_revision_zone_assignments BEGIN SELECT RAISE(ABORT,'immutable_zone_fact'); END;
CREATE TRIGGER config_revision_zone_assignments_sealed BEFORE INSERT ON config_revision_zone_assignments WHEN EXISTS(SELECT 1 FROM config_revision_seals WHERE revision_id=NEW.revision_id) BEGIN SELECT RAISE(ABORT,'sealed_configuration_projection'); END;
