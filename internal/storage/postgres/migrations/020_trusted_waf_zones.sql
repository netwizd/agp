-- Trusted zone publication facts, frozen resolutions and sealed desired provenance.
CREATE TABLE config_zone_validations (
 id TEXT PRIMARY KEY,zone_revision_id TEXT NOT NULL REFERENCES config_zone_revisions(id),
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),author_fingerprint TEXT NOT NULL,
 dependency_digest TEXT NOT NULL,report_json TEXT NOT NULL,created_by TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ NOT NULL,CHECK(expires_at>created_at)
);
CREATE INDEX config_zone_validations_revision_idx ON config_zone_validations(zone_revision_id,created_at);
CREATE TABLE config_zone_operations (
 id TEXT PRIMARY KEY,validation_id TEXT NOT NULL REFERENCES config_zone_validations(id),created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE config_zone_approvals (
 id TEXT PRIMARY KEY,zone_revision_id TEXT NOT NULL REFERENCES config_zone_revisions(id),validation_id TEXT NOT NULL REFERENCES config_zone_validations(id),
 content_digest TEXT NOT NULL,dependency_digest TEXT NOT NULL,author_id TEXT NOT NULL,approver_id TEXT NOT NULL CHECK(approver_id<>author_id),
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),author_fingerprint TEXT NOT NULL,approver_fingerprint TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ NOT NULL,mfa_at TIMESTAMPTZ NOT NULL,reason TEXT NOT NULL,CHECK(expires_at>created_at)
);
CREATE INDEX config_zone_approvals_revision_idx ON config_zone_approvals(zone_revision_id,created_at);
CREATE TABLE config_zone_publications (
 id TEXT PRIMARY KEY,zone_revision_id TEXT NOT NULL UNIQUE REFERENCES config_zone_revisions(id),approval_id TEXT NOT NULL REFERENCES config_zone_approvals(id),
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),content_digest TEXT NOT NULL,dependency_digest TEXT NOT NULL,published_by TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL,mfa_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE config_zone_resolutions (
 id TEXT PRIMARY KEY,zone_revision_id TEXT NOT NULL REFERENCES config_zone_revisions(id),site_id TEXT NOT NULL,
 base_revision_id TEXT NOT NULL REFERENCES config_revisions(id),authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),
 operation_id TEXT NOT NULL UNIQUE,resolution_digest TEXT NOT NULL,request_json TEXT NOT NULL,report_json TEXT NOT NULL,created_by TEXT NOT NULL,author_fingerprint TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ NOT NULL,CHECK(expires_at>created_at)
);
CREATE INDEX config_zone_resolutions_site_idx ON config_zone_resolutions(site_id,id);
CREATE TABLE config_zone_changes (
 id TEXT PRIMARY KEY,resolution_id TEXT NOT NULL REFERENCES config_zone_resolutions(id),request_json TEXT NOT NULL,request_digest TEXT NOT NULL,
 result_revision_id TEXT NOT NULL UNIQUE REFERENCES config_revisions(id),operation_id TEXT NOT NULL UNIQUE,created_by TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE config_revision_zone_assignments (
 revision_id TEXT NOT NULL REFERENCES config_revisions(id),gateway_id TEXT NOT NULL,zone_revision_id TEXT NOT NULL REFERENCES config_zone_revisions(id),
 resolution_id TEXT NOT NULL REFERENCES config_zone_resolutions(id),binding_digest TEXT NOT NULL,
 PRIMARY KEY(revision_id,gateway_id),FOREIGN KEY(revision_id,gateway_id) REFERENCES config_gateways(revision_id,id)
);
CREATE TRIGGER config_zone_validations_immutable BEFORE UPDATE OR DELETE ON config_zone_validations FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER config_zone_operations_immutable BEFORE UPDATE OR DELETE ON config_zone_operations FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER config_zone_approvals_immutable BEFORE UPDATE OR DELETE ON config_zone_approvals FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER config_zone_publications_immutable BEFORE UPDATE OR DELETE ON config_zone_publications FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER config_zone_resolutions_immutable BEFORE UPDATE OR DELETE ON config_zone_resolutions FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER config_zone_changes_immutable BEFORE UPDATE OR DELETE ON config_zone_changes FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER config_revision_zone_assignments_immutable BEFORE UPDATE OR DELETE ON config_revision_zone_assignments FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE FUNCTION agp_zone_assignment_sealed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM config_revision_seals WHERE revision_id=NEW.revision_id) THEN RAISE EXCEPTION 'sealed_configuration_projection' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER config_revision_zone_assignments_sealed BEFORE INSERT ON config_revision_zone_assignments FOR EACH ROW EXECUTE FUNCTION agp_zone_assignment_sealed();
