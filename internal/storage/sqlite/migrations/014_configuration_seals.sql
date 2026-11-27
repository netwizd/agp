CREATE TABLE config_revision_seals (revision_id TEXT PRIMARY KEY REFERENCES config_revisions(id),created_at TIMESTAMP NOT NULL);
CREATE TRIGGER config_seals_no_update BEFORE UPDATE ON config_revision_seals BEGIN SELECT RAISE(ABORT,'immutable_configuration_seal'); END;
CREATE TRIGGER config_seals_no_delete BEFORE DELETE ON config_revision_seals BEGIN SELECT RAISE(ABORT,'immutable_configuration_seal'); END;
CREATE TRIGGER config_head_cas BEFORE UPDATE ON config_head WHEN NEW.row_version<>OLD.row_version+1 OR NOT EXISTS(SELECT 1 FROM config_revisions r JOIN config_revision_seals s ON s.revision_id=r.id WHERE r.id=NEW.revision_id AND r.parent_id IS OLD.revision_id AND r.revision_number=NEW.row_version) BEGIN SELECT RAISE(ABORT,'configuration_head_cas_required'); END;
CREATE TRIGGER config_head_no_delete BEFORE DELETE ON config_head BEGIN SELECT RAISE(ABORT,'immutable_configuration_head'); END;
CREATE TRIGGER config_gateways_sealed BEFORE INSERT ON config_gateways WHEN EXISTS(SELECT 1 FROM config_revision_seals WHERE revision_id=NEW.revision_id) BEGIN SELECT RAISE(ABORT,'sealed_configuration_projection'); END;
CREATE TRIGGER config_routes_sealed BEFORE INSERT ON config_routes WHEN EXISTS(SELECT 1 FROM config_revision_seals WHERE revision_id=NEW.revision_id) BEGIN SELECT RAISE(ABORT,'sealed_configuration_projection'); END;
CREATE TRIGGER config_gateway_nodes_sealed BEFORE INSERT ON config_gateway_nodes WHEN EXISTS(SELECT 1 FROM config_revision_seals WHERE revision_id=NEW.revision_id) BEGIN SELECT RAISE(ABORT,'sealed_configuration_projection'); END;
CREATE TRIGGER config_profile_assignments_sealed BEFORE INSERT ON config_profile_assignments WHEN EXISTS(SELECT 1 FROM config_revision_seals WHERE revision_id=NEW.revision_id) BEGIN SELECT RAISE(ABORT,'sealed_configuration_projection'); END;

