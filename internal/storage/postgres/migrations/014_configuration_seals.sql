CREATE TABLE config_revision_seals (revision_id TEXT PRIMARY KEY REFERENCES config_revisions(id),created_at TIMESTAMPTZ NOT NULL);
CREATE TRIGGER config_seals_immutable BEFORE UPDATE OR DELETE ON config_revision_seals FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE FUNCTION agp_configuration_projection_open() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM 1 FROM config_revisions WHERE id=NEW.revision_id FOR UPDATE;
  IF EXISTS(SELECT 1 FROM config_revision_seals WHERE revision_id=NEW.revision_id) THEN RAISE EXCEPTION 'sealed_configuration_projection' USING ERRCODE='55000'; END IF;
  RETURN NEW;
END $$;
CREATE FUNCTION agp_configuration_seal_lock() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM 1 FROM config_revisions WHERE id=NEW.revision_id FOR UPDATE;
  RETURN NEW;
END $$;
CREATE TRIGGER config_seal_lock BEFORE INSERT ON config_revision_seals FOR EACH ROW EXECUTE FUNCTION agp_configuration_seal_lock();
CREATE FUNCTION agp_configuration_head_cas() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.row_version<>OLD.row_version+1 OR NOT EXISTS(SELECT 1 FROM config_revisions r JOIN config_revision_seals s ON s.revision_id=r.id WHERE r.id=NEW.revision_id AND r.parent_id IS NOT DISTINCT FROM OLD.revision_id AND r.revision_number=NEW.row_version) THEN RAISE EXCEPTION 'configuration_head_cas_required' USING ERRCODE='55000'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER config_head_cas BEFORE UPDATE ON config_head FOR EACH ROW EXECUTE FUNCTION agp_configuration_head_cas();
CREATE TRIGGER config_head_no_delete BEFORE DELETE ON config_head FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER config_gateways_sealed BEFORE INSERT ON config_gateways FOR EACH ROW EXECUTE FUNCTION agp_configuration_projection_open();
CREATE TRIGGER config_routes_sealed BEFORE INSERT ON config_routes FOR EACH ROW EXECUTE FUNCTION agp_configuration_projection_open();
CREATE TRIGGER config_gateway_nodes_sealed BEFORE INSERT ON config_gateway_nodes FOR EACH ROW EXECUTE FUNCTION agp_configuration_projection_open();
CREATE TRIGGER config_profile_assignments_sealed BEFORE INSERT ON config_profile_assignments FOR EACH ROW EXECUTE FUNCTION agp_configuration_projection_open();

