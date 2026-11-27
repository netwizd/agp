-- Authored WAF zones have no published or qualified state in this pilot.
CREATE TABLE config_zone_revisions (
  id TEXT PRIMARY KEY,
  parent_id TEXT REFERENCES config_zone_revisions(id),
  zone_id TEXT NOT NULL,
  site_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  revision_number BIGINT NOT NULL CHECK (revision_number>0),
  content_digest TEXT NOT NULL,
  canonical_json TEXT NOT NULL,
  canonical_size_bytes BIGINT NOT NULL CHECK (canonical_size_bytes BETWEEN 1 AND 2097152),
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  UNIQUE(zone_id,revision_number),
  UNIQUE(id,zone_id,site_id,owner_id),
  CHECK (parent_id IS NULL OR parent_id<>id)
);
CREATE TABLE config_zone_heads (
  zone_id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  revision_id TEXT NOT NULL UNIQUE,
  row_version BIGINT NOT NULL CHECK (row_version>0),
  FOREIGN KEY(revision_id,zone_id,site_id,owner_id) REFERENCES config_zone_revisions(id,zone_id,site_id,owner_id)
);
CREATE INDEX config_zone_heads_site_idx ON config_zone_heads(site_id,zone_id);
CREATE TABLE config_zone_previews (
  id TEXT PRIMARY KEY,
  zone_revision_id TEXT NOT NULL REFERENCES config_zone_revisions(id),
  site_id TEXT NOT NULL,
  base_revision_id TEXT NOT NULL REFERENCES config_revisions(id),
  catalog_id TEXT NOT NULL REFERENCES config_catalog_snapshots(id),
  preview_digest TEXT NOT NULL,
  report_json TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  CHECK (expires_at>created_at)
);
CREATE INDEX config_zone_previews_zone_idx ON config_zone_previews(zone_revision_id,created_at);
CREATE TRIGGER config_zone_revisions_immutable BEFORE UPDATE OR DELETE ON config_zone_revisions FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER config_zone_previews_immutable BEFORE UPDATE OR DELETE ON config_zone_previews FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER config_zone_heads_no_delete BEFORE DELETE ON config_zone_heads FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE FUNCTION agp_zone_head_cas() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='INSERT' THEN
    IF NOT EXISTS(SELECT 1 FROM config_zone_revisions r WHERE r.id=NEW.revision_id AND r.parent_id IS NULL AND r.revision_number=1 AND NEW.row_version=1) THEN RAISE EXCEPTION 'zone_head_cas_required' USING ERRCODE='55000'; END IF;
  ELSE
    IF NEW.zone_id<>OLD.zone_id OR NEW.site_id<>OLD.site_id OR NEW.owner_id<>OLD.owner_id OR NEW.row_version<>OLD.row_version+1 OR NOT EXISTS(SELECT 1 FROM config_zone_revisions r WHERE r.id=NEW.revision_id AND r.parent_id=OLD.revision_id AND r.revision_number=NEW.row_version) THEN RAISE EXCEPTION 'zone_head_cas_required' USING ERRCODE='55000'; END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER config_zone_heads_cas BEFORE INSERT OR UPDATE ON config_zone_heads FOR EACH ROW EXECUTE FUNCTION agp_zone_head_cas();
