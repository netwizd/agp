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
  created_at TIMESTAMP NOT NULL,
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
  created_at TIMESTAMP NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  CHECK (expires_at>created_at)
);
CREATE INDEX config_zone_previews_zone_idx ON config_zone_previews(zone_revision_id,created_at);
CREATE TRIGGER config_zone_revisions_no_update BEFORE UPDATE ON config_zone_revisions BEGIN SELECT RAISE(ABORT,'immutable_zone_content'); END;
CREATE TRIGGER config_zone_revisions_no_delete BEFORE DELETE ON config_zone_revisions BEGIN SELECT RAISE(ABORT,'immutable_zone_content'); END;
CREATE TRIGGER config_zone_previews_no_update BEFORE UPDATE ON config_zone_previews BEGIN SELECT RAISE(ABORT,'immutable_zone_preview'); END;
CREATE TRIGGER config_zone_previews_no_delete BEFORE DELETE ON config_zone_previews BEGIN SELECT RAISE(ABORT,'immutable_zone_preview'); END;
CREATE TRIGGER config_zone_heads_no_delete BEFORE DELETE ON config_zone_heads BEGIN SELECT RAISE(ABORT,'immutable_zone_identity'); END;
CREATE TRIGGER config_zone_heads_initial BEFORE INSERT ON config_zone_heads WHEN NOT EXISTS(SELECT 1 FROM config_zone_revisions r WHERE r.id=NEW.revision_id AND r.parent_id IS NULL AND r.revision_number=1 AND NEW.row_version=1) BEGIN SELECT RAISE(ABORT,'zone_head_cas_required'); END;
CREATE TRIGGER config_zone_heads_cas BEFORE UPDATE ON config_zone_heads WHEN NEW.zone_id<>OLD.zone_id OR NEW.site_id<>OLD.site_id OR NEW.owner_id<>OLD.owner_id OR NEW.row_version<>OLD.row_version+1 OR NOT EXISTS(SELECT 1 FROM config_zone_revisions r WHERE r.id=NEW.revision_id AND r.parent_id=OLD.revision_id AND r.revision_number=NEW.row_version) BEGIN SELECT RAISE(ABORT,'zone_head_cas_required'); END;
