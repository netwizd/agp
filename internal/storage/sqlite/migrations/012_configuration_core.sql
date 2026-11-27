-- S1 expands the existing identity database; canonical bytes are stored verbatim.
CREATE TABLE configuration_profile (
  id INTEGER PRIMARY KEY CHECK (id=1),
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  activated_at TIMESTAMP,
  CHECK ((enabled=FALSE AND activated_at IS NULL) OR (enabled=TRUE AND activated_at IS NOT NULL))
);
INSERT INTO configuration_profile(id,enabled) VALUES(1,FALSE);
CREATE TABLE config_revisions (
  id TEXT PRIMARY KEY,
  revision_number BIGINT NOT NULL UNIQUE CHECK (revision_number>0),
  parent_id TEXT REFERENCES config_revisions(id),
  schema_version TEXT NOT NULL CHECK (schema_version IN ('agp.config/v1alpha1','agp.config/v1alpha2')),
  capacity_profile TEXT NOT NULL CHECK (capacity_profile IN ('pilot-500','fleet-10k')),
  canonical_size_bytes BIGINT NOT NULL CHECK (canonical_size_bytes BETWEEN 1 AND 67108864),
  content_digest TEXT NOT NULL,
  canonical_json TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'draft' CHECK (state IN ('draft','validated','approved','published','superseded')),
  created_by TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL,
  row_version BIGINT NOT NULL DEFAULT 0 CHECK (row_version>=0),
  CHECK (parent_id IS NULL OR parent_id<>id),
  CHECK ((schema_version='agp.config/v1alpha1' AND capacity_profile='pilot-500' AND canonical_size_bytes<=2097152) OR (schema_version='agp.config/v1alpha2' AND capacity_profile='fleet-10k'))
);
CREATE INDEX config_revisions_digest_idx ON config_revisions(content_digest);
CREATE TABLE config_head (
  id INTEGER PRIMARY KEY CHECK (id=1),
  revision_id TEXT REFERENCES config_revisions(id),
  row_version BIGINT NOT NULL DEFAULT 0 CHECK (row_version>=0)
);
INSERT INTO config_head(id) VALUES(1);
CREATE TABLE config_drafts (
  id TEXT PRIMARY KEY,
  base_revision_id TEXT REFERENCES config_revisions(id),
  current_version BIGINT NOT NULL CHECK (current_version>=0),
  created_by TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL
);
CREATE TABLE config_draft_versions (
  draft_id TEXT NOT NULL REFERENCES config_drafts(id),
  version BIGINT NOT NULL CHECK (version>=0),
  content_digest TEXT NOT NULL,
  canonical_json TEXT NOT NULL,
  canonical_size_bytes BIGINT NOT NULL CHECK (canonical_size_bytes BETWEEN 1 AND 67108864),
  created_by TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL,
  PRIMARY KEY(draft_id,version)
);
CREATE TABLE config_catalog_snapshots (
  id TEXT PRIMARY KEY,
  content_digest TEXT NOT NULL UNIQUE,
  canonical_json TEXT NOT NULL,
  source_kind TEXT NOT NULL CHECK (source_kind='operator_declared'),
  source_ref TEXT NOT NULL,
  recorded_at TIMESTAMP NOT NULL
);
CREATE TABLE config_requests (
  actor_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  request_key TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  resource_kind TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  resource_version BIGINT NOT NULL DEFAULT 0 CHECK (resource_version>=0),
  created_at TIMESTAMP NOT NULL,
  PRIMARY KEY(actor_id,operation,request_key)
);
CREATE TABLE config_reports (
  id TEXT PRIMARY KEY,
  target_kind TEXT NOT NULL CHECK (target_kind IN ('revision','draft')),
  target_id TEXT NOT NULL,
  target_version BIGINT NOT NULL CHECK (target_version>=0),
  content_digest TEXT NOT NULL,
  catalog_id TEXT REFERENCES config_catalog_snapshots(id),
  report_json TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('passed','failed')),
  created_by TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL
);
CREATE TABLE config_operations (
  id TEXT PRIMARY KEY,
  resource_id TEXT NOT NULL REFERENCES config_reports(id),
  state TEXT NOT NULL CHECK (state IN ('succeeded','failed')),
  created_at TIMESTAMP NOT NULL
);
CREATE TRIGGER config_revisions_immutable_update BEFORE UPDATE ON config_revisions BEGIN SELECT RAISE(ABORT,'immutable_configuration_content'); END;
CREATE TRIGGER config_revisions_immutable_delete BEFORE DELETE ON config_revisions BEGIN SELECT RAISE(ABORT,'immutable_configuration_content'); END;
CREATE TRIGGER config_draft_versions_immutable_update BEFORE UPDATE ON config_draft_versions BEGIN SELECT RAISE(ABORT,'immutable_configuration_content'); END;
CREATE TRIGGER config_draft_versions_immutable_delete BEFORE DELETE ON config_draft_versions BEGIN SELECT RAISE(ABORT,'immutable_configuration_content'); END;
CREATE TRIGGER config_catalog_snapshots_immutable_update BEFORE UPDATE ON config_catalog_snapshots BEGIN SELECT RAISE(ABORT,'immutable_configuration_content'); END;
CREATE TRIGGER config_catalog_snapshots_immutable_delete BEFORE DELETE ON config_catalog_snapshots BEGIN SELECT RAISE(ABORT,'immutable_configuration_content'); END;
CREATE TRIGGER config_reports_immutable_update BEFORE UPDATE ON config_reports BEGIN SELECT RAISE(ABORT,'immutable_configuration_content'); END;
CREATE TRIGGER config_reports_immutable_delete BEFORE DELETE ON config_reports BEGIN SELECT RAISE(ABORT,'immutable_configuration_content'); END;
CREATE TRIGGER resources_configuration_fence_insert BEFORE INSERT ON resources WHEN (SELECT enabled FROM configuration_profile WHERE id=1)=1 BEGIN SELECT RAISE(ABORT,'configuration_revision_required'); END;
CREATE TRIGGER resources_configuration_fence_update BEFORE UPDATE ON resources WHEN (SELECT enabled FROM configuration_profile WHERE id=1)=1 AND NOT (NEW.id=OLD.id AND NEW.name=OLD.name AND NEW.description=OLD.description AND NEW.category=OLD.category AND NEW.icon=OLD.icon AND NEW.internal_url=OLD.internal_url AND NEW.public_host=OLD.public_host AND NEW.public_path=OLD.public_path AND NEW.created_at=OLD.created_at AND NOT (NEW.enabled=1 AND OLD.enabled=0)) BEGIN SELECT RAISE(ABORT,'configuration_revision_required'); END;
CREATE TRIGGER resources_configuration_fence_delete BEFORE DELETE ON resources WHEN (SELECT enabled FROM configuration_profile WHERE id=1)=1 BEGIN SELECT RAISE(ABORT,'configuration_revision_required'); END;
CREATE TRIGGER resource_groups_configuration_fence_insert BEFORE INSERT ON resource_groups WHEN (SELECT enabled FROM configuration_profile WHERE id=1)=1 BEGIN SELECT RAISE(ABORT,'configuration_revision_required'); END;
CREATE TRIGGER resource_groups_configuration_fence_update BEFORE UPDATE ON resource_groups WHEN (SELECT enabled FROM configuration_profile WHERE id=1)=1 BEGIN SELECT RAISE(ABORT,'configuration_revision_required'); END;
CREATE TRIGGER resource_ip_allowlists_configuration_fence_insert BEFORE INSERT ON resource_ip_allowlists WHEN (SELECT enabled FROM configuration_profile WHERE id=1)=1 BEGIN SELECT RAISE(ABORT,'configuration_revision_required'); END;
CREATE TRIGGER resource_ip_allowlists_configuration_fence_update BEFORE UPDATE ON resource_ip_allowlists WHEN (SELECT enabled FROM configuration_profile WHERE id=1)=1 BEGIN SELECT RAISE(ABORT,'configuration_revision_required'); END;
CREATE TRIGGER resource_ip_allowlists_configuration_fence_delete BEFORE DELETE ON resource_ip_allowlists WHEN (SELECT enabled FROM configuration_profile WHERE id=1)=1 BEGIN SELECT RAISE(ABORT,'configuration_revision_required'); END;
CREATE TRIGGER configuration_profile_no_delete BEFORE DELETE ON configuration_profile BEGIN SELECT RAISE(ABORT,'configuration_profile_downgrade_forbidden'); END;
CREATE TRIGGER configuration_profile_monotonic BEFORE UPDATE ON configuration_profile WHEN OLD.enabled=1 AND NEW.enabled=0 BEGIN SELECT RAISE(ABORT,'configuration_profile_downgrade_forbidden'); END;

