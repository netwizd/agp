-- Approved grants have independent immutable incarnations. No positive grant
-- is reconstructed from the deny journal or written to bootstrap-only scopes.
CREATE TABLE role_definitions (
 role_digest TEXT PRIMARY KEY,role_id TEXT NOT NULL,version BIGINT NOT NULL CHECK(version>0),
 name TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL,sealed BOOLEAN NOT NULL DEFAULT FALSE,UNIQUE(role_id,version)
);
CREATE TABLE role_definition_permissions (
 role_digest TEXT NOT NULL REFERENCES role_definitions(role_digest),permission TEXT NOT NULL,PRIMARY KEY(role_digest,permission)
);
CREATE TABLE role_definition_scopes (
 role_digest TEXT NOT NULL REFERENCES role_definitions(role_digest),scope_type TEXT NOT NULL CHECK(scope_type IN ('global','site','node_group','node','resource')),PRIMARY KEY(role_digest,scope_type)
);
CREATE TABLE role_bindings (
 binding_id TEXT PRIMARY KEY CHECK(left(binding_id,9)='rbinding_'),principal_id TEXT NOT NULL REFERENCES users(id),authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),role_digest TEXT NOT NULL REFERENCES role_definitions(role_digest),
 scope_type TEXT NOT NULL CHECK(scope_type IN ('global','site','node_group','node','resource')),scope_id TEXT NOT NULL,
 expires_at TIMESTAMPTZ NULL,revision BIGINT NOT NULL CHECK(revision IN (1,2)),created_at TIMESTAMPTZ NOT NULL,revoked_at TIMESTAMPTZ NULL,
 CHECK((scope_type='global' AND scope_id='') OR (scope_type<>'global' AND length(scope_id)>0)),CHECK(expires_at IS NULL OR expires_at>created_at),CHECK((revoked_at IS NULL AND revision=1) OR (revoked_at IS NOT NULL AND revision=2))
);
CREATE INDEX role_binding_principal ON role_bindings(principal_id,authority_epoch,revoked_at);
-- No FK: a deny must survive replay before the corresponding positive row exists.
CREATE TABLE role_binding_revocations (
 binding_id TEXT PRIMARY KEY CHECK(left(binding_id,9)='rbinding_'),authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),event_id TEXT NOT NULL,revoked_at TIMESTAMPTZ NOT NULL
);
CREATE FUNCTION agp_role_definition_monotonic() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'immutable_role_definition'; END IF;
 IF (to_jsonb(NEW)-'sealed')<>(to_jsonb(OLD)-'sealed') OR OLD.sealed OR NOT NEW.sealed THEN RAISE EXCEPTION 'immutable_role_definition'; END IF; RETURN NEW; END $$;
CREATE TRIGGER role_definitions_monotonic BEFORE UPDATE OR DELETE ON role_definitions FOR EACH ROW EXECUTE FUNCTION agp_role_definition_monotonic();
CREATE FUNCTION agp_role_mapping_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM role_definitions WHERE role_digest=NEW.role_digest AND sealed=FALSE) THEN RAISE EXCEPTION 'sealed_role_definition'; END IF; RETURN NEW; END $$;
CREATE TRIGGER role_permissions_insert BEFORE INSERT ON role_definition_permissions FOR EACH ROW EXECUTE FUNCTION agp_role_mapping_insert();
CREATE TRIGGER role_permissions_immutable BEFORE UPDATE OR DELETE ON role_definition_permissions FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER role_scopes_insert BEFORE INSERT ON role_definition_scopes FOR EACH ROW EXECUTE FUNCTION agp_role_mapping_insert();
CREATE TRIGGER role_scopes_immutable BEFORE UPDATE OR DELETE ON role_definition_scopes FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE FUNCTION agp_role_binding_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF EXISTS(SELECT 1 FROM role_binding_revocations WHERE binding_id=NEW.binding_id) OR NOT EXISTS(SELECT 1 FROM role_definitions WHERE role_digest=NEW.role_digest AND sealed=TRUE) THEN RAISE EXCEPTION 'role_binding_denied'; END IF; RETURN NEW; END $$;
CREATE TRIGGER role_bindings_insert BEFORE INSERT ON role_bindings FOR EACH ROW EXECUTE FUNCTION agp_role_binding_insert();
CREATE FUNCTION agp_role_binding_monotonic() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'immutable_role_binding'; END IF;
 IF (to_jsonb(NEW)-'revoked_at'-'revision')<>(to_jsonb(OLD)-'revoked_at'-'revision') OR (OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at OR NEW.revision<>OLD.revision)) OR (OLD.revoked_at IS NULL AND NOT ((NEW.revoked_at IS NULL AND NEW.revision=OLD.revision) OR (NEW.revoked_at IS NOT NULL AND NEW.revision=OLD.revision+1))) THEN RAISE EXCEPTION 'immutable_role_binding'; END IF;RETURN NEW; END $$;
CREATE TRIGGER role_bindings_monotonic BEFORE UPDATE OR DELETE ON role_bindings FOR EACH ROW EXECUTE FUNCTION agp_role_binding_monotonic();
CREATE TRIGGER role_revocations_immutable BEFORE UPDATE OR DELETE ON role_binding_revocations FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
