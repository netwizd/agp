-- Approved grants have independent immutable incarnations. No positive grant
-- is reconstructed from the deny journal or written to bootstrap-only scopes.
CREATE TABLE role_definitions (
 role_digest TEXT PRIMARY KEY, role_id TEXT NOT NULL, version BIGINT NOT NULL CHECK(version>0),
 name TEXT NOT NULL, created_at TIMESTAMP NOT NULL, sealed BOOLEAN NOT NULL DEFAULT FALSE,
 UNIQUE(role_id,version)
);
CREATE TABLE role_definition_permissions (
 role_digest TEXT NOT NULL REFERENCES role_definitions(role_digest), permission TEXT NOT NULL,
 PRIMARY KEY(role_digest,permission)
);
CREATE TABLE role_definition_scopes (
 role_digest TEXT NOT NULL REFERENCES role_definitions(role_digest), scope_type TEXT NOT NULL CHECK(scope_type IN ('global','site','node_group','node','resource')),
 PRIMARY KEY(role_digest,scope_type)
);
CREATE TABLE role_bindings (
 binding_id TEXT PRIMARY KEY CHECK(substr(binding_id,1,9)='rbinding_'), principal_id TEXT NOT NULL REFERENCES users(id),
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0), role_digest TEXT NOT NULL REFERENCES role_definitions(role_digest),
 scope_type TEXT NOT NULL CHECK(scope_type IN ('global','site','node_group','node','resource')), scope_id TEXT NOT NULL,
 expires_at TIMESTAMP NULL, revision BIGINT NOT NULL CHECK(revision IN (1,2)), created_at TIMESTAMP NOT NULL, revoked_at TIMESTAMP NULL,
 CHECK((scope_type='global' AND scope_id='') OR (scope_type<>'global' AND length(scope_id)>0)),
 CHECK(expires_at IS NULL OR expires_at>created_at), CHECK((revoked_at IS NULL AND revision=1) OR (revoked_at IS NOT NULL AND revision=2))
);
CREATE INDEX role_binding_principal ON role_bindings(principal_id,authority_epoch,revoked_at);
-- No FK: a deny must survive replay before the corresponding positive row exists.
CREATE TABLE role_binding_revocations (
 binding_id TEXT PRIMARY KEY CHECK(substr(binding_id,1,9)='rbinding_'),authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),event_id TEXT NOT NULL,revoked_at TIMESTAMP NOT NULL
);
CREATE TRIGGER role_definitions_monotonic BEFORE UPDATE ON role_definitions WHEN NEW.role_digest<>OLD.role_digest OR NEW.role_id<>OLD.role_id OR NEW.version<>OLD.version OR NEW.name<>OLD.name OR NEW.created_at<>OLD.created_at OR OLD.sealed=TRUE OR NEW.sealed<>TRUE BEGIN SELECT RAISE(ABORT,'immutable_role_definition'); END;
CREATE TRIGGER role_definitions_no_delete BEFORE DELETE ON role_definitions BEGIN SELECT RAISE(ABORT,'immutable_role_definition'); END;
CREATE TRIGGER role_permissions_insert BEFORE INSERT ON role_definition_permissions WHEN NOT EXISTS(SELECT 1 FROM role_definitions WHERE role_digest=NEW.role_digest AND sealed=FALSE) BEGIN SELECT RAISE(ABORT,'sealed_role_definition'); END;
CREATE TRIGGER role_permissions_no_update BEFORE UPDATE ON role_definition_permissions BEGIN SELECT RAISE(ABORT,'immutable_role_definition'); END;
CREATE TRIGGER role_permissions_no_delete BEFORE DELETE ON role_definition_permissions BEGIN SELECT RAISE(ABORT,'immutable_role_definition'); END;
CREATE TRIGGER role_scopes_insert BEFORE INSERT ON role_definition_scopes WHEN NOT EXISTS(SELECT 1 FROM role_definitions WHERE role_digest=NEW.role_digest AND sealed=FALSE) BEGIN SELECT RAISE(ABORT,'sealed_role_definition'); END;
CREATE TRIGGER role_scopes_no_update BEFORE UPDATE ON role_definition_scopes BEGIN SELECT RAISE(ABORT,'immutable_role_definition'); END;
CREATE TRIGGER role_scopes_no_delete BEFORE DELETE ON role_definition_scopes BEGIN SELECT RAISE(ABORT,'immutable_role_definition'); END;
CREATE TRIGGER role_bindings_insert BEFORE INSERT ON role_bindings WHEN EXISTS(SELECT 1 FROM role_binding_revocations WHERE binding_id=NEW.binding_id) OR NOT EXISTS(SELECT 1 FROM role_definitions WHERE role_digest=NEW.role_digest AND sealed=TRUE) BEGIN SELECT RAISE(ABORT,'role_binding_denied'); END;
CREATE TRIGGER role_bindings_monotonic BEFORE UPDATE ON role_bindings WHEN NEW.binding_id<>OLD.binding_id OR NEW.principal_id<>OLD.principal_id OR NEW.authority_epoch<>OLD.authority_epoch OR NEW.role_digest<>OLD.role_digest OR NEW.scope_type<>OLD.scope_type OR NEW.scope_id<>OLD.scope_id OR NEW.created_at<>OLD.created_at OR NEW.expires_at IS NOT OLD.expires_at OR (OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS NOT OLD.revoked_at OR NEW.revision<>OLD.revision)) OR (OLD.revoked_at IS NULL AND NOT ((NEW.revoked_at IS NULL AND NEW.revision=OLD.revision) OR (NEW.revoked_at IS NOT NULL AND NEW.revision=OLD.revision+1))) BEGIN SELECT RAISE(ABORT,'immutable_role_binding'); END;
CREATE TRIGGER role_bindings_no_delete BEFORE DELETE ON role_bindings BEGIN SELECT RAISE(ABORT,'immutable_role_binding'); END;
CREATE TRIGGER role_revocations_no_update BEFORE UPDATE ON role_binding_revocations BEGIN SELECT RAISE(ABORT,'immutable_role_revocation'); END;
CREATE TRIGGER role_revocations_no_delete BEFORE DELETE ON role_binding_revocations BEGIN SELECT RAISE(ABORT,'immutable_role_revocation'); END;
