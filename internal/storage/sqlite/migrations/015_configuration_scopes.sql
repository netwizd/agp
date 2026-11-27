-- Explicit initial scopes; no grants are inferred from imported catalogs.
CREATE TABLE config_scope_grants (
 id TEXT PRIMARY KEY CHECK (id LIKE 'cgrant_%'), principal_id TEXT NOT NULL,
 permission TEXT NOT NULL CHECK(permission IN ('config.read','config.edit','config.approve')),
 scope_type TEXT NOT NULL CHECK(scope_type IN ('global','site')), scope_id TEXT NOT NULL,
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0), revoked BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMP NOT NULL,
 CHECK ((scope_type='global' AND scope_id='') OR (scope_type='site' AND length(scope_id)>0))
);
CREATE INDEX config_scope_principal_idx ON config_scope_grants(principal_id,authority_epoch,revoked);
CREATE TABLE config_gateway_ownership(gateway_id TEXT PRIMARY KEY,site_id TEXT NOT NULL);
CREATE TRIGGER config_scope_bootstrap_only BEFORE INSERT ON config_scope_grants WHEN EXISTS(SELECT 1 FROM security_state) BEGIN SELECT RAISE(ABORT,'configuration_bootstrap_closed'); END;
CREATE TRIGGER config_ownership_bootstrap_only BEFORE INSERT ON config_gateway_ownership WHEN EXISTS(SELECT 1 FROM security_state) BEGIN SELECT RAISE(ABORT,'configuration_bootstrap_closed'); END;
CREATE TRIGGER config_scope_restrictive_update BEFORE UPDATE ON config_scope_grants WHEN NEW.id<>OLD.id OR NEW.principal_id<>OLD.principal_id OR NEW.permission<>OLD.permission OR NEW.scope_type<>OLD.scope_type OR NEW.scope_id<>OLD.scope_id OR NEW.authority_epoch<>OLD.authority_epoch OR NEW.created_at<>OLD.created_at OR (OLD.revoked=TRUE AND NEW.revoked=FALSE) BEGIN SELECT RAISE(ABORT,'immutable_configuration_grant'); END;
CREATE TRIGGER config_scope_no_delete BEFORE DELETE ON config_scope_grants BEGIN SELECT RAISE(ABORT,'immutable_configuration_grant'); END;
CREATE TRIGGER config_ownership_no_update BEFORE UPDATE ON config_gateway_ownership BEGIN SELECT RAISE(ABORT,'immutable_gateway_ownership'); END;
CREATE TRIGGER config_ownership_no_delete BEFORE DELETE ON config_gateway_ownership BEGIN SELECT RAISE(ABORT,'immutable_gateway_ownership'); END;

INSERT INTO permissions(id,description) VALUES('config.read','Read authorized configuration'),('config.edit','Author authorized configuration'),('config.approve','Approve exact configuration publication');
