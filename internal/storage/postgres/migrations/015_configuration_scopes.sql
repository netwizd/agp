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
CREATE FUNCTION agp_config_bootstrap_only() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF EXISTS(SELECT 1 FROM security_state) THEN RAISE EXCEPTION 'configuration_bootstrap_closed'; END IF; RETURN NEW; END $$;
CREATE TRIGGER config_scope_bootstrap_only BEFORE INSERT ON config_scope_grants FOR EACH ROW EXECUTE FUNCTION agp_config_bootstrap_only();
CREATE TRIGGER config_ownership_bootstrap_only BEFORE INSERT ON config_gateway_ownership FOR EACH ROW EXECUTE FUNCTION agp_config_bootstrap_only();
CREATE FUNCTION agp_config_scope_monotonic() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF TG_OP='DELETE' OR (to_jsonb(NEW)-'revoked')<>(to_jsonb(OLD)-'revoked') OR (OLD.revoked AND NOT NEW.revoked) THEN RAISE EXCEPTION 'immutable_configuration_grant'; END IF; RETURN NEW; END $$;
CREATE TRIGGER config_scope_restrictive_update BEFORE UPDATE OR DELETE ON config_scope_grants FOR EACH ROW EXECUTE FUNCTION agp_config_scope_monotonic();
CREATE FUNCTION agp_config_ownership_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable_gateway_ownership'; END $$;
CREATE TRIGGER config_ownership_immutable BEFORE UPDATE OR DELETE ON config_gateway_ownership FOR EACH ROW EXECUTE FUNCTION agp_config_ownership_immutable();

INSERT INTO permissions(id,description) VALUES('config.read','Read authorized configuration'),('config.edit','Author authorized configuration'),('config.approve','Approve exact configuration publication');
