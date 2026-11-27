-- Installation-owned scope facts; authoring catalog entries are not authority.
CREATE TABLE role_scope_graph (
 id INTEGER PRIMARY KEY CHECK(id=1), graph_id TEXT NOT NULL UNIQUE,
 revision BIGINT NOT NULL CHECK(revision=1), authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),
 graph_digest TEXT NOT NULL, manifest_json TEXT NOT NULL CHECK(octet_length(manifest_json)<=16777216),
 created_at TIMESTAMPTZ NOT NULL
);
CREATE FUNCTION agp_role_scope_graph_bootstrap() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF EXISTS(SELECT 1 FROM security_state) THEN RAISE EXCEPTION 'role_scope_bootstrap_closed'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER role_scope_graph_bootstrap BEFORE INSERT ON role_scope_graph FOR EACH ROW EXECUTE FUNCTION agp_role_scope_graph_bootstrap();
CREATE FUNCTION agp_role_scope_graph_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable_role_scope_graph'; END $$;
CREATE TRIGGER role_scope_graph_immutable BEFORE UPDATE OR DELETE ON role_scope_graph FOR EACH ROW EXECUTE FUNCTION agp_role_scope_graph_immutable();
