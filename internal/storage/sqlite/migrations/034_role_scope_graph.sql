-- Installation-owned scope facts; authoring catalog entries are not authority.
CREATE TABLE role_scope_graph (
 id INTEGER PRIMARY KEY CHECK(id=1), graph_id TEXT NOT NULL UNIQUE,
 revision BIGINT NOT NULL CHECK(revision=1), authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),
 graph_digest TEXT NOT NULL, manifest_json TEXT NOT NULL CHECK(length(CAST(manifest_json AS BLOB))<=16777216),
 created_at TIMESTAMP NOT NULL
);
CREATE TRIGGER role_scope_graph_bootstrap BEFORE INSERT ON role_scope_graph WHEN EXISTS(SELECT 1 FROM security_state) BEGIN SELECT RAISE(ABORT,'role_scope_bootstrap_closed'); END;
CREATE TRIGGER role_scope_graph_no_update BEFORE UPDATE ON role_scope_graph BEGIN SELECT RAISE(ABORT,'immutable_role_scope_graph'); END;
CREATE TRIGGER role_scope_graph_no_delete BEFORE DELETE ON role_scope_graph BEGIN SELECT RAISE(ABORT,'immutable_role_scope_graph'); END;
