CREATE TABLE config_gateways (
  revision_id TEXT NOT NULL REFERENCES config_revisions(id),
  id TEXT NOT NULL,
  site_id TEXT NOT NULL,
  canonical_json TEXT NOT NULL,
  PRIMARY KEY(revision_id,id)
);
CREATE TABLE config_routes (
  revision_id TEXT NOT NULL,
  id TEXT NOT NULL,
  gateway_id TEXT NOT NULL,
  hostname TEXT NOT NULL,
  path_prefix TEXT NOT NULL,
  upstream_url TEXT NOT NULL,
  PRIMARY KEY(revision_id,id),
  UNIQUE(revision_id,gateway_id,hostname,path_prefix),
  FOREIGN KEY(revision_id,gateway_id) REFERENCES config_gateways(revision_id,id)
);
CREATE TABLE config_gateway_nodes (
  revision_id TEXT NOT NULL,
  gateway_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  PRIMARY KEY(revision_id,gateway_id,node_id),
  FOREIGN KEY(revision_id,gateway_id) REFERENCES config_gateways(revision_id,id)
);
CREATE TABLE config_profile_assignments (
  revision_id TEXT NOT NULL REFERENCES config_revisions(id),
  id TEXT NOT NULL,
  canonical_json TEXT NOT NULL,
  PRIMARY KEY(revision_id,id)
);
CREATE TRIGGER config_gateways_immutable BEFORE UPDATE OR DELETE ON config_gateways FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER config_routes_immutable BEFORE UPDATE OR DELETE ON config_routes FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER config_gateway_nodes_immutable BEFORE UPDATE OR DELETE ON config_gateway_nodes FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER config_profile_assignments_immutable BEFORE UPDATE OR DELETE ON config_profile_assignments FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();

