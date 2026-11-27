-- AGP v2 / Proposed reference schema / PostgreSQL 17+.
-- NOT a migration, NOT a command to execute against production.
-- Run once in an empty disposable database for contract verification.
-- Legacy public.* is deliberately untouched. No extensions/superuser/global grants.
-- Application owns permissions, canonicalization, graph validation, state transitions,
-- write audit, retention, key access, external journal, and cross-row invariants noted below.
BEGIN;
CREATE SCHEMA agp_v2;

CREATE DOMAIN agp_v2.object_id AS text
  CHECK (VALUE ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$');
CREATE DOMAIN agp_v2.digest AS text
  CHECK (VALUE ~ '^sha256:[0-9a-f]{64}$');
CREATE DOMAIN agp_v2.uint63 AS bigint CHECK (VALUE >= 0);
CREATE DOMAIN agp_v2.short_seconds AS integer CHECK (VALUE BETWEEN 0 AND 86400);
CREATE DOMAIN agp_v2.extension_metadata AS jsonb
  CHECK (jsonb_typeof(VALUE) = 'object' AND octet_length(VALUE::text) <= 16384);

CREATE TABLE agp_v2.principals (
  id agp_v2.object_id PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('local','oidc','directory','service')),
  username text NOT NULL CHECK (length(username) BETWEEN 1 AND 128),
  username_key text NOT NULL UNIQUE CHECK (length(username_key) BETWEEN 1 AND 256),
  display_name text NOT NULL DEFAULT '' CHECK (length(display_name) <= 256),
  state text NOT NULL CHECK (state IN ('invited','active','blocked','disabled','deleted')),
  lifecycle_state text NOT NULL CHECK (lifecycle_state IN ('invited','active')),
  is_break_glass boolean NOT NULL DEFAULT false,
  security_version agp_v2.uint63 NOT NULL DEFAULT 0,
  row_version agp_v2.uint63 NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CHECK (NOT is_break_glass OR kind = 'local'),
  CHECK ((state = 'deleted') = (deleted_at IS NOT NULL)),
  CHECK (state <> 'invited' OR lifecycle_state = 'invited'),
  CHECK (state <> 'active' OR lifecycle_state = 'active')
);
-- username_key is Unicode/normalization-policy output, never PostgreSQL lower() alone.
-- Block/disable state is orthogonal to setup lifecycle. Normal allow requires
-- lifecycle_state=active and an enabled principal. Invited local principals have
-- no active local_credentials row; only a private typed setup context admits them.
CREATE TABLE agp_v2.identity_bridges (
  entity_kind text NOT NULL CHECK (entity_kind IN ('principal','access_group','resource')),
  legacy_id text NOT NULL,
  canonical_id agp_v2.object_id NOT NULL,
  source_schema text NOT NULL DEFAULT 'public' CHECK (source_schema = 'public'),
  imported_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (entity_kind, legacy_id),
  UNIQUE (entity_kind, canonical_id)
);
-- Polymorphic canonical_id resolved by migration adapter; not a fabricated FK to legacy.
CREATE TABLE agp_v2.local_credentials (
  principal_id agp_v2.object_id PRIMARY KEY REFERENCES agp_v2.principals(id),
  id agp_v2.object_id NOT NULL UNIQUE,
  authenticator_version agp_v2.uint63 NOT NULL CHECK (authenticator_version > 0),
  password_phc text NOT NULL CHECK (password_phc LIKE '$argon2id$%' AND length(password_phc) <= 1024),
  password_changed_at timestamptz NOT NULL,
  must_change boolean NOT NULL DEFAULT false,
  row_version agp_v2.uint63 NOT NULL DEFAULT 0
);
CREATE TABLE agp_v2.identity_providers (
  id agp_v2.object_id PRIMARY KEY,
  security_guard_id agp_v2.object_id NOT NULL UNIQUE,
  name text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 128),
  issuer text COLLATE "C" NOT NULL UNIQUE CHECK (length(issuer) <= 2048),
  enabled boolean NOT NULL DEFAULT false,
  row_version agp_v2.uint63 NOT NULL DEFAULT 0
);
-- One immutable exact issuer per provider. Login and management clients belong
-- to immutable purpose-scoped version rows below, never a shared client fallback.
CREATE TABLE agp_v2.external_identities (
  provider_id agp_v2.object_id NOT NULL REFERENCES agp_v2.identity_providers(id),
  subject text COLLATE "C" NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
  principal_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  id agp_v2.object_id NOT NULL UNIQUE,
  security_guard_id agp_v2.object_id NOT NULL UNIQUE,
  authenticator_version agp_v2.uint63 NOT NULL CHECK (authenticator_version > 0),
  enabled boolean NOT NULL DEFAULT false,
  row_version agp_v2.uint63 NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (provider_id, subject)
);
CREATE TABLE agp_v2.access_groups (
  id agp_v2.object_id PRIMARY KEY,
  name text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 128),
  description text NOT NULL DEFAULT '' CHECK (length(description) <= 2048),
  mfa_required boolean NOT NULL DEFAULT false,
  row_version agp_v2.uint63 NOT NULL DEFAULT 0,
  deleted_at timestamptz
);
CREATE TABLE agp_v2.group_memberships (
  principal_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  group_id agp_v2.object_id NOT NULL REFERENCES agp_v2.access_groups(id),
  granted_by agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  PRIMARY KEY (principal_id, group_id),
  CHECK (expires_at IS NULL OR expires_at > created_at)
);
CREATE INDEX group_memberships_group_idx ON agp_v2.group_memberships(group_id, principal_id);

CREATE TABLE agp_v2.sites (
  id agp_v2.object_id PRIMARY KEY,
  name text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 128),
  timezone text NOT NULL DEFAULT 'UTC' CHECK (length(timezone) <= 64),
  row_version agp_v2.uint63 NOT NULL DEFAULT 0,
  deleted_at timestamptz
);
CREATE TABLE agp_v2.node_groups (
  id agp_v2.object_id PRIMARY KEY,
  site_id agp_v2.object_id REFERENCES agp_v2.sites(id),
  name text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 128),
  row_version agp_v2.uint63 NOT NULL DEFAULT 0
);
CREATE TABLE agp_v2.nodes (
  id agp_v2.object_id PRIMARY KEY,
  site_id agp_v2.object_id NOT NULL REFERENCES agp_v2.sites(id),
  name text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 128),
  ownership text NOT NULL CHECK (ownership IN ('unmanaged','managed','adopted')),
  state text NOT NULL CHECK (state IN ('pending','enrolled','active','quarantined','detached','retired')),
  operating_system text NOT NULL CHECK (length(operating_system) <= 64),
  architecture text NOT NULL CHECK (architecture IN ('amd64','arm64')),
  last_seen_at timestamptz,
  high_writer_epoch agp_v2.uint63 NOT NULL DEFAULT 0,
  high_deployment_sequence agp_v2.uint63 NOT NULL DEFAULT 0,
  allocated_deployment_sequence agp_v2.uint63 NOT NULL DEFAULT 0,
  row_version agp_v2.uint63 NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  CHECK (allocated_deployment_sequence >= high_deployment_sequence)
);
CREATE INDEX nodes_site_state_idx ON agp_v2.nodes(site_id, state);
CREATE TABLE agp_v2.node_group_memberships (
  node_group_id agp_v2.object_id NOT NULL REFERENCES agp_v2.node_groups(id),
  node_id agp_v2.object_id NOT NULL REFERENCES agp_v2.nodes(id),
  PRIMARY KEY (node_group_id, node_id)
);
CREATE TABLE agp_v2.node_labels (
  node_id agp_v2.object_id NOT NULL REFERENCES agp_v2.nodes(id),
  key text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_.-]{0,62}$'),
  value text NOT NULL CHECK (length(value) <= 128),
  PRIMARY KEY (node_id, key)
);
CREATE INDEX node_labels_selector_idx ON agp_v2.node_labels(key, value, node_id);
CREATE TABLE agp_v2.node_identities (
  id agp_v2.object_id PRIMARY KEY,
  node_id agp_v2.object_id NOT NULL REFERENCES agp_v2.nodes(id),
  service_role text NOT NULL CHECK (service_role IN ('agent','edge_auth')),
  certificate_fingerprint agp_v2.digest NOT NULL UNIQUE,
  public_key_fingerprint agp_v2.digest NOT NULL,
  issuer_key_id agp_v2.object_id NOT NULL,
  serial_number text NOT NULL CHECK (serial_number ~ '^[0-9a-f]{1,64}$'),
  not_before timestamptz NOT NULL,
  not_after timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (issuer_key_id, serial_number),
  CHECK (not_after > not_before)
);
CREATE INDEX node_identities_node_idx ON agp_v2.node_identities(node_id, not_after);
CREATE TABLE agp_v2.enrollment_tokens (
  id agp_v2.object_id PRIMARY KEY,
  node_id agp_v2.object_id NOT NULL REFERENCES agp_v2.nodes(id),
  service_role text NOT NULL CHECK (service_role IN ('agent','edge_auth')),
  token_hash agp_v2.digest NOT NULL UNIQUE,
  issued_authority_epoch agp_v2.uint63 NOT NULL CHECK (issued_authority_epoch > 0),
  issued_by agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at > created_at)
);
CREATE TABLE agp_v2.capability_snapshots (
  id agp_v2.object_id PRIMARY KEY,
  node_id agp_v2.object_id NOT NULL REFERENCES agp_v2.nodes(id),
  digest agp_v2.digest NOT NULL,
  observed_at timestamptz NOT NULL,
  agent_version text NOT NULL CHECK (length(agent_version) <= 64),
  protocol_version text NOT NULL CHECK (length(protocol_version) <= 64),
  os_release text NOT NULL CHECK (length(os_release) <= 128),
  architecture text NOT NULL CHECK (architecture IN ('amd64','arm64')),
  component_profile_digest agp_v2.digest,
  free_bytes agp_v2.uint63 NOT NULL,
  inventory_json jsonb NOT NULL CHECK (jsonb_typeof(inventory_json) = 'object' AND octet_length(inventory_json::text) <= 262144),
  UNIQUE (node_id, digest)
);
-- inventory_json follows a closed capability schema; never authorizes arbitrary commands.
CREATE INDEX capability_snapshots_latest_idx ON agp_v2.capability_snapshots(node_id, observed_at DESC);
CREATE TABLE agp_v2.resources (
  id agp_v2.object_id PRIMARY KEY,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  description text NOT NULL DEFAULT '' CHECK (length(description) <= 2048),
  category text NOT NULL DEFAULT '' CHECK (length(category) <= 128),
  icon_name text NOT NULL DEFAULT '' CHECK (length(icon_name) <= 128),
  disabled_at timestamptz,
  row_version agp_v2.uint63 NOT NULL DEFAULT 0
);

CREATE TABLE agp_v2.permissions (
  key text PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_.]{2,95}$'),
  description text NOT NULL CHECK (length(description) <= 1024)
);
CREATE TABLE agp_v2.roles (
  id agp_v2.object_id PRIMARY KEY,
  name text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 128),
  system_role boolean NOT NULL DEFAULT false,
  row_version agp_v2.uint63 NOT NULL DEFAULT 0
);
-- Stable roles are catalog anchors; immutable definitions carry authority.
CREATE TABLE agp_v2.role_definitions (
  role_digest agp_v2.digest PRIMARY KEY,
  role_id agp_v2.object_id NOT NULL REFERENCES agp_v2.roles(id),
  version agp_v2.uint63 NOT NULL CHECK (version > 0),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  created_at timestamptz NOT NULL DEFAULT now(),
  creation_tx xid8 NOT NULL DEFAULT pg_current_xact_id(),
  UNIQUE (role_id, version),
  UNIQUE (role_id, role_digest)
);
CREATE TABLE agp_v2.role_definition_permissions (
  role_digest agp_v2.digest NOT NULL REFERENCES agp_v2.role_definitions(role_digest),
  permission_key text NOT NULL REFERENCES agp_v2.permissions(key),
  PRIMARY KEY (role_digest, permission_key)
);
CREATE TABLE agp_v2.role_definition_scopes (
  role_digest agp_v2.digest NOT NULL REFERENCES agp_v2.role_definitions(role_digest),
  scope_kind text NOT NULL CHECK (scope_kind IN ('global','site','node_group','node','resource')),
  PRIMARY KEY (role_digest, scope_kind)
);
CREATE TABLE agp_v2.role_bindings (
  id agp_v2.object_id PRIMARY KEY,
  principal_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  role_id agp_v2.object_id NOT NULL REFERENCES agp_v2.roles(id),
  role_digest agp_v2.digest NOT NULL,
  authority_epoch agp_v2.uint63 NOT NULL CHECK (authority_epoch > 0),
  scope_kind text NOT NULL CHECK (scope_kind IN ('global','site','node_group','node','resource')),
  site_id agp_v2.object_id REFERENCES agp_v2.sites(id),
  node_group_id agp_v2.object_id REFERENCES agp_v2.node_groups(id),
  node_id agp_v2.object_id REFERENCES agp_v2.nodes(id),
  resource_id agp_v2.object_id REFERENCES agp_v2.resources(id),
  granted_by agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  expires_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  row_version agp_v2.uint63 NOT NULL DEFAULT 1 CHECK (row_version > 0),
  FOREIGN KEY (role_id, role_digest) REFERENCES agp_v2.role_definitions(role_id, role_digest),
  CHECK (
    (scope_kind = 'global' AND site_id IS NULL AND node_group_id IS NULL AND node_id IS NULL AND resource_id IS NULL) OR
    (scope_kind = 'site' AND site_id IS NOT NULL AND node_group_id IS NULL AND node_id IS NULL AND resource_id IS NULL) OR
    (scope_kind = 'node_group' AND site_id IS NULL AND node_group_id IS NOT NULL AND node_id IS NULL AND resource_id IS NULL) OR
    (scope_kind = 'node' AND site_id IS NULL AND node_group_id IS NULL AND node_id IS NOT NULL AND resource_id IS NULL) OR
    (scope_kind = 'resource' AND site_id IS NULL AND node_group_id IS NULL AND node_id IS NULL AND resource_id IS NOT NULL)
  ),
  CHECK (expires_at IS NULL OR expires_at > created_at),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
CREATE INDEX role_bindings_principal_idx ON agp_v2.role_bindings(principal_id, authority_epoch);
-- No tuple UNIQUE across history: renewed/reissued approval creates a fresh ID.
-- Effective reads check active lifecycle, current epoch/floors, expiry and tombstone.
CREATE TABLE agp_v2.role_binding_revocations (
  binding_id agp_v2.object_id PRIMARY KEY,
  authority_epoch agp_v2.uint63 NOT NULL CHECK (authority_epoch > 0),
  event_id agp_v2.object_id NOT NULL,
  revoked_at timestamptz NOT NULL
);
-- Deliberately no FK to a positive binding: restrictive replay keeps the tombstone
-- even when a restored database never contained that binding incarnation.

CREATE TABLE agp_v2.secret_versions (
  id agp_v2.object_id PRIMARY KEY,
  secret_id agp_v2.object_id NOT NULL,
  version agp_v2.uint63 NOT NULL CHECK (version > 0),
  kind text NOT NULL CHECK (kind IN ('tls_private_key','totp_seed','oidc_client','directory_bind','directory_ca','smtp','webhook','probe','profile_pii','delivery_payload')),
  cipher_object_key text NOT NULL UNIQUE CHECK (length(cipher_object_key) BETWEEN 1 AND 512),
  cipher_digest agp_v2.digest NOT NULL,
  wrapped_dek bytea NOT NULL CHECK (octet_length(wrapped_dek) BETWEEN 16 AND 4096),
  kek_key_id text NOT NULL CHECK (length(kek_key_id) BETWEEN 1 AND 256),
  encryption_suite text NOT NULL CHECK (encryption_suite = 'aead-envelope-v1'),
  created_by agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  UNIQUE (secret_id, version),
  CHECK (expires_at IS NULL OR expires_at > created_at)
);
-- Ciphertext/object key never appears in canonical config or unrestricted API output.
CREATE TABLE agp_v2.sensitive_profiles (
  principal_id agp_v2.object_id PRIMARY KEY REFERENCES agp_v2.principals(id),
  secret_version_id agp_v2.object_id NOT NULL REFERENCES agp_v2.secret_versions(id),
  row_version agp_v2.uint63 NOT NULL DEFAULT 0
);
CREATE TABLE agp_v2.identity_provider_versions (
  id agp_v2.object_id PRIMARY KEY,
  provider_id agp_v2.object_id NOT NULL REFERENCES agp_v2.identity_providers(id),
  content_digest agp_v2.digest NOT NULL UNIQUE,
  security_guard_version agp_v2.uint63 NOT NULL CHECK (security_guard_version > 0),
  authorization_endpoint text NOT NULL CHECK (length(authorization_endpoint) BETWEEN 1 AND 2048),
  token_endpoint text NOT NULL CHECK (length(token_endpoint) BETWEEN 1 AND 2048),
  jwks_uri text NOT NULL CHECK (length(jwks_uri) BETWEEN 1 AND 2048),
  ca_secret_version_id agp_v2.object_id NOT NULL REFERENCES agp_v2.secret_versions(id),
  config_json jsonb NOT NULL CHECK (jsonb_typeof(config_json) = 'object' AND octet_length(config_json::text) <= 262144),
  allowed_signing_algorithms text[] NOT NULL CHECK (cardinality(allowed_signing_algorithms) BETWEEN 1 AND 8),
  mfa_claim_mode text NOT NULL CHECK (mfa_claim_mode IN ('none','acr_any','amr_all','acr_and_amr')),
  accepted_acr text[] NOT NULL DEFAULT '{}' CHECK (cardinality(accepted_acr) <= 16),
  required_amr text[] NOT NULL DEFAULT '{}' CHECK (cardinality(required_amr) <= 16),
  created_by agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider_id, security_guard_version),
  UNIQUE (provider_id, id)
);
CREATE TABLE agp_v2.identity_provider_clients (
  provider_version_id agp_v2.object_id NOT NULL REFERENCES agp_v2.identity_provider_versions(id),
  purpose text NOT NULL CHECK (purpose IN ('login','management')),
  client_id text COLLATE "C" NOT NULL CHECK (length(client_id) BETWEEN 1 AND 256),
  client_secret_version_id agp_v2.object_id NOT NULL REFERENCES agp_v2.secret_versions(id),
  redirect_uri text NOT NULL CHECK (length(redirect_uri) BETWEEN 1 AND 2048),
  maximum_auth_age_seconds integer NOT NULL CHECK (maximum_auth_age_seconds BETWEEN 1 AND 300),
  PRIMARY KEY (provider_version_id, purpose),
  UNIQUE (provider_version_id, client_id),
  UNIQUE (provider_version_id, client_secret_version_id),
  UNIQUE (provider_version_id, redirect_uri)
);
ALTER TABLE agp_v2.identity_providers ADD COLUMN current_version_id agp_v2.object_id
  REFERENCES agp_v2.identity_provider_versions(id);
ALTER TABLE agp_v2.identity_providers ADD FOREIGN KEY (id, current_version_id)
  REFERENCES agp_v2.identity_provider_versions(provider_id, id);
-- Service enforces exactly one client for each purpose, distinct protected secret
-- contents, endpoint equality with verified discovery, canonical HTTPS/SSRF and
-- exact listener-origin + provider-specific callback URI. First qualified profile
-- is RS256/basic/S256 with mfa_claim_mode=none and approved_directory_link.
-- Existing one-client snapshots cannot be auto-enabled/migrated by inventing a
-- second credential: provision both clients, test and approve a successor first.
CREATE TABLE agp_v2.mfa_factors (
  id agp_v2.object_id PRIMARY KEY,
  principal_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  authenticator_version agp_v2.uint63 NOT NULL CHECK (authenticator_version > 0),
  kind text NOT NULL CHECK (kind = 'totp'),
  seed_secret_version_id agp_v2.object_id NOT NULL REFERENCES agp_v2.secret_versions(id),
  verified_at timestamptz,
  last_accepted_step agp_v2.uint63,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX mfa_factors_principal_idx ON agp_v2.mfa_factors(principal_id);
CREATE TABLE agp_v2.recovery_codes (
  principal_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  code_hash agp_v2.digest NOT NULL,
  issued_authority_epoch agp_v2.uint63 NOT NULL CHECK (issued_authority_epoch > 0),
  batch_id agp_v2.object_id NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  consumed_at timestamptz,
  PRIMARY KEY (principal_id, code_hash)
);
CREATE TABLE agp_v2.invitations (
  id agp_v2.object_id PRIMARY KEY,
  principal_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  purpose text NOT NULL CHECK (purpose IN ('activate','reset_password','recover_mfa')),
  proof_kind text NOT NULL CHECK (proof_kind IN ('email','supervised')),
  allowed_action text NOT NULL CHECK (allowed_action IN ('activate','replace_mfa','reset_password')),
  token_hash agp_v2.digest NOT NULL UNIQUE,
  security_guard_id agp_v2.object_id NOT NULL UNIQUE,
  security_guard_version agp_v2.uint63 NOT NULL CHECK (security_guard_version > 0),
  issued_authority_epoch agp_v2.uint63 NOT NULL CHECK (issued_authority_epoch > 0),
  principal_security_version agp_v2.uint63 NOT NULL,
  password_version agp_v2.uint63 NOT NULL,
  policy_digest agp_v2.digest NOT NULL,
  issued_by agp_v2.object_id REFERENCES agp_v2.principals(id),
  issuer_fingerprint agp_v2.digest,
  contact_id agp_v2.object_id,
  contact_authenticator_version agp_v2.uint63,
  generation agp_v2.uint63 NOT NULL CHECK (generation > 0),
  expires_at timestamptz NOT NULL,
  reserved_flow_id agp_v2.object_id,
  reserved_binding_hash agp_v2.digest,
  reserved_at timestamptz,
  consumed_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at > created_at),
  CHECK ((reserved_flow_id IS NULL) = (reserved_binding_hash IS NULL)),
  CHECK ((reserved_flow_id IS NULL) = (reserved_at IS NULL)),
  CHECK (consumed_at IS NULL OR reserved_at IS NOT NULL),
  CHECK (consumed_at IS NULL OR revoked_at IS NULL),
  CHECK ((issued_by IS NULL) = (issuer_fingerprint IS NULL)),
  CHECK (proof_kind <> 'email' OR (contact_id IS NOT NULL AND contact_authenticator_version > 0)),
  CHECK ((purpose='activate' AND proof_kind='email' AND allowed_action='activate' AND issued_by IS NOT NULL) OR
    (purpose='reset_password' AND allowed_action='reset_password') OR
    (purpose='recover_mfa' AND proof_kind='supervised' AND allowed_action='replace_mfa' AND issued_by IS NOT NULL))
);
-- Native identity_one_time_tokens adapts this canonical token registry.
-- Security fields are immutable; reservation/consume/revoke are irreversible.
-- Token guard floors use guardId/guardId reserved service subjects. Anonymous
-- issuance never bumps human principal/password floors or revokes sessions.
-- Email tokens consume with final activation/reset; supervised tickets consume
-- with the authorized recover transition. A lost reservation is never unclaimed.
CREATE TABLE agp_v2.sessions (
  id agp_v2.object_id PRIMARY KEY,
  principal_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  audience text NOT NULL CHECK (audience IN ('management','login')),
  token_hash agp_v2.digest NOT NULL UNIQUE,
  issued_authority_epoch agp_v2.uint63 NOT NULL CHECK (issued_authority_epoch > 0),
  csrf_hash agp_v2.digest NOT NULL,
  principal_security_version agp_v2.uint63 NOT NULL,
  authentication_time timestamptz NOT NULL,
  primary_at timestamptz,
  authentication_method text NOT NULL CHECK (authentication_method IN ('local_password','local_mfa','directory_password','directory_mfa','oidc','recovery','break_glass')),
  authentication_strength text NOT NULL CHECK (authentication_strength IN ('single_factor','multi_factor','recovery','break_glass')),
  authentication_issuer text CHECK (length(authentication_issuer) <= 2048),
  authentication_acr text CHECK (length(authentication_acr) <= 256),
  authentication_amr text[] NOT NULL DEFAULT '{}' CHECK (cardinality(authentication_amr) <= 16),
  claim_policy_version agp_v2.object_id REFERENCES agp_v2.identity_provider_versions(id),
  mfa_verified_at timestamptz,
  client_ip inet NOT NULL,
  user_agent_redacted text NOT NULL DEFAULT '' CHECK (length(user_agent_redacted) <= 512),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CHECK (expires_at > created_at AND absolute_expires_at >= expires_at),
  CHECK (authentication_method <> 'oidc' OR claim_policy_version IS NOT NULL)
);
CREATE INDEX sessions_principal_idx ON agp_v2.sessions(principal_id, expires_at);
CREATE INDEX sessions_expiry_idx ON agp_v2.sessions(expires_at);
CREATE TABLE agp_v2.browser_handoffs (
  id agp_v2.object_id PRIMARY KEY,
  code_hash agp_v2.digest NOT NULL UNIQUE,
  issued_authority_epoch agp_v2.uint63 NOT NULL CHECK (issued_authority_epoch > 0),
  source_session_id agp_v2.object_id NOT NULL REFERENCES agp_v2.sessions(id),
  principal_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  gateway_id agp_v2.object_id NOT NULL,
  node_id agp_v2.object_id NOT NULL REFERENCES agp_v2.nodes(id),
  client_identity_id agp_v2.object_id NOT NULL REFERENCES agp_v2.node_identities(id),
  redirect_uri text NOT NULL CHECK (length(redirect_uri) BETWEEN 1 AND 2048),
  state_hash agp_v2.digest NOT NULL,
  pkce_challenge text NOT NULL CHECK (pkce_challenge ~ '^[A-Za-z0-9_-]{43}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '60 seconds')
);
CREATE TABLE agp_v2.gateway_sessions (
  id agp_v2.object_id PRIMARY KEY,
  token_hash agp_v2.digest NOT NULL UNIQUE,
  issued_authority_epoch agp_v2.uint63 NOT NULL CHECK (issued_authority_epoch > 0),
  principal_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  source_session_id agp_v2.object_id NOT NULL REFERENCES agp_v2.sessions(id),
  gateway_id agp_v2.object_id NOT NULL,
  node_id agp_v2.object_id NOT NULL REFERENCES agp_v2.nodes(id),
  client_identity_id agp_v2.object_id NOT NULL REFERENCES agp_v2.node_identities(id),
  principal_security_version agp_v2.uint63 NOT NULL,
  authentication_time timestamptz NOT NULL,
  authentication_method text NOT NULL CHECK (authentication_method IN ('local_password','local_mfa','directory_password','directory_mfa','oidc','recovery','break_glass')),
  authentication_strength text NOT NULL CHECK (authentication_strength IN ('single_factor','multi_factor','recovery','break_glass')),
  claim_policy_version agp_v2.object_id REFERENCES agp_v2.identity_provider_versions(id),
  mfa_verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CHECK (expires_at > created_at),
  CHECK (authentication_method <> 'oidc' OR claim_policy_version IS NOT NULL)
);
CREATE INDEX gateway_sessions_principal_idx ON agp_v2.gateway_sessions(principal_id, expires_at);
-- gateway_id is stable logical ID, not a FK to an arbitrary current config revision.
-- Source session active status and live principal security_version checked on every allow.

CREATE TABLE agp_v2.config_revisions (
  id agp_v2.object_id PRIMARY KEY,
  revision_number agp_v2.uint63 NOT NULL UNIQUE CHECK (revision_number > 0),
  parent_id agp_v2.object_id REFERENCES agp_v2.config_revisions(id),
  schema_version text NOT NULL CHECK (schema_version IN ('agp.config/v1alpha1','agp.config/v1alpha2')),
  capacity_profile text NOT NULL CHECK (capacity_profile IN ('pilot-500','fleet-10k')),
  canonical_size_bytes agp_v2.uint63 NOT NULL,
  CHECK ((schema_version = 'agp.config/v1alpha1' AND capacity_profile = 'pilot-500' AND canonical_size_bytes <= 2097152) OR
         (schema_version = 'agp.config/v1alpha2' AND capacity_profile = 'fleet-10k' AND canonical_size_bytes <= 67108864)),
  content_digest agp_v2.digest NOT NULL,
  canonical_json jsonb NOT NULL CHECK (jsonb_typeof(canonical_json) = 'object' AND octet_length(canonical_json::text) <= CASE WHEN capacity_profile = 'pilot-500' THEN 4194304 ELSE 134217728 END),
  state text NOT NULL CHECK (state IN ('draft','validated','approved','published','superseded')),
  created_by agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  row_version agp_v2.uint63 NOT NULL DEFAULT 0,
  CHECK (parent_id IS DISTINCT FROM id)
);
CREATE INDEX config_revisions_digest_idx ON agp_v2.config_revisions(content_digest);
-- Same semantic config has the same digest; a new lineage/reapproval may have a new ID.
CREATE TABLE agp_v2.config_head (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  revision_id agp_v2.object_id REFERENCES agp_v2.config_revisions(id),
  row_version agp_v2.uint63 NOT NULL DEFAULT 0
);
CREATE TABLE agp_v2.policy_profiles (
  id agp_v2.object_id PRIMARY KEY,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  site_id agp_v2.object_id REFERENCES agp_v2.sites(id),
  row_version agp_v2.uint63 NOT NULL DEFAULT 0
);
CREATE TABLE agp_v2.policy_profile_versions (
  id agp_v2.object_id PRIMARY KEY,
  profile_id agp_v2.object_id NOT NULL REFERENCES agp_v2.policy_profiles(id),
  version agp_v2.uint63 NOT NULL CHECK (version > 0),
  content_digest agp_v2.digest NOT NULL,
  level text NOT NULL CHECK (level IN ('global','site','node_group','node','route')),
  state text NOT NULL CHECK (state IN ('draft','validated','approved','published','superseded')),
  waf_mode text CHECK (waf_mode IN ('off','detection','blocking')),
  overrides_groups boolean NOT NULL DEFAULT false,
  overrides_cidrs boolean NOT NULL DEFAULT false,
  require_mfa boolean,
  connect_timeout_seconds agp_v2.short_seconds CHECK (connect_timeout_seconds > 0),
  read_timeout_seconds agp_v2.short_seconds CHECK (read_timeout_seconds > 0),
  locked_fields text[] NOT NULL DEFAULT '{}' CHECK (locked_fields <@ ARRAY['waf_mode','allowed_group_ids','allow_cidrs','require_mfa','connect_timeout_seconds','read_timeout_seconds']::text[]),
  created_by agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  row_version agp_v2.uint63 NOT NULL DEFAULT 0,
  UNIQUE (profile_id, version)
);
CREATE TABLE agp_v2.profile_override_groups (
  profile_version_id agp_v2.object_id NOT NULL REFERENCES agp_v2.policy_profile_versions(id),
  group_id agp_v2.object_id NOT NULL REFERENCES agp_v2.access_groups(id),
  PRIMARY KEY (profile_version_id, group_id)
);
CREATE TABLE agp_v2.profile_override_cidrs (
  profile_version_id agp_v2.object_id NOT NULL REFERENCES agp_v2.policy_profile_versions(id),
  network cidr NOT NULL,
  PRIMARY KEY (profile_version_id, network)
);
CREATE TABLE agp_v2.access_policies (
  revision_id agp_v2.object_id NOT NULL REFERENCES agp_v2.config_revisions(id),
  id agp_v2.object_id NOT NULL,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  auth_mode text NOT NULL CHECK (auth_mode = 'central'),
  require_mfa boolean NOT NULL DEFAULT false,
  session_max_age_seconds agp_v2.short_seconds NOT NULL CHECK (session_max_age_seconds > 0),
  PRIMARY KEY (revision_id, id)
);
CREATE TABLE agp_v2.policy_groups (
  revision_id agp_v2.object_id NOT NULL,
  policy_id agp_v2.object_id NOT NULL,
  group_id agp_v2.object_id NOT NULL REFERENCES agp_v2.access_groups(id),
  PRIMARY KEY (revision_id, policy_id, group_id),
  FOREIGN KEY (revision_id, policy_id) REFERENCES agp_v2.access_policies(revision_id, id)
);
CREATE TABLE agp_v2.policy_cidrs (
  revision_id agp_v2.object_id NOT NULL,
  policy_id agp_v2.object_id NOT NULL,
  network cidr NOT NULL,
  PRIMARY KEY (revision_id, policy_id, network),
  FOREIGN KEY (revision_id, policy_id) REFERENCES agp_v2.access_policies(revision_id, id)
);
CREATE TABLE agp_v2.waf_policies (
  revision_id agp_v2.object_id NOT NULL REFERENCES agp_v2.config_revisions(id),
  id agp_v2.object_id NOT NULL,
  source_policy_revision_id agp_v2.object_id NOT NULL,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  engine text NOT NULL CHECK (engine = 'modsecurity'),
  ruleset_digest agp_v2.digest NOT NULL,
  paranoia_level smallint NOT NULL CHECK (paranoia_level BETWEEN 1 AND 4),
  inbound_anomaly_threshold integer NOT NULL CHECK (inbound_anomaly_threshold BETWEEN 1 AND 100),
  outbound_anomaly_threshold integer NOT NULL CHECK (outbound_anomaly_threshold BETWEEN 1 AND 100),
  PRIMARY KEY (revision_id, id),
  UNIQUE (revision_id, id, source_policy_revision_id)
);
CREATE TABLE agp_v2.gateways (
  revision_id agp_v2.object_id NOT NULL REFERENCES agp_v2.config_revisions(id),
  id agp_v2.object_id NOT NULL,
  site_id agp_v2.object_id NOT NULL REFERENCES agp_v2.sites(id),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  topology text NOT NULL CHECK (topology IN ('all_in_one','distributed','split_waf')),
  ownership text NOT NULL CHECK (ownership IN ('manual','managed','adopted')),
  component_profile_digest agp_v2.digest NOT NULL,
  waf_policy_id agp_v2.object_id NOT NULL,
  waf_policy_revision_id agp_v2.object_id NOT NULL,
  waf_mode text NOT NULL CHECK (waf_mode IN ('off','detection','blocking')),
  listen_address inet NOT NULL,
  listen_port integer NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
  PRIMARY KEY (revision_id, id),
  UNIQUE (revision_id, id, waf_policy_id),
  FOREIGN KEY (revision_id, waf_policy_id, waf_policy_revision_id)
    REFERENCES agp_v2.waf_policies(revision_id, id, source_policy_revision_id)
);
CREATE TABLE agp_v2.gateway_nodes (
  revision_id agp_v2.object_id NOT NULL,
  gateway_id agp_v2.object_id NOT NULL,
  node_id agp_v2.object_id NOT NULL REFERENCES agp_v2.nodes(id),
  role text NOT NULL CHECK (role IN ('gateway','waf_proxy')),
  PRIMARY KEY (revision_id, gateway_id, node_id),
  FOREIGN KEY (revision_id, gateway_id) REFERENCES agp_v2.gateways(revision_id, id)
);
CREATE TABLE agp_v2.routes (
  revision_id agp_v2.object_id NOT NULL,
  id agp_v2.object_id NOT NULL,
  gateway_id agp_v2.object_id NOT NULL,
  resource_id agp_v2.object_id NOT NULL REFERENCES agp_v2.resources(id),
  host_ascii text NOT NULL CHECK (length(host_ascii) BETWEEN 1 AND 253 AND host_ascii = lower(host_ascii)),
  path_prefix text NOT NULL CHECK (left(path_prefix, 1) = '/' AND length(path_prefix) <= 2048),
  upstream_scheme text NOT NULL CHECK (upstream_scheme IN ('http','https')),
  upstream_host text NOT NULL CHECK (length(upstream_host) BETWEEN 1 AND 253),
  upstream_port integer NOT NULL CHECK (upstream_port BETWEEN 1 AND 65535),
  upstream_base_path text NOT NULL DEFAULT '/' CHECK (left(upstream_base_path, 1) = '/' AND length(upstream_base_path) <= 2048),
  upstream_tls_server_name text CHECK (length(upstream_tls_server_name) BETWEEN 1 AND 253),
  access_policy_id agp_v2.object_id NOT NULL,
  waf_policy_id agp_v2.object_id NOT NULL,
  tls_secret_version_id agp_v2.object_id NOT NULL REFERENCES agp_v2.secret_versions(id),
  enabled boolean NOT NULL DEFAULT true,
  PRIMARY KEY (revision_id, id),
  UNIQUE (revision_id, gateway_id, host_ascii, path_prefix),
  FOREIGN KEY (revision_id, gateway_id, waf_policy_id) REFERENCES agp_v2.gateways(revision_id, id, waf_policy_id),
  FOREIGN KEY (revision_id, access_policy_id) REFERENCES agp_v2.access_policies(revision_id, id),
  FOREIGN KEY (revision_id, waf_policy_id) REFERENCES agp_v2.waf_policies(revision_id, id)
);
-- Full listener overlap, path normalization, origin isolation, TLS SAN/kind and egress
-- validation are service/compiler checks; UNIQUE alone does not establish route safety.
CREATE INDEX routes_resource_idx ON agp_v2.routes(resource_id, revision_id);
CREATE TABLE agp_v2.waf_exceptions (
  revision_id agp_v2.object_id NOT NULL,
  id agp_v2.object_id NOT NULL,
  policy_id agp_v2.object_id NOT NULL,
  route_id agp_v2.object_id NOT NULL,
  match_field text NOT NULL CHECK (match_field IN ('query_arg','header','cookie','body_field')),
  parameter_name text NOT NULL CHECK (length(parameter_name) BETWEEN 1 AND 256),
  reason text NOT NULL CHECK (length(reason) BETWEEN 8 AND 2048),
  owner_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  review_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (revision_id, id),
  FOREIGN KEY (revision_id, policy_id) REFERENCES agp_v2.waf_policies(revision_id, id),
  FOREIGN KEY (revision_id, route_id) REFERENCES agp_v2.routes(revision_id, id)
);
CREATE TABLE agp_v2.waf_exception_rules (
  revision_id agp_v2.object_id NOT NULL,
  exception_id agp_v2.object_id NOT NULL,
  rule_id text NOT NULL CHECK (rule_id ~ '^[0-9]{6,9}$'),
  PRIMARY KEY (revision_id, exception_id, rule_id),
  FOREIGN KEY (revision_id, exception_id) REFERENCES agp_v2.waf_exceptions(revision_id, id)
);
CREATE TABLE agp_v2.waf_policy_revisions (
  id agp_v2.object_id PRIMARY KEY,
  policy_id agp_v2.object_id NOT NULL,
  site_id agp_v2.object_id NOT NULL REFERENCES agp_v2.sites(id),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  revision_number agp_v2.uint63 NOT NULL CHECK (revision_number > 0),
  content_digest agp_v2.digest NOT NULL,
  canonical_json jsonb NOT NULL CHECK (jsonb_typeof(canonical_json) = 'object' AND octet_length(canonical_json::text) <= 1048576),
  engine text NOT NULL CHECK (engine = 'modsecurity'),
  ruleset_version_id agp_v2.object_id NOT NULL,
  paranoia_level smallint NOT NULL CHECK (paranoia_level BETWEEN 1 AND 4),
  inbound_anomaly_threshold integer NOT NULL CHECK (inbound_anomaly_threshold BETWEEN 1 AND 100),
  outbound_anomaly_threshold integer NOT NULL CHECK (outbound_anomaly_threshold BETWEEN 1 AND 100),
  state text NOT NULL CHECK (state IN ('draft','validated','approved','published','superseded')),
  created_by agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  row_version agp_v2.uint63 NOT NULL DEFAULT 0,
  UNIQUE (policy_id, revision_number)
);
ALTER TABLE agp_v2.waf_policies ADD FOREIGN KEY (source_policy_revision_id)
  REFERENCES agp_v2.waf_policy_revisions(id);
CREATE TABLE agp_v2.waf_policy_revision_exceptions (
  policy_revision_id agp_v2.object_id NOT NULL REFERENCES agp_v2.waf_policy_revisions(id),
  id agp_v2.object_id NOT NULL,
  route_id agp_v2.object_id NOT NULL,
  match_field text NOT NULL CHECK (match_field IN ('query_arg','header','cookie','body_field')),
  parameter_name text NOT NULL CHECK (length(parameter_name) BETWEEN 1 AND 128),
  owner_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  reason text NOT NULL CHECK (length(reason) BETWEEN 8 AND 2048),
  review_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (policy_revision_id, id)
);
CREATE TABLE agp_v2.waf_policy_revision_exception_rules (
  policy_revision_id agp_v2.object_id NOT NULL,
  exception_id agp_v2.object_id NOT NULL,
  rule_id text NOT NULL CHECK (rule_id ~ '^[0-9]{6,9}$'),
  PRIMARY KEY (policy_revision_id, exception_id, rule_id),
  FOREIGN KEY (policy_revision_id, exception_id)
    REFERENCES agp_v2.waf_policy_revision_exceptions(policy_revision_id, id)
);
CREATE TABLE agp_v2.policy_revision_approvals (
  id agp_v2.object_id PRIMARY KEY,
  waf_revision_id agp_v2.object_id REFERENCES agp_v2.waf_policy_revisions(id),
  profile_version_id agp_v2.object_id REFERENCES agp_v2.policy_profile_versions(id),
  content_digest agp_v2.digest NOT NULL,
  approver_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  decision text NOT NULL CHECK (decision IN ('approve','reject')),
  reason_redacted text NOT NULL CHECK (length(reason_redacted) BETWEEN 8 AND 2048),
  decided_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  CONSTRAINT policy_revision_approvals_target_check CHECK ((waf_revision_id IS NOT NULL)::integer + (profile_version_id IS NOT NULL)::integer = 1),
  CHECK (expires_at > decided_at),
  CONSTRAINT policy_revision_approval_actor_unique UNIQUE NULLS NOT DISTINCT (waf_revision_id, profile_version_id, approver_id)
);
CREATE TABLE agp_v2.profile_assignments (
  revision_id agp_v2.object_id NOT NULL REFERENCES agp_v2.config_revisions(id),
  id agp_v2.object_id NOT NULL,
  profile_version_id agp_v2.object_id NOT NULL REFERENCES agp_v2.policy_profile_versions(id),
  scope_kind text NOT NULL CHECK (scope_kind IN ('global','site','node_group','node','route')),
  site_id agp_v2.object_id REFERENCES agp_v2.sites(id),
  node_group_id agp_v2.object_id REFERENCES agp_v2.node_groups(id),
  node_id agp_v2.object_id REFERENCES agp_v2.nodes(id),
  route_id agp_v2.object_id,
  PRIMARY KEY (revision_id, id),
  FOREIGN KEY (revision_id, route_id) REFERENCES agp_v2.routes(revision_id, id),
  CHECK (
    (scope_kind = 'global' AND site_id IS NULL AND node_group_id IS NULL AND node_id IS NULL AND route_id IS NULL) OR
    (scope_kind = 'site' AND site_id IS NOT NULL AND node_group_id IS NULL AND node_id IS NULL AND route_id IS NULL) OR
    (scope_kind = 'node_group' AND site_id IS NULL AND node_group_id IS NOT NULL AND node_id IS NULL AND route_id IS NULL) OR
    (scope_kind = 'node' AND site_id IS NULL AND node_group_id IS NULL AND node_id IS NOT NULL AND route_id IS NULL) OR
    (scope_kind = 'route' AND site_id IS NULL AND node_group_id IS NULL AND node_id IS NULL AND route_id IS NOT NULL)
  ),
  UNIQUE NULLS NOT DISTINCT (revision_id, profile_version_id, scope_kind, site_id, node_group_id, node_id, route_id)
);
CREATE TABLE agp_v2.validation_reports (
  id agp_v2.object_id PRIMARY KEY,
  revision_id agp_v2.object_id REFERENCES agp_v2.config_revisions(id),
  waf_revision_id agp_v2.object_id REFERENCES agp_v2.waf_policy_revisions(id),
  profile_version_id agp_v2.object_id REFERENCES agp_v2.policy_profile_versions(id),
  content_digest agp_v2.digest NOT NULL,
  validator_version text NOT NULL CHECK (length(validator_version) <= 128),
  outcome text NOT NULL CHECK (outcome IN ('passed','failed')),
  findings_json jsonb NOT NULL CHECK (jsonb_typeof(findings_json) = 'array' AND octet_length(findings_json::text) <= 262144),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT validation_reports_target_check CHECK ((revision_id IS NOT NULL)::integer + (waf_revision_id IS NOT NULL)::integer +
    (profile_version_id IS NOT NULL)::integer = 1)
);

CREATE TABLE agp_v2.artifacts (
  digest agp_v2.digest PRIMARY KEY,
  size_bytes agp_v2.uint63 NOT NULL,
  media_type text NOT NULL CHECK (length(media_type) BETWEEN 1 AND 128),
  storage_backend text NOT NULL CHECK (storage_backend IN ('filesystem','s3')),
  object_key text NOT NULL UNIQUE CHECK (length(object_key) BETWEEN 1 AND 512),
  state text NOT NULL CHECK (state IN ('staged','verified','quarantined','deleting')),
  created_at timestamptz NOT NULL DEFAULT now(),
  verified_at timestamptz,
  metadata agp_v2.extension_metadata NOT NULL DEFAULT '{}'
);
CREATE TABLE agp_v2.release_manifests (
  id agp_v2.object_id PRIMARY KEY,
  release_sequence agp_v2.uint63 NOT NULL UNIQUE CHECK (release_sequence > 0),
  manifest_digest agp_v2.digest NOT NULL UNIQUE REFERENCES agp_v2.artifacts(digest),
  dependency_closure_digest agp_v2.digest NOT NULL REFERENCES agp_v2.artifacts(digest),
  sbom_digest agp_v2.digest NOT NULL REFERENCES agp_v2.artifacts(digest),
  component_profile_digest agp_v2.digest NOT NULL,
  os_release text NOT NULL CHECK (length(os_release) <= 128),
  architecture text NOT NULL CHECK (architecture IN ('amd64','arm64')),
  expires_at timestamptz NOT NULL,
  verified_at timestamptz NOT NULL,
  minimum_protocol text NOT NULL CHECK (length(minimum_protocol) <= 64)
);
CREATE TABLE agp_v2.release_artifacts (
  release_id agp_v2.object_id NOT NULL REFERENCES agp_v2.release_manifests(id),
  artifact_digest agp_v2.digest NOT NULL REFERENCES agp_v2.artifacts(digest),
  relative_path text NOT NULL CHECK (length(relative_path) BETWEEN 1 AND 512),
  PRIMARY KEY (release_id, relative_path)
);
CREATE TABLE agp_v2.compiled_bundles (
  digest agp_v2.digest PRIMARY KEY REFERENCES agp_v2.artifacts(digest),
  revision_id agp_v2.object_id NOT NULL REFERENCES agp_v2.config_revisions(id),
  node_id agp_v2.object_id NOT NULL REFERENCES agp_v2.nodes(id),
  capability_digest agp_v2.digest NOT NULL,
  compiler_version text NOT NULL CHECK (length(compiler_version) <= 128),
  compiler_digest agp_v2.digest NOT NULL,
  auth_snapshot_digest agp_v2.digest NOT NULL,
  deployment_generation agp_v2.object_id NOT NULL UNIQUE,
  component_profile_digest agp_v2.digest NOT NULL,
  capacity_profile text NOT NULL CHECK (capacity_profile IN ('pilot-500','fleet-10k')),
  resolved_inputs_json jsonb NOT NULL CHECK (jsonb_typeof(resolved_inputs_json) = 'array' AND
    jsonb_array_length(resolved_inputs_json) <= CASE WHEN capacity_profile = 'pilot-500' THEN 1000 ELSE 50000 END AND
    octet_length(resolved_inputs_json::text) <= CASE WHEN capacity_profile = 'pilot-500' THEN 262144 ELSE 16777216 END),
  resolved_inputs_digest agp_v2.digest NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (node_id, capability_digest) REFERENCES agp_v2.capability_snapshots(node_id, digest),
  UNIQUE (revision_id, node_id, capability_digest, compiler_digest, resolved_inputs_digest)
);
CREATE TABLE agp_v2.node_baselines (
  id agp_v2.object_id PRIMARY KEY,
  node_id agp_v2.object_id NOT NULL REFERENCES agp_v2.nodes(id),
  revision_id agp_v2.object_id NOT NULL REFERENCES agp_v2.config_revisions(id),
  bundle_digest agp_v2.digest NOT NULL REFERENCES agp_v2.compiled_bundles(digest),
  ownership_inventory_digest agp_v2.digest NOT NULL,
  capability_digest agp_v2.digest NOT NULL,
  captured_by agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  captured_at timestamptz NOT NULL DEFAULT now(),
  verified_at timestamptz NOT NULL,
  FOREIGN KEY (node_id, capability_digest) REFERENCES agp_v2.capability_snapshots(node_id, digest)
);
CREATE TABLE agp_v2.effective_route_policies (
  bundle_digest agp_v2.digest NOT NULL REFERENCES agp_v2.compiled_bundles(digest),
  revision_id agp_v2.object_id NOT NULL,
  route_id agp_v2.object_id NOT NULL,
  waf_mode text NOT NULL CHECK (waf_mode IN ('off','detection','blocking')),
  require_mfa boolean NOT NULL,
  connect_timeout_seconds agp_v2.short_seconds NOT NULL CHECK (connect_timeout_seconds > 0),
  read_timeout_seconds agp_v2.short_seconds NOT NULL CHECK (read_timeout_seconds > 0),
  policy_digest agp_v2.digest NOT NULL,
  PRIMARY KEY (bundle_digest, route_id),
  FOREIGN KEY (revision_id, route_id) REFERENCES agp_v2.routes(revision_id, id)
);
CREATE TABLE agp_v2.effective_policy_groups (
  bundle_digest agp_v2.digest NOT NULL,
  route_id agp_v2.object_id NOT NULL,
  group_id agp_v2.object_id NOT NULL REFERENCES agp_v2.access_groups(id),
  PRIMARY KEY (bundle_digest, route_id, group_id),
  FOREIGN KEY (bundle_digest, route_id) REFERENCES agp_v2.effective_route_policies(bundle_digest, route_id)
);
CREATE TABLE agp_v2.effective_policy_cidrs (
  bundle_digest agp_v2.digest NOT NULL,
  route_id agp_v2.object_id NOT NULL,
  network cidr NOT NULL,
  PRIMARY KEY (bundle_digest, route_id, network),
  FOREIGN KEY (bundle_digest, route_id) REFERENCES agp_v2.effective_route_policies(bundle_digest, route_id)
);
CREATE TABLE agp_v2.effective_policy_provenance (
  bundle_digest agp_v2.digest NOT NULL,
  revision_id agp_v2.object_id NOT NULL,
  route_id agp_v2.object_id NOT NULL,
  field_key text NOT NULL CHECK (field_key IN ('waf_mode','allowed_group_ids','allow_cidrs','require_mfa','connect_timeout_seconds','read_timeout_seconds','waf_policy_revision','paranoia_level','inbound_anomaly_threshold','outbound_anomaly_threshold','exception_count')),
  source_kind text NOT NULL CHECK (source_kind IN ('default','gateway','profile','route','zone','local_policy','security_floor')),
  assignment_id agp_v2.object_id,
  source_zone_revision_id agp_v2.object_id,
  source_policy_revision_id agp_v2.object_id REFERENCES agp_v2.waf_policy_revisions(id),
  profile_version_id agp_v2.object_id REFERENCES agp_v2.policy_profile_versions(id),
  effective_value_digest agp_v2.digest NOT NULL,
  locked_by_profile_version_id agp_v2.object_id REFERENCES agp_v2.policy_profile_versions(id),
  PRIMARY KEY (bundle_digest, route_id, field_key),
  FOREIGN KEY (bundle_digest, route_id) REFERENCES agp_v2.effective_route_policies(bundle_digest, route_id),
  FOREIGN KEY (revision_id, assignment_id) REFERENCES agp_v2.profile_assignments(revision_id, id),
  CHECK (
    (source_kind = 'profile' AND assignment_id IS NOT NULL AND profile_version_id IS NOT NULL) OR
    (source_kind <> 'profile' AND assignment_id IS NULL AND profile_version_id IS NULL)
  )
);
CREATE TABLE agp_v2.deployment_plans (
  id agp_v2.object_id PRIMARY KEY,
  revision_id agp_v2.object_id NOT NULL REFERENCES agp_v2.config_revisions(id),
  plan_digest agp_v2.digest NOT NULL UNIQUE,
  schema_version text NOT NULL CHECK (schema_version IN ('agp.plan/v1alpha1','agp.plan/v1alpha2')),
  capacity_profile text NOT NULL CHECK (capacity_profile IN ('pilot-500','fleet-10k')),
  canonical_size_bytes agp_v2.uint63 NOT NULL,
  CHECK ((schema_version = 'agp.plan/v1alpha1' AND capacity_profile = 'pilot-500' AND canonical_size_bytes <= 2097152) OR
         (schema_version = 'agp.plan/v1alpha2' AND capacity_profile = 'fleet-10k' AND canonical_size_bytes <= 33554432)),
  authority_epoch agp_v2.uint63 NOT NULL CHECK (authority_epoch > 0),
  state text NOT NULL CHECK (state IN ('draft','validated','approved','expired','superseded')),
  operation text NOT NULL CHECK (operation IN ('apply_config','upgrade_components','rollback_config')),
  risk_class text NOT NULL CHECK (risk_class IN ('normal','dangerous')),
  created_by agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  row_version agp_v2.uint63 NOT NULL DEFAULT 0,
  CHECK (expires_at > created_at)
);
CREATE TABLE agp_v2.plan_targets (
  plan_id agp_v2.object_id NOT NULL REFERENCES agp_v2.deployment_plans(id),
  node_id agp_v2.object_id NOT NULL REFERENCES agp_v2.nodes(id),
  base_revision_id agp_v2.object_id NOT NULL REFERENCES agp_v2.config_revisions(id),
  base_bundle_digest agp_v2.digest NOT NULL REFERENCES agp_v2.compiled_bundles(digest),
  capability_digest agp_v2.digest NOT NULL,
  target_bundle_digest agp_v2.digest NOT NULL REFERENCES agp_v2.compiled_bundles(digest),
  target_release_id agp_v2.object_id REFERENCES agp_v2.release_manifests(id),
  wave_index integer NOT NULL CHECK (wave_index BETWEEN 0 AND 10000),
  expected_node_row_version agp_v2.uint63 NOT NULL,
  expected_node_deployment_sequence agp_v2.uint63 NOT NULL,
  minimum_deny_sequence agp_v2.uint63 NOT NULL,
  PRIMARY KEY (plan_id, node_id),
  FOREIGN KEY (node_id, capability_digest) REFERENCES agp_v2.capability_snapshots(node_id, digest)
);
CREATE TABLE agp_v2.plan_target_secrets (
  plan_id agp_v2.object_id NOT NULL,
  node_id agp_v2.object_id NOT NULL,
  secret_version_id agp_v2.object_id NOT NULL REFERENCES agp_v2.secret_versions(id),
  PRIMARY KEY (plan_id, node_id, secret_version_id),
  FOREIGN KEY (plan_id, node_id) REFERENCES agp_v2.plan_targets(plan_id, node_id)
);
CREATE TABLE agp_v2.approvals (
  id agp_v2.object_id PRIMARY KEY,
  plan_id agp_v2.object_id NOT NULL REFERENCES agp_v2.deployment_plans(id),
  plan_digest agp_v2.digest NOT NULL,
  approver_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  decision text NOT NULL CHECK (decision IN ('approve','reject')),
  comment_redacted text NOT NULL DEFAULT '' CHECK (length(comment_redacted) <= 2048),
  decided_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  UNIQUE (plan_id, approver_id),
  CHECK (expires_at > decided_at)
);
-- App verifies digest equality, author != approver for dangerous operation, scope,
-- live delegation, distinct humans, MFA freshness and approval expiry at dispatch.
CREATE TABLE agp_v2.rollouts (
  id agp_v2.object_id PRIMARY KEY,
  plan_id agp_v2.object_id NOT NULL UNIQUE REFERENCES agp_v2.deployment_plans(id),
  state text NOT NULL CHECK (state IN ('queued','running','paused','cancelling','succeeded','failed','cancelled','recovery_required')),
  dispatched_by agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  current_wave integer NOT NULL DEFAULT 0 CHECK (current_wave >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  row_version agp_v2.uint63 NOT NULL DEFAULT 0
);
CREATE TABLE agp_v2.node_deployments (
  id agp_v2.object_id PRIMARY KEY,
  rollout_id agp_v2.object_id NOT NULL REFERENCES agp_v2.rollouts(id),
  plan_id agp_v2.object_id NOT NULL,
  node_id agp_v2.object_id NOT NULL REFERENCES agp_v2.nodes(id),
  deployment_sequence agp_v2.uint63 NOT NULL CHECK (deployment_sequence > 0),
  writer_epoch agp_v2.uint63 NOT NULL CHECK (writer_epoch > 0),
  state text NOT NULL CHECK (state IN ('pending','prepared','validated','activating','reloading','verifying','succeeded','rejected','failed','rollback_pending','rolled_back','recovery_required')),
  actual_bundle_digest agp_v2.digest REFERENCES agp_v2.compiled_bundles(digest),
  reason_code text CHECK (length(reason_code) <= 128),
  started_at timestamptz,
  completed_at timestamptz,
  row_version agp_v2.uint63 NOT NULL DEFAULT 0,
  FOREIGN KEY (plan_id, node_id) REFERENCES agp_v2.plan_targets(plan_id, node_id),
  UNIQUE (rollout_id, node_id),
  UNIQUE (node_id, deployment_sequence)
);
CREATE UNIQUE INDEX node_deployments_active_idx ON agp_v2.node_deployments(node_id)
  WHERE state IN ('pending','prepared','validated','activating','reloading','verifying','rollback_pending','recovery_required');
CREATE TABLE agp_v2.agent_tasks (
  id agp_v2.object_id PRIMARY KEY,
  node_id agp_v2.object_id NOT NULL REFERENCES agp_v2.nodes(id),
  deployment_id agp_v2.object_id REFERENCES agp_v2.node_deployments(id),
  kind text NOT NULL CHECK (kind IN ('inventory','validate_config','apply_config','upgrade_components','rollback_config','collect_diagnostics')),
  payload_digest agp_v2.digest NOT NULL,
  payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object'),
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  writer_epoch agp_v2.uint63 NOT NULL,
  authority_epoch agp_v2.uint63 NOT NULL CHECK (authority_epoch > 0),
  deployment_sequence agp_v2.uint63 NOT NULL,
  state text NOT NULL CHECK (state IN ('queued','dispatched','running','succeeded','failed','unknown','cancelled')),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  UNIQUE (node_id, idempotency_key),
  CHECK (expires_at > created_at),
  CHECK (kind NOT IN ('apply_config','upgrade_components','rollback_config') OR deployment_id IS NOT NULL)
);
CREATE INDEX agent_tasks_dispatch_idx ON agp_v2.agent_tasks(node_id, state, created_at);
CREATE TABLE agp_v2.task_receipts (
  task_id agp_v2.object_id NOT NULL REFERENCES agp_v2.agent_tasks(id),
  attempt_id agp_v2.object_id NOT NULL,
  event_id agp_v2.object_id NOT NULL UNIQUE,
  receipt_digest agp_v2.digest NOT NULL,
  receipt_sequence agp_v2.uint63 NOT NULL,
  attempt integer CHECK (attempt BETWEEN 1 AND 10000),
  state text NOT NULL CHECK (state IN ('pending','prepared','validated','activating','reloading','verifying','succeeded','rejected','failed','rollback_pending','rolled_back','recovery_required')),
  node_id agp_v2.object_id NOT NULL REFERENCES agp_v2.nodes(id),
  node_identity_id agp_v2.object_id NOT NULL REFERENCES agp_v2.node_identities(id),
  writer_epoch agp_v2.uint63 NOT NULL,
  authority_epoch agp_v2.uint63 NOT NULL CHECK (authority_epoch > 0),
  deployment_sequence agp_v2.uint63 NOT NULL,
  observed_bundle_digest agp_v2.digest,
  result_json jsonb NOT NULL CHECK (jsonb_typeof(result_json) = 'object' AND octet_length(result_json::text) <= 262144),
  observed_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (task_id, attempt_id, receipt_sequence)
);
-- result_json is per-kind closed schema; terminal result projection uses sequence+CAS.
CREATE TABLE agp_v2.auth_snapshot_readiness (
  bundle_digest agp_v2.digest PRIMARY KEY REFERENCES agp_v2.compiled_bundles(digest),
  auth_snapshot_digest agp_v2.digest NOT NULL,
  minimum_deny_sequence agp_v2.uint63 NOT NULL,
  ready_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  CHECK (expires_at > ready_at)
);
-- A DB readiness row alone is not a runtime health attestation; dispatch rechecks Auth.
CREATE TABLE agp_v2.writer_leases (
  name text PRIMARY KEY CHECK (name = 'rollout_writer'),
  holder_id agp_v2.object_id NOT NULL,
  writer_epoch agp_v2.uint63 NOT NULL CHECK (writer_epoch > 0),
  lease_expires_at timestamptz NOT NULL,
  row_version agp_v2.uint63 NOT NULL DEFAULT 0
);

CREATE TABLE agp_v2.security_authorities (
  id agp_v2.object_id PRIMARY KEY,
  authority_epoch agp_v2.uint63 NOT NULL CHECK (authority_epoch > 0),
  applied_sequence agp_v2.uint63 NOT NULL DEFAULT 0,
  applied_digest agp_v2.digest,
  observed_journal_sequence agp_v2.uint63 NOT NULL DEFAULT 0,
  observed_journal_digest agp_v2.digest,
  restored_at timestamptz,
  reconciled_at timestamptz,
  CHECK (applied_sequence <= observed_journal_sequence)
);
CREATE TABLE agp_v2.authenticator_floors (
  authority_id agp_v2.object_id NOT NULL REFERENCES agp_v2.security_authorities(id),
  principal_id agp_v2.object_id NOT NULL,
  authenticator_id agp_v2.object_id NOT NULL,
  minimum_version agp_v2.uint63 NOT NULL CHECK (minimum_version > 0),
  journal_sequence agp_v2.uint63 NOT NULL CHECK (journal_sequence > 0),
  PRIMARY KEY (authority_id, principal_id, authenticator_id)
);
CREATE TABLE agp_v2.security_operations (
  id agp_v2.object_id PRIMARY KEY,
  authority_id agp_v2.object_id NOT NULL REFERENCES agp_v2.security_authorities(id),
  expected_authority_epoch agp_v2.uint63 NOT NULL CHECK (expected_authority_epoch > 0),
  expected_journal_sequence agp_v2.uint63 NOT NULL,
  payload_digest agp_v2.digest NOT NULL,
  payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object' AND octet_length(payload_json::text) <= 262144),
  journal_mode text NOT NULL CHECK (journal_mode IN ('required','none_positive_grant')),
  approval_status text NOT NULL CHECK (approval_status IN ('not_required','pending','approved','rejected','expired')),
  actor_id agp_v2.object_id NOT NULL,
  state text NOT NULL CHECK (state IN ('pending','journaled','applied','rejected','recovery_required')),
  journal_sequence agp_v2.uint63,
  journal_event_digest agp_v2.digest,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  CHECK ((journal_sequence IS NULL) = (journal_event_digest IS NULL)),
  CHECK (octet_length(payload_json::text) <= 262144 OR
    (journal_mode = 'none_positive_grant' AND octet_length(payload_json::text) <= 67108864)),
  CHECK (journal_mode <> 'none_positive_grant' OR journal_sequence IS NULL)
);
CREATE TABLE agp_v2.security_barriers (
  operation_id agp_v2.object_id NOT NULL REFERENCES agp_v2.security_operations(id),
  scope_kind text NOT NULL CHECK (scope_kind IN ('global','principal','session','node','resource','secret_version','route','role_binding','membership')),
  scope_id text NOT NULL CHECK (length(scope_id) BETWEEN 1 AND 256),
  established_at timestamptz NOT NULL DEFAULT now(),
  cleared_at timestamptz,
  PRIMARY KEY (operation_id, scope_kind, scope_id)
);
CREATE INDEX security_barriers_active_idx ON agp_v2.security_barriers(scope_kind, scope_id) WHERE cleared_at IS NULL;
CREATE TABLE agp_v2.security_operation_approvals (
  id agp_v2.object_id PRIMARY KEY,
  operation_id agp_v2.object_id NOT NULL REFERENCES agp_v2.security_operations(id),
  payload_digest agp_v2.digest NOT NULL,
  approver_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  decided_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  UNIQUE (operation_id, approver_id),
  CHECK (expires_at > decided_at)
);
CREATE TABLE agp_v2.security_events (
  id agp_v2.object_id PRIMARY KEY,
  operation_id agp_v2.object_id NOT NULL UNIQUE REFERENCES agp_v2.security_operations(id),
  authority_id agp_v2.object_id NOT NULL REFERENCES agp_v2.security_authorities(id),
  authority_epoch agp_v2.uint63 NOT NULL CHECK (authority_epoch > 0),
  sequence agp_v2.uint63 NOT NULL CHECK (sequence > 0),
  kind text NOT NULL CHECK (kind IN ('block_principal','unblock_principal','revoke_session','revoke_node','disable_resource','enable_resource','revoke_secret','raise_security_floor','remove_membership','deny_route','clear_route_deny','revoke_role_binding','bump_authenticator_floor','advance_authority_epoch')),
  subject_kind text NOT NULL CHECK (subject_kind IN ('principal','session','node','resource','secret_version','release','membership','route','role_binding','authenticator','authority')),
  subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 256),
  subject_version agp_v2.uint63 NOT NULL,
  referenced_event_id agp_v2.object_id REFERENCES agp_v2.security_events(id),
  actor_id agp_v2.object_id NOT NULL,
  reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 2048),
  event_digest agp_v2.digest NOT NULL UNIQUE,
  previous_digest agp_v2.digest,
  created_at timestamptz NOT NULL DEFAULT now(),
  journal_acked_at timestamptz NOT NULL,
  UNIQUE (authority_id, sequence)
);
CREATE INDEX security_events_replay_idx ON agp_v2.security_events(authority_id, authority_epoch, sequence);
-- Sequence comes ONLY from independent journal; PostgreSQL never allocates it.
-- Subject references intentionally survive entity tombstones. Application checks kind/id,
-- deny-lift referenced event, second approval, chain digest and journal receipt.
-- Independent journal access and highwater are OUTSIDE this DB/backup; see architecture.
CREATE TABLE agp_v2.audit_events (
  id agp_v2.object_id PRIMARY KEY,
  occurred_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  actor_id agp_v2.object_id,
  actor_kind text NOT NULL CHECK (actor_kind IN ('principal','node','system','anonymous')),
  event_type text NOT NULL CHECK (length(event_type) BETWEEN 1 AND 128),
  object_kind text NOT NULL CHECK (length(object_kind) BETWEEN 1 AND 64),
  object_id text CHECK (length(object_id) <= 256),
  outcome text NOT NULL CHECK (outcome IN ('success','denied','failure','pending')),
  reason_code text NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 128),
  correlation_id agp_v2.object_id NOT NULL,
  client_ip inet,
  metadata agp_v2.extension_metadata NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_events_time_idx ON agp_v2.audit_events(occurred_at DESC, id);
CREATE INDEX audit_events_actor_idx ON agp_v2.audit_events(actor_id, occurred_at DESC);
CREATE INDEX audit_events_object_idx ON agp_v2.audit_events(object_kind, object_id, occurred_at DESC);
CREATE TABLE agp_v2.traffic_event_segments (
  id agp_v2.object_id PRIMARY KEY,
  node_id agp_v2.object_id NOT NULL REFERENCES agp_v2.nodes(id),
  first_event_at timestamptz NOT NULL,
  last_event_at timestamptz NOT NULL,
  event_count agp_v2.uint63 NOT NULL,
  dropped_count agp_v2.uint63 NOT NULL DEFAULT 0,
  artifact_digest agp_v2.digest NOT NULL REFERENCES agp_v2.artifacts(digest),
  retain_until timestamptz NOT NULL,
  CHECK (last_event_at >= first_event_at AND retain_until >= last_event_at)
);
CREATE TABLE agp_v2.outbox (
  id agp_v2.object_id PRIMARY KEY,
  topic text NOT NULL CHECK (length(topic) BETWEEN 1 AND 128),
  aggregate_kind text NOT NULL CHECK (length(aggregate_kind) BETWEEN 1 AND 64),
  aggregate_id text NOT NULL CHECK (length(aggregate_id) BETWEEN 1 AND 256),
  aggregate_version agp_v2.uint63 NOT NULL,
  event_json jsonb NOT NULL CHECK (jsonb_typeof(event_json) = 'object' AND octet_length(event_json::text) <= 262144),
  event_digest agp_v2.digest NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  available_at timestamptz NOT NULL DEFAULT now(),
  lease_owner agp_v2.object_id,
  lease_until timestamptz,
  delivered_at timestamptz,
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  UNIQUE (topic, aggregate_kind, aggregate_id, aggregate_version)
);
CREATE INDEX outbox_pending_idx ON agp_v2.outbox(available_at, id) WHERE delivered_at IS NULL;
CREATE TABLE agp_v2.idempotency_records (
  actor_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  operation text NOT NULL CHECK (length(operation) BETWEEN 1 AND 128),
  key text NOT NULL CHECK (length(key) BETWEEN 1 AND 128),
  request_digest agp_v2.digest NOT NULL,
  response_status integer NOT NULL CHECK (response_status BETWEEN 100 AND 599),
  response_json jsonb NOT NULL CHECK (octet_length(response_json::text) <= 262144),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (actor_id, operation, key),
  CHECK (expires_at > created_at)
);
CREATE TABLE agp_v2.notification_channels (
  id agp_v2.object_id PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('smtp','webhook','alertmanager','telegram')),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  endpoint text NOT NULL CHECK (length(endpoint) BETWEEN 1 AND 2048),
  chat_id text CHECK (length(chat_id) BETWEEN 1 AND 128),
  credential_secret_version_id agp_v2.object_id REFERENCES agp_v2.secret_versions(id),
  enabled boolean NOT NULL DEFAULT false,
  row_version agp_v2.uint63 NOT NULL DEFAULT 0,
  CHECK ((kind = 'telegram') = (chat_id IS NOT NULL))
);
CREATE TABLE agp_v2.notification_deliveries (
  id agp_v2.object_id PRIMARY KEY,
  channel_id agp_v2.object_id NOT NULL REFERENCES agp_v2.notification_channels(id),
  source_event_id agp_v2.object_id NOT NULL,
  dedup_key text NOT NULL CHECK (length(dedup_key) BETWEEN 1 AND 256),
  state text NOT NULL CHECK (state IN ('pending','sending','delivered','failed','suppressed')),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  next_attempt_at timestamptz NOT NULL,
  delivered_at timestamptz,
  UNIQUE (channel_id, dedup_key)
);
CREATE TABLE agp_v2.retention_policies (
  data_class text PRIMARY KEY CHECK (data_class IN ('audit','traffic','diagnostics','task_receipts','sessions','invites','config_history','artifacts','backups','idempotency')),
  retention_days integer NOT NULL CHECK (retention_days BETWEEN 1 AND 36500),
  approved_by agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  updated_at timestamptz NOT NULL DEFAULT now(),
  row_version agp_v2.uint63 NOT NULL DEFAULT 0
);
CREATE TABLE agp_v2.legal_holds (
  id agp_v2.object_id PRIMARY KEY,
  object_kind text NOT NULL CHECK (object_kind IN ('artifact','revision','audit_range','principal','release')),
  object_id text NOT NULL CHECK (length(object_id) BETWEEN 1 AND 256),
  reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 2048),
  created_by agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  released_by agp_v2.object_id REFERENCES agp_v2.principals(id),
  released_at timestamptz,
  CHECK ((released_at IS NULL) = (released_by IS NULL))
);
CREATE INDEX legal_holds_active_idx ON agp_v2.legal_holds(object_kind, object_id) WHERE released_at IS NULL;
CREATE TABLE agp_v2.artifact_pins (
  artifact_digest agp_v2.digest NOT NULL REFERENCES agp_v2.artifacts(digest),
  owner_kind text NOT NULL CHECK (owner_kind IN ('active_deployment','rollback','plan','release','legal_hold','backup')),
  owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 256),
  expires_at timestamptz,
  PRIMARY KEY (artifact_digest, owner_kind, owner_id)
);
CREATE TABLE agp_v2.schema_versions (
  version agp_v2.uint63 PRIMARY KEY,
  checksum agp_v2.digest NOT NULL,
  phase text NOT NULL CHECK (phase IN ('expand','backfill','contract')),
  applied_at timestamptz NOT NULL DEFAULT now()
);

-- AD/MFA/email extension (2026-11-17). TARGET reference, no production migration.
ALTER TABLE agp_v2.invitations ADD COLUMN authorization_operation_id agp_v2.object_id
  REFERENCES agp_v2.security_operations(id);
ALTER TABLE agp_v2.invitations ADD UNIQUE (authorization_operation_id);
ALTER TABLE agp_v2.invitations ADD CHECK ((proof_kind='supervised') = (authorization_operation_id IS NOT NULL));
ALTER TABLE agp_v2.invitations ADD CHECK (proof_kind <> 'supervised' OR issued_by IS NOT NULL);
CREATE TABLE agp_v2.directory_providers (
  id agp_v2.object_id PRIMARY KEY,
  name text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 128),
  forest_guid uuid NOT NULL,
  security_guard_id agp_v2.object_id NOT NULL UNIQUE,
  enabled boolean NOT NULL DEFAULT false,
  row_version agp_v2.uint63 NOT NULL DEFAULT 0,
  UNIQUE (id, forest_guid)
);
CREATE TABLE agp_v2.directory_provider_versions (
  id agp_v2.object_id PRIMARY KEY,
  provider_id agp_v2.object_id NOT NULL REFERENCES agp_v2.directory_providers(id),
  security_guard_version agp_v2.uint63 NOT NULL CHECK (security_guard_version > 0),
  content_digest agp_v2.digest NOT NULL UNIQUE,
  bind_secret_version_id agp_v2.object_id NOT NULL REFERENCES agp_v2.secret_versions(id),
  ca_secret_version_id agp_v2.object_id NOT NULL REFERENCES agp_v2.secret_versions(id),
  config_json jsonb NOT NULL CHECK (jsonb_typeof(config_json) = 'object' AND octet_length(config_json::text) <= 262144),
  created_by agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider_id, security_guard_version),
  UNIQUE (provider_id, id)
);
ALTER TABLE agp_v2.directory_providers ADD COLUMN current_version_id agp_v2.object_id;
ALTER TABLE agp_v2.directory_providers ADD FOREIGN KEY (id, current_version_id)
  REFERENCES agp_v2.directory_provider_versions(provider_id, id);
CREATE TABLE agp_v2.directory_identities (
  id agp_v2.object_id PRIMARY KEY,
  provider_id agp_v2.object_id NOT NULL,
  forest_guid uuid NOT NULL,
  object_guid uuid NOT NULL,
  principal_id agp_v2.object_id NOT NULL UNIQUE REFERENCES agp_v2.principals(id),
  authenticator_version agp_v2.uint63 NOT NULL CHECK (authenticator_version > 0),
  last_observed_at timestamptz,
  revoked_at timestamptz,
  UNIQUE (provider_id, forest_guid, object_guid),
  FOREIGN KEY (provider_id, forest_guid) REFERENCES agp_v2.directory_providers(id, forest_guid)
);
-- OIDC association head is (provider_id, exact subject). Its stable service guard
-- does not change when a successor moves the target, so old-target CP backups and
-- sessions cannot bypass the same independent authenticator floor.
CREATE TABLE agp_v2.external_identity_versions (
  id agp_v2.object_id PRIMARY KEY,
  external_identity_id agp_v2.object_id NOT NULL REFERENCES agp_v2.external_identities(id),
  security_guard_version agp_v2.uint63 NOT NULL CHECK (security_guard_version > 0),
  directory_identity_id agp_v2.object_id NOT NULL REFERENCES agp_v2.directory_identities(id),
  principal_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  content_digest agp_v2.digest NOT NULL UNIQUE,
  config_json jsonb NOT NULL CHECK (jsonb_typeof(config_json) = 'object' AND octet_length(config_json::text) <= 16384),
  authorization_operation_id agp_v2.object_id NOT NULL REFERENCES agp_v2.security_operations(id),
  created_by agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (external_identity_id, security_guard_version),
  UNIQUE (external_identity_id, id)
);
ALTER TABLE agp_v2.external_identities ADD COLUMN current_version_id agp_v2.object_id;
ALTER TABLE agp_v2.external_identities ADD FOREIGN KEY (id, current_version_id)
  REFERENCES agp_v2.external_identity_versions(external_identity_id, id);
-- family=oidc_identity_link, closed oidcLinkChange JCS intent. Initial link and
-- every relink/disable/re-enable require distinct approval, current actor floors,
-- fresh primary/MFA and exact epoch/CAS. Enable/relink additionally checks current
-- target floors and bounded live AD proof collected outside the DB writer and
-- revalidated at its final head. Disable preserves target and needs no live target
-- AD read. journal_mode=required:
-- stable guard barrier -> durable floor (guardId/guardId) -> positive projection.
-- The journal contains denies/floors only and cannot restore an approved link.
CREATE TABLE agp_v2.directory_group_mappings (
  provider_version_id agp_v2.object_id NOT NULL REFERENCES agp_v2.directory_provider_versions(id),
  group_object_guid uuid NOT NULL,
  access_group_id agp_v2.object_id NOT NULL REFERENCES agp_v2.access_groups(id),
  PRIMARY KEY (provider_version_id, group_object_guid, access_group_id)
);
CREATE TABLE agp_v2.directory_membership_observations (
  directory_identity_id agp_v2.object_id NOT NULL REFERENCES agp_v2.directory_identities(id),
  provider_version_id agp_v2.object_id NOT NULL,
  group_object_guid uuid NOT NULL,
  access_group_id agp_v2.object_id NOT NULL,
  observed_at timestamptz NOT NULL,
  observation_expires_at timestamptz NOT NULL,
  PRIMARY KEY (directory_identity_id, provider_version_id, group_object_guid, access_group_id),
  FOREIGN KEY (provider_version_id, group_object_guid, access_group_id)
    REFERENCES agp_v2.directory_group_mappings(provider_version_id, group_object_guid, access_group_id),
  CHECK (observation_expires_at > observed_at)
);
-- Observations are UI evidence only. Never substitute them for the required live AD read.
CREATE TABLE agp_v2.identity_contacts (
  id agp_v2.object_id PRIMARY KEY,
  principal_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  authenticator_version agp_v2.uint63 NOT NULL CHECK (authenticator_version > 0),
  address_secret_version_id agp_v2.object_id NOT NULL REFERENCES agp_v2.secret_versions(id),
  verified_at timestamptz,
  revoked_at timestamptz,
  row_version agp_v2.uint63 NOT NULL DEFAULT 0
);
CREATE TABLE agp_v2.identity_flows (
  id agp_v2.object_id PRIMARY KEY,
  principal_id agp_v2.object_id REFERENCES agp_v2.principals(id),
  purpose text NOT NULL CHECK (purpose IN ('login','step_up','verify_email','activate','recover')),
  audience text NOT NULL CHECK (audience IN ('management','login','setup')),
  state text NOT NULL CHECK (state IN ('pending_primary','pending_mfa','ready','completed','expired','cancelled')),
  binding_hash agp_v2.digest NOT NULL UNIQUE,
  issued_authority_epoch agp_v2.uint63 NOT NULL CHECK (issued_authority_epoch > 0),
  principal_security_version agp_v2.uint63,
  primary_authenticator_id agp_v2.object_id,
  primary_authenticator_version agp_v2.uint63,
  primary_verified_at timestamptz,
  mfa_factor_id agp_v2.object_id REFERENCES agp_v2.mfa_factors(id),
  mfa_authenticator_version agp_v2.uint63,
  mfa_verified_at timestamptz,
  oidc_provider_version_id agp_v2.object_id REFERENCES agp_v2.identity_provider_versions(id),
  oidc_external_identity_id agp_v2.object_id REFERENCES agp_v2.external_identities(id),
  oidc_link_version_id agp_v2.object_id REFERENCES agp_v2.external_identity_versions(id),
  directory_provider_version_id agp_v2.object_id REFERENCES agp_v2.directory_provider_versions(id),
  invitation_id agp_v2.object_id REFERENCES agp_v2.invitations(id),
  context_json jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(context_json) = 'object' AND octet_length(context_json::text) <= 16384),
  failed_attempts integer NOT NULL DEFAULT 0 CHECK (failed_attempts BETWEEN 0 AND 5),
  email_sends integer NOT NULL DEFAULT 0 CHECK (email_sends BETWEEN 0 AND 3),
  email_generation agp_v2.uint63 NOT NULL DEFAULT 0,
  row_version agp_v2.uint63 NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  completed_at timestamptz,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes'),
  CHECK ((principal_id IS NULL) = (principal_security_version IS NULL)),
  CHECK ((primary_authenticator_id IS NULL) = (primary_authenticator_version IS NULL)),
  CHECK (primary_authenticator_version IS NULL OR primary_authenticator_version > 0),
  CHECK (mfa_authenticator_version IS NULL OR mfa_authenticator_version > 0),
  CHECK ((state = 'completed') = (completed_at IS NOT NULL))
);
-- context_json is closed server-owned context (verified OIDC claims, policy version,
-- recovery authorization, source session); never raw client claims/credentials.
ALTER TABLE agp_v2.invitations ADD FOREIGN KEY (reserved_flow_id) REFERENCES agp_v2.identity_flows(id);
ALTER TABLE agp_v2.invitations ADD FOREIGN KEY (contact_id) REFERENCES agp_v2.identity_contacts(id);
CREATE TABLE agp_v2.identity_activation_stages (
  flow_id agp_v2.object_id PRIMARY KEY REFERENCES agp_v2.identity_flows(id),
  invitation_id agp_v2.object_id NOT NULL UNIQUE REFERENCES agp_v2.invitations(id),
  principal_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  issued_authority_epoch agp_v2.uint63 NOT NULL CHECK (issued_authority_epoch > 0),
  expected_security_version agp_v2.uint63 NOT NULL,
  expected_password_version agp_v2.uint63 NOT NULL,
  policy_digest agp_v2.digest NOT NULL,
  email_confirmed boolean NOT NULL DEFAULT false,
  password_phc text CHECK (password_phc LIKE '$argon2id$%' AND length(password_phc) <= 1024),
  factor_id agp_v2.object_id,
  factor_version agp_v2.uint63 CHECK (factor_version > 0),
  seed_key_id text CHECK (length(seed_key_id) BETWEEN 1 AND 256),
  seed_nonce bytea CHECK (octet_length(seed_nonce) = 12),
  seed_ciphertext bytea CHECK (octet_length(seed_ciphertext) BETWEEN 16 AND 4096),
  verified_totp_step agp_v2.uint63,
  factor_proof_at timestamptz,
  recovery_code_hashes jsonb NOT NULL DEFAULT '[]'
    CHECK (jsonb_typeof(recovery_code_hashes)='array' AND jsonb_array_length(recovery_code_hashes) <= 20),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes'),
  CHECK ((factor_id IS NULL) = (factor_version IS NULL)),
  CHECK ((factor_id IS NULL) = (seed_key_id IS NULL)),
  CHECK ((factor_id IS NULL) = (seed_nonce IS NULL)),
  CHECK ((factor_id IS NULL) = (seed_ciphertext IS NULL)),
  CHECK ((verified_totp_step IS NULL) = (factor_proof_at IS NULL)),
  CHECK (factor_proof_at IS NULL OR factor_id IS NOT NULL)
);
-- Stage is never an active credential. All seed/AAD ownership, bounded hashes,
-- reserved token/current policy/floors and deadlines are rechecked by private
-- service. email_confirmed is set only by consumed invite_confirmation for the
-- reserved contact/version; enrollment requires it. Confirmation cannot invoke
-- generic live-factor materialization.
-- After durable floor receipts one TX publishes password+factor+recovery hashes,
-- principal active state, invitation consumed_at and completed flow; no session.
CREATE TABLE agp_v2.identity_password_reset_stages (
  flow_id agp_v2.object_id PRIMARY KEY REFERENCES agp_v2.identity_flows(id),
  invitation_id agp_v2.object_id NOT NULL UNIQUE REFERENCES agp_v2.invitations(id),
  principal_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  issued_authority_epoch agp_v2.uint63 NOT NULL CHECK (issued_authority_epoch > 0),
  expected_security_version agp_v2.uint63 NOT NULL,
  expected_password_version agp_v2.uint63 NOT NULL,
  policy_digest agp_v2.digest NOT NULL,
  password_phc text NOT NULL CHECK (password_phc LIKE '$argon2id$%' AND length(password_phc) <= 1024),
  mfa_factor_id agp_v2.object_id REFERENCES agp_v2.mfa_factors(id),
  mfa_authenticator_version agp_v2.uint63 CHECK (mfa_authenticator_version > 0),
  mfa_proof_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes'),
  CHECK ((mfa_factor_id IS NULL) = (mfa_authenticator_version IS NULL)),
  CHECK ((mfa_factor_id IS NULL) = (mfa_proof_at IS NULL))
);
-- Ordinary reset requires current verified-contact token plus active TOTP and
-- monotonic replay proof. Runtime pins totp_factor_version plus flow.mfa_at;
-- a changed current factor or expired proof rejects finalization. Supervised
-- reset requires the exact consumed ticket
-- and applied reset_password action. Neither branch can replace MFA or issue
-- session. Hash/seed material never enters identity_flows.context_json.
CREATE TABLE agp_v2.identity_invite_outbox (
  id agp_v2.object_id PRIMARY KEY,
  invitation_id agp_v2.object_id NOT NULL UNIQUE REFERENCES agp_v2.invitations(id),
  issued_authority_epoch agp_v2.uint63 NOT NULL CHECK (issued_authority_epoch > 0),
  generation agp_v2.uint63 NOT NULL CHECK (generation > 0),
  key_ref agp_v2.object_id NOT NULL,
  nonce bytea NOT NULL CHECK (octet_length(nonce)=12),
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 16 AND 262144),
  state text NOT NULL CHECK (state IN ('prepared','queued','sending','accepted','failed','unknown','expired','cancelled')),
  claim_id agp_v2.object_id,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes'),
  CHECK (state <> 'sending' OR claim_id IS NOT NULL)
);
CREATE INDEX identity_invite_queue_idx ON agp_v2.identity_invite_outbox(state,created_at,id);
-- Separate pre-flow encrypted delivery, not an artificial email challenge/flow.
-- prepared is internal-only before durable issue receipts; materialization may
-- move it to queued. After restart, a missing volatile key makes it terminal
-- failed; prepared work is never sent before issue materialization.
-- key_ref resolves only a volatile per-message DEK, never secret_versions/wrapped
-- DEK in CP backup. One bounded SMTP send; unknown/restart/lost key is terminal,
-- public failed means delivery unconfirmed. Re-send requires a new generation.
-- Target/issuer/contact, token generation/epoch and expiry checked before send;
-- message payload expires within 5 min even if already delivered invite lasts 24 h.
CREATE TABLE agp_v2.oidc_authorization_requests (
  id agp_v2.object_id PRIMARY KEY,
  flow_id agp_v2.object_id NOT NULL REFERENCES agp_v2.identity_flows(id),
  provider_id agp_v2.object_id NOT NULL REFERENCES agp_v2.identity_providers(id),
  provider_version_id agp_v2.object_id NOT NULL,
  purpose text NOT NULL CHECK (purpose IN ('login','management')),
  flow_purpose text NOT NULL CHECK (flow_purpose IN ('login','step_up')),
  origin text NOT NULL CHECK (length(origin) BETWEEN 1 AND 2048),
  redirect_uri text NOT NULL CHECK (length(redirect_uri) BETWEEN 1 AND 2048),
  binding_hash agp_v2.digest NOT NULL,
  state_hash agp_v2.digest NOT NULL UNIQUE,
  issued_authority_epoch agp_v2.uint63 NOT NULL CHECK (issued_authority_epoch > 0),
  state text NOT NULL CHECK (state IN ('issued','exchanging','succeeded','failed')),
  encrypted_proof bytea CHECK (octet_length(encrypted_proof) BETWEEN 29 AND 16384),
  encryption_key_id text CHECK (length(encryption_key_id) BETWEEN 1 AND 256),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  completed_at timestamptz,
  FOREIGN KEY (provider_id, provider_version_id)
    REFERENCES agp_v2.identity_provider_versions(provider_id, id),
  FOREIGN KEY (provider_version_id, purpose)
    REFERENCES agp_v2.identity_provider_clients(provider_version_id, purpose),
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes'),
  CHECK ((state = 'issued') = (consumed_at IS NULL)),
  CHECK ((state IN ('succeeded','failed')) = (completed_at IS NOT NULL)),
  CHECK ((encrypted_proof IS NULL) = (encryption_key_id IS NULL)),
  CHECK (state NOT IN ('issued','exchanging') OR encrypted_proof IS NOT NULL),
  CHECK (state NOT IN ('succeeded','failed') OR encrypted_proof IS NULL)
);
CREATE UNIQUE INDEX oidc_authorization_one_live_idx ON agp_v2.oidc_authorization_requests(flow_id)
  WHERE state IN ('issued','exchanging');
CREATE INDEX oidc_authorization_expiry_idx ON agp_v2.oidc_authorization_requests(expires_at);
-- AEAD plaintext is only nonce/verifier; AAD binds all IDs, purpose/origin,
-- browser binding, redirect URI and epoch. Dedicated protected key outside CP
-- backup, never a TOTP key. No raw state/code/ID/access/refresh token is persisted.
-- Request expiry never exceeds its parent flow; at most three requests per flow.
-- Terminal/expired proofs are erased, including after interrupted exchange.
-- Atomic issued->exchanging consumes state before exactly one bounded exchange.
-- No requeue/retry after uncertain network/process result. Repeated callbacks
-- return only fixed own-flow continuation; expiry/restart closes uncertainty.
-- Bounded live AD proof is collected outside the DB writer. Final issuer/sub,
-- provider/link/directory/principal floors, source principal and fresh proof/head
-- precede atomic succeeded + pending_mfa flow transition.
-- Failed/unknown exchange cancels the flow. Lost response uses GET own flow.
CREATE TABLE agp_v2.email_challenges (
  id agp_v2.object_id PRIMARY KEY,
  flow_id agp_v2.object_id NOT NULL REFERENCES agp_v2.identity_flows(id),
  contact_id agp_v2.object_id NOT NULL REFERENCES agp_v2.identity_contacts(id),
  contact_authenticator_version agp_v2.uint63 NOT NULL CHECK (contact_authenticator_version > 0),
  purpose text NOT NULL CHECK (purpose IN ('verify_email','invite_confirmation','recovery_confirmation')),
  audience text NOT NULL CHECK (audience IN ('management','login','setup')),
  issued_authority_epoch agp_v2.uint63 NOT NULL CHECK (issued_authority_epoch > 0),
  generation agp_v2.uint63 NOT NULL CHECK (generation > 0),
  code_mac bytea NOT NULL CHECK (octet_length(code_mac) = 32),
  mac_key_id text NOT NULL CHECK (length(mac_key_id) BETWEEN 1 AND 256),
  failed_attempts integer NOT NULL DEFAULT 0 CHECK (failed_attempts BETWEEN 0 AND 5),
  delivery_state text NOT NULL CHECK (delivery_state IN ('queued','accepted','failed','expired')),
  delivery_secret_version_id agp_v2.object_id REFERENCES agp_v2.secret_versions(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  revoked_at timestamptz,
  UNIQUE (flow_id, generation),
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes'),
  CHECK (consumed_at IS NULL OR revoked_at IS NULL)
);
CREATE UNIQUE INDEX email_challenges_one_live_idx ON agp_v2.email_challenges(flow_id)
  WHERE consumed_at IS NULL AND revoked_at IS NULL;
CREATE INDEX identity_flows_expiry_idx ON agp_v2.identity_flows(expires_at);
CREATE INDEX email_challenges_expiry_idx ON agp_v2.email_challenges(expires_at);
ALTER TABLE agp_v2.sessions ADD COLUMN directory_identity_id agp_v2.object_id REFERENCES agp_v2.directory_identities(id);
ALTER TABLE agp_v2.sessions ADD COLUMN directory_provider_version_id agp_v2.object_id REFERENCES agp_v2.directory_provider_versions(id);
ALTER TABLE agp_v2.sessions ADD CHECK (authentication_method NOT IN ('directory_password','directory_mfa') OR
  (directory_identity_id IS NOT NULL AND directory_provider_version_id IS NOT NULL));
ALTER TABLE agp_v2.gateway_sessions ADD COLUMN directory_identity_id agp_v2.object_id REFERENCES agp_v2.directory_identities(id);
ALTER TABLE agp_v2.gateway_sessions ADD COLUMN directory_provider_version_id agp_v2.object_id REFERENCES agp_v2.directory_provider_versions(id);
ALTER TABLE agp_v2.gateway_sessions ADD CHECK (authentication_method NOT IN ('directory_password','directory_mfa') OR
  (directory_identity_id IS NOT NULL AND directory_provider_version_id IS NOT NULL));
ALTER TABLE agp_v2.sessions ADD COLUMN oidc_external_identity_id agp_v2.object_id REFERENCES agp_v2.external_identities(id);
ALTER TABLE agp_v2.sessions ADD COLUMN oidc_link_version_id agp_v2.object_id REFERENCES agp_v2.external_identity_versions(id);
ALTER TABLE agp_v2.gateway_sessions ADD COLUMN oidc_external_identity_id agp_v2.object_id REFERENCES agp_v2.external_identities(id);
ALTER TABLE agp_v2.gateway_sessions ADD COLUMN oidc_link_version_id agp_v2.object_id REFERENCES agp_v2.external_identity_versions(id);
-- First AD-backed OIDC profile requires all OIDC link/version plus directory pins
-- even though authentication_method='oidc'. Every allow/handoff/refresh validates
-- both provider and stable link guard floors and performs the same live AD check.
-- primary_at is verified auth_time only (never iat/callback time); legacy rows
-- remain NULL. AGP TOTP records an independent mfa_verified_at.
-- App enforces provider/version/principal ownership, config/schema/digest equality,
-- current guard+link+contact floors, flow transitions, challenge budget and atomic consume.

-- Accepted WAF Zone authoring model (2026-11-17). Projection writes belong to one
-- revision-service transaction; this remains reference DDL, not a production migration.
ALTER TABLE agp_v2.waf_policy_revisions ADD UNIQUE (id, site_id);
ALTER TABLE agp_v2.gateways ADD UNIQUE (revision_id, id, site_id);
ALTER TABLE agp_v2.gateways ADD FOREIGN KEY (waf_policy_revision_id, site_id)
  REFERENCES agp_v2.waf_policy_revisions(id, site_id);
ALTER TABLE agp_v2.nodes ADD UNIQUE (id, site_id);

CREATE TABLE agp_v2.waf_zones (
  id agp_v2.object_id PRIMARY KEY,
  site_id agp_v2.object_id NOT NULL REFERENCES agp_v2.sites(id),
  created_by agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  row_version agp_v2.uint63 NOT NULL DEFAULT 0,
  UNIQUE (id, site_id)
);
-- Name/owner/selector live in immutable revisions; no mutable "active policy" pointer.
CREATE TABLE agp_v2.waf_zone_revisions (
  id agp_v2.object_id PRIMARY KEY,
  zone_id agp_v2.object_id NOT NULL,
  site_id agp_v2.object_id NOT NULL,
  parent_id agp_v2.object_id REFERENCES agp_v2.waf_zone_revisions(id),
  revision_number agp_v2.uint63 NOT NULL CHECK (revision_number > 0),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  owner_id agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  policy_revision_id agp_v2.object_id NOT NULL,
  mode text NOT NULL CHECK (mode IN ('detection','blocking')),
  membership_kind text NOT NULL CHECK (membership_kind IN ('explicit','labels','site_default')),
  reason text NOT NULL CHECK (length(reason) BETWEEN 8 AND 1024),
  canonical_json jsonb NOT NULL CHECK (jsonb_typeof(canonical_json) = 'object' AND octet_length(canonical_json::text) <= 4194304),
  content_digest agp_v2.digest NOT NULL,
  state text NOT NULL CHECK (state IN ('draft','validated','approved','published','superseded')),
  created_by agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  row_version agp_v2.uint63 NOT NULL DEFAULT 0,
  UNIQUE (zone_id, revision_number),
  UNIQUE (id, site_id),
  UNIQUE (id, zone_id, site_id),
  FOREIGN KEY (zone_id, site_id) REFERENCES agp_v2.waf_zones(id, site_id),
  FOREIGN KEY (policy_revision_id, site_id) REFERENCES agp_v2.waf_policy_revisions(id, site_id),
  CHECK (parent_id IS DISTINCT FROM id)
);
CREATE INDEX waf_zone_revision_site_idx ON agp_v2.waf_zone_revisions(site_id, zone_id, revision_number);
CREATE TABLE agp_v2.waf_zone_selector_labels (
  zone_revision_id agp_v2.object_id NOT NULL REFERENCES agp_v2.waf_zone_revisions(id),
  key text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_.-]{0,62}$'),
  value text NOT NULL CHECK (length(value) BETWEEN 1 AND 128),
  PRIMARY KEY (zone_revision_id, key)
);
CREATE TABLE agp_v2.waf_zone_explicit_gateways (
  zone_revision_id agp_v2.object_id NOT NULL REFERENCES agp_v2.waf_zone_revisions(id),
  gateway_id agp_v2.object_id NOT NULL,
  PRIMARY KEY (zone_revision_id, gateway_id)
);
-- Explicit authored IDs are resolved against a fixed Configuration, not an invented
-- global Gateway table. Service checks 1..10000 explicit IDs / 1..32 AND labels.
CREATE TABLE agp_v2.gateway_labels (
  revision_id agp_v2.object_id NOT NULL,
  gateway_id agp_v2.object_id NOT NULL,
  key text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_.-]{0,62}$'),
  value text NOT NULL CHECK (length(value) BETWEEN 1 AND 128),
  PRIMARY KEY (revision_id, gateway_id, key),
  FOREIGN KEY (revision_id, gateway_id) REFERENCES agp_v2.gateways(revision_id, id)
);
CREATE INDEX gateway_labels_selector_idx ON agp_v2.gateway_labels(revision_id, key, value, gateway_id);

CREATE TABLE agp_v2.waf_zone_resolutions (
  id agp_v2.object_id PRIMARY KEY,
  site_id agp_v2.object_id NOT NULL REFERENCES agp_v2.sites(id),
  zone_revision_id agp_v2.object_id NOT NULL,
  base_revision_id agp_v2.object_id NOT NULL REFERENCES agp_v2.config_revisions(id),
  action text NOT NULL CHECK (action IN ('reconcile','retire')),
  capacity_profile text NOT NULL CHECK (capacity_profile IN ('pilot-500','fleet-10k')),
  inventory_digest agp_v2.digest NOT NULL,
  resolution_digest agp_v2.digest NOT NULL,
  canonical_json jsonb NOT NULL CHECK (jsonb_typeof(canonical_json) = 'object' AND octet_length(canonical_json::text) <= 134217728),
  created_by agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  UNIQUE (id, site_id, base_revision_id),
  CHECK (expires_at = created_at + interval '30 minutes'),
  FOREIGN KEY (zone_revision_id, site_id) REFERENCES agp_v2.waf_zone_revisions(id, site_id),
  CHECK (expires_at > created_at)
);
CREATE TABLE agp_v2.waf_zone_resolution_members (
  resolution_id agp_v2.object_id NOT NULL,
  site_id agp_v2.object_id NOT NULL,
  base_revision_id agp_v2.object_id NOT NULL,
  gateway_id agp_v2.object_id NOT NULL,
  source_zone_revision_id agp_v2.object_id,
  target_zone_revision_id agp_v2.object_id,
  source_policy_revision_id agp_v2.object_id NOT NULL,
  target_policy_revision_id agp_v2.object_id,
  base_binding_digest agp_v2.digest NOT NULL,
  target_binding_digest agp_v2.digest,
  disposition text NOT NULL CHECK (disposition IN ('inherited','derived','conflict')),
  PRIMARY KEY (resolution_id, gateway_id),
  FOREIGN KEY (resolution_id, site_id, base_revision_id) REFERENCES agp_v2.waf_zone_resolutions(id, site_id, base_revision_id),
  FOREIGN KEY (base_revision_id, gateway_id, site_id) REFERENCES agp_v2.gateways(revision_id, id, site_id),
  FOREIGN KEY (source_zone_revision_id, site_id) REFERENCES agp_v2.waf_zone_revisions(id, site_id),
  FOREIGN KEY (target_zone_revision_id, site_id) REFERENCES agp_v2.waf_zone_revisions(id, site_id),
  FOREIGN KEY (source_policy_revision_id, site_id) REFERENCES agp_v2.waf_policy_revisions(id, site_id),
  FOREIGN KEY (target_policy_revision_id, site_id) REFERENCES agp_v2.waf_policy_revisions(id, site_id),
  CHECK ((disposition = 'conflict' AND target_zone_revision_id IS NULL AND target_policy_revision_id IS NULL AND target_binding_digest IS NULL) OR
         (disposition IN ('inherited','derived') AND target_zone_revision_id IS NOT NULL AND target_policy_revision_id IS NOT NULL AND target_binding_digest IS NOT NULL))
);
CREATE INDEX waf_zone_resolution_gateway_idx ON agp_v2.waf_zone_resolution_members(gateway_id, resolution_id);
CREATE TABLE agp_v2.waf_zone_resolution_routes (
  resolution_id agp_v2.object_id NOT NULL,
  gateway_id agp_v2.object_id NOT NULL,
  base_revision_id agp_v2.object_id NOT NULL,
  route_id agp_v2.object_id NOT NULL,
  PRIMARY KEY (resolution_id, gateway_id, route_id),
  FOREIGN KEY (resolution_id, gateway_id) REFERENCES agp_v2.waf_zone_resolution_members(resolution_id, gateway_id),
  FOREIGN KEY (base_revision_id, route_id) REFERENCES agp_v2.routes(revision_id, id)
);
CREATE TABLE agp_v2.waf_zone_resolution_nodes (
  resolution_id agp_v2.object_id NOT NULL,
  gateway_id agp_v2.object_id NOT NULL,
  node_id agp_v2.object_id NOT NULL,
  site_id agp_v2.object_id NOT NULL,
  PRIMARY KEY (resolution_id, gateway_id, node_id),
  FOREIGN KEY (resolution_id, gateway_id) REFERENCES agp_v2.waf_zone_resolution_members(resolution_id, gateway_id),
  FOREIGN KEY (node_id, site_id) REFERENCES agp_v2.nodes(id, site_id)
);
-- Route->Gateway and member->site/base equality are also checked by the frozen
-- resolver; stronger composite FKs below keep projections attached to their parent.
ALTER TABLE agp_v2.waf_zone_resolution_members ADD UNIQUE (resolution_id, gateway_id, base_revision_id, site_id);
ALTER TABLE agp_v2.waf_zone_resolution_routes ADD COLUMN site_id agp_v2.object_id NOT NULL;
ALTER TABLE agp_v2.waf_zone_resolution_routes ADD FOREIGN KEY (resolution_id, gateway_id, base_revision_id, site_id)
  REFERENCES agp_v2.waf_zone_resolution_members(resolution_id, gateway_id, base_revision_id, site_id);
ALTER TABLE agp_v2.routes ADD UNIQUE (revision_id, id, gateway_id);
ALTER TABLE agp_v2.waf_zone_resolution_routes ADD FOREIGN KEY (base_revision_id, route_id, gateway_id)
  REFERENCES agp_v2.routes(revision_id, id, gateway_id);
ALTER TABLE agp_v2.waf_zone_resolution_members ADD UNIQUE (resolution_id, gateway_id, site_id);
ALTER TABLE agp_v2.waf_zone_resolution_nodes ADD FOREIGN KEY (resolution_id, gateway_id, site_id)
  REFERENCES agp_v2.waf_zone_resolution_members(resolution_id, gateway_id, site_id);

CREATE TABLE agp_v2.waf_zone_resolution_conflicts (
  resolution_id agp_v2.object_id NOT NULL REFERENCES agp_v2.waf_zone_resolutions(id),
  gateway_id agp_v2.object_id NOT NULL,
  code text NOT NULL CHECK (length(code) BETWEEN 1 AND 96),
  path text NOT NULL CHECK (length(path) <= 512),
  message_redacted text NOT NULL CHECK (length(message_redacted) BETWEEN 1 AND 1024),
  candidate_zone_revision_ids agp_v2.object_id[] NOT NULL DEFAULT '{}' CHECK (cardinality(candidate_zone_revision_ids) <= 100),
  PRIMARY KEY (resolution_id, gateway_id, code, path),
  FOREIGN KEY (resolution_id, gateway_id) REFERENCES agp_v2.waf_zone_resolution_members(resolution_id, gateway_id)
);
-- Candidate array references/codes and all FK-external semantic checks use the closed DTO.
CREATE TABLE agp_v2.config_waf_zones (
  revision_id agp_v2.object_id NOT NULL REFERENCES agp_v2.config_revisions(id),
  zone_id agp_v2.object_id NOT NULL,
  zone_revision_id agp_v2.object_id NOT NULL,
  site_id agp_v2.object_id NOT NULL,
  is_default boolean NOT NULL,
  PRIMARY KEY (revision_id, zone_id),
  UNIQUE (revision_id, zone_revision_id, site_id),
  FOREIGN KEY (zone_revision_id, zone_id, site_id) REFERENCES agp_v2.waf_zone_revisions(id, zone_id, site_id)
);
CREATE UNIQUE INDEX config_waf_zone_default_idx ON agp_v2.config_waf_zones(revision_id, site_id) WHERE is_default;
CREATE TABLE agp_v2.waf_zone_assignments (
  revision_id agp_v2.object_id NOT NULL,
  gateway_id agp_v2.object_id NOT NULL,
  site_id agp_v2.object_id NOT NULL,
  zone_revision_id agp_v2.object_id NOT NULL,
  resolution_id agp_v2.object_id NOT NULL,
  policy_revision_id agp_v2.object_id NOT NULL,
  mode text NOT NULL CHECK (mode IN ('detection','blocking')),
  source_kind text NOT NULL CHECK (source_kind IN ('inherited','derived')),
  binding_digest agp_v2.digest NOT NULL,
  PRIMARY KEY (revision_id, gateway_id),
  FOREIGN KEY (revision_id, gateway_id, site_id) REFERENCES agp_v2.gateways(revision_id, id, site_id),
  FOREIGN KEY (revision_id, zone_revision_id, site_id) REFERENCES agp_v2.config_waf_zones(revision_id, zone_revision_id, site_id),
  FOREIGN KEY (resolution_id, gateway_id, site_id) REFERENCES agp_v2.waf_zone_resolution_members(resolution_id, gateway_id, site_id),
  FOREIGN KEY (policy_revision_id, site_id) REFERENCES agp_v2.waf_policy_revisions(id, site_id)
);
ALTER TABLE agp_v2.waf_zone_resolution_members ADD UNIQUE
  (resolution_id, gateway_id, site_id, target_zone_revision_id, target_policy_revision_id, target_binding_digest);
ALTER TABLE agp_v2.waf_zone_assignments ADD FOREIGN KEY
  (resolution_id, gateway_id, site_id, zone_revision_id, policy_revision_id, binding_digest)
  REFERENCES agp_v2.waf_zone_resolution_members
  (resolution_id, gateway_id, site_id, target_zone_revision_id, target_policy_revision_id, target_binding_digest);
ALTER TABLE agp_v2.gateways ADD UNIQUE (revision_id, id, site_id, waf_policy_revision_id, waf_mode);
ALTER TABLE agp_v2.waf_zone_assignments ADD FOREIGN KEY (revision_id, gateway_id, site_id, policy_revision_id, mode)
  REFERENCES agp_v2.gateways(revision_id, id, site_id, waf_policy_revision_id, waf_mode);
CREATE INDEX waf_zone_assignments_zone_idx ON agp_v2.waf_zone_assignments(zone_revision_id, revision_id, gateway_id);
CREATE TABLE agp_v2.waf_policy_lineage (
  derived_policy_revision_id agp_v2.object_id PRIMARY KEY,
  base_policy_revision_id agp_v2.object_id NOT NULL,
  zone_revision_id agp_v2.object_id NOT NULL,
  site_id agp_v2.object_id NOT NULL,
  source_config_revision_id agp_v2.object_id NOT NULL,
  gateway_id agp_v2.object_id NOT NULL,
  source_derived_policy_revision_id agp_v2.object_id,
  override_fields text[] NOT NULL CHECK (cardinality(override_fields) BETWEEN 1 AND 4 AND override_fields <@ ARRAY['paranoiaLevel','inboundAnomalyThreshold','outboundAnomalyThreshold','exceptions']::text[]),
  local_overrides_digest agp_v2.digest NOT NULL,
  FOREIGN KEY (derived_policy_revision_id, site_id) REFERENCES agp_v2.waf_policy_revisions(id, site_id),
  FOREIGN KEY (base_policy_revision_id, site_id) REFERENCES agp_v2.waf_policy_revisions(id, site_id),
  FOREIGN KEY (zone_revision_id, site_id) REFERENCES agp_v2.waf_zone_revisions(id, site_id),
  FOREIGN KEY (source_config_revision_id, gateway_id, site_id) REFERENCES agp_v2.gateways(revision_id, id, site_id),
  FOREIGN KEY (source_derived_policy_revision_id, site_id) REFERENCES agp_v2.waf_policy_revisions(id, site_id),
  CHECK (derived_policy_revision_id <> base_policy_revision_id)
);
CREATE TABLE agp_v2.waf_zone_changes (
  id agp_v2.object_id PRIMARY KEY,
  resolution_id agp_v2.object_id NOT NULL REFERENCES agp_v2.waf_zone_resolutions(id),
  base_revision_id agp_v2.object_id NOT NULL REFERENCES agp_v2.config_revisions(id),
  zone_revision_id agp_v2.object_id NOT NULL REFERENCES agp_v2.waf_zone_revisions(id),
  request_digest agp_v2.digest NOT NULL,
  resolution_digest agp_v2.digest NOT NULL,
  reason text NOT NULL CHECK (length(reason) BETWEEN 8 AND 1024),
  created_by agp_v2.object_id NOT NULL REFERENCES agp_v2.principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  result_revision_id agp_v2.object_id REFERENCES agp_v2.config_revisions(id),
  state text NOT NULL CHECK (state IN ('pending','materialized','failed')),
  row_version agp_v2.uint63 NOT NULL DEFAULT 0,
  CHECK ((state = 'materialized') = (result_revision_id IS NOT NULL))
);
ALTER TABLE agp_v2.waf_zone_revisions ADD FOREIGN KEY (parent_id, zone_id, site_id)
  REFERENCES agp_v2.waf_zone_revisions(id, zone_id, site_id);
ALTER TABLE agp_v2.waf_zone_revisions ADD UNIQUE (id, site_id, policy_revision_id);
ALTER TABLE agp_v2.waf_policy_lineage ADD FOREIGN KEY (zone_revision_id, site_id, base_policy_revision_id)
  REFERENCES agp_v2.waf_zone_revisions(id, site_id, policy_revision_id);
ALTER TABLE agp_v2.waf_policy_lineage ADD UNIQUE (derived_policy_revision_id, gateway_id);
ALTER TABLE agp_v2.waf_policy_lineage ADD FOREIGN KEY (source_derived_policy_revision_id, gateway_id)
  REFERENCES agp_v2.waf_policy_lineage(derived_policy_revision_id, gateway_id);
ALTER TABLE agp_v2.config_waf_zones ADD UNIQUE (revision_id, zone_revision_id);
ALTER TABLE agp_v2.effective_policy_provenance ADD FOREIGN KEY (revision_id, source_zone_revision_id)
  REFERENCES agp_v2.config_waf_zones(revision_id, zone_revision_id);
ALTER TABLE agp_v2.effective_policy_provenance ADD CHECK (
  (source_kind = 'zone') = (source_zone_revision_id IS NOT NULL));
ALTER TABLE agp_v2.effective_policy_provenance ADD CHECK (
  source_kind <> 'local_policy' OR source_policy_revision_id IS NOT NULL);
-- Publication updates desired Configuration+zone mappings+outbox atomically under
-- config_head CAS. Reject any conflict/stale/expired resolution, recomputed target
-- set, omitted destination closure or source mismatch. FK alone is not an approval.
ALTER TABLE agp_v2.policy_revision_approvals ADD COLUMN zone_revision_id agp_v2.object_id REFERENCES agp_v2.waf_zone_revisions(id);
ALTER TABLE agp_v2.policy_revision_approvals DROP CONSTRAINT policy_revision_approvals_target_check;
ALTER TABLE agp_v2.policy_revision_approvals ADD CHECK (
  (waf_revision_id IS NOT NULL)::integer + (profile_version_id IS NOT NULL)::integer + (zone_revision_id IS NOT NULL)::integer = 1);
ALTER TABLE agp_v2.policy_revision_approvals DROP CONSTRAINT policy_revision_approval_actor_unique;
CREATE UNIQUE INDEX policy_revision_approval_actor_idx ON agp_v2.policy_revision_approvals
  (waf_revision_id, profile_version_id, zone_revision_id, approver_id) NULLS NOT DISTINCT;
ALTER TABLE agp_v2.validation_reports ADD COLUMN zone_revision_id agp_v2.object_id REFERENCES agp_v2.waf_zone_revisions(id);
ALTER TABLE agp_v2.validation_reports DROP CONSTRAINT validation_reports_target_check;
ALTER TABLE agp_v2.validation_reports ADD CONSTRAINT validation_reports_target_check CHECK (
  (revision_id IS NOT NULL)::integer + (waf_revision_id IS NOT NULL)::integer +
  (profile_version_id IS NOT NULL)::integer + (zone_revision_id IS NOT NULL)::integer = 1);

-- Immutable facts: deleting history requires a dedicated retention maintenance role.
-- Reference trigger rejects UPDATE and DELETE; production migration must introduce
-- explicit narrowly scoped retention procedures, privileges and audit before enabling GC.
CREATE FUNCTION agp_v2.reject_fact_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'immutable fact in %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME;
END;
$$;
CREATE TRIGGER directory_provider_versions_immutable BEFORE UPDATE OR DELETE ON agp_v2.directory_provider_versions
  FOR EACH ROW EXECUTE FUNCTION agp_v2.reject_fact_mutation();
CREATE TRIGGER directory_mappings_immutable BEFORE UPDATE OR DELETE ON agp_v2.directory_group_mappings
  FOR EACH ROW EXECUTE FUNCTION agp_v2.reject_fact_mutation();
CREATE FUNCTION agp_v2.guard_revision_content() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (to_jsonb(NEW) - ARRAY['state','row_version']) IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['state','row_version']) THEN
    RAISE EXCEPTION 'revision content is immutable; create a successor';
  END IF;
  IF NEW.row_version <> OLD.row_version + 1 THEN
    RAISE EXCEPTION 'revision CAS version must increase by one';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER revisions_content_guard BEFORE UPDATE ON agp_v2.config_revisions
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_revision_content();
CREATE FUNCTION agp_v2.guard_plan_content() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (to_jsonb(NEW) - ARRAY['state','row_version']) IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['state','row_version']) THEN
    RAISE EXCEPTION 'plan content is immutable; create a successor';
  END IF;
  IF NEW.row_version <> OLD.row_version + 1 THEN
    RAISE EXCEPTION 'plan CAS version must increase by one';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER plans_content_guard BEFORE UPDATE ON agp_v2.deployment_plans
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_plan_content();
CREATE TRIGGER profile_content_guard BEFORE UPDATE ON agp_v2.policy_profile_versions
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_revision_content();
CREATE TRIGGER waf_policy_content_guard BEFORE UPDATE ON agp_v2.waf_policy_revisions
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_revision_content();
CREATE TRIGGER waf_zone_identity_guard BEFORE UPDATE ON agp_v2.waf_zones
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_revision_content();
CREATE TRIGGER waf_zone_identity_no_delete BEFORE DELETE ON agp_v2.waf_zones
  FOR EACH ROW EXECUTE FUNCTION agp_v2.reject_fact_mutation();
CREATE TRIGGER waf_zone_content_guard BEFORE UPDATE ON agp_v2.waf_zone_revisions
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_revision_content();
CREATE TRIGGER waf_zone_revision_no_delete BEFORE DELETE ON agp_v2.waf_zone_revisions
  FOR EACH ROW EXECUTE FUNCTION agp_v2.reject_fact_mutation();
CREATE FUNCTION agp_v2.guard_zone_change_content() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (to_jsonb(NEW) - ARRAY['state','result_revision_id','row_version']) IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['state','result_revision_id','row_version']) OR
     NEW.row_version <> OLD.row_version + 1 OR OLD.state <> 'pending' THEN
    RAISE EXCEPTION 'zone change is immutable except one terminal CAS transition';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER waf_zone_change_content_guard BEFORE UPDATE ON agp_v2.waf_zone_changes
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_zone_change_content();
CREATE TRIGGER waf_zone_change_no_delete BEFORE DELETE ON agp_v2.waf_zone_changes
  FOR EACH ROW EXECUTE FUNCTION agp_v2.reject_fact_mutation();
CREATE FUNCTION agp_v2.guard_zone_child_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE parent_state text; parent_kind text;
BEGIN
  SELECT state, membership_kind INTO parent_state, parent_kind FROM agp_v2.waf_zone_revisions
    WHERE id = NEW.zone_revision_id FOR SHARE;
  IF parent_state IS DISTINCT FROM 'draft' OR
     (TG_TABLE_NAME = 'waf_zone_selector_labels' AND parent_kind <> 'labels') OR
     (TG_TABLE_NAME = 'waf_zone_explicit_gateways' AND parent_kind <> 'explicit') THEN
    RAISE EXCEPTION 'zone membership children require a matching draft revision';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER draft_zone_labels BEFORE INSERT ON agp_v2.waf_zone_selector_labels
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_zone_child_insert();
CREATE TRIGGER draft_zone_gateways BEFORE INSERT ON agp_v2.waf_zone_explicit_gateways
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_zone_child_insert();
-- Resolution row+all normalized children are inserted in one transaction. Deferred
-- closure validation is the service responsibility; no child may be appended after
-- the creating transaction commits, even if expiry has not yet elapsed.
ALTER TABLE agp_v2.waf_zone_resolutions ADD COLUMN creation_tx xid8 NOT NULL DEFAULT pg_current_xact_id();
CREATE FUNCTION agp_v2.guard_resolution_child_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE parent_tx xid8;
BEGIN
  SELECT creation_tx INTO parent_tx FROM agp_v2.waf_zone_resolutions
    WHERE id = NEW.resolution_id FOR SHARE;
  IF parent_tx IS DISTINCT FROM pg_current_xact_id() THEN
    RAISE EXCEPTION 'frozen resolution children can only be inserted in creating transaction';
  END IF;
  RETURN NEW;
END;
$$;
DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY['waf_zone_resolution_members','waf_zone_resolution_routes','waf_zone_resolution_nodes','waf_zone_resolution_conflicts'] LOOP
    EXECUTE format('CREATE TRIGGER frozen_resolution_insert BEFORE INSERT ON agp_v2.%I FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_resolution_child_insert()', table_name);
  END LOOP;
END;
$$;
CREATE TRIGGER waf_policy_no_delete BEFORE DELETE ON agp_v2.waf_policy_revisions
  FOR EACH ROW EXECUTE FUNCTION agp_v2.reject_fact_mutation();
CREATE TRIGGER revisions_no_delete BEFORE DELETE ON agp_v2.config_revisions
  FOR EACH ROW EXECUTE FUNCTION agp_v2.reject_fact_mutation();
CREATE TRIGGER plans_no_delete BEFORE DELETE ON agp_v2.deployment_plans
  FOR EACH ROW EXECUTE FUNCTION agp_v2.reject_fact_mutation();
CREATE TRIGGER profiles_no_delete BEFORE DELETE ON agp_v2.policy_profile_versions
  FOR EACH ROW EXECUTE FUNCTION agp_v2.reject_fact_mutation();
CREATE TRIGGER secrets_no_delete BEFORE DELETE ON agp_v2.secret_versions
  FOR EACH ROW EXECUTE FUNCTION agp_v2.reject_fact_mutation();
CREATE FUNCTION agp_v2.guard_profile_child_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE parent_state text;
BEGIN
  SELECT state INTO parent_state FROM agp_v2.policy_profile_versions
    WHERE id = NEW.profile_version_id FOR SHARE;
  IF parent_state IS DISTINCT FROM 'draft' THEN
    RAISE EXCEPTION 'profile children can only be inserted into draft version';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER draft_profile_groups BEFORE INSERT ON agp_v2.profile_override_groups
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_profile_child_insert();
CREATE TRIGGER draft_profile_cidrs BEFORE INSERT ON agp_v2.profile_override_cidrs
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_profile_child_insert();
CREATE FUNCTION agp_v2.guard_waf_child_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE parent_state text;
BEGIN
  SELECT state INTO parent_state FROM agp_v2.waf_policy_revisions
    WHERE id = NEW.policy_revision_id FOR SHARE;
  IF parent_state IS DISTINCT FROM 'draft' THEN
    RAISE EXCEPTION 'WAF policy children can only be inserted into draft version';
  END IF;
  RETURN NEW;
END;
$$;
CREATE FUNCTION agp_v2.guard_waf_lineage_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE parent_state text;
BEGIN
  SELECT state INTO parent_state FROM agp_v2.waf_policy_revisions
    WHERE id = NEW.derived_policy_revision_id FOR SHARE;
  IF parent_state IS DISTINCT FROM 'draft' THEN
    RAISE EXCEPTION 'lineage must be sealed with draft derived policy, before validation';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER draft_waf_lineage BEFORE INSERT ON agp_v2.waf_policy_lineage
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_waf_lineage_insert();
CREATE TRIGGER draft_waf_exceptions BEFORE INSERT ON agp_v2.waf_policy_revision_exceptions
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_waf_child_insert();
CREATE TRIGGER draft_waf_exception_rules BEFORE INSERT ON agp_v2.waf_policy_revision_exception_rules
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_waf_child_insert();
CREATE FUNCTION agp_v2.guard_bundle_child_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE artifact_state text;
BEGIN
  SELECT state INTO artifact_state FROM agp_v2.artifacts
    WHERE digest = NEW.bundle_digest FOR SHARE;
  IF artifact_state IS DISTINCT FROM 'staged' THEN
    RAISE EXCEPTION 'effective policy rows must be inserted before bundle verification';
  END IF;
  RETURN NEW;
END;
$$;
DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY['effective_route_policies','effective_policy_groups','effective_policy_cidrs','effective_policy_provenance'] LOOP
    EXECUTE format('CREATE TRIGGER staging_policy_insert BEFORE INSERT ON agp_v2.%I FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_bundle_child_insert()', table_name);
  END LOOP;
END;
$$;
CREATE FUNCTION agp_v2.guard_revision_child_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE parent_state text;
BEGIN
  SELECT state INTO parent_state FROM agp_v2.config_revisions
    WHERE id = NEW.revision_id FOR SHARE;
  IF parent_state IS DISTINCT FROM 'draft' THEN
    RAISE EXCEPTION 'versioned config children can only be inserted into draft revision';
  END IF;
  RETURN NEW;
END;
$$;
CREATE FUNCTION agp_v2.guard_plan_child_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE parent_state text;
BEGIN
  SELECT state INTO parent_state FROM agp_v2.deployment_plans
    WHERE id = NEW.plan_id FOR SHARE;
  IF parent_state IS DISTINCT FROM 'draft' THEN
    RAISE EXCEPTION 'plan targets can only be inserted into draft plan';
  END IF;
  RETURN NEW;
END;
$$;
DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'access_policies','policy_groups','policy_cidrs','waf_policies',
    'gateways','gateway_nodes','routes','waf_exceptions','waf_exception_rules','profile_assignments',
    'gateway_labels','config_waf_zones','waf_zone_assignments'
  ] LOOP
    EXECUTE format('CREATE TRIGGER draft_child_insert BEFORE INSERT ON agp_v2.%I FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_revision_child_insert()', table_name);
  END LOOP;
  FOREACH table_name IN ARRAY ARRAY['plan_targets','plan_target_secrets'] LOOP
    EXECUTE format('CREATE TRIGGER draft_child_insert BEFORE INSERT ON agp_v2.%I FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_plan_child_insert()', table_name);
  END LOOP;
END;
$$;
DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'role_definitions','role_definition_permissions','role_definition_scopes','role_binding_revocations',
    'capability_snapshots','access_policies','policy_groups','policy_cidrs',
    'waf_policies','gateways','gateway_nodes','routes','waf_exceptions','waf_exception_rules','profile_assignments',
    'validation_reports','release_manifests','release_artifacts','compiled_bundles',
    'plan_targets','plan_target_secrets','approvals','task_receipts','security_operation_approvals',
    'identity_provider_versions','identity_provider_clients','external_identity_versions','node_baselines',
    'profile_override_groups','profile_override_cidrs','effective_route_policies',
    'effective_policy_groups','effective_policy_cidrs','effective_policy_provenance',
    'waf_policy_revision_exceptions','waf_policy_revision_exception_rules','policy_revision_approvals',
    'gateway_labels','waf_zone_selector_labels','waf_zone_explicit_gateways',
    'waf_zone_resolutions','waf_zone_resolution_members','waf_zone_resolution_routes',
    'waf_zone_resolution_nodes','waf_zone_resolution_conflicts',
    'config_waf_zones','waf_zone_assignments','waf_policy_lineage'
  ] LOOP
    EXECUTE format('CREATE TRIGGER immutable_fact BEFORE UPDATE OR DELETE ON agp_v2.%I FOR EACH ROW EXECUTE FUNCTION agp_v2.reject_fact_mutation()', table_name);
  END LOOP;
END;
$$;
CREATE FUNCTION agp_v2.guard_role_definition_child_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE parent_tx xid8;
BEGIN
  SELECT creation_tx INTO parent_tx FROM agp_v2.role_definitions
    WHERE role_digest = NEW.role_digest FOR SHARE;
  IF parent_tx IS DISTINCT FROM pg_current_xact_id() THEN
    RAISE EXCEPTION 'role definition children must be sealed in the creating transaction';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER role_permissions_seal BEFORE INSERT ON agp_v2.role_definition_permissions
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_role_definition_child_insert();
CREATE TRIGGER role_scopes_seal BEFORE INSERT ON agp_v2.role_definition_scopes
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_role_definition_child_insert();
CREATE FUNCTION agp_v2.guard_role_binding_transition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (to_jsonb(NEW) - ARRAY['revoked_at','row_version']) IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['revoked_at','row_version']) OR
     OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL OR
     NEW.row_version <> OLD.row_version + 1 THEN
    RAISE EXCEPTION 'immutable role binding incarnation except one terminal revocation';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER role_binding_transition BEFORE UPDATE ON agp_v2.role_bindings
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_role_binding_transition();
CREATE TRIGGER role_binding_no_delete BEFORE DELETE ON agp_v2.role_bindings
  FOR EACH ROW EXECUTE FUNCTION agp_v2.reject_fact_mutation();
CREATE TRIGGER identity_token_keys_immutable BEFORE UPDATE OF
  id,principal_id,purpose,proof_kind,allowed_action,token_hash,security_guard_id,
  security_guard_version,issued_authority_epoch,principal_security_version,
  password_version,policy_digest,issued_by,issuer_fingerprint,contact_id,
  contact_authenticator_version,generation,expires_at,created_at,authorization_operation_id
  ON agp_v2.invitations FOR EACH ROW EXECUTE FUNCTION agp_v2.reject_fact_mutation();
CREATE FUNCTION agp_v2.guard_identity_token_transition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    IF OLD.consumed_at IS NULL AND OLD.revoked_at IS NULL THEN
      RAISE EXCEPTION 'live_identity_token';
    END IF;
    RETURN OLD;
  END IF;
  IF OLD.reserved_at IS NOT NULL AND
    ROW(NEW.reserved_flow_id,NEW.reserved_binding_hash,NEW.reserved_at) IS DISTINCT FROM
    ROW(OLD.reserved_flow_id,OLD.reserved_binding_hash,OLD.reserved_at) THEN
    RAISE EXCEPTION 'irreversible_identity_reservation';
  END IF;
  IF (OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at) OR
    (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) THEN
    RAISE EXCEPTION 'irreversible_identity_token';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER identity_token_terminal BEFORE UPDATE OR DELETE ON agp_v2.invitations
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_identity_token_transition();
CREATE FUNCTION agp_v2.guard_node_highwater() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.high_writer_epoch < OLD.high_writer_epoch OR
     NEW.high_deployment_sequence < OLD.high_deployment_sequence OR
     NEW.allocated_deployment_sequence < OLD.allocated_deployment_sequence THEN
    RAISE EXCEPTION 'node highwater cannot decrease';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER nodes_highwater_guard BEFORE UPDATE ON agp_v2.nodes
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_node_highwater();
CREATE FUNCTION agp_v2.guard_secret_content() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (to_jsonb(NEW) - ARRAY['revoked_at','wrapped_dek','kek_key_id']) IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['revoked_at','wrapped_dek','kek_key_id']) OR
     (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) THEN
    RAISE EXCEPTION 'secret plaintext version/content and revocation are immutable';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER secret_content_guard BEFORE UPDATE ON agp_v2.secret_versions
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_secret_content();
CREATE FUNCTION agp_v2.guard_authenticator_floor() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.authority_id <> OLD.authority_id OR NEW.principal_id <> OLD.principal_id OR
     NEW.authenticator_id <> OLD.authenticator_id OR NEW.minimum_version < OLD.minimum_version OR
     NEW.journal_sequence < OLD.journal_sequence THEN
    RAISE EXCEPTION 'authenticator floor cannot decrease';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER authenticator_floor_guard BEFORE UPDATE ON agp_v2.authenticator_floors
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_authenticator_floor();
CREATE TRIGGER authenticator_floor_no_delete BEFORE DELETE ON agp_v2.authenticator_floors
  FOR EACH ROW EXECUTE FUNCTION agp_v2.reject_fact_mutation();
-- security_events journal_acked_at is mutable delivery metadata; event fields immutable.
CREATE FUNCTION agp_v2.guard_security_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (to_jsonb(NEW) - 'journal_acked_at') IS DISTINCT FROM
     (to_jsonb(OLD) - 'journal_acked_at') OR
     (OLD.journal_acked_at IS NOT NULL AND NEW.journal_acked_at IS DISTINCT FROM OLD.journal_acked_at) THEN
    RAISE EXCEPTION 'security event content/ack is immutable';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER security_event_content_guard BEFORE UPDATE ON agp_v2.security_events
  FOR EACH ROW EXECUTE FUNCTION agp_v2.guard_security_event();
CREATE TRIGGER security_event_delete_guard BEFORE DELETE ON agp_v2.security_events
  FOR EACH ROW EXECUTE FUNCTION agp_v2.reject_fact_mutation();
CREATE TRIGGER audit_event_mutation_guard BEFORE UPDATE OR DELETE ON agp_v2.audit_events
  FOR EACH ROW EXECUTE FUNCTION agp_v2.reject_fact_mutation();
COMMIT;
