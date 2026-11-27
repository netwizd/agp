-- Proposed reference ONLY: run in a DIFFERENT disposable PostgreSQL 17+ database.
-- Production security journal needs its OWN PostgreSQL cluster, account, storage,
-- credentials, backup/restore domain and independent service PKI; preferably a dedicated VM.
-- This is NOT another schema to add to the Control Plane database.
-- No plaintext authenticators, PKI private keys or grants are stored in events.
BEGIN;
CREATE SCHEMA agp_security_journal;
CREATE DOMAIN agp_security_journal.object_id AS text
  CHECK (VALUE ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$');
CREATE DOMAIN agp_security_journal.digest AS text
  CHECK (VALUE ~ '^sha256:[0-9a-f]{64}$');
CREATE DOMAIN agp_security_journal.uint63 AS bigint CHECK (VALUE >= 0);

CREATE TABLE agp_security_journal.authorities (
  id agp_security_journal.object_id PRIMARY KEY,
  authority_epoch agp_security_journal.uint63 NOT NULL CHECK (authority_epoch > 0),
  head_sequence agp_security_journal.uint63 NOT NULL DEFAULT 0,
  head_digest agp_security_journal.digest,
  row_version agp_security_journal.uint63 NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((head_sequence = 0) = (head_digest IS NULL))
);
CREATE TABLE agp_security_journal.operations (
  id agp_security_journal.object_id PRIMARY KEY,
  authority_id agp_security_journal.object_id NOT NULL REFERENCES agp_security_journal.authorities(id),
  request_digest agp_security_journal.digest NOT NULL,
  expected_authority_epoch agp_security_journal.uint63 NOT NULL CHECK (expected_authority_epoch > 0),
  expected_head_sequence agp_security_journal.uint63 NOT NULL,
  actor_id agp_security_journal.object_id NOT NULL,
  authorization_digest agp_security_journal.digest NOT NULL,
  accepted_at timestamptz NOT NULL DEFAULT now()
);
-- actor_id is historical: replay never recreates a principal or gives it permission.
CREATE TABLE agp_security_journal.events (
  id agp_security_journal.object_id NOT NULL UNIQUE,
  authority_id agp_security_journal.object_id NOT NULL REFERENCES agp_security_journal.authorities(id),
  sequence agp_security_journal.uint63 NOT NULL CHECK (sequence > 0),
  authority_epoch agp_security_journal.uint63 NOT NULL CHECK (authority_epoch > 0),
  operation_id agp_security_journal.object_id NOT NULL UNIQUE REFERENCES agp_security_journal.operations(id),
  kind text NOT NULL CHECK (kind IN (
    'block_principal','unblock_principal','revoke_session','revoke_node',
    'disable_resource','enable_resource','revoke_secret','raise_security_floor',
    'remove_membership','deny_route','clear_route_deny','revoke_role_binding',
    'bump_authenticator_floor','advance_authority_epoch'
  )),
  payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object' AND octet_length(payload_json::text) <= 262144),
  payload_digest agp_security_journal.digest NOT NULL,
  previous_digest agp_security_journal.digest,
  event_digest agp_security_journal.digest NOT NULL UNIQUE,
  signing_key_id agp_security_journal.object_id NOT NULL,
  receipt_signature bytea NOT NULL CHECK (octet_length(receipt_signature) = 64),
  accepted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (authority_id, sequence)
);
CREATE INDEX events_epoch_sequence_idx ON agp_security_journal.events(authority_id, authority_epoch, sequence);
CREATE TABLE agp_security_journal.authenticator_floors (
  authority_id agp_security_journal.object_id NOT NULL REFERENCES agp_security_journal.authorities(id),
  principal_id agp_security_journal.object_id NOT NULL,
  authenticator_id agp_security_journal.object_id NOT NULL,
  minimum_version agp_security_journal.uint63 NOT NULL CHECK (minimum_version > 0),
  source_sequence agp_security_journal.uint63 NOT NULL CHECK (source_sequence > 0),
  PRIMARY KEY (authority_id, principal_id, authenticator_id),
  FOREIGN KEY (authority_id, source_sequence) REFERENCES agp_security_journal.events(authority_id, sequence)
);

CREATE FUNCTION agp_security_journal.reject_fact_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'journal facts are append-only';
END;
$$;
CREATE TRIGGER operations_append_only BEFORE UPDATE OR DELETE ON agp_security_journal.operations
  FOR EACH ROW EXECUTE FUNCTION agp_security_journal.reject_fact_mutation();
CREATE TRIGGER events_append_only BEFORE UPDATE OR DELETE ON agp_security_journal.events
  FOR EACH ROW EXECUTE FUNCTION agp_security_journal.reject_fact_mutation();
CREATE FUNCTION agp_security_journal.guard_authority() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.id <> OLD.id OR NEW.authority_epoch < OLD.authority_epoch OR
     NEW.head_sequence < OLD.head_sequence OR NEW.row_version <> OLD.row_version + 1 THEN
    RAISE EXCEPTION 'journal authority/head/version cannot decrease or be renamed';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER authority_highwater BEFORE UPDATE ON agp_security_journal.authorities
  FOR EACH ROW EXECUTE FUNCTION agp_security_journal.guard_authority();
CREATE FUNCTION agp_security_journal.guard_floor() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.authority_id <> OLD.authority_id OR NEW.principal_id <> OLD.principal_id OR
     NEW.authenticator_id <> OLD.authenticator_id OR NEW.minimum_version < OLD.minimum_version OR
     NEW.source_sequence < OLD.source_sequence THEN
    RAISE EXCEPTION 'authenticator floor cannot decrease or change identity';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER floor_highwater BEFORE UPDATE ON agp_security_journal.authenticator_floors
  FOR EACH ROW EXECUTE FUNCTION agp_security_journal.guard_floor();
CREATE TRIGGER floor_no_delete BEFORE DELETE ON agp_security_journal.authenticator_floors
  FOR EACH ROW EXECUTE FUNCTION agp_security_journal.reject_fact_mutation();
COMMIT;

-- Required Go service transaction, NOT implemented by this DDL:
-- 1 Authenticate independent CP service identity and verify typed authorization/2nd approval.
-- 2 If operation_id exists, compare request digest and return SAME persisted signed receipt;
--   return idempotency conflict for a different request. Do not allocate a new sequence.
-- 3 SELECT authority FOR UPDATE; verify expected epoch/head and valid schema/typed subject.
-- 4 Allocate head_sequence+1 (no reset on epoch advance); compute/sign canonical chained event.
-- 5 Insert operation+event; materialize floor for bump_authenticator_floor; update head/CAS.
--   advance_authority_epoch increments epoch under supervised authorization BEFORE CP unblocks.
-- 6 COMMIT with required synchronous durability, then return receipt. Crash/timeout -> GetByOperationId.
--   No receipt is returned from uncommitted state. No external I/O under this row lock except
--   bounded local signing; external signer failure aborts the whole transaction.
-- SQL checks do NOT verify signatures, authorization, schema payload union, head adjacency,
-- floor/event payload equality or physical storage/backup separation: service+deployment tests do.
-- Owner/superuser can bypass triggers: restricted grants plus independently retained signed
-- checkpoints/replicas are necessary. Rollback of BOTH CP and journal VM snapshots is unsafe.
