-- Actual privileged execution, separate from planning-only authoring reviews.
CREATE TABLE execution_plans (
 id TEXT PRIMARY KEY, plan_digest TEXT NOT NULL UNIQUE, plan_json TEXT NOT NULL CHECK(octet_length(CAST(plan_json AS TEXT))<=2097152),
 snapshot_json TEXT NOT NULL CHECK(octet_length(CAST(snapshot_json AS TEXT))<=4194304),
 creator_fingerprint TEXT NOT NULL, parent_plan_id TEXT NULL REFERENCES execution_plans(id),
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0), created_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('validated','approved','running','succeeded','failed','cancelled','recovery_required'))
);
CREATE TABLE execution_approvals (
 id TEXT PRIMARY KEY, plan_id TEXT NOT NULL UNIQUE REFERENCES execution_plans(id), approval_digest TEXT NOT NULL UNIQUE,
 approval_json TEXT NOT NULL CHECK(octet_length(CAST(approval_json AS TEXT))<=65536), participants_json TEXT NOT NULL CHECK(octet_length(CAST(participants_json AS TEXT))<=131072),
 approver_fingerprint TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE execution_rollouts (
 plan_id TEXT PRIMARY KEY REFERENCES execution_plans(id), dispatcher_id TEXT NOT NULL, dispatcher_fingerprint TEXT NOT NULL,
 dispatcher_token_hash TEXT NOT NULL, permission TEXT NOT NULL CHECK(permission IN ('rollouts.create','rollouts.rollback')), created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE execution_node_counters (
 node_id TEXT PRIMARY KEY, allocated_sequence BIGINT NOT NULL CHECK(allocated_sequence>=0),
 accepted_sequence BIGINT NOT NULL CHECK(accepted_sequence>=0 AND accepted_sequence<=allocated_sequence),
 receipt_sequence BIGINT NOT NULL DEFAULT 0 CHECK(receipt_sequence>=0)
);
CREATE TABLE execution_tasks (
 id TEXT PRIMARY KEY, plan_id TEXT NOT NULL REFERENCES execution_plans(id), node_id TEXT NOT NULL,
 sequence BIGINT NOT NULL CHECK(sequence>0), request_digest TEXT NOT NULL UNIQUE,
 request_json TEXT NOT NULL CHECK(octet_length(CAST(request_json AS TEXT))<=2162688),
 target_json TEXT NOT NULL CHECK(octet_length(CAST(target_json AS TEXT))<=65536),
 state TEXT NOT NULL CHECK(state IN ('dispatched','succeeded','failed','recovered','recovery_required')),
 issued_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL, completed_at TIMESTAMPTZ NULL,
 UNIQUE(node_id,sequence), UNIQUE(plan_id,node_id)
);
CREATE UNIQUE INDEX execution_one_active_node ON execution_tasks(node_id) WHERE state IN ('dispatched','recovery_required');
CREATE TABLE execution_receipts (
 receipt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL UNIQUE REFERENCES execution_tasks(id), node_id TEXT NOT NULL,
 receipt_sequence BIGINT NOT NULL CHECK(receipt_sequence>0), receipt_digest TEXT NOT NULL,
 receipt_json TEXT NOT NULL CHECK(octet_length(CAST(receipt_json AS TEXT))<=65536), received_at TIMESTAMPTZ NOT NULL,
 UNIQUE(node_id,receipt_sequence)
);
CREATE TABLE execution_requests (
 actor_id TEXT NOT NULL, operation TEXT NOT NULL, request_key TEXT NOT NULL, fingerprint TEXT NOT NULL,
 result_id TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, PRIMARY KEY(actor_id,operation,request_key)
);
CREATE FUNCTION agp_execution_plan_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='DELETE' OR (to_jsonb(NEW)-'state')<>(to_jsonb(OLD)-'state') THEN RAISE EXCEPTION 'immutable_execution_plan'; END IF; RETURN NEW; END $$;
CREATE TRIGGER execution_plans_immutable BEFORE UPDATE OR DELETE ON execution_plans FOR EACH ROW EXECUTE FUNCTION agp_execution_plan_immutable();
CREATE FUNCTION agp_execution_counter_monotonic() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'execution_counter_rollback'; END IF;
 IF NEW.node_id<>OLD.node_id OR NEW.allocated_sequence<OLD.allocated_sequence OR NEW.accepted_sequence<OLD.accepted_sequence OR NEW.receipt_sequence<OLD.receipt_sequence THEN RAISE EXCEPTION 'execution_counter_rollback'; END IF; RETURN NEW; END $$;
CREATE TRIGGER execution_counters_monotonic BEFORE UPDATE OR DELETE ON execution_node_counters FOR EACH ROW EXECUTE FUNCTION agp_execution_counter_monotonic();
CREATE FUNCTION agp_execution_task_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='DELETE' OR OLD.state<>'dispatched' OR (to_jsonb(NEW)-'state'-'completed_at')<>(to_jsonb(OLD)-'state'-'completed_at') THEN RAISE EXCEPTION 'immutable_execution_task'; END IF; RETURN NEW; END $$;
CREATE TRIGGER execution_tasks_immutable BEFORE UPDATE OR DELETE ON execution_tasks FOR EACH ROW EXECUTE FUNCTION agp_execution_task_immutable();
CREATE TRIGGER execution_approvals_immutable BEFORE UPDATE OR DELETE ON execution_approvals FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER execution_rollouts_immutable BEFORE UPDATE OR DELETE ON execution_rollouts FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER execution_receipts_immutable BEFORE UPDATE OR DELETE ON execution_receipts FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
CREATE TRIGGER execution_requests_immutable BEFORE UPDATE OR DELETE ON execution_requests FOR EACH ROW EXECUTE FUNCTION agp_config_immutable();
