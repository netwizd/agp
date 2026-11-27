-- Actual privileged execution, separate from planning-only authoring reviews.
CREATE TABLE execution_plans (
 id TEXT PRIMARY KEY, plan_digest TEXT NOT NULL UNIQUE, plan_json TEXT NOT NULL CHECK(length(CAST(plan_json AS BLOB))<=2097152),
 snapshot_json TEXT NOT NULL CHECK(length(CAST(snapshot_json AS BLOB))<=4194304),
 creator_fingerprint TEXT NOT NULL, parent_plan_id TEXT NULL REFERENCES execution_plans(id),
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0), created_at TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('validated','approved','running','succeeded','failed','cancelled','recovery_required'))
);
CREATE TABLE execution_approvals (
 id TEXT PRIMARY KEY, plan_id TEXT NOT NULL UNIQUE REFERENCES execution_plans(id), approval_digest TEXT NOT NULL UNIQUE,
 approval_json TEXT NOT NULL CHECK(length(CAST(approval_json AS BLOB))<=65536), participants_json TEXT NOT NULL CHECK(length(CAST(participants_json AS BLOB))<=131072),
 approver_fingerprint TEXT NOT NULL, created_at TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL
);
CREATE TABLE execution_rollouts (
 plan_id TEXT PRIMARY KEY REFERENCES execution_plans(id), dispatcher_id TEXT NOT NULL, dispatcher_fingerprint TEXT NOT NULL,
 dispatcher_token_hash TEXT NOT NULL, permission TEXT NOT NULL CHECK(permission IN ('rollouts.create','rollouts.rollback')), created_at TIMESTAMP NOT NULL
);
CREATE TABLE execution_node_counters (
 node_id TEXT PRIMARY KEY, allocated_sequence BIGINT NOT NULL CHECK(allocated_sequence>=0),
 accepted_sequence BIGINT NOT NULL CHECK(accepted_sequence>=0 AND accepted_sequence<=allocated_sequence),
 receipt_sequence BIGINT NOT NULL DEFAULT 0 CHECK(receipt_sequence>=0)
);
CREATE TABLE execution_tasks (
 id TEXT PRIMARY KEY, plan_id TEXT NOT NULL REFERENCES execution_plans(id), node_id TEXT NOT NULL,
 sequence BIGINT NOT NULL CHECK(sequence>0), request_digest TEXT NOT NULL UNIQUE,
 request_json TEXT NOT NULL CHECK(length(CAST(request_json AS BLOB))<=2162688),
 target_json TEXT NOT NULL CHECK(length(CAST(target_json AS BLOB))<=65536),
 state TEXT NOT NULL CHECK(state IN ('dispatched','succeeded','failed','recovered','recovery_required')),
 issued_at TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL, completed_at TIMESTAMP NULL,
 UNIQUE(node_id,sequence), UNIQUE(plan_id,node_id)
);
CREATE UNIQUE INDEX execution_one_active_node ON execution_tasks(node_id) WHERE state IN ('dispatched','recovery_required');
CREATE TABLE execution_receipts (
 receipt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL UNIQUE REFERENCES execution_tasks(id), node_id TEXT NOT NULL,
 receipt_sequence BIGINT NOT NULL CHECK(receipt_sequence>0), receipt_digest TEXT NOT NULL,
 receipt_json TEXT NOT NULL CHECK(length(CAST(receipt_json AS BLOB))<=65536), received_at TIMESTAMP NOT NULL,
 UNIQUE(node_id,receipt_sequence)
);
CREATE TABLE execution_requests (
 actor_id TEXT NOT NULL, operation TEXT NOT NULL, request_key TEXT NOT NULL, fingerprint TEXT NOT NULL,
 result_id TEXT NOT NULL, created_at TIMESTAMP NOT NULL, PRIMARY KEY(actor_id,operation,request_key)
);
CREATE TRIGGER execution_plans_immutable BEFORE UPDATE ON execution_plans WHEN NEW.id<>OLD.id OR NEW.plan_digest<>OLD.plan_digest OR NEW.plan_json<>OLD.plan_json OR NEW.snapshot_json<>OLD.snapshot_json OR NEW.creator_fingerprint<>OLD.creator_fingerprint OR NEW.parent_plan_id IS NOT OLD.parent_plan_id OR NEW.authority_epoch<>OLD.authority_epoch OR NEW.created_at<>OLD.created_at OR NEW.expires_at<>OLD.expires_at BEGIN SELECT RAISE(ABORT,'immutable_execution_plan'); END;
CREATE TRIGGER execution_plans_no_delete BEFORE DELETE ON execution_plans BEGIN SELECT RAISE(ABORT,'immutable_execution_plan'); END;
CREATE TRIGGER execution_approvals_no_update BEFORE UPDATE ON execution_approvals BEGIN SELECT RAISE(ABORT,'immutable_execution_approval'); END;
CREATE TRIGGER execution_approvals_no_delete BEFORE DELETE ON execution_approvals BEGIN SELECT RAISE(ABORT,'immutable_execution_approval'); END;
CREATE TRIGGER execution_rollouts_no_update BEFORE UPDATE ON execution_rollouts BEGIN SELECT RAISE(ABORT,'immutable_execution_rollout'); END;
CREATE TRIGGER execution_rollouts_no_delete BEFORE DELETE ON execution_rollouts BEGIN SELECT RAISE(ABORT,'immutable_execution_rollout'); END;
CREATE TRIGGER execution_counters_monotonic BEFORE UPDATE ON execution_node_counters WHEN NEW.node_id<>OLD.node_id OR NEW.allocated_sequence<OLD.allocated_sequence OR NEW.accepted_sequence<OLD.accepted_sequence OR NEW.receipt_sequence<OLD.receipt_sequence BEGIN SELECT RAISE(ABORT,'execution_counter_rollback'); END;
CREATE TRIGGER execution_counters_no_delete BEFORE DELETE ON execution_node_counters BEGIN SELECT RAISE(ABORT,'execution_counter_rollback'); END;
CREATE TRIGGER execution_tasks_immutable BEFORE UPDATE ON execution_tasks WHEN NEW.id<>OLD.id OR NEW.plan_id<>OLD.plan_id OR NEW.node_id<>OLD.node_id OR NEW.sequence<>OLD.sequence OR NEW.request_digest<>OLD.request_digest OR NEW.request_json<>OLD.request_json OR NEW.target_json<>OLD.target_json OR NEW.issued_at<>OLD.issued_at OR NEW.expires_at<>OLD.expires_at OR OLD.state<>'dispatched' BEGIN SELECT RAISE(ABORT,'immutable_execution_task'); END;
CREATE TRIGGER execution_tasks_no_delete BEFORE DELETE ON execution_tasks BEGIN SELECT RAISE(ABORT,'immutable_execution_task'); END;
CREATE TRIGGER execution_receipts_no_update BEFORE UPDATE ON execution_receipts BEGIN SELECT RAISE(ABORT,'immutable_execution_receipt'); END;
CREATE TRIGGER execution_receipts_no_delete BEFORE DELETE ON execution_receipts BEGIN SELECT RAISE(ABORT,'immutable_execution_receipt'); END;
CREATE TRIGGER execution_requests_no_update BEFORE UPDATE ON execution_requests BEGIN SELECT RAISE(ABORT,'immutable_execution_request'); END;
CREATE TRIGGER execution_requests_no_delete BEFORE DELETE ON execution_requests BEGIN SELECT RAISE(ABORT,'immutable_execution_request'); END;
