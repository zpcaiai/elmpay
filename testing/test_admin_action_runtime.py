"""Static contract gates for the deployable, durable internal Admin Action API.

These checks deliberately do not claim external human review, provider certification,
PCI/UAT, penetration testing, or production rollout acceptance.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AdminActionRuntimeContractTest(unittest.TestCase):
    def test_edge_only_enqueues_and_queries_owner_routed_commands(self) -> None:
        source = (ROOT / "apps/edge-gateway/src/main/java/com/elmpay/gateway/"
                  "JdbcAdminActionService.java").read_text(encoding="utf-8")
        for marker in (
            "queue.findReceipt(",
            "queue.enqueue(connection, command)",
            "existingCommand(",
            "AdminDomainCommand.computeCommandDigest(",
            "connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE)",
            "fencingToken() != claim.fencingToken()",
            "approval.proposerId().equals(approval.decidedBy())",
        ):
            self.assertIn(marker, source)
        for forbidden in ("UPDATE risk_", "INSERT INTO risk_", "UPDATE refund",
                          "INSERT INTO refund_action_receipt", "UPDATE rollout_execution"):
            self.assertNotIn(forbidden, source)

    def test_queue_serializes_tenant_group_and_fences_recovery(self) -> None:
        source = (ROOT / "libs/domain-events/src/main/java/com/elmpay/admin/"
                  "JdbcAdminDomainCommandQueue.java").read_text(encoding="utf-8")
        for marker in (
            "elmpay_admin_enqueue_command(",
            "elmpay_admin_claim_command(?, ?)",
            "elmpay_admin_complete_command(",
            "elmpay_admin_retry_command(",
            "elmpay_admin_block_command(",
            "elmpay_admin_find_effect_receipt(",
            "elmpay_admin_observe_effect_receipt(",
            "set_config('app.tenant_id'",
            "IdempotencyConflictException",
        ):
            self.assertIn(marker, source)
        for forbidden in ("INSERT INTO admin_domain_command",
                          "UPDATE admin_domain_command",
                          "FROM admin_domain_command_signal"):
            self.assertNotIn(forbidden, source)

        hardening = (ROOT / "apps/edge-gateway/src/main/resources/db/migration/"
                     "V103__admin_queue_runtime_role_hardening.sql").read_text(
                         encoding="utf-8")
        for marker in ("FOR UPDATE SKIP LOCKED LIMIT 1", "active.state = 'CLAIMED'",
                       "consumer_fencing_token = command.consumer_fencing_token + 1",
                       "STALE_LEASE", "attempts >= 8", "session_user",
                       "ALTER TABLE admin_domain_command_signal FORCE ROW LEVEL SECURITY",
                       "elmpay.admin-command-db-api.v1",
                       "edge-exact-envelope-receipt-observe"):
            self.assertIn(marker, hardening)
        self.assertNotIn("current_setting('elmpay.tenant_id'", hardening)

    def test_payment_and_rollout_owners_commit_effect_outbox_and_receipt(self) -> None:
        payment = (ROOT / "services/payment-core/src/main/java/com/elmpay/payment/admin/"
                   "PaymentAdminDomainCommandConsumer.java").read_text(encoding="utf-8")
        rollout = (ROOT / "services/worker-scheduler/src/main/java/com/elmpay/scheduler/admin/"
                   "RolloutAdminDomainCommandConsumer.java").read_text(encoding="utf-8")
        for source, mutation in ((payment, "UPDATE refund"),
                                 (rollout, "elmpay_apply_admin_rollout_approval")):
            self.assertIn(mutation, source)
            self.assertIn("SemanticOutboxAppender.append", source)
            self.assertIn("queue.complete(connection, claim", source)
            self.assertLess(source.index(mutation), source.index("queue.complete(connection, claim"))
            self.assertLess(source.index("queue.complete(connection, claim"),
                            source.index("connection.commit()", source.index("queue.complete")))
            self.assertNotIn("HttpClient", source)
        self.assertIn("REFUND_SEPARATION_OF_DUTIES_INVALID", payment)
        self.assertIn("proposalDigest(command.tenantId()", rollout)
        for source in (payment, rollout):
            self.assertIn("AdminActionPolicyBinding", source)
            self.assertIn("policy.validate(command", source)

        edge_runtime = (ROOT / "apps/edge-gateway/src/main/java/com/elmpay/gateway/"
                        "PaymentAdminCommandRuntime.java").read_text(encoding="utf-8")
        worker_runtime = (ROOT / "services/worker-scheduler/src/main/java/com/elmpay/scheduler/"
                          "WorkerSchedulerRuntime.java").read_text(encoding="utf-8")
        self.assertIn("PaymentAdminCommandSchemaVerifier", edge_runtime)
        self.assertIn("RolloutAdminDomainCommandConsumer", worker_runtime)
        self.assertIn("WorkerAdminCommandSchemaVerifier", worker_runtime)

    def test_admin_web_sends_fence_and_tenant_scoped_unknown_recovery(self) -> None:
        dispatcher = (ROOT / "apps/admin-web/src/action-dispatcher.mjs").read_text(
            encoding="utf-8")
        upstream = (ROOT / "apps/admin-web/src/upstream-client.mjs").read_text(
            encoding="utf-8")
        for marker in ("projectId: claim.projectId", "operationCode: claim.operationCode",
                       "workerId: claim.workerId", "fencingToken: Number(claim.fencingToken)",
                       "leaseUntil: claim.leaseUntil", "queryActionReceipt(action)",
                       "claim.outcomeUnknown === true"):
            self.assertIn(marker, dispatcher)
        self.assertGreaterEqual(upstream.count('"x-elmpay-tenant-id": envelope.tenantId'), 2)
        self.assertIn("result.status === 202", upstream)
        self.assertIn("throw new DispatchOutcomeUnknownError()", upstream)
        store = (ROOT / "apps/admin-web/src/postgres-store.mjs").read_text(
            encoding="utf-8")
        self.assertIn("dispatch_candidate.previous_state = 'DISPATCHING'", store)
        self.assertIn("receipt_poll_attempts", store)
        self.assertNotIn(
            "d.state IN ('PENDING','RETRY','DISPATCHING') AND NOT d.outcome_unknown",
            store,
        )

    def test_owner_least_privilege_and_event_allowlist_are_explicit(self) -> None:
        edge_verifier = (ROOT / "apps/edge-gateway/src/main/java/com/elmpay/gateway/"
                         "PaymentAdminCommandSchemaVerifier.java").read_text(encoding="utf-8")
        worker_verifier = (ROOT / "services/worker-scheduler/src/main/java/com/elmpay/scheduler/admin/"
                           "WorkerAdminCommandSchemaVerifier.java").read_text(encoding="utf-8")
        for table in ("rollout_execution", "risk_runtime_operation_request"):
            self.assertIn(table, edge_verifier)
        for table in ("refund", "refund_action_receipt", "risk_runtime_operation_request"):
            self.assertIn(table, worker_verifier)
        for verifier in (edge_verifier, worker_verifier):
            self.assertIn("has_any_column_privilege", verifier)
            self.assertIn("MAINTAIN", verifier)
            self.assertIn("requireNoWritableView", verifier)
            self.assertIn("elmpay_admin_claim_command", verifier)
        ledger = (ROOT / "services/worker-scheduler/src/main/java/com/elmpay/scheduler/"
                  "LedgerPostingConsumer.java").read_text(encoding="utf-8")
        for event in ("refund.approved.v1", "risk.admin_operation.applied.v1",
                      "rollout.approval_recorded.v1"):
            self.assertIn(event, ledger)

    def test_worker_environment_schema_matches_kubernetes_admin_configuration(self) -> None:
        schema = json.loads((ROOT / "services/worker-scheduler/"
                             "worker-scheduler.env.schema.json").read_text(encoding="utf-8"))
        policy = json.loads((ROOT / "platform/kubernetes/workload-policy.json").read_text(
            encoding="utf-8"))
        worker = next(service for service in policy["services"]
                      if service["name"] == "worker-scheduler")
        required = {
            "ELMPAY_ADMIN_ACTION_POLICY_BINDING_FILE",
            "ELMPAY_ADMIN_COMMAND_MAX_PER_CYCLE",
            "ELMPAY_ADMIN_COMMAND_LEASE_TTL",
        }
        self.assertTrue(required.issubset(schema["required"]))
        self.assertTrue(required.issubset(schema["properties"]))
        configured = set(worker["fixedEnvironment"]) | set(
            worker["configuration"]["configMapData"])
        self.assertTrue(required.issubset(configured))

    def test_kubernetes_exposes_only_existing_edge_workload_and_exact_peer(self) -> None:
        policy = json.loads((ROOT / "platform/kubernetes/workload-policy.json").read_text(
            encoding="utf-8"))
        services = {service["name"]: service for service in policy["services"]}
        edge = services["edge-gateway"]
        self.assertEqual("true", edge["fixedEnvironment"]["ELMPAY_ADMIN_ACTIONS_ENABLED"])
        self.assertEqual("spiffe://elmpay.example/admin-web",
                         edge["fixedEnvironment"]["ELMPAY_ADMIN_ACTION_EXPECTED_SPIFFE_ID"])
        callers = json.loads((ROOT / "platform/kubernetes/service-callers.json").read_text(
            encoding="utf-8"))
        self.assertIn("admin-web", callers["edge-gateway"])
        egress = json.loads((ROOT / "platform/kubernetes/egress-policy.json").read_text(
            encoding="utf-8"))
        self.assertIn("edge-gateway-internal", egress["workloads"]["admin-web"])


if __name__ == "__main__":
    unittest.main()
