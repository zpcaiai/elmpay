from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import json
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.infrastructure import (  # noqa: E402
    SQLiteFencingStore,
    evaluate_region_promotion,
    evaluate_restore_exercise,
    render_regional_data_plane,
    render_service_controls,
)
from elmpay_runtime.attestation import attach_dsse, generate_ed25519_keypair  # noqa: E402
from elmpay_runtime.common import sha256_json  # noqa: E402
from elmpay_runtime.downstream_receipt import receipt_binding  # noqa: E402


NOW = datetime(2026, 8, 28, tzinfo=timezone.utc)


class InfrastructureControlTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = json.loads((ROOT / "platform/kubernetes/workload-policy.json").read_text())
        self.names = [item["name"] for item in self.policy["services"]]

    def test_every_workload_gets_identity_availability_and_default_deny(self) -> None:
        allowed = json.loads(
            (ROOT / "platform/kubernetes/service-callers.json").read_text(encoding="utf-8")
        )
        bundle = render_service_controls(self.policy, allowed)
        kinds = [item["kind"] for item in bundle["items"]]
        exposed = sum(item.get("exposeService", True) for item in self.policy["services"])
        self.assertEqual(exposed, kinds.count("Service"))
        for kind in ("ServiceAccount", "PodDisruptionBudget", "HorizontalPodAutoscaler",
                     "NetworkPolicy", "AuthorizationPolicy"):
            self.assertEqual(len(self.names) + (1 if kind == "NetworkPolicy" else 0),
                             kinds.count(kind))
        peer = [item for item in bundle["items"] if item["kind"] == "PeerAuthentication"]
        self.assertEqual("STRICT", peer[0]["spec"]["mtls"]["mode"])
        for health_only in ("worker-scheduler", "webhook-processor"):
            workload_service = [item for item in bundle["items"]
                                if item["kind"] == "Service"
                                and item["metadata"]["name"] == health_only]
            self.assertEqual([], workload_service)
            workload_network = next(item for item in bundle["items"]
                                    if item["kind"] == "NetworkPolicy"
                                    and item["metadata"]["name"] == f"allow-{health_only}")
            self.assertEqual([], workload_network["spec"]["ingress"])
            self.assertEqual(1, len(workload_network["spec"]["egress"]))
            self.assertEqual(
                {"k8s-app": "kube-dns"},
                workload_network["spec"]["egress"][0]["to"][0]
                ["podSelector"]["matchLabels"],
            )
            workload_auth = next(item for item in bundle["items"]
                                 if item["kind"] == "AuthorizationPolicy"
                                 and item["metadata"]["name"] == health_only)
            self.assertEqual([], workload_auth["spec"]["rules"])
        services = {item["metadata"]["name"]: item for item in bundle["items"]
                    if item["kind"] == "Service"}
        self.assertEqual(
            [{"name": "https", "port": 8443, "targetPort": "https"}],
            services["edge-gateway"]["spec"]["ports"],
        )
        for service_name in ("admin-web", "risk-engine"):
            self.assertEqual(
                [{"name": "https", "port": 8443, "targetPort": "https"}],
                services[service_name]["spec"]["ports"],
            )
        self.assertNotIn(8081, {
            port["port"] for service in services.values() for port in service["spec"]["ports"]
        })
        self.assertNotIn(9081, {
            port["port"] for service in services.values() for port in service["spec"]["ports"]
        })

    def test_static_bundle_inventory_exactly_matches_runnable_workloads(self) -> None:
        bundle = json.loads(
            (ROOT / "platform/kubernetes/static-bundle.json").read_text(encoding="utf-8")
        )
        callers = json.loads(
            (ROOT / "platform/kubernetes/service-callers.json").read_text(encoding="utf-8")
        )
        rendered = render_service_controls(self.policy, callers)
        controlled_kinds = {
            "ServiceAccount", "Service", "PodDisruptionBudget", "HorizontalPodAutoscaler",
            "NetworkPolicy", "PeerAuthentication", "AuthorizationPolicy",
        }
        rendered_controls = {
            (item["kind"], item["metadata"]["name"]): item
            for item in rendered["items"] if item["kind"] in controlled_kinds
        }
        static_controls = {
            (item["kind"], item["metadata"]["name"]): item
            for item in bundle["items"] if item["kind"] in controlled_kinds
        }
        self.assertEqual(rendered_controls, static_controls)
        expected = set(self.names)
        for kind in (
            "ServiceAccount", "PodDisruptionBudget",
            "HorizontalPodAutoscaler", "AuthorizationPolicy",
        ):
            actual = {
                item["metadata"]["name"] for item in bundle["items"]
                if item["kind"] == kind
            }
            self.assertEqual(expected, actual, kind)
        services = {
            item["metadata"]["name"] for item in bundle["items"]
            if item["kind"] == "Service"
        }
        self.assertEqual(
            {item["name"] for item in self.policy["services"]
             if item.get("exposeService", True)},
            services,
        )
        policies = {
            item["metadata"]["name"] for item in bundle["items"]
            if item["kind"] == "NetworkPolicy"
            and item["metadata"]["name"].startswith("allow-")
        }
        self.assertEqual({f"allow-{name}" for name in expected}, policies)

    def test_mesh_map_must_cover_exactly_all_workloads(self) -> None:
        with self.assertRaises(ValueError):
            render_service_controls(self.policy, {"edge-gateway": []})

        invalid_caller = json.loads(
            (ROOT / "platform/kubernetes/service-callers.json").read_text(encoding="utf-8")
        )
        invalid_caller["edge-gateway"].append("worker-scheduler")
        with self.assertRaises(ValueError):
            render_service_controls(self.policy, invalid_caller)

        self_call = json.loads(
            (ROOT / "platform/kubernetes/service-callers.json").read_text(encoding="utf-8")
        )
        self_call["risk-engine"].append("risk-engine")
        with self.assertRaises(ValueError):
            render_service_controls(self.policy, self_call)

    def test_regional_data_plane_has_ha_durable_encrypted_stores(self) -> None:
        policy = json.loads((ROOT / "platform/kubernetes/data-plane-policy.json").read_text())
        bundle = render_regional_data_plane(policy)
        regions = len(policy["regions"])
        kinds = [item["kind"] for item in bundle["items"]]
        self.assertEqual(regions, kinds.count("Cluster"))
        self.assertEqual(regions, kinds.count("Kafka"))
        self.assertEqual(regions, kinds.count("RedisFailover"))
        for cluster in (item for item in bundle["items"] if item["kind"] == "Cluster"):
            self.assertGreaterEqual(cluster["spec"]["instances"], 3)
            self.assertEqual("on", cluster["spec"]["postgresql"]["parameters"]["synchronous_commit"])
            self.assertEqual("AES256", cluster["spec"]["backup"]["barmanObjectStore"]["wal"]["encryption"])
            managed = cluster["spec"]["managed"]["roles"]
            self.assertEqual(
                ["elmpay_partition_precreator", "elmpay_archive_verifier",
                 "elmpay_partition_detacher"],
                [role["name"] for role in managed],
            )
            for role in managed:
                self.assertTrue(role["login"])
                self.assertFalse(role["inherit"])
                self.assertFalse(role["superuser"])
                self.assertFalse(role["createdb"])
                self.assertFalse(role["createrole"])
                self.assertFalse(role["replication"])
                self.assertFalse(role["bypassrls"])
                self.assertRegex(role["passwordSecret"]["name"], r"^[a-z0-9-]+$")
        for kafka in (item for item in bundle["items"] if item["kind"] == "Kafka"):
            self.assertFalse(kafka["spec"]["kafka"]["config"]["unclean.leader.election.enable"])
            self.assertEqual(2, kafka["spec"]["kafka"]["config"]["min.insync.replicas"])

    def test_lease_expiry_increments_fence_and_stale_holder_cannot_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteFencingStore(str(Path(directory) / "lease.sqlite"))
            first = store.acquire("reconciliation:tenant-a", "worker-a", NOW, timedelta(seconds=5))
            self.assertIsNotNone(first)
            self.assertIsNone(store.acquire("reconciliation:tenant-a", "worker-b", NOW, timedelta(seconds=5)))
            second = store.acquire(
                "reconciliation:tenant-a", "worker-b", NOW + timedelta(seconds=6), timedelta(seconds=5)
            )
            self.assertIsNotNone(second)
            assert first is not None and second is not None
            self.assertGreater(second.fencing_token, first.fencing_token)
            self.assertFalse(store.is_current(first, NOW + timedelta(seconds=6)))
            self.assertTrue(store.is_current(second, NOW + timedelta(seconds=6)))
            store.close()

    def test_restore_and_promotion_fail_closed(self) -> None:
        plan = json.loads((ROOT / "platform/dr/plan.json").read_text())
        digest = hashlib.sha256(b"immutable-backup").hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            roles = {
                "restore": ("restore-a", "dr_restore_verifier", True),
                "controller": ("controller-a", "dr_controller", False),
                "approver-a": ("ops-a", "dr_promotion_approver", True),
                "approver-b": ("security-b", "dr_promotion_approver", True),
            }
            private: dict[str, str] = {}
            keys: dict[str, dict[str, object]] = {}
            for key_id, (identity, role, independent) in roles.items():
                private[key_id], public = generate_ed25519_keypair()
                keys[key_id] = {
                    "algorithm": "Ed25519", "publicKeyPem": public,
                    "identity": identity, "role": role, "independent": independent,
                    "revoked": False, "notBefore": "2026-08-01T00:00:00Z",
                    "notAfter": "2027-01-01T00:00:00Z",
                }
            trust = {"replayDatabase": str(Path(directory) / "receipts.sqlite"), "keys": keys}

            def receipt(key_id: str, receipt_id: str, receipt_type: str,
                        outcome: str, fields: dict[str, object], nonce: str) -> dict[str, object]:
                identity, role, _ = roles[key_id]
                return attach_dsse({
                    "receiptId": receipt_id, "receiptType": receipt_type,
                    "outcome": outcome, "fields": fields, "actor": identity,
                    "role": role, "bindingDigest": receipt_binding(receipt_type, fields),
                    "nonce": nonce, "issuedAt": "2026-08-27T00:00:00Z",
                    "expiresAt": "2026-09-01T00:00:00Z",
                }, key_id, private[key_id])

            restore_facts: dict[str, object] = {
                "backupDigest": digest, "backupImmutable": True,
                "restoreChecksumVerified": True, "ledgerBalanced": True,
                "failbackVerified": True, "measuredRpoSeconds": 30,
                "measuredRtoSeconds": 600, "completedAt": "2026-08-27T00:00:00Z",
            }
            report = {**restore_facts, "receipt": receipt(
                "restore", "restore-receipt-0001", "DR_RESTORE_EXERCISE",
                "VERIFIED", restore_facts, "restore-receipt-nonce-0001",
            )}
            self.assertTrue(evaluate_restore_exercise(plan, report, digest, trust, now=NOW).allowed)
            # A local caller cannot change a signed fact by changing a boolean.
            self.assertFalse(evaluate_restore_exercise(
                plan, {**report, "ledgerBalanced": False}, digest, trust, now=NOW
            ).allowed)

            promotion_facts: dict[str, object] = {
                "targetRegion": "cn-north-1", "fencingToken": 7,
                "replicationLagSeconds": 20, "writeFenceAcquired": True,
                "providerRoutingChecked": True, "rollbackPlanVerified": True,
                "targetRegionHealthy": True, "sourceRegionWritesStopped": True,
                "changedAt": "2026-08-28T00:00:00Z",
            }
            request_digest = sha256_json({"promotion": promotion_facts})
            approval_fields = {
                "requestDigest": request_digest, "targetRegion": "cn-north-1", "fencingToken": 7,
            }
            promotion = {
                **promotion_facts,
                "requestDigest": request_digest,
                "observation": receipt(
                    "controller", "promotion-observation-0001",
                    "REGION_PROMOTION_OBSERVATION", "VERIFIED",
                    {**promotion_facts, "requestDigest": request_digest},
                    "promotion-observe-nonce-0001",
                ),
                "approvals": [
                    receipt("approver-a", "promotion-approval-0001",
                            "REGION_PROMOTION_APPROVAL", "APPROVED", approval_fields,
                            "promotion-approve-nonce-0001"),
                    receipt("approver-b", "promotion-approval-0002",
                            "REGION_PROMOTION_APPROVAL", "APPROVED", approval_fields,
                            "promotion-approve-nonce-0002"),
                ],
            }
            store = SQLiteFencingStore(str(Path(directory) / "fence.sqlite"))
            try:
                self.assertTrue(evaluate_region_promotion(
                    plan, promotion, trust, store, now=NOW
                ).allowed)
                self.assertEqual("cn-north-1", store.current_region()["activeRegion"])
                self.assertEqual(7, store.current_region()["fencingToken"])
                # Exact replay is idempotent; unsigned fact mutation is blocked.
                self.assertTrue(evaluate_region_promotion(
                    plan, promotion, trust, store, now=NOW
                ).allowed)
                self.assertFalse(evaluate_region_promotion(
                    plan, {**promotion, "sourceRegionWritesStopped": False}, trust, store, now=NOW
                ).allowed)
                unknown = evaluate_region_promotion(
                    plan, {**promotion, "targetRegion": "region-unknown"}, trust, store, now=NOW
                )
                self.assertIn("target_region_not_in_inventory", unknown.reasons)
                same_region = evaluate_region_promotion(
                    plan, {**promotion, "fencingToken": 8}, trust, store, now=NOW
                )
                self.assertIn("target_region_already_active", same_region.reasons)
                stale = evaluate_region_promotion(
                    plan, {**promotion, "changedAt": "2026-08-27T23:50:00Z"},
                    trust, store, now=NOW
                )
                self.assertIn("region_promotion_observation_stale", stale.reasons)
            finally:
                store.close()

    def test_dr_region_inventory_matches_rendered_data_plane(self) -> None:
        plan = json.loads((ROOT / "platform/dr/plan.json").read_text())
        data_plane = json.loads(
            (ROOT / "platform/kubernetes/data-plane-policy.json").read_text()
        )
        expected = [region["name"] for region in data_plane["regions"]]
        self.assertEqual(expected, plan["regionInventory"]["allowedRegions"])
        primary = [region["name"] for region in data_plane["regions"] if region["primary"]]
        self.assertEqual([plan["regionInventory"]["initialActiveRegion"]], primary)

    def test_production_platform_migration_has_rls_fencing_and_four_eyes_state(self) -> None:
        migration = (ROOT / "tools/runtime/migrations/V088_117__platform_controls.sql").read_text()
        for marker in ("CREATE TABLE edge_nonce", "CREATE TABLE resource_fence",
                       "CREATE TABLE provider_health", "CREATE TABLE admin_action",
                       "CREATE TABLE deletion_job", "ENABLE ROW LEVEL SECURITY",
                       "approver <> proposer"):
            self.assertIn(marker, migration)


if __name__ == "__main__":
    unittest.main()
