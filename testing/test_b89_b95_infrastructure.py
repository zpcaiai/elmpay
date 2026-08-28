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
        allowed = {name: ["edge-gateway"] if name != "edge-gateway" else ["checkout-web", "admin-web"]
                   for name in self.names}
        bundle = render_service_controls(self.policy, allowed)
        kinds = [item["kind"] for item in bundle["items"]]
        for kind in ("ServiceAccount", "Service", "PodDisruptionBudget", "HorizontalPodAutoscaler", "NetworkPolicy", "AuthorizationPolicy"):
            self.assertEqual(len(self.names) + (1 if kind == "NetworkPolicy" else 0), kinds.count(kind))
        peer = [item for item in bundle["items"] if item["kind"] == "PeerAuthentication"]
        self.assertEqual("STRICT", peer[0]["spec"]["mtls"]["mode"])

    def test_mesh_map_must_cover_exactly_all_workloads(self) -> None:
        with self.assertRaises(ValueError):
            render_service_controls(self.policy, {"edge-gateway": []})

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
                "targetRegion": "region-b", "fencingToken": 7,
                "replicationLagSeconds": 20, "writeFenceAcquired": True,
                "providerRoutingChecked": True, "rollbackPlanVerified": True,
                "targetRegionHealthy": True, "sourceRegionWritesStopped": True,
                "changedAt": "2026-08-28T00:00:00Z",
            }
            request_digest = sha256_json({"promotion": promotion_facts})
            approval_fields = {
                "requestDigest": request_digest, "targetRegion": "region-b", "fencingToken": 7,
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
                self.assertEqual("region-b", store.current_region()["activeRegion"])
                self.assertEqual(7, store.current_region()["fencingToken"])
                # Exact replay is idempotent; unsigned fact mutation is blocked.
                self.assertTrue(evaluate_region_promotion(
                    plan, promotion, trust, store, now=NOW
                ).allowed)
                self.assertFalse(evaluate_region_promotion(
                    plan, {**promotion, "sourceRegionWritesStopped": False}, trust, store, now=NOW
                ).allowed)
            finally:
                store.close()

    def test_production_platform_migration_has_rls_fencing_and_four_eyes_state(self) -> None:
        migration = (ROOT / "tools/runtime/migrations/V088_117__platform_controls.sql").read_text()
        for marker in ("CREATE TABLE edge_nonce", "CREATE TABLE resource_fence",
                       "CREATE TABLE provider_health", "CREATE TABLE admin_action",
                       "CREATE TABLE deletion_job", "ENABLE ROW LEVEL SECURITY",
                       "approver <> proposer"):
            self.assertIn(marker, migration)


if __name__ == "__main__":
    unittest.main()
