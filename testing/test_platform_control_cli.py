from __future__ import annotations

from datetime import datetime, timedelta, timezone
from contextlib import closing
from pathlib import Path
import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.attestation import attach_dsse, generate_ed25519_keypair  # noqa: E402
from elmpay_runtime.common import sha256_json  # noqa: E402
from elmpay_runtime.downstream_receipt import receipt_binding  # noqa: E402


class PlatformControlCliTest(unittest.TestCase):
    def test_renders_controls_for_every_workload(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/platform_control.py"), "render-service-controls"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        output = json.loads(result.stdout)
        workloads = json.loads((ROOT / "platform/kubernetes/workload-policy.json").read_text())
        deployments = [item for item in output["items"] if item["kind"] == "ServiceAccount"]
        self.assertEqual(len(workloads["services"]), len(deployments))

    def test_missing_external_inputs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.json"
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/platform_control.py"), "pci-scope-gate", "--inventory", str(missing)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
        self.assertEqual(2, result.returncode)
        self.assertFalse(json.loads(result.stdout)["allowed"])

    def test_renders_two_region_data_plane(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/platform_control.py"), "render-data-plane"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        items = json.loads(result.stdout)["items"]
        self.assertEqual(2, len([item for item in items if item["kind"] == "Cluster"]))

    def test_restore_and_region_promotion_cli_require_signed_receipts_and_persist_fence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current = datetime.now(timezone.utc)
            roles = {
                "restore": ("restore-a", "dr_restore_verifier", True),
                "controller": ("controller-a", "dr_controller", False),
                "approver-a": ("ops-a", "dr_promotion_approver", True),
                "approver-b": ("security-b", "dr_promotion_approver", True),
            }
            private: dict[str, str] = {}
            keys: dict[str, object] = {}
            for key_id, (identity, role, independent) in roles.items():
                private[key_id], public = generate_ed25519_keypair()
                keys[key_id] = {
                    "algorithm": "Ed25519", "publicKeyPem": public,
                    "identity": identity, "role": role, "independent": independent,
                    "revoked": False, "notBefore": "2020-01-01T00:00:00Z",
                    "notAfter": "2035-01-01T00:00:00Z",
                }
            trust = {"replayDatabase": str(root / "nonces.sqlite"), "keys": keys}
            trust_path = root / "trust.json"
            trust_path.write_text(json.dumps(trust), encoding="utf-8")

            def receipt(key_id: str, kind: str, outcome: str,
                        fields: dict[str, object], suffix: str) -> dict[str, object]:
                identity, role, _ = roles[key_id]
                return attach_dsse({
                    "receiptId": f"{suffix}-receipt", "receiptType": kind,
                    "outcome": outcome, "fields": fields, "actor": identity, "role": role,
                    "bindingDigest": receipt_binding(kind, fields),
                    "nonce": f"{suffix}-nonce-0001",
                    "issuedAt": (current - timedelta(minutes=1)).isoformat(),
                    "expiresAt": (current + timedelta(hours=1)).isoformat(),
                }, key_id, private[key_id])

            digest = hashlib.sha256(b"immutable-backup").hexdigest()
            restore_fields: dict[str, object] = {
                "backupDigest": digest, "backupImmutable": True,
                "restoreChecksumVerified": True, "ledgerBalanced": True,
                "failbackVerified": True, "measuredRpoSeconds": 10,
                "measuredRtoSeconds": 100,
                "completedAt": (current - timedelta(hours=1)).isoformat(),
            }
            report_path = root / "restore.json"
            report_path.write_text(json.dumps({
                **restore_fields,
                "receipt": receipt("restore", "DR_RESTORE_EXERCISE", "VERIFIED",
                                   restore_fields, "restore-cli"),
            }), encoding="utf-8")
            restored = subprocess.run(
                [
                    sys.executable, str(ROOT / "tools/platform_control.py"), "restore-gate",
                    "--report", str(report_path), "--backup-digest", digest,
                    "--trust", str(trust_path),
                ],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, restored.returncode, restored.stderr + restored.stdout)

            facts: dict[str, object] = {
                "targetRegion": "region-b", "fencingToken": 11,
                "replicationLagSeconds": 5, "writeFenceAcquired": True,
                "providerRoutingChecked": True, "rollbackPlanVerified": True,
                "targetRegionHealthy": True, "sourceRegionWritesStopped": True,
                "changedAt": current.isoformat(),
            }
            request_digest = sha256_json({"promotion": facts})
            approval_fields = {
                "requestDigest": request_digest, "targetRegion": "region-b",
                "fencingToken": 11,
            }
            promotion_path = root / "promotion.json"
            promotion_path.write_text(json.dumps({
                **facts, "requestDigest": request_digest,
                "observation": receipt(
                    "controller", "REGION_PROMOTION_OBSERVATION", "VERIFIED",
                    {**facts, "requestDigest": request_digest}, "promotion-observe-cli",
                ),
                "approvals": [
                    receipt("approver-a", "REGION_PROMOTION_APPROVAL", "APPROVED",
                            approval_fields, "promotion-approve-a-cli"),
                    receipt("approver-b", "REGION_PROMOTION_APPROVAL", "APPROVED",
                            approval_fields, "promotion-approve-b-cli"),
                ],
            }), encoding="utf-8")
            state = root / "fence.sqlite"
            promoted = subprocess.run(
                [
                    sys.executable, str(ROOT / "tools/platform_control.py"),
                    "region-promotion-gate", "--request", str(promotion_path),
                    "--trust", str(trust_path), "--state", str(state),
                ],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, promoted.returncode, promoted.stderr + promoted.stdout)
            with closing(sqlite3.connect(state)) as connection:
                self.assertEqual(("region-b", 11), connection.execute(
                    "SELECT active_region,fencing_token FROM region_epoch"
                ).fetchone())


if __name__ == "__main__":
    unittest.main()
