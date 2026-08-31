from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.assurance import evaluate_sca_transaction  # noqa: E402
from elmpay_runtime.attestation import attach_dsse, generate_ed25519_keypair  # noqa: E402
from elmpay_runtime.common import canonical_json  # noqa: E402
from elmpay_runtime.downstream_receipt import receipt_binding  # noqa: E402


NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)


class PlatformRuntimeEntrypointTest(unittest.TestCase):
    def run_platform(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/platform_control.py"), *arguments],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )

    def write_json(self, root: Path, name: str, value: object) -> Path:
        path = root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def downstream_trust(self, root: Path) -> tuple[Path, dict[str, str]]:
        private: dict[str, str] = {}
        keys: dict[str, object] = {}
        roles = {
            "admin": ("admin-adapter", "admin_downstream", False),
            "data": ("data-adapter", "data_store_operator", False),
            "backup": ("backup-auditor", "backup_verifier", True),
        }
        for key_id, (identity, role, independent) in roles.items():
            private[key_id], public = generate_ed25519_keypair()
            keys[key_id] = {
                "algorithm": "Ed25519", "publicKeyPem": public,
                "identity": identity, "role": role, "independent": independent,
                "revoked": False, "notBefore": "2026-01-01T00:00:00Z",
                "notAfter": "2027-01-01T00:00:00Z",
            }
        path = self.write_json(root, "downstream-trust.json", {
            "replayDatabase": str(root / "downstream-nonces.sqlite"), "keys": keys,
        })
        return path, private

    @staticmethod
    def signed_receipt(
        key_id: str,
        private_key: str,
        identity: str,
        role: str,
        receipt_type: str,
        outcome: str,
        fields: dict[str, object],
        nonce: str,
    ) -> dict[str, object]:
        current = datetime.now(timezone.utc)
        return attach_dsse({
            "receiptId": nonce,
            "receiptType": receipt_type,
            "outcome": outcome,
            "fields": fields,
            "actor": identity,
            "role": role,
            "bindingDigest": receipt_binding(receipt_type, fields),
            "nonce": nonce,
            "issuedAt": (current - timedelta(minutes=1)).isoformat(),
            "expiresAt": (current + timedelta(hours=1)).isoformat(),
        }, key_id, private_key)

    def test_funnel_cli_is_tenant_scoped_and_policy_governed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = self.write_json(root, "events.json", [
                {"eventId": "e1", "tenantId": "tenant-a", "stage": "STARTED",
                 "amountMinor": 0, "projectId": "p1", "provider": "stripe"},
                {"eventId": "e2", "tenantId": "tenant-a", "stage": "CAPTURED",
                 "amountMinor": 125, "projectId": "p1", "provider": "stripe"},
            ])
            result = self.run_platform("funnel-aggregate", "--events", str(events),
                                       "--tenant-id", "tenant-a")
            self.assertEqual(0, result.returncode, result.stderr + result.stdout)
            cells = json.loads(result.stdout)
            self.assertEqual(125, sum(item["amountMinor"] for item in cells))
            wrong = self.run_platform("funnel-aggregate", "--events", str(events),
                                      "--tenant-id", "tenant-b")
            self.assertEqual(2, wrong.returncode)

    def test_provider_breaker_admin_and_incident_entrypoints_are_durable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "operations.sqlite"
            trust, private = self.downstream_trust(root)
            before = self.run_platform(
                "provider-health", "--state", str(state), "--tenant-id", "tenant-a",
                "--account-id", "account-a", "--operation", "before-call",
            )
            self.assertEqual(0, before.returncode, before.stderr)

            proposal = {"tenantId": "tenant-a", "actionType": "WEBHOOK_REPLAY",
                        "target": "delivery-1", "payload": {"eventId": "event-1"},
                        "proposer": "operator-a"}
            request = self.write_json(root, "admin-propose.json", proposal)
            proposed = self.run_platform("admin-action", "--state", str(state),
                                         "--operation", "propose", "--request", str(request))
            self.assertEqual(0, proposed.returncode, proposed.stderr)
            action_id = json.loads(proposed.stdout)["actionId"]
            request = self.write_json(root, "admin-approve.json",
                                      {"actionId": action_id, "approver": "operator-b"})
            approved = self.run_platform("admin-action", "--state", str(state),
                                         "--operation", "approve", "--request", str(request))
            self.assertEqual(0, approved.returncode, approved.stderr)
            payload_digest = hashlib.sha256(canonical_json(proposal["payload"])).hexdigest()
            forged = self.write_json(root, "admin-forged.json", {
                "actionId": action_id, "tenantId": "tenant-a", "target": "delivery-1",
                "payloadDigest": payload_digest, "downstreamVerified": True,
                "receipt": "caller-created-receipt",
            })
            self.assertEqual(2, self.run_platform(
                "admin-action", "--state", str(state), "--operation", "execute",
                "--request", str(forged),
            ).returncode)
            request = self.write_json(root, "admin-execute.json", {
                "actionId": action_id, "tenantId": "tenant-a", "target": "delivery-1",
                "payloadDigest": payload_digest,
                "receipt": self.signed_receipt(
                    "admin", private["admin"], "admin-adapter", "admin_downstream",
                    "ADMIN_ACTION", "APPLIED", {
                        "actionId": action_id, "tenantId": "tenant-a",
                        "target": "delivery-1", "payloadDigest": payload_digest,
                    }, "admin-downstream-receipt-0001",
                ),
            })
            executed = self.run_platform("admin-action", "--state", str(state),
                                         "--operation", "execute", "--request", str(request),
                                         "--downstream-trust", str(trust))
            self.assertEqual(0, executed.returncode, executed.stderr + executed.stdout)

            opened_request = self.write_json(root, "incident-open.json", {
                "incidentId": "INC-2026-001", "severity": "SEV1", "service": "payments",
                "publicSummary": "Payment processing is delayed", "owner": "incident-a",
            })
            opened = self.run_platform("incident-open", "--state", str(state),
                                       "--request", str(opened_request))
            self.assertEqual(0, opened.returncode, opened.stderr)
            self.assertEqual("OPEN", json.loads(opened.stdout)["statusPage"]["state"])
            transition = self.write_json(root, "incident-transition.json", {
                "incidentId": "INC-2026-001", "expectedVersion": 1,
                "targetState": "MITIGATING",
            })
            changed = self.run_platform("incident-transition", "--state", str(state),
                                        "--request", str(transition))
            self.assertEqual(0, changed.returncode, changed.stderr)
            self.assertEqual("MITIGATING", json.loads(changed.stdout)["statusPage"]["state"])

    def test_deletion_cli_requires_four_eyes_and_bound_downstream_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "deletion.sqlite"
            trust, private = self.downstream_trust(root)
            records = [hashlib.sha256(f"record-{index}".encode()).hexdigest() for index in range(2)]
            proposal = self.write_json(root, "deletion-propose.json", {
                "tenantId": "tenant-a", "dataClass": "payment-record",
                "recordDigests": records, "legalHoldClear": True, "proposer": "privacy-a",
            })
            proposed = self.run_platform("deletion-propose", "--state", str(state),
                                         "--request", str(proposal))
            self.assertEqual(0, proposed.returncode, proposed.stderr)
            job_id = json.loads(proposed.stdout)["jobId"]
            approval = self.write_json(root, "deletion-approve.json",
                                       {"jobId": job_id, "approver": "legal-b"})
            self.assertEqual(0, self.run_platform(
                "deletion-approve", "--state", str(state), "--request", str(approval)
            ).returncode)
            selection = hashlib.sha256(canonical_json(sorted(records))).hexdigest()
            execution_fields = {
                "jobId": job_id, "tenantId": "tenant-a", "dataClass": "payment-record",
                "selectionDigest": selection, "recordCount": 2, "deletedCount": 2,
            }
            forged = self.write_json(root, "deletion-forged.json", {
                "jobId": job_id, "tenantId": "tenant-a", "dataClass": "payment-record",
                "selectionDigest": selection, "recordCount": 2,
                "downstreamVerified": True, "executor": "data-c", "receipt": "self-proof",
            })
            self.assertEqual(2, self.run_platform(
                "deletion-execute", "--state", str(state), "--request", str(forged)
            ).returncode)
            execution = self.write_json(root, "deletion-execute.json", {
                "jobId": job_id, "tenantId": "tenant-a", "dataClass": "payment-record",
                "selectionDigest": selection, "recordCount": 2,
                "executor": "data-c", "receipt": self.signed_receipt(
                    "data", private["data"], "data-adapter", "data_store_operator",
                    "DATA_DELETION", "DELETED", execution_fields,
                    "data-deletion-receipt-0001",
                ),
            })
            executed = self.run_platform("deletion-execute", "--state", str(state),
                                         "--request", str(execution),
                                         "--downstream-trust", str(trust))
            self.assertEqual(0, executed.returncode, executed.stderr + executed.stdout)
            execution_receipt = json.loads(executed.stdout)["receipt"]
            backup_fields = {"jobId": job_id, "executionReceiptDigest": execution_receipt}
            confirmation = self.write_json(root, "deletion-confirm.json", {
                "jobId": job_id, "verifier": "backup-auditor",
                "receipt": self.signed_receipt(
                    "backup", private["backup"], "backup-auditor", "backup_verifier",
                    "BACKUP_EXPIRY", "EXPIRED", backup_fields,
                    "backup-expiry-receipt-0001",
                ),
            })
            confirmed = self.run_platform("deletion-confirm", "--state", str(state),
                                          "--request", str(confirmation),
                                          "--downstream-trust", str(trust))
            self.assertEqual(0, confirmed.returncode, confirmed.stderr)

    def test_supply_chain_cli_verifies_ed25519_dsse_not_a_boolean_claim(self) -> None:
        private_key, public_key = generate_ed25519_keypair()
        digest = hashlib.sha256(b"artifact").hexdigest()
        current = datetime.now(timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            statement = {
                "artifactDigest": digest, "sbomDigest": "b" * 64,
                "provenanceDigest": "c" * 64, "dependenciesLocked": True,
                "hermeticBuild": True, "sourceCommit": "d" * 40,
                "provenanceSourceCommit": "d" * 40,
                "builderId": "https://github.com/zpcaiai/elmpay/.github/workflows/ci.yml",
                "materials": ["source", "dependency-locks", "build-toolchain", "container-base"],
                "bindingDigest": digest, "nonce": "supply-chain-nonce-0001",
                "issuedAt": (current - timedelta(minutes=1)).isoformat(),
                "expiresAt": (current + timedelta(minutes=5)).isoformat(),
                "actor": "release-builder", "role": "BUILD_ATTESTOR",
            }
            signed = attach_dsse(statement, "builder-key", private_key)
            statement_path = self.write_json(root, "statement.json", signed)
            trust_path = self.write_json(root, "trust.json", {
                "replayDatabase": str(root / "nonce.sqlite"),
                "keys": {"builder-key": {
                    "algorithm": "Ed25519", "publicKeyPem": public_key,
                    "identity": "release-builder", "role": "BUILD_ATTESTOR",
                    "independent": True, "revoked": False,
                    "notBefore": (current - timedelta(days=1)).isoformat(),
                    "notAfter": (current + timedelta(days=1)).isoformat(),
                }},
            })
            result = self.run_platform(
                "supply-chain-gate", "--statement", str(statement_path),
                "--trust", str(trust_path), "--artifact-digest", digest,
            )
            self.assertEqual(0, result.returncode, result.stderr + result.stdout)
            expired = attach_dsse({
                **statement,
                "nonce": "supply-chain-nonce-expired-0001",
                "issuedAt": (current - timedelta(minutes=10)).isoformat(),
                "expiresAt": (current - timedelta(minutes=5)).isoformat(),
            }, "builder-key", private_key)
            expired_path = self.write_json(root, "expired.json", expired)
            expired_result = self.run_platform(
                "supply-chain-gate", "--statement", str(expired_path),
                "--trust", str(trust_path), "--artifact-digest", digest,
            )
            self.assertEqual(2, expired_result.returncode)
            self.assertIn("artifact_signature_unverified", expired_result.stdout)
            tampered = {**signed, "artifactDigest": "e" * 64}
            statement_path = self.write_json(root, "tampered.json", tampered)
            rejected = self.run_platform(
                "supply-chain-gate", "--statement", str(statement_path),
                "--trust", str(trust_path), "--artifact-digest", digest,
            )
            self.assertEqual(2, rejected.returncode)


class ScaRuntimeTest(unittest.TestCase):
    def test_sca_requires_provider_verified_two_factor_dynamic_linking(self) -> None:
        policy = json.loads((ROOT / "platform/compliance/psd2-sca-policy.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            private, public = generate_ed25519_keypair()
            trust = {
                "replayDatabase": str(Path(directory) / "sca-nonces.sqlite"),
                "keys": {"sca-provider": {
                    "algorithm": "Ed25519", "publicKeyPem": public,
                    "identity": "provider-3ds", "role": "sca_provider",
                    "independent": True, "revoked": False,
                    "notBefore": "2026-01-01T00:00:00Z",
                    "notAfter": "2027-01-01T00:00:00Z",
                }},
            }
            base = {
                "tenantId": "tenant-a", "transactionId": "tx-1", "market": "EU",
                "amountMinor": 5000, "currency": "EUR", "payeeReference": "merchant-a",
            }
            fields = {
                "provider": "provider-3ds", "providerAuthenticationId": "3ds-1",
                "tenantId": "tenant-a", "transactionId": "tx-1", "amountMinor": 5000,
                "currency": "EUR", "payeeReference": "merchant-a",
                "factors": ["POSSESSION", "INHERENCE"],
                "observedAt": "2026-08-28T11:59:00Z",
            }
            receipt = attach_dsse({
                "receiptId": "sca-authentication-receipt-0001",
                "receiptType": "SCA_AUTHENTICATION", "outcome": "SUCCEEDED",
                "fields": fields, "actor": "provider-3ds", "role": "sca_provider",
                "bindingDigest": receipt_binding("SCA_AUTHENTICATION", fields),
                "nonce": "sca-authentication-nonce-0001",
                "issuedAt": "2026-08-28T11:58:00Z",
                "expiresAt": "2026-08-28T13:00:00Z",
            }, "sca-provider", private)
            authenticated = {**base, "authentication": receipt}
            self.assertTrue(evaluate_sca_transaction(
                policy, authenticated, trust, now=NOW
            ).allowed)
            self.assertFalse(evaluate_sca_transaction(policy, base, trust, now=NOW).allowed)
            # Legacy self-reported provider/signature booleans no longer authorize.
            legacy = {**base, "providerAvailable": True, "authentication": {
                "status": "SUCCEEDED", "signatureVerified": True,
                "transactionId": "tx-1", "amountMinor": 5000,
                "currency": "EUR", "payeeReference": "merchant-a",
                "factors": ["POSSESSION", "INHERENCE"],
                "observedAt": "2026-08-28T11:59:00Z",
            }}
            with self.assertRaises(ValueError):
                evaluate_sca_transaction(policy, legacy, trust, now=NOW)
            tampered_fields = {**fields, "amountMinor": 4999}
            tampered = {**base, "authentication": {**receipt, "fields": tampered_fields}}
            self.assertFalse(evaluate_sca_transaction(
                policy, tampered, trust, now=NOW
            ).allowed)


class QualityRuntimeEntrypointTest(unittest.TestCase):
    def run_quality(self, *arguments: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/quality_gate.py"), *arguments],
            cwd=ROOT, text=True, capture_output=True, check=False,
            env={**os.environ, **(env or {})},
        )

    def test_provider_fault_concurrency_and_load_commands_are_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = root / "request.json"
            request.write_text(json.dumps({
                "provider": "stripe", "tenantId": "tenant-a",
                "providerAccountId": "account-a", "operation": "PAYMENT",
                "idempotencyKey": "idem-provider-runtime", "amountMinor": 100,
                "currency": "USD", "timestamp": 1770000000,
            }), encoding="utf-8")
            env = {"ELMPAY_TEST_SIM_SECRET": "sim-" + "s" * 40}
            simulated = self.run_quality(
                "simulate-provider", "--request", str(request), "--state",
                str(root / "sim.sqlite"), "--secret-env", "ELMPAY_TEST_SIM_SECRET", env=env,
            )
            self.assertEqual(0, simulated.returncode, simulated.stderr)
            concurrent = self.run_quality(
                "concurrency", "--request", str(request), "--state", str(root / "conc.sqlite"),
                "--secret-env", "ELMPAY_TEST_SIM_SECRET", "--workers", "8", "--calls", "32",
                env=env,
            )
            self.assertEqual(0, concurrent.returncode, concurrent.stderr)
            payload = root / "payload.json"
            payload.write_bytes(b'{"event":"synthetic"}')
            faults = self.run_quality("webhook-fault-corpus", "--payload", str(payload), "--seed", "114")
            self.assertEqual(0, faults.returncode, faults.stderr)
            self.assertGreaterEqual(len(json.loads(faults.stdout)["cases"]), 8)
            profile = root / "load.json"
            profile.write_text(json.dumps({
                "target": "synthetic-handler-v1", "workers": 4,
                "requests": [
                    {"id": f"req-{index}", "ok": True,
                     "sideEffectId": f"effect-{index}", "score": 1.0}
                    for index in range(64)
                ],
            }), encoding="utf-8")
            load = self.run_quality("load-profile", "--profile", str(profile))
            self.assertEqual(0, load.returncode, load.stderr)
            self.assertEqual(64, json.loads(load.stdout)["requests"])


if __name__ == "__main__":
    unittest.main()
