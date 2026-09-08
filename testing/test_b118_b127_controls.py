from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import sqlite3
import subprocess
import tempfile
from typing import Any, Mapping
import unittest


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.attestation import attach_dsse, generate_ed25519_keypair, verify_dsse_record  # noqa: E402
from elmpay_runtime.commercial import CommercialLedger  # noqa: E402
from elmpay_runtime.common import ValidationError, read_json, sha256_json  # noqa: E402
from elmpay_runtime.downstream_receipt import receipt_binding  # noqa: E402
from elmpay_runtime.migration_pipeline import MigrationPipeline  # noqa: E402
from elmpay_runtime.onboarding import OnboardingControl  # noqa: E402
from elmpay_runtime.postlaunch import PostLaunchControl  # noqa: E402
from elmpay_runtime.release_control import ReleaseControl, rollout_target_digest  # noqa: E402
from elmpay_runtime.release import release_binding, sign_record  # noqa: E402
from elmpay_runtime.uat import UatAdapter, UatRunner  # noqa: E402
from testing.test_external_evidence import ExternalEvidenceGateTest  # noqa: E402


NOW = datetime(2026, 8, 26, 0, 0, tzinfo=timezone.utc)


class DurableControlsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)

    def database(self, name: str = "control.db") -> str:
        return str(Path(self.temporary.name) / name)

    def reconciliation_sources(
        self,
        *,
        tenant_id: str,
        window_id: str,
        window_kind: str,
        period_start: datetime,
        period_end: datetime,
        currency: str,
        totals: dict[str, int],
        prefix: str,
        verification_time: datetime = NOW,
        item_keys_by_source: dict[str, list[str]] | None = None,
    ) -> tuple[dict[str, object], dict[str, object]]:
        roles = {
            "transaction": ("ledger-source", "ledger_reconciliation_source", False),
            "provider": ("provider-source", "provider_reconciliation_source", True),
            "bank": ("bank-source", "bank_reconciliation_source", True),
        }
        keys: dict[str, object] = {}
        receipts: dict[str, object] = {}
        for source, (identity, role, independent) in roles.items():
            private, public = generate_ed25519_keypair()
            item_keys = (item_keys_by_source or {}).get(
                source, ["payment:one", "payment:two"]
            )
            item_digests = sorted(sha256_json({"reconciliationKey": key}) for key in item_keys)
            keys[source] = {
                "algorithm": "Ed25519", "publicKeyPem": public,
                "identity": identity, "role": role, "independent": independent,
                "revoked": False,
                "notBefore": (verification_time - timedelta(days=30)).isoformat(),
                "notAfter": (verification_time + timedelta(days=30)).isoformat(),
            }
            fields = {
                "source": source, "tenantId": tenant_id, "windowId": window_id,
                "windowKind": window_kind,
                "periodStart": period_start.astimezone(timezone.utc).isoformat(),
                "periodEnd": period_end.astimezone(timezone.utc).isoformat(),
                "currency": currency, "totalMinor": totals[source],
                "recordCount": len(item_digests),
                "itemDigests": item_digests,
                "sourceSnapshotDigest": sha256_json(item_digests),
            }
            receipts[source] = attach_dsse({
                "receiptId": f"{prefix}-{source}-receipt",
                "receiptType": "RECONCILIATION_SOURCE_TOTAL", "outcome": "FINAL",
                "fields": fields, "actor": identity, "role": role,
                "bindingDigest": receipt_binding("RECONCILIATION_SOURCE_TOTAL", fields),
                "nonce": f"{prefix}-{source}-nonce-0001",
                "issuedAt": (verification_time - timedelta(hours=1)).isoformat(),
                "expiresAt": (verification_time + timedelta(hours=2)).isoformat(),
            }, source, private)
        trust = {
            "replayDatabase": self.database(f"{prefix}-source-nonces.db"),
            "keys": keys,
        }
        return receipts, trust

    def test_uat_executes_wired_dsl_and_only_emits_candidate_bundle(self) -> None:
        runner = UatRunner(self.database(), {"authorize": UatAdapter(lambda value: {"status": "AUTHORIZED", "amountMinor": value["amountMinor"]})})
        suite = {
            "schemaVersion": 1,
            "environment": "UAT",
            "syntheticOnly": True,
            "tenantId": "tenant-a",
            "suiteId": "merchant-smoke",
            "version": "1.0.0",
            "releaseBindingDigest": "a" * 64,
            "scenarios": [{"id": "authorization", "steps": [{"action": "authorize", "input": {"amountMinor": 100}, "expect": {"equals": {"status": "AUTHORIZED"}}}]}],
        }
        bundle = runner.run(suite, now=NOW)
        self.assertEqual("CANDIDATE", bundle["status"])
        self.assertEqual("NOT_CERTIFIED", bundle["certificationStatus"])
        self.assertTrue(bundle["humanSignoffRequired"])
        self.assertEqual(bundle, UatRunner(self.database(), {}).run(suite, now=NOW))
        with self.assertRaisesRegex(ValidationError, "synthetic-only"):
            UatRunner(self.database("unsafe.db"), {"authorize": UatAdapter(lambda value: value, environment="PRODUCTION")})
        with self.assertRaises(ValidationError):
            runner.run({**suite, "suiteId": "unsafe", "pan": "4111"}, now=NOW)

    def test_migration_is_tenant_scoped_checkpointed_and_shadow_is_immutable(self) -> None:
        webhook_private, webhook_public = generate_ed25519_keypair()
        request_private, request_public = generate_ed25519_keypair()
        payment_private, payment_public = generate_ed25519_keypair()
        signer_identities = {
            "webhook": "migration-webhook-verifier-a",
            "request": "migration-request-signer-a",
            "payment": "migration-payment-service-a",
        }
        trust = {
            "replayDatabase": self.database("migration-receipt-nonces.db"),
            "keys": {
                "webhook": {
                    "algorithm": "Ed25519", "publicKeyPem": webhook_public,
                    "identity": "migration-webhook-verifier-a",
                    "role": "migration_webhook_verifier", "independent": True,
                    "revoked": False, "notBefore": "2026-08-01T00:00:00Z",
                    "notAfter": "2026-09-01T00:00:00Z",
                },
                "request": {
                    "algorithm": "Ed25519", "publicKeyPem": request_public,
                    "identity": "migration-request-signer-a",
                    "role": "migration_request_signer", "independent": False,
                    "revoked": False, "notBefore": "2026-08-01T00:00:00Z",
                    "notAfter": "2026-09-01T00:00:00Z",
                },
                "payment": {
                    "algorithm": "Ed25519", "publicKeyPem": payment_public,
                    "identity": "migration-payment-service-a",
                    "role": "migration_payment_service", "independent": False,
                    "revoked": False, "notBefore": "2026-08-01T00:00:00Z",
                    "notAfter": "2026-09-01T00:00:00Z",
                },
            },
        }

        def signed_receipt(
            receipt_type: str,
            outcome: str,
            fields: Mapping[str, Any],
            key_id: str,
            private_key: str,
            role: str,
            nonce: str,
        ) -> dict[str, Any]:
            return attach_dsse({
                "receiptId": f"{receipt_type.lower()}-{nonce}",
                "receiptType": receipt_type,
                "outcome": outcome,
                "fields": dict(fields),
                "actor": signer_identities[key_id],
                "role": role,
                "bindingDigest": receipt_binding(receipt_type, fields),
                "nonce": nonce,
                "issuedAt": (NOW - timedelta(minutes=1)).isoformat(),
                "expiresAt": (NOW + timedelta(hours=1)).isoformat(),
            }, key_id, private_key)

        mapping = {
            "fieldMap": {
                "requestId": "legacyId", "amountMinor": "amount",
                "currency": "currency",
            },
            "constants": {"action": "AUTHORIZE"},
        }
        pipeline = MigrationPipeline(
            self.database(), webhook_trust=trust, execution_trust=trust,
        )
        digest = pipeline.register(
            tenant_id="tenant-a", project_id="project-a", source_system="legacy",
            canonical_version="payment-v2", mapping=mapping,
            credential_ref="vault://elmpay/migration/a", now=NOW,
        )
        self.assertEqual(64, len(digest))
        pipeline.transition("tenant-a", "project-a", "REGISTERED", "IMPORT", now=NOW)
        self.assertTrue(pipeline.checkpoint("tenant-a", "project-a", "payments", 1, {"id": "p1"}, now=NOW))
        self.assertFalse(pipeline.checkpoint("tenant-a", "project-a", "payments", 1, {"id": "p1"}, now=NOW))
        with self.assertRaises(ValidationError):
            pipeline.checkpoint("tenant-a", "project-a", "payments", 0, {"id": "p0"}, now=NOW)
        self.assertTrue(pipeline.ingest_fact("tenant-a", "project-a", "legacy-1", "payment-v2", {"amountMinor": 100, "currency": "USD", "customerEmail": "person@example.test"}, now=NOW))
        with pipeline.store.connect() as connection:
            stored = connection.execute("SELECT canonical_json FROM migration_fact WHERE source_record_id='legacy-1'").fetchone()[0]
        self.assertNotIn("person@example.test", stored)
        self.assertIn("[REDACTED]", stored)

        webhook_payload = {"event": "payment"}
        webhook_fields = {
            "tenantId": "tenant-a", "projectId": "project-a",
            "sourceSystem": "legacy", "deliveryId": "delivery-1",
            "payloadDigest": sha256_json(webhook_payload),
        }
        webhook_receipt = signed_receipt(
            "MIGRATION_WEBHOOK_VERIFICATION", "VERIFIED", webhook_fields,
            "webhook", webhook_private, "migration_webhook_verifier",
            "migration-webhook-nonce-0001",
        )
        self.assertTrue(pipeline.accept_webhook(
            "tenant-a", "project-a", "delivery-1", webhook_payload,
            webhook_receipt, now=NOW,
        ))
        self.assertFalse(pipeline.accept_webhook(
            "tenant-a", "project-a", "delivery-1", webhook_payload,
            webhook_receipt, now=NOW,
        ))
        mutated_fields = {
            **webhook_fields, "payloadDigest": sha256_json({"event": "refund"}),
        }
        replayed_mutation = signed_receipt(
            "MIGRATION_WEBHOOK_VERIFICATION", "VERIFIED", mutated_fields,
            "webhook", webhook_private, "migration_webhook_verifier",
            "migration-webhook-nonce-0001",
        )
        with self.assertRaisesRegex(ValidationError, "nonce_reused"):
            pipeline.accept_webhook(
                "tenant-a", "project-a", "delivery-1", {"event": "refund"},
                replayed_mutation, now=NOW,
            )
        with self.assertRaises(ValidationError):
            pipeline.accept_webhook(
                "tenant-a", "project-a", "delivery-unsigned", webhook_payload,
                {"signatureVerified": True}, now=NOW,
            )

        with self.assertRaisesRegex(ValidationError, "precomputed shadow candidates"):
            pipeline.shadow(
                "tenant-a", "project-a", "shadow-legacy", "payment-v2",
                [{"requestId": "r1"}], [{"requestId": "r1"}], now=NOW,
            )
        source_records = [{"legacyId": "r1", "amount": 100, "currency": "USD"}]
        expected = [{
            "requestId": "r1", "amountMinor": 100, "currency": "USD",
            "action": "AUTHORIZE",
        }]
        result = pipeline.shadow_execute(
            "tenant-a", "project-a", "shadow-1", "payment-v2",
            expected, source_records, mapping, now=NOW,
        )
        self.assertEqual("PASSED", result["status"])
        self.assertEqual(0, result["candidateSideEffects"])
        reopened = MigrationPipeline(
            self.database(), webhook_trust=trust, execution_trust=trust,
        ).shadow_execute(
            "tenant-a", "project-a", "shadow-1", "payment-v2",
            expected, source_records, mapping, now=NOW,
        )
        self.assertEqual(result["resultDigest"], reopened["resultDigest"])
        with self.assertRaisesRegex(ValidationError, "immutable shadow run id collision"):
            pipeline.shadow_execute(
                "tenant-a", "project-a", "shadow-1", "payment-v2", expected,
                [{"legacyId": "r1", "amount": 101, "currency": "USD"}],
                mapping, now=NOW,
            )

        class PaymentPort:
            def __init__(self) -> None:
                self.submissions: list[Mapping[str, Any]] = []
                self.rollbacks: list[Mapping[str, Any]] = []

            def submit(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
                self.submissions.append(request)
                fields = {
                    "tenantId": request["tenantId"],
                    "projectId": request["projectId"],
                    "sourceRecordId": request["sourceRecordId"],
                    "canonicalDigest": request["canonicalDigest"],
                    "idempotencyKey": request["idempotencyKey"],
                    "fenceToken": request["fenceToken"],
                    "providerReference": "provider-order-0001",
                }
                return {"receipt": signed_receipt(
                    "MIGRATION_PAYMENT_SUBMISSION", "ACCEPTED", fields,
                    "payment", payment_private, "migration_payment_service",
                    "migration-payment-nonce-0001",
                )}

            def rollback(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
                self.rollbacks.append(request)
                fields = {
                    "tenantId": request["tenantId"],
                    "projectId": request["projectId"],
                    "reason": request["reason"],
                    "mappingDigest": request["mappingDigest"],
                    "idempotencyKey": request["idempotencyKey"],
                    "fenceToken": request["fenceToken"],
                }
                return {"receipt": signed_receipt(
                    "MIGRATION_PROJECT_ROLLBACK", "ROLLED_BACK", fields,
                    "payment", payment_private, "migration_payment_service",
                    "migration-rollback-nonce-0001",
                )}

        port = PaymentPort()
        source_order = {"legacyId": "order-1", "amount": 250, "currency": "USD"}
        canonical = {
            "requestId": "order-1", "amountMinor": 250, "currency": "USD",
            "action": "AUTHORIZE",
        }
        canonical_digest = sha256_json(canonical)
        idempotency_key = sha256_json({
            "tenantId": "tenant-a", "projectId": "project-a",
            "sourceRecordId": "legacy-order-1", "canonicalDigest": canonical_digest,
        })
        request_fields = {
            "tenantId": "tenant-a", "projectId": "project-a",
            "sourceSystem": "legacy", "sourceRecordId": "legacy-order-1",
            "canonicalDigest": canonical_digest, "idempotencyKey": idempotency_key,
            "credentialRef": "vault://elmpay/migration/a",
        }
        request_receipt = signed_receipt(
            "MIGRATION_REQUEST_SIGNATURE", "SIGNED", request_fields,
            "request", request_private, "migration_request_signer",
            "migration-request-nonce-0001",
        )
        submitted = pipeline.migrate_order(
            "tenant-a", "project-a", "legacy-order-1", source_order, mapping,
            request_receipt, port, now=NOW,
        )
        self.assertFalse(submitted["duplicate"])
        self.assertEqual("provider-order-0001", submitted["providerReference"])
        duplicate = pipeline.migrate_order(
            "tenant-a", "project-a", "legacy-order-1", source_order, mapping,
            request_receipt, port, now=NOW,
        )
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(1, len(port.submissions))
        with self.assertRaisesRegex(ValidationError, "different mapped order"):
            pipeline.migrate_order(
                "tenant-a", "project-a", "legacy-order-1",
                {**source_order, "amount": 251}, mapping,
                request_receipt, port, now=NOW,
            )

        recovering_source = {
            "legacyId": "order-unknown", "amount": 300, "currency": "USD",
        }
        recovering_canonical = {
            "requestId": "order-unknown", "amountMinor": 300,
            "currency": "USD", "action": "AUTHORIZE",
        }
        recovering_digest = sha256_json(recovering_canonical)
        recovering_idempotency = sha256_json({
            "tenantId": "tenant-a", "projectId": "project-a",
            "sourceRecordId": "legacy-order-unknown",
            "canonicalDigest": recovering_digest,
        })
        recovering_signature = signed_receipt(
            "MIGRATION_REQUEST_SIGNATURE", "SIGNED",
            {
                "tenantId": "tenant-a", "projectId": "project-a",
                "sourceSystem": "legacy",
                "sourceRecordId": "legacy-order-unknown",
                "canonicalDigest": recovering_digest,
                "idempotencyKey": recovering_idempotency,
                "credentialRef": "vault://elmpay/migration/a",
            },
            "request", request_private, "migration_request_signer",
            "migration-request-unknown-nonce-0001",
        )

        class RecoveringPort:
            def __init__(self) -> None:
                self.requests: list[Mapping[str, Any]] = []

            def submit(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
                self.requests.append(request)
                raise TimeoutError("provider response was lost")

            def reconcile_order(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
                self.requests.append(request)
                fields = {
                    "tenantId": request["tenantId"],
                    "projectId": request["projectId"],
                    "sourceRecordId": request["sourceRecordId"],
                    "canonicalDigest": request["canonicalDigest"],
                    "idempotencyKey": request["idempotencyKey"],
                    "fenceToken": request["fenceToken"],
                    "providerReference": "provider-order-recovered",
                }
                return {"receipt": signed_receipt(
                    "MIGRATION_PAYMENT_SUBMISSION", "ACCEPTED", fields,
                    "payment", payment_private, "migration_payment_service",
                    "migration-payment-recovered-nonce-0001",
                )}

            def rollback(self, _request: Mapping[str, Any]) -> Mapping[str, Any]:
                raise AssertionError("rollback is not used by this test")

        recovering_port = RecoveringPort()
        with self.assertRaisesRegex(ValidationError, "outcome is UNKNOWN"):
            pipeline.migrate_order(
                "tenant-a", "project-a", "legacy-order-unknown",
                recovering_source, mapping, recovering_signature,
                recovering_port, now=NOW,
            )
        with self.assertRaisesRegex(ValidationError, "external outcome is unresolved"):
            pipeline.transition(
                "tenant-a", "project-a", "IMPORT", "DUAL_WRITE", now=NOW,
            )
        recovered = pipeline.migrate_order(
            "tenant-a", "project-a", "legacy-order-unknown",
            recovering_source, mapping, recovering_signature,
            recovering_port, now=NOW,
        )
        self.assertEqual("provider-order-recovered", recovered["providerReference"])
        self.assertEqual(["SUBMIT", "RECONCILE"], [
            request["mode"] for request in recovering_port.requests
        ])
        self.assertEqual([1, 2], [
            request["fenceToken"] for request in recovering_port.requests
        ])
        rollback_digest = pipeline.rollback_project(
            "tenant-a", "project-a", "provider cutover aborted", port, now=NOW,
        )
        self.assertEqual(64, len(rollback_digest))
        self.assertEqual(1, len(port.rollbacks))

    def test_ed25519_trust_root_rejects_revocation_and_replay_mutation(self) -> None:
        with self.assertRaisesRegex(ValidationError, "symmetric HMAC"):
            sign_record({"legacy": True}, "x" * 32)
        private, public = generate_ed25519_keypair()
        trust = {"replayDatabase": self.database("nonces.db"), "keys": {"reviewer": {"algorithm": "Ed25519", "publicKeyPem": public, "identity": "reviewer-a", "role": "external_verifier", "independent": True, "revoked": False, "notBefore": "2026-08-01T00:00:00Z", "notAfter": "2026-09-01T00:00:00Z"}}}
        record = {"verifier": "reviewer-a", "role": "external_verifier", "bindingDigest": "b" * 64, "nonce": "review-record-00000001", "issuedAt": "2026-08-25T23:00:00Z", "expiresAt": "2026-08-26T01:00:00Z", "decision": "APPROVE"}
        signed = attach_dsse(record, "reviewer", private)
        verify_dsse_record(signed, trust, "b" * 64, now=NOW)
        verify_dsse_record(signed, trust, "b" * 64, now=NOW)
        mutated = attach_dsse({**record, "decision": "REJECT"}, "reviewer", private)
        with self.assertRaisesRegex(ValidationError, "nonce_reused"):
            verify_dsse_record(mutated, trust, "b" * 64, now=NOW)
        trust["keys"]["reviewer"]["revoked"] = True
        with self.assertRaisesRegex(ValidationError, "revoked_key"):
            verify_dsse_record(signed, trust, "b" * 64, now=NOW)

    def test_signed_go_decision_binds_target_and_auto_rollback_is_invoked(self) -> None:
        rm_private, rm_public = generate_ed25519_keypair()
        observer_private, observer_public = generate_ed25519_keypair()
        operations_private, operations_public = generate_ed25519_keypair()
        rollback_private, rollback_public = generate_ed25519_keypair()
        trust = {"replayDatabase": self.database("release-nonces.db"), "keys": {
            "rm": {"algorithm": "Ed25519", "publicKeyPem": rm_public, "identity": "release-a", "role": "release_manager", "independent": False, "revoked": False, "notBefore": "2026-08-01T00:00:00Z", "notAfter": "2026-09-01T00:00:00Z"},
            "observer": {"algorithm": "Ed25519", "publicKeyPem": observer_public, "identity": "observer-a", "role": "rollout_observer", "independent": True, "revoked": False, "notBefore": "2026-08-01T00:00:00Z", "notAfter": "2026-09-01T00:00:00Z"},
            "operations": {"algorithm": "Ed25519", "publicKeyPem": operations_public, "identity": "operations-a", "role": "operations_verifier", "independent": True, "revoked": False, "notBefore": "2026-08-01T00:00:00Z", "notAfter": "2026-09-01T00:00:00Z"},
            "rollback": {"algorithm": "Ed25519", "publicKeyPem": rollback_public, "identity": "rollback-executor-a", "role": "rollout_rollback_executor", "independent": False, "revoked": False, "notBefore": "2026-08-01T00:00:00Z", "notAfter": "2026-09-01T00:00:00Z"},
        }}
        external = ExternalEvidenceGateTest()
        external.setUp()
        self.addCleanup(external.doCleanups)
        governed_release_policy = read_json(
            ROOT / "platform/compliance/required-release-gates.json"
        )
        manifest = {
            "releaseId": "release-control-1", "commitSha": "c" * 40,
            "artifactDigest": "e" * 64,
            "productImageManifestDigest": governed_release_policy["productImageManifestDigest"],
            "imageAdmissionPolicyDigest": governed_release_policy["imageAdmissionPolicyDigest"],
            "productImageIndexDigest": "f" * 64,
            "images": {
                name: f"ghcr.io/zpcaiai/elmpay/{name}@sha256:" + f"{index + 1:064x}"
                for index, name in enumerate(governed_release_policy["requiredProductImages"])
            },
            "generatedAt": "2026-08-25T22:00:00Z",
            "expiresAt": "2026-08-26T03:00:00Z", "approvals": [], "evidence": [],
        }
        product_index = {
            "schemaVersion": 1,
            "productImageManifestDigest": manifest["productImageManifestDigest"],
            "admissionPolicyDigest": manifest["imageAdmissionPolicyDigest"],
            "sourceCommit": manifest["commitSha"],
            "artifactDigest": manifest["artifactDigest"],
            "targetPlatform": "linux/amd64",
            "evidenceToolchain": {
                "build": {"name": "docker-buildx", "version": "v0.30.1", "executableDigest": "1" * 64},
                "scan": {"name": "trivy", "version": "v0.67.2", "executableDigest": "2" * 64},
                "scanDatabaseDigest": "3" * 64,
                "publish": {"name": "skopeo", "version": "v1.20.0", "executableDigest": "0" * 63 + "1"},
                "sign": {"name": "cosign", "version": "v3.0.6", "executableDigest": "4" * 64},
            },
            "buildIndexDigest": "5" * 64,
            "scanIndexDigest": "6" * 64,
            "publicationIndexDigest": "7" * 64,
            "signatureIndexDigest": "8" * 64,
            "images": [{
                "name": name,
                "reference": reference,
                "imageDigest": reference.rsplit("@sha256:", 1)[1],
                "baseImage": "registry.example/base@sha256:" + "9" * 64,
                "artifactDigest": "a" * 64,
                "containerfileDigest": "b" * 64,
                "runtimeInspectionDigest": "9" * 64,
                "sbomDigest": "c" * 64,
                "sbomAttestedPredicateDigest": "1" * 64,
                "provenanceDigest": "d" * 64,
                "provenanceAttestedPredicateDigest": "2" * 64,
                "scanReportDigest": "e" * 64,
                "signatureBundleDigest": "f" * 64,
                "status": "SIGNED_SCANNED_VERIFIED",
            } for name, reference in manifest["images"].items()],
        }
        manifest["productImageIndexDigest"] = sha256_json(product_index)
        binding = release_binding(manifest)
        target = {"tenantId": "tenant-a", "projectId": "project-a", "providerId": "stripe", "region": "us-east-1"}
        target_digest = rollout_target_digest(target)
        external_bundle = external._bundle()
        external_bundle["releaseBindingDigest"] = binding
        external_bundle["expiresAt"] = "2026-08-26T00:30:00Z"
        for item in external_bundle["evidence"]:
            item["bindingDigest"] = binding
            item["expiresAt"] = "2026-08-26T00:30:00Z"
            if item["category"] in {
                "uat_acceptance", "shadow_rollout", "canary_rollout",
                "merchant_acceptance", "post_launch_reconciliation",
                "go_no_go", "final_release_signoff",
            }:
                item["attestation"]["tenantId"] = "tenant-a"
            if item["category"] == "production_kubernetes":
                item["attestation"].update({
                    "artifactDigest": manifest["artifactDigest"],
                    "commitSha": manifest["commitSha"],
                    "imageDigests": list(manifest["images"].values()),
                    "admissionPolicyDigest": manifest["imageAdmissionPolicyDigest"],
                })
            if item["category"] in {
                "uat_acceptance", "shadow_rollout", "canary_rollout",
                "merchant_acceptance", "post_launch_reconciliation",
                "go_no_go", "final_release_signoff",
            }:
                item["attestation"]["targetDigest"] = target_digest
            external._resign(item, external._key_id(item))
        release_policy = {
            "maximumApprovalAgeHours": 24, "requiredApprovalRoles": [],
            "minimumDistinctApprovers": 0, "requiredEvidence": [],
            "evidenceMustBeIndependent": True,
            "productImageIndexRequired": True,
            "productImageManifestDigest": governed_release_policy["productImageManifestDigest"],
            "imageAdmissionPolicyDigest": governed_release_policy["imageAdmissionPolicyDigest"],
            "requiredProductImages": governed_release_policy["requiredProductImages"],
        }
        control = ReleaseControl(
            self.database(), trust, read_json(ROOT / "platform/rollout/policy.json"),
            release_policy, read_json(ROOT / "platform/observability/capacity.json"),
            external.policy, external.trust,
        )
        operations_fields = {
            "releaseBindingDigest": binding,
            "targetDigest": rollout_target_digest(target),
            "rollbackTestPassed": True,
            "gitopsDriftCount": 0,
            "openCriticalIncidents": 0,
        }
        operations_receipt = attach_dsse({
            "receiptId": "release-operations-receipt-1",
            "receiptType": "RELEASE_OPERATIONS", "outcome": "VERIFIED",
            "fields": operations_fields, "actor": "operations-a",
            "role": "operations_verifier",
            "bindingDigest": receipt_binding("RELEASE_OPERATIONS", operations_fields),
            "nonce": "release-operations-nonce-0001",
            "issuedAt": "2026-08-25T23:00:00Z",
            "expiresAt": "2026-08-26T02:00:00Z",
        }, "operations", operations_private)
        shadow = [{"requestId": "request-1", "action": "AUTHORIZE", "amountMinor": 100,
                   "currency": "USD", "reasonCodes": [], "sideEffects": []}]
        capacity = {
            resource: [
                {"used": 10, "capacity": 100, "observedAt": f"2026-08-{day:02d}T00:00:00Z"}
                for day in (23, 24, 25)
            ]
            for resource in read_json(ROOT / "platform/observability/capacity.json")["resources"]
        }
        gate_inputs = {
            "releaseManifest": manifest,
            "productImageIndex": product_index,
            "shadowBaseline": shadow,
            "shadowCandidate": shadow,
            "canaryBaseline": self.metrics(),
            "canaryCandidate": self.metrics(),
            "capacitySamples": capacity,
            "operationsReceipt": operations_receipt,
            "externalEvidenceBundle": external_bundle,
        }
        evaluated_binding, evaluated = control.evaluate_gates(target, gate_inputs, now=NOW)
        self.assertEqual(binding, evaluated_binding)
        gate_doc = {
            name: {
                "allowed": report.allowed,
                "reasons": list(report.reasons),
                "checks": list(report.checks),
            }
            for name, report in sorted(evaluated.items())
        }
        decision = {"decisionId": "go-1", "actor": "release-a", "role": "release_manager", "decision": "GO", "bindingDigest": binding, "targetDigest": rollout_target_digest(target), "gateDigest": sha256_json(gate_doc), "gateInputsDigest": sha256_json(gate_inputs), "controlPolicyDigest": control.control_policy_digest(), "nonce": "release-decision-000001", "issuedAt": "2026-08-25T23:00:00Z", "expiresAt": "2026-08-26T02:00:00Z"}
        control.record_go_no_go(
            attach_dsse(decision, "rm", rm_private), target, gate_inputs, now=NOW,
        )
        with self.assertRaisesRegex(ValidationError, "artifact does not match"):
            control.start_rollout(
                "rollout-substitution", binding, target, "d" * 64, "f" * 64,
                now=NOW,
            )
        control.start_rollout("rollout-1", binding, target, "e" * 64, "f" * 64, now=NOW)
        control.policy["goNoGo"]["approvalMaximumAgeHours"] = 1
        with self.assertRaisesRegex(ValidationError, "control policy binding mismatch"):
            control.start_rollout(
                "rollout-stale-go", binding, target, "e" * 64, "f" * 64,
                now=NOW + timedelta(minutes=1),
            )
        control.policy["goNoGo"]["approvalMaximumAgeHours"] = 24
        with self.assertRaisesRegex(ValidationError, "external release evidence"):
            control.start_rollout(
                "rollout-stale-evidence", binding, target, "e" * 64, "f" * 64,
                now=NOW + timedelta(hours=1),
            )
        baseline = self.metrics()
        candidate = self.metrics(ledgerMismatchCount=1)
        metrics_digest = sha256_json({"baseline": baseline, "candidate": candidate})
        observation = {"observationId": "obs-1", "verifier": "observer-a", "role": "rollout_observer", "rolloutId": "rollout-1", "stage": "shadow", "trafficPercent": 0, "shadowDiffPassed": True, "targetDigest": rollout_target_digest(target), "metricsDigest": metrics_digest, "fenceToken": 1, "bindingDigest": binding, "observedAt": "2026-08-26T01:00:00Z", "nonce": "rollout-observation-0001", "issuedAt": "2026-08-26T00:59:00Z", "expiresAt": "2026-08-26T02:00:00Z"}
        calls: list[str] = []
        def rollback_adapter(request: Mapping[str, Any]) -> Mapping[str, Any]:
            fields = {key: value for key, value in request.items() if key != "mode"}
            calls.append(fields["previousArtifactDigest"])
            return {"receipt": attach_dsse({
                "receiptId": "rollout-rollback-receipt-1",
                "receiptType": "ROLLOUT_ROLLBACK",
                "outcome": "ROLLED_BACK",
                "fields": fields,
                "actor": "rollback-executor-a",
                "role": "rollout_rollback_executor",
                "bindingDigest": receipt_binding("ROLLOUT_ROLLBACK", fields),
                "nonce": "rollout-rollback-receipt-nonce-0001",
                "issuedAt": "2026-08-26T00:59:00Z",
                "expiresAt": "2026-08-26T02:00:00Z",
            }, "rollback", rollback_private)}

        future_observation = {
            **observation,
            "observationId": "obs-future",
            "observedAt": "2026-08-26T01:01:00Z",
            "nonce": "rollout-observation-future-0001",
        }
        with self.assertRaisesRegex(ValidationError, "cannot be in the future"):
            control.observe_and_advance(
                "rollout-1",
                attach_dsse(future_observation, "observer", observer_private),
                baseline, candidate, rollback_adapter,
                now=datetime(2026, 8, 26, 1, 0, tzinfo=timezone.utc),
            )
        result = control.observe_and_advance("rollout-1", attach_dsse(observation, "observer", observer_private), baseline, candidate, rollback_adapter, now=datetime(2026, 8, 26, 1, 0, tzinfo=timezone.utc))
        self.assertEqual("ROLLED_BACK", result["status"])
        self.assertEqual(["f" * 64], calls)

        control.start_rollout(
            "rollout-unknown", binding, target, "e" * 64, "f" * 64, now=NOW
        )
        unknown_observation = {
            **observation,
            "observationId": "obs-unknown",
            "rolloutId": "rollout-unknown",
            "nonce": "rollout-observation-unknown-0001",
        }
        with self.assertRaisesRegex(ValidationError, "outcome is UNKNOWN"):
            control.observe_and_advance(
                "rollout-unknown",
                attach_dsse(unknown_observation, "observer", observer_private),
                baseline,
                candidate,
                lambda _request: (_ for _ in ()).throw(TimeoutError("lost response")),
                now=datetime(2026, 8, 26, 1, 0, tzinfo=timezone.utc),
            )
        with control.store.connect() as connection:
            operation = connection.execute(
                "SELECT status,request_digest FROM rollout_rollback_operation "
                "WHERE rollout_id='rollout-unknown'"
            ).fetchone()
            rollout_state = connection.execute(
                "SELECT status FROM rollout_execution WHERE rollout_id='rollout-unknown'"
            ).fetchone()[0]
        self.assertEqual("UNKNOWN", operation["status"])
        self.assertEqual("UNKNOWN", rollout_state)

        def reconcile_adapter(request: Mapping[str, Any]) -> Mapping[str, Any]:
            fields = {key: value for key, value in request.items() if key != "mode"}
            return {"receipt": attach_dsse({
                "receiptId": "rollout-rollback-reconcile-receipt-1",
                "receiptType": "ROLLOUT_ROLLBACK",
                "outcome": "ROLLED_BACK",
                "fields": fields,
                "actor": "rollback-executor-a",
                "role": "rollout_rollback_executor",
                "bindingDigest": receipt_binding("ROLLOUT_ROLLBACK", fields),
                "nonce": "rollout-rollback-reconcile-nonce-0001",
                "issuedAt": "2026-08-26T01:00:00Z",
                "expiresAt": "2026-08-26T02:00:00Z",
            }, "rollback", rollback_private)}

        reconciled = control.reconcile_rollback(
            "rollout-unknown", reconcile_adapter,
            now=datetime(2026, 8, 26, 1, 1, tzinfo=timezone.utc),
        )
        self.assertEqual("ROLLED_BACK", reconciled["status"])
        replayed_rollback = control.reconcile_rollback(
            "rollout-unknown",
            lambda _request: (_ for _ in ()).throw(
                AssertionError("completed rollback must not redispatch")
            ),
            now=datetime(2026, 8, 26, 3, 0, tzinfo=timezone.utc),
        )
        self.assertTrue(replayed_rollback["duplicate"])

    def test_onboarding_requires_all_controls_four_eyes_and_external_activation(self) -> None:
        onboarding = OnboardingControl(self.database())
        onboarding.open_case("tenant-a", "case-a", "stripe", "merchant-a", "requester-a", "v1", now=NOW)
        controls = {
            "merchant_account": {"merchantAccountId": "merchant-a"},
            "domain": {"domain": "merchant.example", "verified": True},
            "certificate": {"certificateRef": "kms://elmpay/certs/merchant-a"},
            "webhook": {"url": "https://merchant.example/webhook", "signedRoundTripVerified": True},
            "limits": {"minorUnitLimits": {"daily": 100000}},
            "alerts": {"alertRouteRef": "alert://elmpay/merchant-a"},
            "billing": {"billingAccountRef": "billing://elmpay/merchant-a"},
            "emergency_contact": {"contactRef": "directory://elmpay/oncall-a"},
        }
        for name, details in controls.items():
            onboarding.verify_control("tenant-a", "case-a", name, details, now=NOW)
        with self.assertRaisesRegex(ValidationError, "self-approve"):
            onboarding.approve("tenant-a", "case-a", "requester-a", now=NOW)
        self.assertEqual(1, onboarding.approve("tenant-a", "case-a", "reviewer-a", now=NOW))
        self.assertEqual(2, onboarding.approve("tenant-a", "case-a", "reviewer-b", now=NOW))
        ready = OnboardingControl(self.database()).readiness("tenant-a", "case-a")
        self.assertEqual("READY_FOR_EXTERNAL_ACTIVATION", ready["state"])
        self.assertEqual("NOT_CERTIFIED", ready["certificationStatus"])
        with self.assertRaisesRegex(ValidationError, "verifier is not configured"):
            onboarding.activate(
                "tenant-a", "case-a", {}, lambda row: row["configuration_digest"], now=NOW
            )
        with onboarding.store.transaction() as connection:
            configuration_digest = connection.execute(
                "SELECT configuration_digest FROM onboarding_case "
                "WHERE tenant_id='tenant-a' AND case_id='case-a'"
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO external_control_operation VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "tenant-a", "ONBOARDING_ACTIVATION", "case-a",
                    configuration_digest, "a" * 64, "UNKNOWN", 1,
                    "onboarding:tenant-a:case-a",
                    (NOW - timedelta(minutes=1)).isoformat(), None, NOW.isoformat(),
                ),
            )
        self.assertEqual(
            "ACTIVE",
            onboarding.reconcile_activation(
                "tenant-a", "case-a", lambda request: request["configurationDigest"],
                now=NOW,
            ),
        )
        self.assertEqual(
            "ACTIVE",
            onboarding.reconcile_activation(
                "tenant-a", "case-a", lambda _request: "must-not-run", now=NOW,
            ),
        )
        with onboarding.store.connect() as connection:
            operation = connection.execute(
                "SELECT status,fence_token FROM external_control_operation "
                "WHERE tenant_id='tenant-a' AND operation_type='ONBOARDING_ACTIVATION' "
                "AND operation_id='case-a'"
            ).fetchone()
        self.assertEqual(("SUCCEEDED", 2), tuple(operation))

    def test_fencing_reconciliation_and_four_eyes_commercial_ledger(self) -> None:
        database = self.database()
        postlaunch = PostLaunchControl(database)
        token = postlaunch.acquire("reconcile:tenant-a:DAILY", "worker-a", now=NOW)
        start, end = postlaunch.window("DAILY", NOW - timedelta(days=1))
        window_id = f"daily:{start.isoformat()}"
        receipts, source_trust = self.reconciliation_sources(
            tenant_id="tenant-a", window_id=window_id, window_kind="DAILY",
            period_start=start, period_end=end, currency="USD",
            totals={"transaction": 100, "provider": 100, "bank": 99},
            prefix="direct-reconcile",
        )
        blocked = postlaunch.reconcile(
            tenant_id="tenant-a", window_id=window_id, window_kind="DAILY",
            period_start=start, period_end=end, currency="USD",
            source_receipts=receipts, trust=source_trust,
            job_key="reconcile:tenant-a:DAILY", owner_id="worker-a",
            fence_token=token, now=NOW,
        )
        self.assertFalse(blocked["allowedToClose"])
        tampered = {**receipts, "bank": {
            **receipts["bank"], "fields": {**receipts["bank"]["fields"], "totalMinor": 100}
        }}
        with self.assertRaisesRegex(ValidationError, "binding|payload|fields"):
            postlaunch.reconcile(
                tenant_id="tenant-a", window_id=window_id, window_kind="DAILY",
                period_start=start, period_end=end, currency="USD",
                source_receipts=tampered, trust=source_trust,
                job_key="reconcile:tenant-a:DAILY", owner_id="worker-a",
                fence_token=token, now=NOW,
            )
        postlaunch.acquire("reconcile:tenant-a:DAILY", "worker-a", now=NOW)
        with self.assertRaisesRegex(ValidationError, "stale"):
            postlaunch.assert_fence("reconcile:tenant-a:DAILY", "worker-a", token, now=NOW)

        ledger = CommercialLedger(database)
        policy = read_json(ROOT / "platform/rollout/billing-policy.json")
        pricing = ledger.create_pricing(
            "tenant-a", "v1", policy, NOW - timedelta(days=1), actor="billing-a", now=NOW
        )
        event = {"tenantId": "tenant-a", "meter": "payment_attempt", "attempt_id": "attempt-1", "occurredAt": "2026-08-26T00:10:00Z"}
        event_time = NOW + timedelta(minutes=10)
        self.assertTrue(ledger.meter("tenant-a", pricing, event, actor="meter-worker", now=event_time))
        self.assertFalse(ledger.meter("tenant-a", pricing, event, actor="meter-worker", now=event_time))
        invoice_time = NOW + timedelta(days=1)
        invoice = ledger.issue_invoice(
            "invoice-1", "tenant-a", pricing, NOW, NOW + timedelta(days=1),
            actor="billing-a", now=invoice_time,
        )
        self.assertEqual(3, invoice["subtotalMinor"])
        ledger.set_sla(
            "tenant-a", "gold-v1", NOW - timedelta(days=1), 30, 1000,
            actor="support-admin", now=invoice_time + timedelta(minutes=1),
        )
        ledger.open_ticket(
            "ticket-1", "tenant-a", "SEV1", actor="support-a",
            opened_at=invoice_time + timedelta(minutes=2),
        )
        response = CommercialLedger(database).respond_ticket(
            "ticket-1", "tenant-a", "support-a",
            responded_at=invoice_time + timedelta(minutes=33),
        )
        self.assertTrue(response["slaBreached"])
        credit_time = invoice_time + timedelta(minutes=34)
        self.assertTrue(ledger.request_credit(
            "credit-1", "tenant-a", "invoice-1", "requester-a", 2, "SLA breach",
            now=credit_time,
        ))
        self.assertFalse(ledger.request_credit(
            "credit-1", "tenant-a", "invoice-1", "requester-a", 2, "SLA breach",
            now=credit_time + timedelta(seconds=1),
        ))
        with self.assertRaisesRegex(ValidationError, "distinct"):
            ledger.approve_credit(
                "credit-1", "tenant-a", "requester-a", now=credit_time
            )
        with self.assertRaisesRegex(ValidationError, "not pending"):
            ledger.approve_credit(
                "credit-1", "tenant-b", "approver-b", now=credit_time
            )
        memo = CommercialLedger(database).approve_credit(
            "credit-1", "tenant-a", "approver-b", now=credit_time + timedelta(minutes=1)
        )
        self.assertEqual(2, memo["amountMinor"])
        self.assertEqual(
            memo,
            CommercialLedger(database).approve_credit(
                "credit-1", "tenant-a", "approver-b",
                now=credit_time + timedelta(minutes=2),
            ),
        )
        self.assertEqual(1, ledger.net_invoice_minor("tenant-a", "invoice-1"))
        manifest = ledger.build_audit_manifest(
            "tenant-a", NOW - timedelta(days=2), NOW + timedelta(days=2)
        )
        self.assertEqual(8, manifest["eventCount"])
        self.assertEqual(
            [
                "PRICING_CREATED", "USAGE_METERED", "INVOICE_ISSUED", "SLA_CREATED",
                "TICKET_OPENED", "TICKET_RESPONDED", "CREDIT_REQUESTED", "CREDIT_APPROVED",
            ],
            [event["eventType"] for event in manifest["events"]],
        )

    def test_postlaunch_requires_completed_item_matched_windows(self) -> None:
        control = PostLaunchControl(self.database("postlaunch-negative.db"))
        token = control.acquire("reconcile:tenant-a:DAILY", "worker-a", now=NOW)
        completed_start, completed_end = control.window("DAILY", NOW - timedelta(days=1))
        completed_window_id = f"daily:{completed_start.isoformat()}"
        completed_receipts, completed_trust = self.reconciliation_sources(
            tenant_id="tenant-a", window_id=completed_window_id, window_kind="DAILY",
            period_start=completed_start, period_end=completed_end, currency="USD",
            totals={"transaction": 100, "provider": 100, "bank": 100},
            prefix="completed-window",
        )
        closed = control.reconcile(
            tenant_id="tenant-a", window_id=completed_window_id, window_kind="DAILY",
            period_start=completed_start, period_end=completed_end, currency="USD",
            source_receipts=completed_receipts, trust=completed_trust,
            job_key="reconcile:tenant-a:DAILY", owner_id="worker-a",
            fence_token=token, now=NOW,
        )
        self.assertTrue(closed["allowedToClose"])
        self.assertTrue(closed["itemLevelMatch"])
        with control.store.transaction() as connection:
            connection.execute(
                "DELETE FROM reconciliation_source_receipt WHERE tenant_id=? "
                "AND window_id=? AND source='bank'",
                ("tenant-a", completed_window_id),
            )
        with self.assertRaisesRegex(ValidationError, "incomplete or corrupt"):
            control.reconcile(
                tenant_id="tenant-a", window_id=completed_window_id,
                window_kind="DAILY", period_start=completed_start,
                period_end=completed_end, currency="USD",
                source_receipts=completed_receipts, trust=completed_trust,
                job_key="reconcile:tenant-a:DAILY", owner_id="worker-a",
                fence_token=token, now=NOW,
            )

        future_start, future_end = control.window("DAILY", NOW)
        future_window_id = f"daily:{future_start.isoformat()}"
        future_receipts, future_trust = self.reconciliation_sources(
            tenant_id="tenant-a", window_id=future_window_id, window_kind="DAILY",
            period_start=future_start, period_end=future_end, currency="USD",
            totals={"transaction": 100, "provider": 100, "bank": 100},
            prefix="future-window",
        )
        with self.assertRaisesRegex(ValidationError, "must be complete"):
            control.reconcile(
                tenant_id="tenant-a", window_id=future_window_id, window_kind="DAILY",
                period_start=future_start, period_end=future_end, currency="USD",
                source_receipts=future_receipts, trust=future_trust,
                job_key="reconcile:tenant-a:DAILY", owner_id="worker-a",
                fence_token=token, now=NOW,
            )

        partial_start = NOW - timedelta(hours=1)
        partial_end = NOW
        partial_window_id = f"daily:{future_start.isoformat()}"
        partial_receipts, partial_trust = self.reconciliation_sources(
            tenant_id="tenant-a", window_id=partial_window_id, window_kind="DAILY",
            period_start=partial_start, period_end=partial_end, currency="USD",
            totals={"transaction": 100, "provider": 100, "bank": 100},
            prefix="partial-window",
        )
        with self.assertRaisesRegex(ValidationError, "canonical window"):
            control.reconcile(
                tenant_id="tenant-a", window_id=partial_window_id, window_kind="DAILY",
                period_start=partial_start, period_end=partial_end, currency="USD",
                source_receipts=partial_receipts, trust=partial_trust,
                job_key="reconcile:tenant-a:DAILY", owner_id="worker-a",
                fence_token=token, now=NOW,
            )

        mismatch_start, mismatch_end = control.window("DAILY", NOW - timedelta(days=2))
        mismatch_window_id = f"daily:{mismatch_start.isoformat()}"
        mismatch_receipts, mismatch_trust = self.reconciliation_sources(
            tenant_id="tenant-a", window_id=mismatch_window_id, window_kind="DAILY",
            period_start=mismatch_start, period_end=mismatch_end, currency="USD",
            totals={"transaction": 100, "provider": 100, "bank": 100},
            prefix="item-mismatch",
            item_keys_by_source={"bank": ["payment:one", "payment:other"]},
        )
        blocked = control.reconcile(
            tenant_id="tenant-a", window_id=mismatch_window_id, window_kind="DAILY",
            period_start=mismatch_start, period_end=mismatch_end, currency="USD",
            source_receipts=mismatch_receipts, trust=mismatch_trust,
            job_key="reconcile:tenant-a:DAILY", owner_id="worker-a",
            fence_token=token, now=NOW,
        )
        self.assertFalse(blocked["allowedToClose"])
        self.assertEqual("item_level_snapshot_mismatch", blocked["reason"])
        self.assertEqual(0, blocked["openDeltaMinor"])

    def test_completed_reconciliation_replays_exact_receipts_after_expiry(self) -> None:
        control = PostLaunchControl(self.database("postlaunch-replay.db"))
        start, end = control.window("DAILY", NOW - timedelta(days=1))
        window_id = f"daily:{start.isoformat()}"
        receipts, trust = self.reconciliation_sources(
            tenant_id="tenant-a", window_id=window_id, window_kind="DAILY",
            period_start=start, period_end=end, currency="USD",
            totals={"transaction": 100, "provider": 100, "bank": 100},
            prefix="completed-replay",
        )
        job_key = "reconcile:tenant-a:DAILY"
        token = control.acquire(job_key, "worker-a", now=NOW)
        closed = control.reconcile(
            tenant_id="tenant-a", window_id=window_id, window_kind="DAILY",
            period_start=start, period_end=end, currency="USD",
            source_receipts=receipts, trust=trust, job_key=job_key,
            owner_id="worker-a", fence_token=token, now=NOW,
        )
        replay_now = NOW + timedelta(days=1)
        replay_token = control.acquire(job_key, "worker-a", now=replay_now)
        replayed = control.reconcile(
            tenant_id="tenant-a", window_id=window_id, window_kind="DAILY",
            period_start=start, period_end=end, currency="USD",
            source_receipts=receipts, trust=trust, job_key=job_key,
            owner_id="worker-a", fence_token=replay_token, now=replay_now,
        )
        self.assertEqual(closed["digest"], replayed["digest"])
        self.assertTrue(replayed["allowedToClose"])

    def test_usage_binds_active_pricing_and_invoices_each_event_version(self) -> None:
        ledger = CommercialLedger(self.database("pricing-provenance.db"))
        base_policy = read_json(ROOT / "platform/rollout/billing-policy.json")
        first = ledger.create_pricing(
            "tenant-a", "v1", base_policy, NOW - timedelta(days=1),
            actor="billing-a", now=NOW,
        )
        second_policy = {
            **base_policy,
            "meters": [
                {**meter, "unitPriceMinor": int(meter["unitPriceMinor"]) + 10}
                for meter in base_policy["meters"]
            ],
        }
        second = ledger.create_pricing(
            "tenant-a", "v2", second_policy, NOW + timedelta(hours=12),
            actor="billing-a", now=NOW,
        )
        with self.assertRaisesRegex(ValidationError, "pricing version is immutable"):
            ledger.create_pricing(
                "tenant-a", "v2", second_policy, NOW + timedelta(hours=13),
                actor="billing-a", now=NOW,
            )
        first_event = {
            "tenantId": "tenant-a", "meter": "payment_attempt",
            "attempt_id": "attempt-v1", "occurredAt": (NOW + timedelta(hours=1)).isoformat(),
        }
        ledger.meter(
            "tenant-a", first, first_event, actor="meter-worker",
            now=NOW + timedelta(hours=1),
        )
        with self.assertRaisesRegex(ValidationError, "not effective"):
            ledger.meter(
                "tenant-a", second,
                {**first_event, "attempt_id": "attempt-premature"},
                actor="meter-worker", now=NOW + timedelta(hours=1),
            )
        second_event = {
            "tenantId": "tenant-a", "meter": "payment_attempt",
            "attempt_id": "attempt-v2", "occurredAt": (NOW + timedelta(hours=13)).isoformat(),
        }
        ledger.meter(
            "tenant-a", second, second_event, actor="meter-worker",
            now=NOW + timedelta(hours=13),
        )
        with ledger.store.connect() as connection:
            bindings = connection.execute(
                "SELECT dedupe_key,pricing_version_id FROM usage_event ORDER BY dedupe_key"
            ).fetchall()
        self.assertEqual(
            [("attempt-v1", first), ("attempt-v2", second)],
            [(row["dedupe_key"], row["pricing_version_id"]) for row in bindings],
        )
        invoice = ledger.issue_invoice(
            "mixed-invoice", "tenant-a", first, NOW, NOW + timedelta(days=1),
            actor="billing-a", now=NOW + timedelta(days=1),
        )
        self.assertEqual(16, invoice["subtotalMinor"])
        self.assertEqual({first, second}, set(invoice["pricingVersionIds"]))
        self.assertEqual(
            {(first, 3), (second, 13)},
            {(line["pricingVersionId"], line["unitPriceMinor"]) for line in invoice["lines"]},
        )

    def test_commercial_future_usage_and_incomplete_invoice_fail_closed(self) -> None:
        ledger = CommercialLedger(self.database("commercial-time-window.db"))
        pricing = ledger.create_pricing(
            "tenant-a", "v1",
            read_json(ROOT / "platform/rollout/billing-policy.json"),
            NOW - timedelta(days=1), actor="billing-a", now=NOW,
        )
        with self.assertRaisesRegex(ValidationError, "future"):
            ledger.meter(
                "tenant-a", pricing,
                {"tenantId": "tenant-a", "meter": "payment_attempt",
                 "attempt_id": "future-attempt",
                 "occurredAt": (NOW + timedelta(minutes=6)).isoformat()},
                actor="meter-worker", now=NOW,
            )
        with self.assertRaisesRegex(ValidationError, "complete"):
            ledger.issue_invoice(
                "incomplete-invoice", "tenant-a", pricing,
                NOW, NOW + timedelta(days=1), actor="billing-a", now=NOW,
            )

    def test_concurrent_credit_requests_cannot_overdraw_invoice(self) -> None:
        database = self.database("credit-concurrency.db")
        ledger = CommercialLedger(database)
        policy = read_json(ROOT / "platform/rollout/billing-policy.json")
        policy = {
            **policy,
            "meters": [
                {**meter, "unitPriceMinor": 10}
                if meter["name"] == "payment_attempt" else meter
                for meter in policy["meters"]
            ],
        }
        pricing = ledger.create_pricing(
            "tenant-a", "credit-v1", policy, NOW - timedelta(days=1),
            actor="billing-a", now=NOW,
        )
        ledger.meter(
            "tenant-a", pricing,
            {"tenantId": "tenant-a", "meter": "payment_attempt",
             "attempt_id": "credit-attempt", "occurredAt": NOW.isoformat()},
            actor="meter-worker", now=NOW,
        )
        invoice = ledger.issue_invoice(
            "credit-invoice", "tenant-a", pricing, NOW, NOW + timedelta(days=1),
            actor="billing-a", now=NOW + timedelta(days=1),
        )
        self.assertEqual(10, invoice["subtotalMinor"])

        def reserve(index: int) -> tuple[int, bool]:
            try:
                CommercialLedger(database).request_credit(
                    f"concurrent-credit-{index}", "tenant-a", "credit-invoice",
                    f"requester-{index}", 4, "concurrent cap test",
                    now=NOW + timedelta(minutes=1),
                )
                return index, True
            except ValidationError:
                return index, False

        with ThreadPoolExecutor(max_workers=4) as executor:
            outcomes = list(executor.map(reserve, range(4)))
        accepted = [index for index, allowed in outcomes if allowed]
        self.assertEqual(2, len(accepted))
        with ledger.store.connect() as connection:
            reserved = connection.execute(
                "SELECT sum(amount_minor) FROM credit_request WHERE invoice_id=?",
                ("credit-invoice",),
            ).fetchone()[0]
        self.assertEqual(8, reserved)
        for index in accepted:
            ledger.approve_credit(
                f"concurrent-credit-{index}", "tenant-a", f"approver-{index}",
                now=NOW + timedelta(minutes=2),
            )
        self.assertEqual(2, ledger.net_invoice_minor("tenant-a", "credit-invoice"))

    def test_legacy_usage_without_pricing_provenance_fails_closed(self) -> None:
        database = self.database("legacy-usage.db")
        with sqlite3.connect(database) as connection:
            connection.executescript("""
                CREATE TABLE usage_event (
                  tenant_id TEXT NOT NULL,
                  meter TEXT NOT NULL,
                  dedupe_key TEXT NOT NULL,
                  occurred_at TEXT NOT NULL,
                  payload_digest TEXT NOT NULL CHECK(length(payload_digest)=64),
                  PRIMARY KEY (tenant_id, meter, dedupe_key)
                );
                INSERT INTO usage_event VALUES(
                  'tenant-a','payment_attempt','legacy-attempt',
                  '2026-08-26T00:00:00+00:00',
                  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                );
            """)
        ledger = CommercialLedger(database)
        with ledger.store.connect() as connection:
            columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(usage_event)")
            }
        self.assertIn("pricing_version_id", columns)
        pricing = ledger.create_pricing(
            "tenant-a", "legacy-v1",
            read_json(ROOT / "platform/rollout/billing-policy.json"),
            NOW - timedelta(days=1), actor="billing-a", now=NOW,
        )
        with self.assertRaisesRegex(ValidationError, "without pricing provenance"):
            ledger.issue_invoice(
                "legacy-invoice", "tenant-a", pricing, NOW, NOW + timedelta(days=1),
                actor="billing-a", now=NOW + timedelta(days=1),
            )

    def test_commercial_cli_executes_and_exports_a_signed_audit_chain(self) -> None:
        root = Path(self.temporary.name)
        database = self.database("commercial-cli.db")
        policy = read_json(ROOT / "platform/rollout/billing-policy.json")
        pricing_request = root / "pricing-request.json"
        pricing_request.write_text(json.dumps({
            "tenantId": "tenant-a", "version": "v1", "policy": policy,
            "effectiveAt": "2026-08-25T00:00:00Z", "actor": "billing-a",
            "now": "2026-08-26T00:00:00Z",
        }), encoding="utf-8")
        created = subprocess.run(
            [
                sys.executable, str(ROOT / "tools/runtime/commercial_control.py"),
                "--database", database, "create-pricing", "--request", str(pricing_request),
            ],
            cwd=ROOT, check=False, capture_output=True, text=True,
        )
        self.assertEqual(0, created.returncode, created.stderr + created.stdout)

        period_start = datetime(2026, 8, 25, tzinfo=timezone.utc)
        period_end = datetime(2026, 8, 27, tzinfo=timezone.utc)
        manifest = CommercialLedger(database).build_audit_manifest(
            "tenant-a", period_start, period_end
        )
        private, public = generate_ed25519_keypair()
        trust = {
            "replayDatabase": self.database("commercial-export-nonces.db"),
            "keys": {"audit-signer": {
                "algorithm": "Ed25519", "publicKeyPem": public,
                "identity": "kms-audit-signer", "role": "audit_export_signer",
                "independent": False, "revoked": False,
                "notBefore": "2026-08-01T00:00:00Z",
                "notAfter": "2026-09-01T00:00:00Z",
            }},
        }
        with self.assertRaisesRegex(ValidationError, "complete"):
            CommercialLedger(database).finalize_audit_export(
                export_id="future-audit-export", tenant_id="tenant-a",
                period_start=period_start, period_end=period_end,
                receipt={}, trust=trust, now=NOW,
            )
        fields = {
            "exportId": "audit-export-1", "tenantId": "tenant-a",
            "periodStart": period_start.isoformat(), "periodEnd": period_end.isoformat(),
            "manifestDigest": manifest["manifestDigest"],
            "eventCount": manifest["eventCount"], "endingDigest": manifest["endingDigest"],
        }
        receipt = attach_dsse({
            "receiptId": "commercial-audit-export-receipt-0001",
            "receiptType": "COMMERCIAL_AUDIT_EXPORT", "outcome": "SIGNED",
            "fields": fields, "actor": "kms-audit-signer", "role": "audit_export_signer",
            "bindingDigest": receipt_binding("COMMERCIAL_AUDIT_EXPORT", fields),
            "nonce": "commercial-export-nonce-0001",
            "issuedAt": "2026-08-27T00:01:00Z",
            "expiresAt": "2026-08-27T02:00:00Z",
        }, "audit-signer", private)
        request_path = root / "audit-export-request.json"
        trust_path = root / "audit-export-trust.json"
        output_path = root / "audit-export.json"
        request_path.write_text(json.dumps({
            "exportId": "audit-export-1", "tenantId": "tenant-a",
            "periodStart": period_start.isoformat(), "periodEnd": period_end.isoformat(),
            "receipt": receipt, "now": "2026-08-27T00:30:00Z",
        }), encoding="utf-8")
        trust_path.write_text(json.dumps(trust), encoding="utf-8")
        exported = subprocess.run(
            [
                sys.executable, str(ROOT / "tools/runtime/commercial_control.py"),
                "--database", database, "export-audit", "--request", str(request_path),
                "--trust", str(trust_path), "--output", str(output_path),
            ],
            cwd=ROOT, check=False, capture_output=True, text=True,
        )
        self.assertEqual(0, exported.returncode, exported.stderr + exported.stdout)
        document = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["manifestDigest"], document["manifest"]["manifestDigest"])
        self.assertEqual("kms-audit-signer", document["signerIdentity"])
        replayed = CommercialLedger(database).finalize_audit_export(
            export_id="audit-export-1", tenant_id="tenant-a",
            period_start=period_start, period_end=period_end,
            receipt=receipt, trust=trust,
            now=datetime(2026, 8, 28, tzinfo=timezone.utc),
        )
        self.assertEqual(document, replayed)

        unsigned_path = root / "unsigned-export-request.json"
        unsigned_path.write_text(json.dumps({
            "exportId": "audit-export-2", "tenantId": "tenant-a",
            "periodStart": period_start.isoformat(), "periodEnd": period_end.isoformat(),
            "receipt": {"signatureVerified": True},
            "now": "2026-08-27T00:30:00Z",
        }), encoding="utf-8")
        rejected = subprocess.run(
            [
                sys.executable, str(ROOT / "tools/runtime/commercial_control.py"),
                "--database", database, "export-audit", "--request", str(unsigned_path),
                "--trust", str(trust_path), "--output", str(root / "unsigned.json"),
            ],
            cwd=ROOT, check=False, capture_output=True, text=True,
        )
        self.assertEqual(2, rejected.returncode)
        self.assertFalse((root / "unsigned.json").exists())

    def test_postlaunch_cron_entrypoint_blocks_an_open_delta(self) -> None:
        execution_now = datetime.now(timezone.utc)
        anchor = execution_now - timedelta(days=1)
        start, end = PostLaunchControl.window("DAILY", anchor)
        window_id = f"daily:{start.isoformat()}"
        receipts, source_trust = self.reconciliation_sources(
            tenant_id="tenant-a", window_id=window_id, window_kind="DAILY",
            period_start=start, period_end=end, currency="USD",
            totals={"transaction": 10, "provider": 10, "bank": 9},
            prefix="cron-reconcile",
            verification_time=execution_now,
        )
        receipts_path = Path(self.temporary.name) / "source-receipts.json"
        trust_path = Path(self.temporary.name) / "source-trust.json"
        receipts_path.write_text(json.dumps(receipts), encoding="utf-8")
        trust_path.write_text(json.dumps(source_trust), encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable, str(ROOT / "tools/runtime/postlaunch_worker.py"),
                "--database", self.database(), "--tenant", "tenant-a", "--owner", "cron-a",
                "--kind", "DAILY", "--anchor", anchor.isoformat(),
                "--currency", "USD", "--source-receipts", str(receipts_path),
                "--source-trust", str(trust_path),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(2, result.returncode)
        self.assertEqual("open_reconciliation_delta", json.loads(result.stdout)["reason"])

    def test_postlaunch_worker_uses_wall_clock_not_historical_anchor(self) -> None:
        execution_now = datetime.now(timezone.utc)
        anchor = execution_now - timedelta(days=1)
        start, end = PostLaunchControl.window("DAILY", anchor)
        window_id = f"daily:{start.isoformat()}"
        receipts, source_trust = self.reconciliation_sources(
            tenant_id="tenant-a", window_id=window_id, window_kind="DAILY",
            period_start=start, period_end=end, currency="USD",
            totals={"transaction": 10, "provider": 10, "bank": 10},
            prefix="stale-cron-reconcile",
            verification_time=anchor,
        )
        root = Path(self.temporary.name)
        receipts_path = root / "stale-source-receipts.json"
        trust_path = root / "stale-source-trust.json"
        receipts_path.write_text(json.dumps(receipts), encoding="utf-8")
        trust_path.write_text(json.dumps(source_trust), encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable, str(ROOT / "tools/runtime/postlaunch_worker.py"),
                "--database", self.database("stale-worker.db"),
                "--tenant", "tenant-a", "--owner", "cron-a",
                "--kind", "DAILY", "--anchor", anchor.isoformat(),
                "--currency", "USD", "--source-receipts", str(receipts_path),
                "--source-trust", str(trust_path),
            ],
            cwd=ROOT, check=False, capture_output=True, text=True,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("attestation_time_window_invalid", json.loads(result.stdout)["reason"])

    @staticmethod
    def metrics(**overrides: object) -> dict[str, object]:
        value: dict[str, object] = {"requestCount": 1000, "errorRate": 0.001, "latencyP99Ms": 200, "authorizationRate": 0.9, "ledgerMismatchCount": 0, "duplicateSideEffectCount": 0, "securityCriticalCount": 0}
        value.update(overrides)
        return value


if __name__ == "__main__":
    unittest.main()
