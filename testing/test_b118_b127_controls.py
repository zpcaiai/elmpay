from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import subprocess
import tempfile
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
    ) -> tuple[dict[str, object], dict[str, object]]:
        roles = {
            "transaction": ("ledger-source", "ledger_reconciliation_source", False),
            "provider": ("provider-source", "provider_reconciliation_source", True),
            "bank": ("bank-source", "bank_reconciliation_source", True),
        }
        keys: dict[str, object] = {}
        receipts: dict[str, object] = {}
        for index, (source, (identity, role, independent)) in enumerate(roles.items()):
            private, public = generate_ed25519_keypair()
            keys[source] = {
                "algorithm": "Ed25519", "publicKeyPem": public,
                "identity": identity, "role": role, "independent": independent,
                "revoked": False, "notBefore": "2026-08-01T00:00:00Z",
                "notAfter": "2026-09-01T00:00:00Z",
            }
            fields = {
                "source": source, "tenantId": tenant_id, "windowId": window_id,
                "windowKind": window_kind,
                "periodStart": period_start.astimezone(timezone.utc).isoformat(),
                "periodEnd": period_end.astimezone(timezone.utc).isoformat(),
                "currency": currency, "totalMinor": totals[source],
                "recordCount": 10 + index,
                "sourceSnapshotDigest": sha256_json({"source": source, "prefix": prefix}),
            }
            receipts[source] = attach_dsse({
                "receiptId": f"{prefix}-{source}-receipt",
                "receiptType": "RECONCILIATION_SOURCE_TOTAL", "outcome": "FINAL",
                "fields": fields, "actor": identity, "role": role,
                "bindingDigest": receipt_binding("RECONCILIATION_SOURCE_TOTAL", fields),
                "nonce": f"{prefix}-{source}-nonce-0001",
                "issuedAt": "2026-08-25T23:00:00Z",
                "expiresAt": "2026-08-26T02:00:00Z",
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
        pipeline = MigrationPipeline(self.database())
        digest = pipeline.register(tenant_id="tenant-a", project_id="project-a", source_system="legacy", canonical_version="payment-v2", mapping={"amount": "amountMinor"}, credential_ref="vault://elmpay/migration/a", now=NOW)
        self.assertEqual(64, len(digest))
        self.assertTrue(pipeline.checkpoint("tenant-a", "project-a", "payments", 1, {"id": "p1"}, now=NOW))
        self.assertFalse(pipeline.checkpoint("tenant-a", "project-a", "payments", 1, {"id": "p1"}, now=NOW))
        with self.assertRaises(ValidationError):
            pipeline.checkpoint("tenant-a", "project-a", "payments", 0, {"id": "p0"}, now=NOW)
        self.assertTrue(pipeline.ingest_fact("tenant-a", "project-a", "legacy-1", "payment-v2", {"amountMinor": 100, "currency": "USD", "customerEmail": "person@example.test"}, now=NOW))
        with pipeline.store.connect() as connection:
            stored = connection.execute("SELECT canonical_json FROM migration_fact WHERE source_record_id='legacy-1'").fetchone()[0]
        self.assertNotIn("person@example.test", stored)
        self.assertIn("[REDACTED]", stored)
        self.assertTrue(pipeline.accept_webhook("tenant-a", "project-a", "delivery-1", {"event": "payment"}, now=NOW))
        baseline = [{"requestId": "r1", "action": "APPROVE", "amountMinor": 100, "currency": "USD"}]
        candidate = [{**baseline[0], "sideEffects": []}]
        result = pipeline.shadow("tenant-a", "project-a", "shadow-1", "payment-v2", baseline, candidate, now=NOW)
        self.assertEqual("PASSED", result["status"])
        reopened = MigrationPipeline(self.database()).shadow("tenant-a", "project-a", "shadow-1", "payment-v2", baseline, candidate, now=NOW)
        self.assertEqual(result["resultDigest"], reopened["resultDigest"])

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
        trust = {"replayDatabase": self.database("release-nonces.db"), "keys": {
            "rm": {"algorithm": "Ed25519", "publicKeyPem": rm_public, "identity": "release-a", "role": "release_manager", "independent": False, "revoked": False, "notBefore": "2026-08-01T00:00:00Z", "notAfter": "2026-09-01T00:00:00Z"},
            "observer": {"algorithm": "Ed25519", "publicKeyPem": observer_public, "identity": "observer-a", "role": "rollout_observer", "independent": True, "revoked": False, "notBefore": "2026-08-01T00:00:00Z", "notAfter": "2026-09-01T00:00:00Z"},
            "operations": {"algorithm": "Ed25519", "publicKeyPem": operations_public, "identity": "operations-a", "role": "operations_verifier", "independent": True, "revoked": False, "notBefore": "2026-08-01T00:00:00Z", "notAfter": "2026-09-01T00:00:00Z"},
        }}
        external = ExternalEvidenceGateTest()
        external.setUp()
        self.addCleanup(external.doCleanups)
        manifest = {
            "releaseId": "release-control-1", "commitSha": "c" * 40,
            "artifactDigest": "e" * 64,
            "images": {"payment": "registry.example/payment@sha256:" + "a" * 64},
            "generatedAt": "2026-08-25T22:00:00Z",
            "expiresAt": "2026-08-26T03:00:00Z", "approvals": [], "evidence": [],
        }
        binding = release_binding(manifest)
        external_bundle = external._bundle()
        external_bundle["releaseBindingDigest"] = binding
        for item in external_bundle["evidence"]:
            item["bindingDigest"] = binding
            external._resign(item, external._key_id(item))
        release_policy = {
            "maximumApprovalAgeHours": 24, "requiredApprovalRoles": [],
            "minimumDistinctApprovers": 0, "requiredEvidence": [],
            "evidenceMustBeIndependent": True,
        }
        control = ReleaseControl(
            self.database(), trust, read_json(ROOT / "platform/rollout/policy.json"),
            release_policy, read_json(ROOT / "platform/observability/capacity.json"),
            external.policy, external.trust,
        )
        target = {"tenantId": "tenant-a", "projectId": "project-a", "providerId": "stripe", "region": "us-east-1"}
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
        decision = {"decisionId": "go-1", "actor": "release-a", "role": "release_manager", "decision": "GO", "bindingDigest": binding, "targetDigest": rollout_target_digest(target), "gateDigest": sha256_json(gate_doc), "nonce": "release-decision-000001", "issuedAt": "2026-08-25T23:00:00Z", "expiresAt": "2026-08-26T02:00:00Z"}
        control.record_go_no_go(
            attach_dsse(decision, "rm", rm_private), target, gate_inputs, now=NOW,
        )
        control.start_rollout("rollout-1", binding, target, "e" * 64, "f" * 64, now=NOW)
        baseline = self.metrics()
        candidate = self.metrics(ledgerMismatchCount=1)
        metrics_digest = sha256_json({"baseline": baseline, "candidate": candidate})
        observation = {"observationId": "obs-1", "verifier": "observer-a", "role": "rollout_observer", "rolloutId": "rollout-1", "stage": "shadow", "trafficPercent": 0, "shadowDiffPassed": True, "targetDigest": rollout_target_digest(target), "metricsDigest": metrics_digest, "bindingDigest": binding, "observedAt": "2026-08-26T01:00:00Z", "nonce": "rollout-observation-0001", "issuedAt": "2026-08-26T00:59:00Z", "expiresAt": "2026-08-26T02:00:00Z"}
        calls: list[str] = []
        result = control.observe_and_advance("rollout-1", attach_dsse(observation, "observer", observer_private), baseline, candidate, lambda row: calls.append(row["previous_artifact_digest"]) or row["previous_artifact_digest"], now=datetime(2026, 8, 26, 1, 0, tzinfo=timezone.utc))
        self.assertEqual("ROLLED_BACK", result["status"])
        self.assertEqual(["f" * 64], calls)

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

    def test_fencing_reconciliation_and_four_eyes_commercial_ledger(self) -> None:
        database = self.database()
        postlaunch = PostLaunchControl(database)
        token = postlaunch.acquire("reconcile:tenant-a", "worker-a", now=NOW)
        start, end = postlaunch.window("DAILY", NOW)
        receipts, source_trust = self.reconciliation_sources(
            tenant_id="tenant-a", window_id="2026-08-26", window_kind="DAILY",
            period_start=start, period_end=end, currency="USD",
            totals={"transaction": 100, "provider": 100, "bank": 99},
            prefix="direct-reconcile",
        )
        blocked = postlaunch.reconcile(
            tenant_id="tenant-a", window_id="2026-08-26", window_kind="DAILY",
            period_start=start, period_end=end, currency="USD",
            source_receipts=receipts, trust=source_trust,
            job_key="reconcile:tenant-a", owner_id="worker-a",
            fence_token=token, now=NOW,
        )
        self.assertFalse(blocked["allowedToClose"])
        tampered = {**receipts, "bank": {
            **receipts["bank"], "fields": {**receipts["bank"]["fields"], "totalMinor": 100}
        }}
        with self.assertRaisesRegex(ValidationError, "binding|payload|fields"):
            postlaunch.reconcile(
                tenant_id="tenant-a", window_id="2026-08-26", window_kind="DAILY",
                period_start=start, period_end=end, currency="USD",
                source_receipts=tampered, trust=source_trust,
                job_key="reconcile:tenant-a", owner_id="worker-a",
                fence_token=token, now=NOW,
            )
        postlaunch.acquire("reconcile:tenant-a", "worker-a", now=NOW)
        with self.assertRaisesRegex(ValidationError, "stale"):
            postlaunch.assert_fence("reconcile:tenant-a", "worker-a", token, now=NOW)

        ledger = CommercialLedger(database)
        policy = read_json(ROOT / "platform/rollout/billing-policy.json")
        pricing = ledger.create_pricing(
            "tenant-a", "v1", policy, NOW - timedelta(days=1), actor="billing-a", now=NOW
        )
        event = {"tenantId": "tenant-a", "meter": "payment_attempt", "attempt_id": "attempt-1", "occurredAt": "2026-08-26T00:10:00Z"}
        self.assertTrue(ledger.meter("tenant-a", pricing, event, actor="meter-worker", now=NOW))
        self.assertFalse(ledger.meter("tenant-a", pricing, event, actor="meter-worker", now=NOW))
        invoice = ledger.issue_invoice(
            "invoice-1", "tenant-a", pricing, NOW, NOW + timedelta(days=1),
            actor="billing-a", now=NOW,
        )
        self.assertEqual(3, invoice["subtotalMinor"])
        ledger.set_sla(
            "tenant-a", "gold-v1", NOW - timedelta(days=1), 30, 1000,
            actor="support-admin", now=NOW,
        )
        ledger.open_ticket(
            "ticket-1", "tenant-a", "SEV1", actor="support-a", opened_at=NOW
        )
        response = CommercialLedger(database).respond_ticket("ticket-1", "tenant-a", "support-a", responded_at=NOW + timedelta(minutes=31))
        self.assertTrue(response["slaBreached"])
        credit_time = NOW + timedelta(minutes=32)
        ledger.request_credit(
            "credit-1", "tenant-a", "invoice-1", "requester-a", 2, "SLA breach",
            now=credit_time,
        )
        with self.assertRaisesRegex(ValidationError, "distinct"):
            ledger.approve_credit("credit-1", "requester-a", now=credit_time)
        memo = CommercialLedger(database).approve_credit(
            "credit-1", "approver-b", now=NOW + timedelta(minutes=33)
        )
        self.assertEqual(2, memo["amountMinor"])
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
            "issuedAt": "2026-08-26T00:01:00Z",
            "expiresAt": "2026-08-26T02:00:00Z",
        }, "audit-signer", private)
        request_path = root / "audit-export-request.json"
        trust_path = root / "audit-export-trust.json"
        output_path = root / "audit-export.json"
        request_path.write_text(json.dumps({
            "exportId": "audit-export-1", "tenantId": "tenant-a",
            "periodStart": period_start.isoformat(), "periodEnd": period_end.isoformat(),
            "receipt": receipt, "now": "2026-08-26T00:30:00Z",
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

        unsigned_path = root / "unsigned-export-request.json"
        unsigned_path.write_text(json.dumps({
            "exportId": "audit-export-2", "tenantId": "tenant-a",
            "periodStart": period_start.isoformat(), "periodEnd": period_end.isoformat(),
            "receipt": {"signatureVerified": True},
            "now": "2026-08-26T00:30:00Z",
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
        start, end = PostLaunchControl.window("DAILY", NOW)
        window_id = f"daily:{start.isoformat()}"
        receipts, source_trust = self.reconciliation_sources(
            tenant_id="tenant-a", window_id=window_id, window_kind="DAILY",
            period_start=start, period_end=end, currency="USD",
            totals={"transaction": 10, "provider": 10, "bank": 9},
            prefix="cron-reconcile",
        )
        receipts_path = Path(self.temporary.name) / "source-receipts.json"
        trust_path = Path(self.temporary.name) / "source-trust.json"
        receipts_path.write_text(json.dumps(receipts), encoding="utf-8")
        trust_path.write_text(json.dumps(source_trust), encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable, str(ROOT / "tools/runtime/postlaunch_worker.py"),
                "--database", self.database(), "--tenant", "tenant-a", "--owner", "cron-a",
                "--kind", "DAILY", "--anchor", "2026-08-26T00:00:00Z",
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

    @staticmethod
    def metrics(**overrides: object) -> dict[str, object]:
        value: dict[str, object] = {"requestCount": 1000, "errorRate": 0.001, "latencyP99Ms": 200, "authorizationRate": 0.9, "ledgerMismatchCount": 0, "duplicateSideEffectCount": 0, "securityCriticalCount": 0}
        value.update(overrides)
        return value


if __name__ == "__main__":
    unittest.main()
