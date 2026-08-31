from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.common import read_json, sha256_json  # noqa: E402
from elmpay_runtime.attestation import attach_dsse, generate_ed25519_keypair  # noqa: E402
from elmpay_runtime.external_evidence import validate_external_evidence  # noqa: E402


NOW = datetime(2026, 8, 26, 0, 0, tzinfo=timezone.utc)


class ExternalEvidenceGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = read_json(ROOT / "platform/compliance/external-evidence-policy.json")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.private = {}
        public = {}
        for key_id in ("external-a", "external-b"):
            self.private[key_id], public[key_id] = generate_ed25519_keypair()
        self.trust = {
            "replayDatabase": str(Path(self.temporary.name) / "external-nonces.db"),
            "keys": {
                "external-a": {
                    "identity": "external-a",
                    "role": "external_verifier",
                    "algorithm": "Ed25519",
                    "publicKeyPem": public["external-a"],
                    "independent": True,
                    "revoked": False,
                    "notBefore": "2026-08-01T00:00:00Z",
                    "notAfter": "2026-09-01T00:00:00Z",
                },
                "external-b": {
                    "identity": "external-b",
                    "role": "external_verifier",
                    "algorithm": "Ed25519",
                    "publicKeyPem": public["external-b"],
                    "independent": True,
                    "revoked": False,
                    "notBefore": "2026-08-01T00:00:00Z",
                    "notAfter": "2026-09-01T00:00:00Z",
                },
            }
        }

    def test_complete_bundle_passes_only_with_independent_signatures(self) -> None:
        bundle = self._bundle()
        report = validate_external_evidence(
            self.policy,
            bundle,
            self.trust,
            now=NOW,
            expected_binding="d" * 64,
        )
        self.assertTrue(report.allowed, report.reasons)
        self.assertGreaterEqual(len(report.checks), len(self.policy["requiredCategories"]))

    def test_missing_bundle_category_blocks(self) -> None:
        bundle = self._bundle()
        bundle["evidence"] = [
            item for item in bundle["evidence"] if item["category"] != "provider_certification"
        ]
        report = self._validate(bundle)
        self.assertFalse(report.allowed)
        self.assertIn("missing_external_evidence:provider_certification", report.reasons)

    def test_reviewer_cannot_be_the_implementer(self) -> None:
        bundle = self._bundle()
        item = self._item(bundle, "independent_human_review")
        item["attestation"]["reviewerId"] = item["attestation"]["implementerId"]
        self._resign(item, "external-a")
        report = self._validate(bundle)
        self.assertFalse(report.allowed)
        self.assertIn("independent_human_review:human_review_not_independent", report.reasons)

    def test_provider_production_certification_and_dr_metrics_are_enforced(self) -> None:
        bundle = self._bundle()
        provider = self._item(bundle, "provider_certification")
        provider["attestation"]["environment"] = "SANDBOX"
        self._resign(provider, self._key_id(provider))
        dr = self._item(bundle, "dr_exercise")
        dr["attestation"]["measuredRtoSeconds"] = 901
        self._resign(dr, self._key_id(dr))
        report = self._validate(bundle)
        self.assertFalse(report.allowed)
        self.assertIn("provider_certification:provider_certification_not_production", report.reasons)
        self.assertIn("dr_exercise:dr_rto_exceeded", report.reasons)

    def test_release_context_must_match_signed_tenant_and_artifact(self) -> None:
        report = validate_external_evidence(
            self.policy,
            self._bundle(),
            self.trust,
            now=NOW,
            expected_binding="d" * 64,
            expected_tenant_id="other-tenant",
            expected_artifact_digest="f" * 64,
            expected_target_digest="f" * 64,
            expected_region="eu-central-1",
        )
        self.assertFalse(report.allowed)
        self.assertIn("uat_acceptance:uat_tenant_binding_mismatch", report.reasons)
        self.assertIn(
            "production_kubernetes:kubernetes_artifact_binding_mismatch",
            report.reasons,
        )
        self.assertIn(
            "production_kubernetes:kubernetes_target_region_missing", report.reasons
        )
        self.assertIn(
            "uat_acceptance:evidence_target_binding_mismatch", report.reasons
        )

    def test_production_kubernetes_binds_exact_images_commit_and_admission_policy(self) -> None:
        report = validate_external_evidence(
            self.policy,
            self._bundle(),
            self.trust,
            now=NOW,
            expected_binding="d" * 64,
            expected_images={
                "edge-gateway": "registry.example/edge-gateway@sha256:" + "c" * 64,
            },
            expected_admission_policy_digest="e" * 64,
            expected_commit_sha="f" * 40,
        )
        self.assertFalse(report.allowed)
        self.assertIn(
            "production_kubernetes:kubernetes_image_inventory_binding_mismatch",
            report.reasons,
        )
        self.assertIn(
            "production_kubernetes:kubernetes_admission_policy_binding_mismatch",
            report.reasons,
        )
        self.assertIn(
            "production_kubernetes:kubernetes_commit_binding_mismatch",
            report.reasons,
        )

    def test_malformed_typed_observations_fail_closed_without_validator_crash(self) -> None:
        bundle = self._bundle()
        kubernetes = self._item(bundle, "production_kubernetes")
        kubernetes["attestation"]["regions"] = ["us-east-1", {"region": "us-west-2"}]
        self._resign(kubernetes, self._key_id(kubernetes))
        canary = self._item(bundle, "canary_rollout")
        canary["attestation"]["trafficPercent"] = 0
        canary["attestation"]["duplicateSideEffectCount"] = False
        self._resign(canary, self._key_id(canary))
        report = self._validate(bundle)
        self.assertFalse(report.allowed)
        self.assertIn(
            "production_kubernetes:kubernetes_regions_insufficient", report.reasons
        )
        self.assertIn(
            "canary_rollout:canary_window_or_traffic_invalid", report.reasons
        )
        self.assertIn(
            "canary_rollout:canary_safety_threshold_exceeded", report.reasons
        )

    def test_tampered_attestation_digest_and_stale_evidence_block(self) -> None:
        bundle = self._bundle()
        human = self._item(bundle, "independent_human_review")
        human["attestation"]["scope"] = "tampered"
        human["observedAt"] = "2026-01-01T00:00:00Z"
        report = self._validate(bundle)
        self.assertFalse(report.allowed)
        self.assertIn("independent_human_review:attestation_digest_mismatch", report.reasons)
        self.assertIn("independent_human_review:evidence_stale", report.reasons)

    def _validate(self, bundle: dict[str, object]):
        return validate_external_evidence(
            self.policy,
            bundle,
            self.trust,
            now=NOW,
            expected_binding="d" * 64,
        )

    def _bundle(self) -> dict[str, object]:
        categories = [item for item in self.policy["requiredCategories"] if item != "provider_certification"]
        evidence = [self._make_item(category, index) for index, category in enumerate(categories)]
        for offset, (provider, capabilities) in enumerate(self.policy["requiredProviderCapabilities"].items(), start=len(evidence)):
            evidence.append(self._make_item("provider_certification", offset, provider, capabilities))
        return {
            "schemaVersion": 1,
            "status": "VERIFIED",
            "releaseBindingDigest": "d" * 64,
            "generatedAt": "2026-08-25T00:00:00Z",
            "expiresAt": "2026-08-27T00:00:00Z",
            "evidence": evidence,
        }

    def _make_item(self, category: str, index: int, provider_id: str | None = None, capabilities: list[str] | None = None) -> dict[str, object]:
        key_id = "external-a" if index % 2 == 0 else "external-b"
        identity = key_id
        attestation: dict[str, object] = {
            "scope": "elmpay-release",
            "reference": f"external-{category}-2026-08-25",
        }
        if category == "independent_human_review":
            attestation.update({"reviewerId": identity, "implementerId": "builder-a", "decision": "APPROVE", "openFindings": 0, "phishingResistantAuth": True})
        elif category == "provider_certification":
            attestation.update({"providerId": provider_id, "officialCertificationId": f"CERT-{provider_id}", "environment": "PRODUCTION", "official": True, "sandboxValidated": True, "capabilities": capabilities, "observedTransactionReference": f"provider-tx-{provider_id}"})
        elif category == "production_kubernetes":
            attestation.update({"environment": "PRODUCTION", "clusterId": "prod-a", "regions": ["us-east-1", "us-west-2"], "commitSha": "c" * 40, "artifactDigest": "a" * 64, "imageDigests": ["registry.example/payment@sha256:" + "b" * 64], "admissionPolicyDigest": "d" * 64, "gitopsDriftCount": 0, "admissionPolicyPassed": True, "rolloutStage": "PRODUCTION"})
        elif category == "dr_exercise":
            attestation.update({"exerciseId": "dr-1", "regions": ["us-east-1", "us-west-2"], "measuredRpoSeconds": 30, "measuredRtoSeconds": 300, "failbackPassed": True, "writeFenceObserved": True, "providerRoutingVerified": True, "dataLossDetected": False})
        elif category == "pci_assessor":
            attestation.update({"assessorType": "QSA", "reportReference": "roc-1", "status": "PASS", "assessorIndependent": True})
        elif category == "uat_acceptance":
            attestation.update({"environment": "UAT", "tenantId": "tenant-1", "targetDigest": "1" * 64, "merchantId": "merchant-1", "suiteDigest": "2" * 64, "resultDigest": "3" * 64, "scenariosTotal": 20, "scenariosPassed": 20, "financeSignoff": True, "operationsSignoff": True, "merchantSignoff": True})
        elif category == "penetration_test":
            attestation.update({"testerId": "tester-1", "testerIndependent": True, "methodology": "OWASP-ASVS", "reportReference": "pentest-1", "findings": {"critical": 0, "high": 0, "medium": 2}})
        elif category == "shadow_rollout":
            attestation.update({"stage": "SHADOW", "tenantId": "tenant-1", "targetDigest": "1" * 64, "datasetDigest": "e" * 64, "resultDigest": "f" * 64, "sampleCount": 1000, "mismatchCount": 0, "candidateSideEffects": 0})
        elif category == "canary_rollout":
            attestation.update({"stage": "CANARY", "tenantId": "tenant-1", "targetDigest": "1" * 64, "trafficPercent": 10, "windowMinutes": 60, "errorRateDelta": 0.001, "latencyP99DeltaMs": 10, "authorizationRateDrop": 0.001, "autoStopTriggered": False, "duplicateSideEffectCount": 0, "securityCriticalCount": 0})
        elif category == "merchant_acceptance":
            attestation.update({"merchantId": "merchant-1", "tenantId": "tenant-1", "targetDigest": "1" * 64, "acceptanceId": "accept-1", "accepted": True, "merchantSignoff": True, "scenarioDigest": "1" * 64})
        else:
            attestation.update({"jurisdiction": "US", "market": "US", "decision": "APPROVE", "externalAuthority": True})
        item: dict[str, object] = {
            "category": category,
            "evidenceId": f"evidence-{category}",
            "verifier": identity,
            "role": "external_verifier",
            "source": self.policy["requiredCategories"][category]["requiredSource"],
            "externallyVerified": True,
            "status": "VERIFIED",
            "observedAt": "2026-08-25T00:00:00Z",
            "expiresAt": "2026-08-27T00:00:00Z",
            "issuedAt": "2026-08-25T00:00:00Z",
            "nonce": f"external-evidence-{category}-{index:04d}",
            "bindingDigest": "d" * 64,
            "attestation": attestation,
        }
        self._resign(item, key_id)
        return item

    def _item(self, bundle: dict[str, object], category: str) -> dict[str, object]:
        return next(item for item in bundle["evidence"] if item["category"] == category)

    def _resign(self, item: dict[str, object], key_id: str) -> None:
        item.pop("dsse", None)
        item["attestationDigest"] = sha256_json(item["attestation"])
        signed = attach_dsse(item, key_id, self.private[key_id])
        item.clear()
        item.update(signed)

    @staticmethod
    def _key_id(item: dict[str, object]) -> str:
        return item["dsse"]["signatures"][0]["keyid"]


if __name__ == "__main__":
    unittest.main()
