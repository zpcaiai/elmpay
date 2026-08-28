from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.assurance import (  # noqa: E402
    SQLiteDeletionWorkflow,
    evaluate_pci_scope,
    evaluate_regional_onboarding,
    evaluate_regulated_identity_decision,
    evaluate_supply_chain,
    evaluate_vulnerability_exception,
)
from elmpay_runtime.attestation import attach_dsse, generate_ed25519_keypair  # noqa: E402
from elmpay_runtime.common import ValidationError  # noqa: E402
from elmpay_runtime.downstream_receipt import receipt_binding  # noqa: E402


NOW = datetime(2026, 8, 28, tzinfo=timezone.utc)


class AssuranceTest(unittest.TestCase):
    def test_pci_scope_rejects_raw_card_storage(self) -> None:
        safe = {
            "components": [{"name": "checkout", "storedDataClasses": ["TOKEN_REFERENCE"],
                            "cardEntry": True, "hostedProviderField": True, "responsibilityOwner": "SHARED"}],
            "segmentationTestRequired": True,
            "externalAssessmentRequired": True,
        }
        self.assertTrue(evaluate_pci_scope(safe).allowed)
        unsafe = {**safe, "components": [{**safe["components"][0], "storedDataClasses": ["PAN"]}]}
        self.assertFalse(evaluate_pci_scope(unsafe).allowed)

    def test_regional_and_regulated_decisions_require_external_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            legal_private, legal_public = generate_ed25519_keypair()
            provider_private, provider_public = generate_ed25519_keypair()
            trust = {
                "replayDatabase": str(Path(directory) / "receipts.sqlite"),
                "keys": {
                    "legal": {
                        "algorithm": "Ed25519", "publicKeyPem": legal_public,
                        "identity": "external-legal", "role": "regional_legal_verifier",
                        "independent": True, "revoked": False,
                        "notBefore": "2026-08-01T00:00:00Z",
                        "notAfter": "2027-01-01T00:00:00Z",
                    },
                    "provider": {
                        "algorithm": "Ed25519", "publicKeyPem": provider_public,
                        "identity": "licensed-psp", "role": "licensed_identity_provider",
                        "independent": True, "revoked": False,
                        "notBefore": "2026-08-01T00:00:00Z",
                        "notAfter": "2027-01-01T00:00:00Z",
                    },
                },
            }

            def signed_receipt(key_id: str, receipt_id: str, receipt_type: str,
                               outcome: str, fields: dict[str, object], nonce: str) -> dict[str, object]:
                key = trust["keys"][key_id]
                return attach_dsse({
                    "receiptId": receipt_id, "receiptType": receipt_type,
                    "outcome": outcome, "fields": fields, "actor": key["identity"],
                    "role": key["role"], "bindingDigest": receipt_binding(receipt_type, fields),
                    "nonce": nonce, "issuedAt": "2026-08-27T23:00:00Z",
                    "expiresAt": "2026-09-01T00:00:00Z",
                }, key_id, legal_private if key_id == "legal" else provider_private)

            regional = json.loads((ROOT / "platform/compliance/regional-boundaries.json").read_text())
            cn = next(item for item in regional["markets"] if item["market"] == "CN")
            evidence: dict[str, object] = {}
            for index, name in enumerate(cn["requiredEvidence"]):
                fields = {
                    "market": "CN", "category": name,
                    "evidenceDigest": hashlib.sha256(name.encode()).hexdigest(),
                    "processingRegion": "cn-east", "crossBorderData": False,
                    "approvedTransferMechanism": None,
                    "expiresAt": "2027-01-01T00:00:00Z",
                }
                evidence[name] = signed_receipt(
                    "legal", f"legal-receipt-{index:04d}", "REGIONAL_LEGAL_EVIDENCE",
                    "VERIFIED", fields, f"regional-legal-nonce-{index:04d}",
                )
            request = {"market": "CN", "evidence": evidence, "crossBorderData": False,
                       "approvedTransferMechanism": None, "processingRegion": "cn-east",
                       "allowedProcessingRegions": ["cn-east"]}
            self.assertTrue(evaluate_regional_onboarding(regional, request, trust, now=NOW).allowed)
            self.assertFalse(evaluate_regional_onboarding(
                regional, {**request, "market": "UNKNOWN"}, trust, now=NOW
            ).allowed)
            # Former caller-authored verifier flags cannot substitute for signatures.
            legacy = {name: {"digest": "a" * 64, "independent": True,
                             "verifier": "external-legal", "expiresAt": "2027-01-01T00:00:00Z"}
                      for name in cn["requiredEvidence"]}
            self.assertFalse(evaluate_regional_onboarding(
                regional, {**request, "evidence": legacy}, trust, now=NOW
            ).allowed)

            boundary = json.loads((ROOT / "platform/compliance/aml-boundary.json").read_text())
            decision_fields = {
                "tenantId": "tenant-a", "provider": "licensed-psp",
                "providerDecisionId": "d1", "subjectReference": "tokenized-subject",
                "policyVersion": "v1", "status": "REVIEW",
                "observedAt": "2026-08-28T00:00:00Z",
            }
            decision = {
                **decision_fields,
                "platformFiledRegulatoryReport": False,
                "receipt": signed_receipt(
                    "provider", "identity-decision-0001", "REGULATED_IDENTITY_DECISION",
                    "REVIEW", decision_fields, "identity-decision-nonce-0001",
                ),
            }
            self.assertTrue(evaluate_regulated_identity_decision(
                boundary, decision, trust, now=NOW
            ).allowed)
            self.assertFalse(evaluate_regulated_identity_decision(
                boundary, {**decision, "providerDecisionId": "tampered"}, trust, now=NOW
            ).allowed)

    def test_deletion_requires_digest_four_eyes_and_independent_backup_receipt(self) -> None:
        policy = json.loads((ROOT / "platform/compliance/data-lifecycle.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            workflow = SQLiteDeletionWorkflow(str(Path(directory) / "deletion.sqlite"))
            records = [hashlib.sha256(f"record-{i}".encode()).hexdigest() for i in range(2)]
            job = workflow.propose(policy, tenant_id="tenant-a", data_class="payment-record",
                                   record_digests=records, legal_hold_clear=True, proposer="privacy-a", now=NOW)
            with self.assertRaises(ValidationError):
                workflow.approve(job, "privacy-a", NOW)
            workflow.approve(job, "legal-b", NOW)
            receipt = workflow.execute(
                job,
                "data-c",
                lambda stable_job_id, tenant, kind, digest, count: (
                    count if stable_job_id == job else -1,
                    "delete-receipt",
                ),
                NOW,
            )
            self.assertEqual("delete-receipt", receipt)
            with self.assertRaises(ValidationError):
                workflow.confirm_backup_expiry(
                    job, "legal-b", lambda stable_job, execution: "backup-receipt", NOW
                )
            workflow.confirm_backup_expiry(
                job,
                "backup-d",
                lambda stable_job, execution: (
                    "backup-receipt"
                    if stable_job == job and execution == "delete-receipt"
                    else ""
                ),
                NOW,
            )
            workflow.close()

    def test_supply_chain_and_exception_are_artifact_bound(self) -> None:
        policy = json.loads((ROOT / "platform/compliance/supply-chain-policy.json").read_text())
        digest = "a" * 64
        statement = {"artifactDigest": digest, "sbomDigest": "b" * 64, "provenanceDigest": "c" * 64,
                     "dependenciesLocked": True, "hermeticBuild": True, "sourceCommit": "d" * 40,
                     "provenanceSourceCommit": "d" * 40, "builderId": policy["allowedBuilders"][0],
                     "materials": policy["requiredMaterials"]}
        self.assertTrue(evaluate_supply_chain(policy, statement, digest, lambda value: True).allowed)
        self.assertFalse(evaluate_supply_chain(policy, statement, digest, lambda value: False).allowed)
        vulnerability = json.loads((ROOT / "platform/compliance/vulnerability-policy.json").read_text())
        exception = {"artifactDigest": digest, "riskOwner": "risk-a", "securityApprover": "security-b",
                     "compensatingControls": ["network-isolation"], "createdAt": "2026-08-28T00:00:00Z",
                     "expiresAt": "2026-09-01T00:00:00Z", "status": "APPROVED"}
        self.assertTrue(evaluate_vulnerability_exception(vulnerability, exception, digest, now=NOW).allowed)


if __name__ == "__main__":
    unittest.main()
