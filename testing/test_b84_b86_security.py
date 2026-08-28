from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.abuse_protection import (  # noqa: E402
    AbusePolicy,
    AbuseProtectionService,
    AbuseRequest,
    LayerLimits,
    SubjectDigester,
    load_abuse_policy,
)
from elmpay_runtime.brand_protection import (  # noqa: E402
    BrandPolicy,
    BrandProtectionService,
    DomainControlPosture,
    DomainObservation,
    assess_domain,
    confusable_skeleton,
    evaluate_domain_posture,
    load_brand_policy,
    normalize_domain,
)
from elmpay_runtime.browser_integrity import BrowserSecurityReportService, validate_script_manifest  # noqa: E402
from elmpay_runtime.common import ValidationError  # noqa: E402
from elmpay_runtime.security_store import SecurityStore  # noqa: E402


NOW = datetime(2026, 8, 28, 1, 0, tzinfo=timezone.utc)


def brand_policy() -> BrandPolicy:
    return BrandPolicy(
        rule_version="brand-test-v1",
        official_domains=("checkout.elmpay.com",),
        protected_labels=("elmpay",),
        allowed_ct_issuers=("Example Public CA",),
    )


def abuse_policy(limit: int = 100) -> AbusePolicy:
    layers = {
        layer: LayerLimits(window_seconds=60, tenant=limit, account=limit, device=limit, ip=limit)
        for layer in ("CDN", "WAF", "API", "IDENTITY")
    }
    return AbusePolicy(
        version="abuse-test-v1",
        layers=layers,
        bot_challenge_basis_points=6000,
        bot_block_basis_points=9000,
        risk_challenge_basis_points=4500,
        risk_block_basis_points=8500,
        challenge_ttl_seconds=300,
        maximum_event_age_seconds=600,
    )


class BrandProtectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = SecurityStore(Path(self.temporary.name) / "security.sqlite")
        self.service = BrandProtectionService(self.store, brand_policy())
        self.service.provision_policy("tenant-a", now=NOW)

    def test_idn_homograph_opens_tenant_scoped_immutable_case(self) -> None:
        # Cyrillic small ie and a are visually confusable with the protected Latin label.
        malicious = "еlmpаy.com"
        self.assertNotEqual(malicious, "elmpay.com")
        self.assertEqual("elmpay.com", confusable_skeleton(malicious))
        observation = DomainObservation(
            "tenant-a", "DNS", "obs-1", malicious, NOW,
        )
        decision = self.service.observe(observation, now=NOW)
        self.assertEqual("TAKEDOWN_CANDIDATE", decision.decision)
        self.assertEqual("CRITICAL", decision.severity)
        self.assertIn("CONFUSABLE_SKELETON_COLLISION", decision.reasons)
        self.assertIsNotNone(decision.case_id)

        replay = self.service.observe(observation, now=NOW)
        self.assertEqual(decision, replay)
        with self.assertRaises(ValidationError):
            self.service.observe(DomainObservation(
                "tenant-a", "DNS", "obs-1", "unrelated.example", NOW,
            ), now=NOW)
        with self.assertRaises(ValidationError):
            self.service.case_snapshot("tenant-b", decision.case_id or "missing")
        with self.store.connect() as connection, self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE brand_observation SET severity='NONE' WHERE tenant_id='tenant-a'"
            )

    def test_takedown_workflow_is_idempotent_reviewed_and_reversible(self) -> None:
        decision = self.service.observe(DomainObservation(
            "tenant-a", "DNS", "obs-2", "еlmpаy.com", NOW,
        ), now=NOW)
        case_id = decision.case_id or "missing"
        self.assertEqual("TRIAGED", self.service.transition_case(
            "tenant-a", case_id, action_id="action-1", action="TRIAGE",
            actor="analyst-a", reviewer=None, reason="confirmed brand collision", now=NOW,
        ))
        self.assertEqual("EVIDENCE_PRESERVED", self.service.transition_case(
            "tenant-a", case_id, action_id="action-2", action="PRESERVE_EVIDENCE",
            actor="analyst-a", reviewer=None, reason="captured signed DNS and page digests", now=NOW,
        ))
        with self.assertRaises(ValidationError):
            self.service.transition_case(
                "tenant-a", case_id, action_id="action-3", action="SUBMIT_PROVIDER",
                actor="analyst-a", reviewer="analyst-a", reason="submit", external_receipt="provider-1", now=NOW,
            )
        self.assertEqual("PROVIDER_SUBMITTED", self.service.transition_case(
            "tenant-a", case_id, action_id="action-3", action="SUBMIT_PROVIDER",
            actor="analyst-a", reviewer="reviewer-b", reason="reviewed evidence package",
            external_receipt="provider-receipt-123", now=NOW,
        ))
        self.assertEqual("PROVIDER_SUBMITTED", self.service.transition_case(
            "tenant-a", case_id, action_id="action-3", action="SUBMIT_PROVIDER",
            actor="analyst-a", reviewer="reviewer-b", reason="reviewed evidence package",
            external_receipt="provider-receipt-123", now=NOW,
        ))
        self.assertEqual("RESOLVED", self.service.transition_case(
            "tenant-a", case_id, action_id="action-4", action="RESOLVE",
            actor="analyst-a", reviewer="reviewer-b", reason="provider confirmed removal", now=NOW,
        ))
        self.assertEqual("OPEN", self.service.transition_case(
            "tenant-a", case_id, action_id="action-5", action="REOPEN",
            actor="analyst-a", reviewer="reviewer-b", reason="domain became active again", now=NOW,
        ))
        snapshot = self.service.case_snapshot("tenant-a", case_id)
        self.assertEqual("OPEN", snapshot["status"])
        self.assertEqual(6, len(snapshot["actions"]))

    def test_official_domain_and_control_posture_are_fail_closed(self) -> None:
        safe = assess_domain(brand_policy(), DomainObservation(
            "tenant-a", "CT", "obs-safe", "pay.checkout.elmpay.com", NOW,
            certificate_issuer="Example Public CA",
        ), now=NOW)
        self.assertEqual("ALLOW", safe.decision)
        suspicious = assess_domain(brand_policy(), DomainObservation(
            "tenant-a", "CT", "obs-ct", "checkout.elmpay.com", NOW,
            certificate_issuer="Unexpected CA",
        ), now=NOW)
        self.assertEqual("TAKEDOWN_CANDIDATE", suspicious.decision)
        report = evaluate_domain_posture(brand_policy(), DomainControlPosture(
            "tenant-a", "checkout.elmpay.com", dnssec=False, caa_issuers=(),
            registry_lock=False, transfer_lock=True, registrar_hardware_mfa=False,
            dmarc_policy="none", observed_at=NOW - timedelta(days=2),
        ), now=NOW)
        self.assertFalse(report.allowed)
        self.assertIn("DNSSEC_DISABLED", report.reasons)
        passing = evaluate_domain_posture(brand_policy(), DomainControlPosture(
            "tenant-a", "checkout.elmpay.com", dnssec=True,
            caa_issuers=("Example Public CA",), registry_lock=True, transfer_lock=True,
            registrar_hardware_mfa=True, dmarc_policy="reject", observed_at=NOW,
        ), now=NOW)
        self.assertTrue(passing.allowed)

    def test_repository_brand_config_cannot_be_used_until_real_domains_are_bound(self) -> None:
        with self.assertRaises(ValidationError):
            load_brand_policy(ROOT / "platform/security/brand-protection-policy.json")
        with self.assertRaises(ValidationError):
            normalize_domain("https://checkout.elmpay.com/token?secret=x")


class BrowserIntegrityTest(unittest.TestCase):
    def test_repository_allowlist_binds_page_and_every_script(self) -> None:
        report = validate_script_manifest(
            ROOT / "apps/checkout-web/public",
            ROOT / "apps/checkout-web/security/script-allowlist.json",
            now=NOW,
        )
        self.assertTrue(report.allowed, report.reasons)
        self.assertIn("SCRIPT_VERIFIED:checkout-controller", report.checks)
        manifest = json.loads((ROOT / "apps/checkout-web/security/script-allowlist.json").read_text())
        self.assertEqual("BLOCKED", manifest["externalAssessmentStatus"])
        self.assertTrue(all(item["thirdParty"] is False for item in manifest["scripts"]))

    def test_tampered_asset_and_expired_review_block(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            shutil.copytree(ROOT / "apps/checkout-web/public", target / "public")
            shutil.copy(ROOT / "apps/checkout-web/security/script-allowlist.json", target / "manifest.json")
            (target / "public/checkout.mjs").write_text("export const compromised = true;\n")
            report = validate_script_manifest(target / "public", target / "manifest.json", now=NOW)
            self.assertFalse(report.allowed)
            self.assertIn("SCRIPT_DIGEST_MISMATCH:checkout-controller", report.reasons)
            manifest = json.loads((target / "manifest.json").read_text())
            manifest["reviewExpiresAt"] = "2026-08-27T00:00:00Z"
            (target / "manifest.json").write_text(json.dumps(manifest))
            expired = validate_script_manifest(target / "public", target / "manifest.json", now=NOW)
            self.assertIn("SCRIPT_MANIFEST_REVIEW_EXPIRED", expired.reasons)

    def test_sanitized_reports_are_durable_idempotent_and_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = SecurityStore(Path(temporary) / "security.sqlite")
            service = BrowserSecurityReportService(store, "checkout-scripts-2026-08-28-v1")
            report = {
                "reportId": "00000000-0000-4000-8000-000000000001",
                "occurredAt": NOW.isoformat(), "category": "CSP",
                "policyVersion": "checkout-scripts-2026-08-28-v1",
                "directive": "script-src-elem", "disposition": "enforce",
                "document": "https://checkout.example/pay", "blocked": "https://evil.example/skimmer.js",
            }
            digest = service.record("checkout-prod-cn", report, now=NOW)
            self.assertEqual(digest, service.record("checkout-prod-cn", report, now=NOW))
            self.assertEqual(report, service.recent("checkout-prod-cn")[0])
            changed = {**report, "blocked": "https://other.example/skimmer.js"}
            with self.assertRaises(ValidationError):
                service.record("checkout-prod-cn", changed, now=NOW)
            unsafe = {**report, "reportId": "00000000-0000-4000-8000-000000000002",
                      "blocked": "https://evil.example/skimmer.js?token=secret"}
            with self.assertRaises(ValidationError):
                service.record("checkout-prod-cn", unsafe, now=NOW)
            with store.connect() as connection, self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM browser_security_report")


class _Verifier:
    def verify(self, challenge_type: str, binding_digest: str, proof: bytes) -> bool:
        return challenge_type == "WEBAUTHN_STEP_UP" and len(binding_digest) == 64 and proof == b"valid-proof"


class AbuseProtectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "security.sqlite"
        self.subjects = SubjectDigester(b"test-only-subject-key-material-32bytes!!")

    def service(self, policy: AbusePolicy | None = None) -> AbuseProtectionService:
        return AbuseProtectionService(SecurityStore(self.database), policy or abuse_policy(), self.subjects)

    def request(self, request_id: str, **changes: object) -> AbuseRequest:
        values: dict[str, object] = {
            "tenant_id": "tenant-a", "request_id": request_id, "layer": "IDENTITY",
            "route_id": "login", "occurred_at": NOW, "source_ip": "203.0.113.8",
            "account_id": "account-sensitive-1", "device_id": "device-sensitive-1",
            "session_id": "session-sensitive-1",
        }
        values.update(changes)
        return AbuseRequest(**values)  # type: ignore[arg-type]

    def test_layered_policy_and_repository_external_boundary(self) -> None:
        policy = load_abuse_policy(ROOT / "platform/security/abuse-protection-policy.json")
        self.assertEqual(set(("CDN", "WAF", "API", "IDENTITY")), set(policy.layers))
        raw = json.loads((ROOT / "platform/security/abuse-protection-policy.json").read_text())
        self.assertEqual("BLOCKED", raw["externalEdgeDeployment"]["status"])

    def test_atomic_dimensions_block_credential_stuffing_and_revoke_session(self) -> None:
        service = self.service(abuse_policy(limit=2))
        first = service.evaluate(self.request("request-1"), now=NOW)
        self.assertEqual("ALLOW", first.action)
        self.assertEqual(first, service.evaluate(self.request("request-1"), now=NOW))
        self.assertEqual("ALLOW", service.evaluate(self.request("request-2"), now=NOW).action)
        blocked = service.evaluate(self.request("request-3"), now=NOW)
        self.assertEqual("BLOCK", blocked.action)
        self.assertIn("IDENTITY_ACCOUNT_RATE_EXCEEDED", blocked.reasons)
        self.assertIsNotNone(blocked.case_id)
        self.assertTrue(service.is_session_revoked("tenant-a", "session-sensitive-1"))
        self.assertFalse(service.is_session_revoked("tenant-b", "session-sensitive-1"))
        with self.assertRaises(ValidationError):
            service.evaluate(self.request("request-1", bot_score_basis_points=7000), now=NOW)
        database_bytes = self.database.read_bytes()
        for raw_identifier in (b"account-sensitive-1", b"device-sensitive-1", b"203.0.113.8", b"session-sensitive-1"):
            self.assertNotIn(raw_identifier, database_bytes)

    def test_ato_challenge_is_bound_one_time_and_high_risk_case_is_four_eyes(self) -> None:
        service = self.service()
        challenged = service.evaluate(self.request(
            "request-challenge", authentication_succeeded=True, new_device=True,
            source_reputation="SUSPICIOUS",
        ), now=NOW)
        self.assertEqual("CHALLENGE", challenged.action)
        self.assertEqual("PASSED", service.complete_challenge(
            "tenant-a", challenged.challenge_id or "missing", b"valid-proof", _Verifier(), now=NOW,
        ))
        with self.assertRaises(ValidationError):
            service.complete_challenge(
                "tenant-a", challenged.challenge_id or "missing", b"valid-proof", _Verifier(), now=NOW,
            )

        blocked = service.evaluate(self.request(
            "request-ato", authentication_succeeded=True, credential_leak_match=True,
            impossible_travel=True,
        ), now=NOW)
        self.assertEqual("BLOCK", blocked.action)
        case_id = blocked.case_id or "missing"
        self.assertEqual("INVESTIGATING", service.transition_case(
            "tenant-a", case_id, event_id="event-1", action="INVESTIGATE",
            actor="security-a", reviewer=None, reason="validated correlated identity signals", now=NOW,
        ))
        self.assertEqual("CONTAINED", service.transition_case(
            "tenant-a", case_id, event_id="event-2", action="CONTAIN",
            actor="security-a", reviewer=None, reason="revoked active sessions", now=NOW,
        ))
        with self.assertRaises(ValidationError):
            service.transition_case(
                "tenant-a", case_id, event_id="event-3", action="RESOLVE",
                actor="security-a", reviewer="security-a", reason="resolved", now=NOW,
            )
        self.assertEqual("RESOLVED", service.transition_case(
            "tenant-a", case_id, event_id="event-3", action="RESOLVE",
            actor="security-a", reviewer="security-b", reason="independent containment review", now=NOW,
        ))

    def test_concurrent_consumers_never_exceed_atomic_allowance(self) -> None:
        service = self.service(abuse_policy(limit=10))

        def execute(index: int) -> str:
            request = AbuseRequest(
                tenant_id="tenant-a", request_id=f"api-{index}", layer="API", route_id="payment-create",
                occurred_at=NOW, source_ip="198.51.100.10",
            )
            return service.evaluate(request, now=NOW).action

        with ThreadPoolExecutor(max_workers=12) as pool:
            actions = list(pool.map(execute, range(25)))
        self.assertEqual(10, actions.count("ALLOW"))
        self.assertEqual(15, actions.count("BLOCK"))


if __name__ == "__main__":
    unittest.main()
