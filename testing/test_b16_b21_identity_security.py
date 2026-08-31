from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.common import ValidationError, canonical_json  # noqa: E402
from elmpay_runtime.attestation import attach_dsse, generate_ed25519_keypair  # noqa: E402
from elmpay_runtime.downstream_receipt import receipt_binding  # noqa: E402
from elmpay_runtime.identity_security import IdentitySecurityStore  # noqa: E402


NOW = datetime(2026, 8, 28, tzinfo=timezone.utc)


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class FakeCa:
    def __init__(self, signer):
        self.signer = signer

    def revoke(self, serial_number: str, reason: str):
        return self.signer(
            "CERTIFICATE_REVOCATION", "REVOKED",
            {"serialNumber": serial_number, "reason": reason}, "ca",
            "ca-revoke-nonce-0001",
        )


class IdentitySecurityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.private_key = self.root / "private.pem"
        self.public_key = self.root / "public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
             "-out", str(self.private_key)], capture_output=True, check=True,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(self.private_key), "-pubout",
             "-out", str(self.public_key)], capture_output=True, check=True,
        )
        self.receipt_private, receipt_public = generate_ed25519_keypair()
        roles = {
            "fido": ("fido-verifier", "webauthn_attestation_verifier", True),
            "ca": ("production-ca", "certificate_authority", True),
            "device": ("device-verifier", "device_attestation_verifier", False),
            "network": ("network-verifier", "network_context_verifier", False),
            "risk": ("risk-service", "risk_decision_service", False),
            "stepup": ("stepup-service", "step_up_authenticator", False),
        }
        self.receipt_trust = {
            "replayDatabase": str(self.root / "identity-receipts.sqlite"),
            "keys": {
                key_id: {
                    "algorithm": "Ed25519", "publicKeyPem": receipt_public,
                    "identity": identity, "role": role, "independent": independent,
                    "revoked": False, "notBefore": "2026-08-01T00:00:00Z",
                    "notAfter": "2026-09-30T00:00:00Z",
                }
                for key_id, (identity, role, independent) in roles.items()
            },
            "oidcIssuers": {
                "https://id.elmpay.example": {
                    "audiences": ["elmpay-api"],
                    "keys": {"issuer-key-1": self.public_key.read_text()},
                },
            },
        }
        self.holder = hashlib.sha256(
            self.public_key.read_text().encode("ascii")
        ).hexdigest()
        self.sequence = 0
        policy = json.loads((ROOT / "platform/security/identity-security-policy.json").read_text())
        self.store = IdentitySecurityStore(
            str(self.root / "identity.sqlite"), policy, self.receipt_trust,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.directory.cleanup()

    def jwt(self, *, nonce: str, token_jti: str, tenant: str = "tenant-a",
            subject: str = "user-1", holder: str | None = None, amr=None) -> str:
        header = b64url(canonical_json({"alg": "RS256", "kid": "issuer-key-1"}))
        claims = b64url(canonical_json({
            "iss": "https://id.elmpay.example", "aud": "elmpay-api", "sub": subject,
            "tenant_id": tenant, "nonce": nonce, "cnf": {"jkt": holder or self.holder},
            "jti": token_jti,
            "iat": int(NOW.timestamp()) - 1, "exp": int(NOW.timestamp()) + 600,
            "amr": amr or ["webauthn"], "acr": "phishing-resistant",
        }))
        signing_input = f"{header}.{claims}".encode("ascii")
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(self.private_key)],
            input=signing_input, capture_output=True, check=True,
        )
        return f"{header}.{claims}.{b64url(result.stdout)}"

    def holder_proof(self, token: str, nonce: str, *, jti: str):
        unsigned = {
            "algorithm": "RS256", "publicKeyPem": self.public_key.read_text(),
            "method": "POST",
            "uri": "https://api.elmpay.example/v1/identity/sessions",
            "nonce": nonce, "tokenDigest": hashlib.sha256(token.encode("ascii")).hexdigest(),
            "jti": jti, "issuedAt": NOW.isoformat(),
        }
        signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(self.private_key)],
            input=canonical_json(unsigned), capture_output=True, check=True,
        ).stdout
        return {**unsigned, "signature": b64url(signature)}

    def issue_session(self):
        self.sequence += 1
        nonce = self.store.issue_oidc_nonce(
            "https://id.elmpay.example", "elmpay-api", NOW,
        )
        token = self.jwt(nonce=nonce, token_jti=f"token-jti-{self.sequence:08d}")
        return self.store.verify_oidc_and_issue_session(
            token,
            expected_issuer="https://id.elmpay.example", expected_audience="elmpay-api",
            expected_nonce=nonce,
            holder_proof=self.holder_proof(
                token, nonce, jti=f"holder-proof-{self.sequence:08d}",
            ),
            device_id="device-1", now=NOW,
        )

    def signed_receipt(self, receipt_type: str, outcome: str,
                       fields: dict[str, object], key_id: str, nonce: str):
        key = self.receipt_trust["keys"][key_id]
        record = {
            "receiptId": f"{key_id}-{nonce}", "receiptType": receipt_type,
            "outcome": outcome, "fields": fields, "actor": key["identity"],
            "role": key["role"], "bindingDigest": receipt_binding(receipt_type, fields),
            "nonce": nonce, "issuedAt": (NOW - timedelta(minutes=1)).isoformat(),
            "expiresAt": (NOW + timedelta(minutes=10)).isoformat(),
        }
        return attach_dsse(record, key_id, self.receipt_private)

    def test_b17_oidc_holder_workload_and_recovery_are_fail_closed(self) -> None:
        principal = self.issue_session()
        self.assertEqual("PHISHING_RESISTANT", principal.assurance_level)
        self.assertEqual(principal, self.store.require_session(
            "tenant-a", principal.session_id, "device-1", self.holder, NOW))
        with self.assertRaises(ValidationError):
            self.store.require_session(
                "tenant-a", principal.session_id, "device-2", self.holder, NOW,
            )
        nonce = self.store.issue_oidc_nonce(
            "https://id.elmpay.example", "elmpay-api", NOW,
        )
        mismatched = self.jwt(
            nonce=nonce, token_jti="token-holder-mismatch-0001", holder="b" * 64,
        )
        with self.assertRaises(ValidationError):
            self.store.verify_oidc_and_issue_session(
                mismatched,
                expected_issuer="https://id.elmpay.example", expected_audience="elmpay-api",
                expected_nonce=nonce,
                holder_proof=self.holder_proof(
                    mismatched, nonce, jti="proof-holder-mismatch-0001",
                ),
                device_id="device-1", now=NOW)

        self.store.register_workload_identity(
            "spiffe://elmpay.example/ns/pay/sa/gateway", "edge-gateway", "c" * 64,
            NOW, NOW + timedelta(minutes=30), "platform-security")
        workload = self.store.authenticate_workload(
            "spiffe://elmpay.example/ns/pay/sa/gateway", "c" * 64, NOW)
        self.assertEqual("WORKLOAD", workload.principal_type)
        recovery = self.store.propose_recovery(
            "tenant-a", "user-1", "support-a", "verified recovery",
            NOW + timedelta(minutes=10), NOW)
        with self.assertRaises(ValidationError):
            self.store.approve_recovery("tenant-a", recovery, "support-a", NOW)
        self.assertEqual(1, self.store.approve_recovery(
            "tenant-a", recovery, "security-b", NOW))
        with self.assertRaises(ValidationError):
            self.store.require_session(
                "tenant-a", principal.session_id, "device-1", self.holder, NOW,
            )

    def test_oidc_uses_configured_issuer_one_time_nonce_jti_and_signed_holder_proof(self) -> None:
        nonce = self.store.issue_oidc_nonce(
            "https://id.elmpay.example", "elmpay-api", NOW,
        )
        token = self.jwt(nonce=nonce, token_jti="token-replay-negative-0001")
        proof = self.holder_proof(token, nonce, jti="holder-replay-negative-0001")
        principal = self.store.verify_oidc_and_issue_session(
            token, expected_issuer="https://id.elmpay.example",
            expected_audience="elmpay-api", expected_nonce=nonce,
            holder_proof=proof, device_id="device-1", now=NOW,
        )
        self.assertEqual(self.holder, principal.holder_thumbprint)
        with self.assertRaisesRegex(ValidationError, "nonce|replay"):
            self.store.verify_oidc_and_issue_session(
                token, expected_issuer="https://id.elmpay.example",
                expected_audience="elmpay-api", expected_nonce=nonce,
                holder_proof=proof, device_id="device-1", now=NOW,
            )
        with self.assertRaisesRegex(ValidationError, "trusted configuration"):
            self.store.issue_oidc_nonce("https://attacker.invalid", "elmpay-api", NOW)
        fresh_nonce = self.store.issue_oidc_nonce(
            "https://id.elmpay.example", "elmpay-api", NOW,
        )
        fresh_token = self.jwt(
            nonce=fresh_nonce, token_jti="token-proof-tamper-0001",
        )
        fresh_proof = self.holder_proof(
            fresh_token, fresh_nonce, jti="holder-proof-tamper-0001",
        )
        with self.assertRaisesRegex(ValidationError, "request binding"):
            self.store.verify_oidc_and_issue_session(
                fresh_token, expected_issuer="https://id.elmpay.example",
                expected_audience="elmpay-api", expected_nonce=fresh_nonce,
                holder_proof={**fresh_proof, "uri": "https://attacker.invalid/session"},
                device_id="device-1", now=NOW,
            )

    def test_b18_webauthn_verifies_rp_origin_uv_signature_counter_and_replay(self) -> None:
        public_pem = self.public_key.read_text()
        credential_id = "credential-1"
        receipt = self.signed_receipt(
            "WEBAUTHN_ATTESTATION", "VERIFIED", {
                "tenantId": "tenant-a", "userId": "user-1",
                "credentialId": credential_id,
                "publicKeyDigest": hashlib.sha256(public_pem.encode("ascii")).hexdigest(),
                "rpId": "admin.elmpay.example", "aaguid": "aaguid-1",
                "signCount": 0, "backupEligible": False, "metadataStatus": "TRUSTED",
            }, "fido", "fido-attest-nonce-0001",
        )
        self.store.register_webauthn_credential(
            tenant_id="tenant-a", user_id="user-1", credential_id=credential_id,
            public_key_pem=public_pem, rp_id="admin.elmpay.example", aaguid="aaguid-1",
            sign_count=0, backup_eligible=False, attestation_receipt=receipt,
            actor="user-1", now=NOW,
        )
        challenge = self.store.issue_webauthn_challenge(
            "tenant-a", "user-1", "REFUND_APPROVE", "https://admin.elmpay.example",
            "admin.elmpay.example", "session-binding-1", NOW)
        client_data = canonical_json({"type": "webauthn.get",
                                      "challenge": challenge["challenge"],
                                      "origin": challenge["origin"]})
        authenticator_data = (hashlib.sha256(b"admin.elmpay.example").digest()
                              + bytes([0x05]) + (1).to_bytes(4, "big"))
        signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(self.private_key)],
            input=authenticator_data + hashlib.sha256(client_data).digest(),
            capture_output=True, check=True,
        ).stdout
        result = self.store.verify_webauthn_assertion(
            tenant_id="tenant-a", challenge_id=challenge["challengeId"],
            credential_id=credential_id, client_data_json=client_data,
            authenticator_data=authenticator_data, signature=signature,
            session_binding="session-binding-1", now=NOW)
        self.assertTrue(result.phishing_resistant)
        with self.assertRaises(ValidationError):
            self.store.verify_webauthn_assertion(
                tenant_id="tenant-a", challenge_id=challenge["challengeId"],
                credential_id=credential_id, client_data_json=client_data,
                authenticator_data=authenticator_data, signature=signature,
                session_binding="session-binding-1", now=NOW)

    def test_b19_scoped_four_eyes_jit_and_separation_of_duties(self) -> None:
        grant = self.store.propose_grant(
            "tenant-a", "user-1", "REFUND_REQUESTER", "payment:*", ["amount", "reason"],
            NOW, NOW + timedelta(minutes=30), "admin-a", NOW)
        with self.assertRaises(ValidationError):
            self.store.approve_grant("tenant-a", grant, "admin-a", NOW)
        self.store.approve_grant("tenant-a", grant, "security-b", NOW)
        allowed = self.store.authorize(
            "tenant-a", "user-1", "REFUND_REQUESTER", "payment:123", ["amount"], NOW)
        self.assertTrue(allowed.allowed)
        self.assertFalse(self.store.authorize(
            "tenant-b", "user-1", "REFUND_REQUESTER", "payment:123", ["amount"], NOW).allowed)
        with self.assertRaises(ValidationError):
            self.store.propose_grant(
                "tenant-a", "user-1", "REFUND_APPROVER", "payment:*", ["*"], NOW,
                NOW + timedelta(minutes=30), "admin-a", NOW)

    def test_b16_zero_trust_combines_identity_device_network_risk_and_abac(self) -> None:
        principal = self.issue_session()
        grant = self.store.propose_grant(
            "tenant-a", "user-1", "REFUND_APPROVER", "payment:*", ["amount"], NOW,
            NOW + timedelta(minutes=30), "admin-a", NOW)
        self.store.approve_grant("tenant-a", grant, "security-b", NOW)
        request = {
            "tenantId": "tenant-a", "sessionId": principal.session_id,
            "deviceId": "device-1", "holderThumbprint": self.holder,
            "devicePosture": "ATTESTED", "networkZone": "TRUSTED_ADMIN",
            "riskAction": "APPROVE", "action": "REFUND_APPROVE",
            "stepUpAt": NOW.isoformat(), "role": "REFUND_APPROVER",
            "objectId": "payment:123", "requestedFields": ["amount"],
        }
        request["contextReceipts"] = {
            "device": self.signed_receipt(
                "DEVICE_POSTURE", "VERIFIED", {
                    "tenantId": "tenant-a", "sessionId": principal.session_id,
                    "deviceDigest": principal.device_digest, "posture": "ATTESTED",
                }, "device", "device-receipt-nonce-0001",
            ),
            "network": self.signed_receipt(
                "NETWORK_ZONE", "VERIFIED", {
                    "tenantId": "tenant-a", "sessionId": principal.session_id,
                    "zone": "TRUSTED_ADMIN",
                }, "network", "network-receipt-nonce-0001",
            ),
            "risk": self.signed_receipt(
                "RISK_DECISION", "VERIFIED", {
                    "tenantId": "tenant-a", "sessionId": principal.session_id,
                    "action": "REFUND_APPROVE", "objectId": "payment:123",
                    "decision": "APPROVE",
                }, "risk", "risk-receipt-nonce-0001",
            ),
            "stepUp": self.signed_receipt(
                "STEP_UP_AUTHENTICATION", "VERIFIED", {
                    "tenantId": "tenant-a", "sessionId": principal.session_id,
                    "subjectId": principal.subject_id, "action": "REFUND_APPROVE",
                    "objectId": "payment:123", "performedAt": NOW.isoformat(),
                    "assuranceLevel": principal.assurance_level,
                }, "stepup", "stepup-receipt-nonce-0001",
            ),
        }
        self.assertTrue(self.store.evaluate_zero_trust(request, NOW).allowed)
        self.assertFalse(self.store.evaluate_zero_trust(
            {**request, "networkZone": "PUBLIC", "riskAction": "BLOCK"}, NOW).allowed)

    def test_b21_certificate_overlap_four_eyes_expiry_and_ca_revocation(self) -> None:
        receipt1 = self.signed_receipt(
            "CERTIFICATE_ISSUANCE", "ISSUED", {
                "serialNumber": "serial-1", "subjectName": "pay.elmpay.example",
                "sanNames": ["pay.elmpay.example"], "issuerName": "elmpay-production-ca",
                "keyReference": "kms://pki/key-1",
                "notBefore": (NOW - timedelta(minutes=1)).isoformat(),
                "notAfter": (NOW + timedelta(days=60)).isoformat(),
            }, "ca", "ca-issue-one-nonce-0001",
        )
        self.store.propose_certificate(
            serial_number="serial-1", subject_name="pay.elmpay.example",
            san_names=["pay.elmpay.example"], issuer_name="elmpay-production-ca",
            key_reference="kms://pki/key-1", overlap_group="public-checkout",
            not_before=NOW - timedelta(minutes=1), not_after=NOW + timedelta(days=60),
            proposer="pki-a", ca_receipt=receipt1, now=NOW)
        with self.assertRaises(ValidationError):
            self.store.approve_certificate("serial-1", "pki-a", NOW)
        self.store.approve_certificate("serial-1", "security-b", NOW)
        receipt2 = self.signed_receipt(
            "CERTIFICATE_ISSUANCE", "ISSUED", {
                "serialNumber": "serial-2", "subjectName": "pay.elmpay.example",
                "sanNames": ["pay.elmpay.example"], "issuerName": "elmpay-production-ca",
                "keyReference": "kms://pki/key-2", "notBefore": NOW.isoformat(),
                "notAfter": (NOW + timedelta(days=90)).isoformat(),
            }, "ca", "ca-issue-two-nonce-0001",
        )
        self.store.propose_certificate(
            serial_number="serial-2", subject_name="pay.elmpay.example",
            san_names=["pay.elmpay.example"], issuer_name="elmpay-production-ca",
            key_reference="kms://pki/key-2", overlap_group="public-checkout",
            not_before=NOW, not_after=NOW + timedelta(days=90), proposer="pki-a",
            ca_receipt=receipt2, now=NOW)
        self.store.approve_certificate("serial-2", "security-b", NOW)
        digest = self.store.revoke_certificate(
            "serial-1", "superseded", "security-b", FakeCa(self.signed_receipt), NOW)
        self.assertEqual(64, len(digest))
        alerts = self.store.certificate_expiry_scan(NOW + timedelta(days=89))
        self.assertTrue(any(item["serialNumber"] == "serial-2" for item in alerts))

    def test_signed_external_receipts_reject_tamper_cross_tenant_and_replay_mutation(self) -> None:
        public_pem = self.public_key.read_text()
        fields = {
            "tenantId": "tenant-a", "userId": "user-1", "credentialId": "credential-x",
            "publicKeyDigest": hashlib.sha256(public_pem.encode("ascii")).hexdigest(),
            "rpId": "admin.elmpay.example", "aaguid": "aaguid-x", "signCount": 0,
            "backupEligible": False, "metadataStatus": "TRUSTED",
        }
        receipt = self.signed_receipt(
            "WEBAUTHN_ATTESTATION", "VERIFIED", fields, "fido",
            "fido-negative-nonce-0001",
        )
        tampered = {**receipt, "fields": {**fields, "tenantId": "tenant-b"}}
        with self.assertRaises(ValidationError):
            self.store.register_webauthn_credential(
                tenant_id="tenant-a", user_id="user-1", credential_id="credential-x",
                public_key_pem=public_pem, rp_id="admin.elmpay.example", aaguid="aaguid-x",
                sign_count=0, backup_eligible=False, attestation_receipt=tampered,
                actor="user-1", now=NOW,
            )
        self.store.register_webauthn_credential(
            tenant_id="tenant-a", user_id="user-1", credential_id="credential-x",
            public_key_pem=public_pem, rp_id="admin.elmpay.example", aaguid="aaguid-x",
            sign_count=0, backup_eligible=False, attestation_receipt=receipt,
            actor="user-1", now=NOW,
        )
        other_fields = {**fields, "credentialId": "credential-y", "aaguid": "aaguid-y"}
        mutated = self.signed_receipt(
            "WEBAUTHN_ATTESTATION", "VERIFIED", other_fields,
            "fido", "fido-negative-nonce-0001",
        )
        with self.assertRaisesRegex(ValidationError, "nonce_reused"):
            self.store.register_webauthn_credential(
                tenant_id="tenant-a", user_id="user-1", credential_id="credential-y",
                public_key_pem=public_pem, rp_id="admin.elmpay.example", aaguid="aaguid-y",
                sign_count=0, backup_eligible=False, attestation_receipt=mutated,
                actor="user-1", now=NOW,
            )

    def test_cli_is_executable_and_never_claims_certification(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/identity_security_control.py"), "--db",
             str(self.root / "cli.sqlite"), "init"], cwd=ROOT,
            capture_output=True, text=True, check=False)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("NOT_CERTIFIED", json.loads(result.stdout)["certificationStatus"])


if __name__ == "__main__":
    unittest.main()
