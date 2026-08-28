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
from elmpay_runtime.identity_security import IdentitySecurityStore  # noqa: E402


NOW = datetime(2026, 8, 28, tzinfo=timezone.utc)
HOLDER = "a" * 64


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class FakeCa:
    def revoke(self, serial_number: str, reason: str):
        return {"status": "REVOKED", "serialNumber": serial_number,
                "reason": reason, "receiptId": "ca-receipt-1"}


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
        policy = json.loads((ROOT / "platform/security/identity-security-policy.json").read_text())
        self.store = IdentitySecurityStore(str(self.root / "identity.sqlite"), policy)

    def tearDown(self) -> None:
        self.store.close()
        self.directory.cleanup()

    def jwt(self, *, tenant: str = "tenant-a", subject: str = "user-1",
            holder: str = HOLDER, amr=None) -> str:
        header = b64url(canonical_json({"alg": "RS256", "kid": "issuer-key-1"}))
        claims = b64url(canonical_json({
            "iss": "https://id.elmpay.example", "aud": "elmpay-api", "sub": subject,
            "tenant_id": tenant, "nonce": "nonce-1", "cnf": {"jkt": holder},
            "iat": int(NOW.timestamp()) - 1, "exp": int(NOW.timestamp()) + 600,
            "amr": amr or ["webauthn"], "acr": "phishing-resistant",
        }))
        signing_input = f"{header}.{claims}".encode("ascii")
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(self.private_key)],
            input=signing_input, capture_output=True, check=True,
        )
        return f"{header}.{claims}.{b64url(result.stdout)}"

    def issue_session(self):
        return self.store.verify_oidc_and_issue_session(
            self.jwt(), {"issuer-key-1": self.public_key.read_text()},
            expected_issuer="https://id.elmpay.example", expected_audience="elmpay-api",
            expected_nonce="nonce-1", holder_thumbprint=HOLDER, device_id="device-1", now=NOW,
        )

    def test_b17_oidc_holder_workload_and_recovery_are_fail_closed(self) -> None:
        principal = self.issue_session()
        self.assertEqual("PHISHING_RESISTANT", principal.assurance_level)
        self.assertEqual(principal, self.store.require_session(
            "tenant-a", principal.session_id, "device-1", HOLDER, NOW))
        with self.assertRaises(ValidationError):
            self.store.require_session("tenant-a", principal.session_id, "device-2", HOLDER, NOW)
        with self.assertRaises(ValidationError):
            self.store.verify_oidc_and_issue_session(
                self.jwt(holder="b" * 64), {"issuer-key-1": self.public_key.read_text()},
                expected_issuer="https://id.elmpay.example", expected_audience="elmpay-api",
                expected_nonce="nonce-1", holder_thumbprint=HOLDER, device_id="device-1", now=NOW)

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
            self.store.require_session("tenant-a", principal.session_id, "device-1", HOLDER, NOW)

    def test_b18_webauthn_verifies_rp_origin_uv_signature_counter_and_replay(self) -> None:
        public_pem = self.public_key.read_text()
        credential_id = "credential-1"
        receipt = {
            "status": "VERIFIED", "metadataStatus": "TRUSTED",
            "credentialId": credential_id,
            "publicKeyDigest": hashlib.sha256(public_pem.encode("ascii")).hexdigest(),
            "verifier": "external-fido-metadata-service",
        }
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
            "deviceId": "device-1", "holderThumbprint": HOLDER,
            "devicePosture": "ATTESTED", "networkZone": "TRUSTED_ADMIN",
            "riskAction": "APPROVE", "action": "REFUND_APPROVE",
            "stepUpAt": NOW.isoformat(), "role": "REFUND_APPROVER",
            "objectId": "payment:123", "requestedFields": ["amount"],
        }
        self.assertTrue(self.store.evaluate_zero_trust(request, NOW).allowed)
        self.assertFalse(self.store.evaluate_zero_trust(
            {**request, "networkZone": "PUBLIC", "riskAction": "BLOCK"}, NOW).allowed)

    def test_b21_certificate_overlap_four_eyes_expiry_and_ca_revocation(self) -> None:
        receipt1 = {"status": "ISSUED", "serialNumber": "serial-1",
                    "keyReference": "kms://pki/key-1", "receiptId": "receipt-1"}
        self.store.propose_certificate(
            serial_number="serial-1", subject_name="pay.elmpay.example",
            san_names=["pay.elmpay.example"], issuer_name="elmpay-production-ca",
            key_reference="kms://pki/key-1", overlap_group="public-checkout",
            not_before=NOW - timedelta(minutes=1), not_after=NOW + timedelta(days=60),
            proposer="pki-a", ca_receipt=receipt1, now=NOW)
        with self.assertRaises(ValidationError):
            self.store.approve_certificate("serial-1", "pki-a", NOW)
        self.store.approve_certificate("serial-1", "security-b", NOW)
        receipt2 = {"status": "ISSUED", "serialNumber": "serial-2",
                    "keyReference": "kms://pki/key-2", "receiptId": "receipt-2"}
        self.store.propose_certificate(
            serial_number="serial-2", subject_name="pay.elmpay.example",
            san_names=["pay.elmpay.example"], issuer_name="elmpay-production-ca",
            key_reference="kms://pki/key-2", overlap_group="public-checkout",
            not_before=NOW, not_after=NOW + timedelta(days=90), proposer="pki-a",
            ca_receipt=receipt2, now=NOW)
        self.store.approve_certificate("serial-2", "security-b", NOW)
        digest = self.store.revoke_certificate(
            "serial-1", "superseded", "security-b", FakeCa(), NOW)
        self.assertEqual(64, len(digest))
        alerts = self.store.certificate_expiry_scan(NOW + timedelta(days=89))
        self.assertTrue(any(item["serialNumber"] == "serial-2" for item in alerts))

    def test_cli_is_executable_and_never_claims_certification(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/identity_security_control.py"), "--db",
             str(self.root / "cli.sqlite"), "init"], cwd=ROOT,
            capture_output=True, text=True, check=False)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("NOT_CERTIFIED", json.loads(result.stdout)["certificationStatus"])


if __name__ == "__main__":
    unittest.main()
