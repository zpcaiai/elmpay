"""B16-B21 durable zero-trust, identity, WebAuthn, authorization and PKI controls."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import subprocess
import tempfile
import threading
from typing import Any, Mapping, Protocol

from .downstream_receipt import verify_downstream_receipt
from .common import (
    GateReport,
    ValidationError,
    canonical_json,
    parse_instant,
    require_list,
    require_mapping,
    require_text,
)


def _b64url_decode(value: str, field: str) -> bytes:
    if not isinstance(value, str) or not value or any(char.isspace() for char in value):
        raise ValidationError(f"{field} is not canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise ValidationError(f"{field} is not canonical base64url") from exc
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ValidationError(f"{field} is not canonical base64url")
    return decoded


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _strict_json(value: bytes, field: str) -> Mapping[str, Any]:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValidationError(f"{field} contains duplicate key {key}")
            result[key] = item
        return result

    try:
        decoded = json.loads(
            value,
            object_pairs_hook=object_pairs,
            parse_constant=lambda item: (_ for _ in ()).throw(
                ValidationError(f"{field} contains non-finite {item}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{field} is not strict JSON") from exc
    return require_mapping(decoded, field)


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValidationError("instant must be timezone aware")
    return value.astimezone(timezone.utc).isoformat()


@dataclass(frozen=True)
class VerifiedPrincipal:
    tenant_id: str
    subject_id: str
    principal_type: str
    assurance_level: str
    device_digest: str
    holder_thumbprint: str
    session_id: str
    expires_at: datetime


@dataclass(frozen=True)
class WebAuthnResult:
    tenant_id: str
    user_id: str
    credential_id: str
    operation: str
    sign_count: int
    phishing_resistant: bool


class CertificateAuthorityClient(Protocol):
    def revoke(self, serial_number: str, reason: str) -> Mapping[str, Any]: ...


class IdentitySecurityStore:
    """SQLite runtime adapter mirroring the production Postgres B16-B21 schema."""

    def __init__(self, path: str, policy: Mapping[str, Any],
                 receipt_trust: Mapping[str, Any] | None = None) -> None:
        self.policy = policy
        self.receipt_trust = receipt_trust
        if policy.get("defaultDecision") != "DENY":
            raise ValidationError("zero-trust policy must default deny")
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, timeout=5, isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS identity_session(
              session_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, subject_id TEXT NOT NULL,
              assurance_level TEXT NOT NULL, device_digest TEXT NOT NULL,
              holder_thumbprint TEXT NOT NULL, refresh_family TEXT NOT NULL,
              refresh_counter INTEGER NOT NULL, issued_at TEXT NOT NULL,
              expires_at TEXT NOT NULL, revoked_at TEXT
            );
            CREATE TABLE IF NOT EXISTS oidc_nonce(
              nonce TEXT PRIMARY KEY, issuer TEXT NOT NULL, audience TEXT NOT NULL,
              expires_at TEXT NOT NULL, consumed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS oidc_token_jti(
              issuer TEXT NOT NULL, token_jti TEXT NOT NULL, token_digest TEXT NOT NULL,
              accepted_at TEXT NOT NULL, PRIMARY KEY(issuer,token_jti)
            );
            CREATE TABLE IF NOT EXISTS holder_proof_replay(
              proof_jti TEXT PRIMARY KEY, proof_digest TEXT NOT NULL, accepted_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS workload_identity(
              spiffe_id TEXT PRIMARY KEY, service_name TEXT NOT NULL,
              certificate_thumbprint TEXT NOT NULL UNIQUE, issued_at TEXT NOT NULL,
              expires_at TEXT NOT NULL, revoked_at TEXT
            );
            CREATE TABLE IF NOT EXISTS webauthn_credential(
              tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, credential_id TEXT NOT NULL,
              public_key_pem TEXT NOT NULL, rp_id TEXT NOT NULL, aaguid TEXT NOT NULL,
              sign_count INTEGER NOT NULL, backup_eligible INTEGER NOT NULL,
              attestation_receipt_digest TEXT NOT NULL, created_at TEXT NOT NULL,
              revoked_at TEXT, PRIMARY KEY(tenant_id,credential_id)
            );
            CREATE TABLE IF NOT EXISTS webauthn_challenge(
              challenge_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, user_id TEXT NOT NULL,
              operation TEXT NOT NULL, challenge TEXT NOT NULL UNIQUE, origin TEXT NOT NULL,
              rp_id TEXT NOT NULL, session_binding TEXT NOT NULL, expires_at TEXT NOT NULL,
              consumed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS authorization_grant(
              grant_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, subject_id TEXT NOT NULL,
              role_name TEXT NOT NULL, object_scope TEXT NOT NULL, field_scope BLOB NOT NULL,
              proposed_by TEXT NOT NULL, approved_by TEXT, state TEXT NOT NULL,
              valid_from TEXT NOT NULL, valid_until TEXT NOT NULL, payload_digest TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS identity_recovery(
              recovery_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, subject_id TEXT NOT NULL,
              proposed_by TEXT NOT NULL, approved_by TEXT, reason TEXT NOT NULL,
              state TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL,
              decided_at TEXT
            );
            CREATE TABLE IF NOT EXISTS certificate_inventory(
              serial_number TEXT PRIMARY KEY, subject_name TEXT NOT NULL, san_names BLOB NOT NULL,
              issuer_name TEXT NOT NULL, key_reference TEXT NOT NULL, overlap_group TEXT NOT NULL,
              status TEXT NOT NULL, not_before TEXT NOT NULL, not_after TEXT NOT NULL,
              proposer TEXT NOT NULL, approver TEXT, ca_receipt_digest TEXT NOT NULL,
              created_at TEXT NOT NULL, revoked_at TEXT
            );
            CREATE TABLE IF NOT EXISTS identity_security_audit(
              sequence_no INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT,
              event_type TEXT NOT NULL, object_digest TEXT NOT NULL, actor_id TEXT NOT NULL,
              previous_hash TEXT NOT NULL, audit_hash TEXT NOT NULL UNIQUE,
              occurred_at TEXT NOT NULL
            );
            """
        )

    def close(self) -> None:
        self._db.close()

    def verify_oidc_and_issue_session(
        self,
        compact_token: str,
        *,
        expected_issuer: str,
        expected_audience: str,
        expected_nonce: str,
        holder_proof: Mapping[str, Any],
        device_id: str,
        now: datetime,
    ) -> VerifiedPrincipal:
        """Verify an RS256 OIDC assertion and bind its short session to holder and device."""

        parts = compact_token.split(".")
        if len(parts) != 3:
            raise ValidationError("OIDC token must have three compact parts")
        header = _strict_json(_b64url_decode(parts[0], "JWT header"), "JWT header")
        claims = _strict_json(_b64url_decode(parts[1], "JWT claims"), "JWT claims")
        algorithm = require_text(header.get("alg"), "JWT alg")
        allowed = set(require_list(require_mapping(self.policy.get("oidc"), "oidc policy").get(
            "allowedAlgorithms"), "OIDC algorithms"))
        if algorithm != "RS256" or algorithm not in allowed:
            raise ValidationError("OIDC algorithm is not allowed")
        issuer_trust = self._oidc_issuer(expected_issuer)
        audiences = {
            require_text(item, "trusted OIDC audience")
            for item in require_list(issuer_trust.get("audiences"), "trusted OIDC audiences")
        }
        if expected_audience not in audiences:
            raise ValidationError("OIDC audience is not configured for the trusted issuer")
        public_keys = require_mapping(issuer_trust.get("keys"), "trusted OIDC keys")
        key_id = require_text(header.get("kid"), "JWT kid")
        public_key = public_keys.get(key_id)
        if public_key is None:
            raise ValidationError("OIDC signing key is unknown")
        self._verify_rs256(require_text(public_key, "trusted OIDC public key"),
                           f"{parts[0]}.{parts[1]}".encode("ascii"),
                           _b64url_decode(parts[2], "JWT signature"))
        if require_text(claims.get("iss"), "iss") != expected_issuer:
            raise ValidationError("OIDC issuer mismatch")
        audience = claims.get("aud")
        audiences = {audience} if isinstance(audience, str) else set(require_list(audience, "aud"))
        if expected_audience not in audiences:
            raise ValidationError("OIDC audience mismatch")
        if require_text(claims.get("nonce"), "nonce") != expected_nonce:
            raise ValidationError("OIDC nonce mismatch")
        current = int(now.astimezone(timezone.utc).timestamp())
        skew = int(self.policy.get("clockSkewSeconds", 0))
        issued_at = claims.get("iat")
        expires_at = claims.get("exp")
        if isinstance(issued_at, bool) or not isinstance(issued_at, int):
            raise ValidationError("OIDC iat must be integer epoch seconds")
        if isinstance(expires_at, bool) or not isinstance(expires_at, int):
            raise ValidationError("OIDC exp must be integer epoch seconds")
        if issued_at > current + skew or expires_at <= current - skew:
            raise ValidationError("OIDC assertion is outside its validity window")
        if expires_at - issued_at > int(self.policy["sessionMaximumSeconds"]):
            raise ValidationError("OIDC assertion lifetime exceeds policy")
        token_digest = hashlib.sha256(compact_token.encode("ascii")).hexdigest()
        holder_thumbprint, proof_jti, proof_digest = self._verify_holder_proof(
            holder_proof, token_digest=token_digest, expected_nonce=expected_nonce, now=now,
        )
        confirmation = require_mapping(claims.get("cnf"), "cnf")
        bound_thumbprint = confirmation.get("jkt", confirmation.get("x5t#S256"))
        if not secrets.compare_digest(require_text(bound_thumbprint, "cnf thumbprint"),
                                      require_text(holder_thumbprint, "holder thumbprint")):
            raise ValidationError("OIDC holder binding mismatch")
        tenant = require_text(claims.get("tenant_id"), "tenant_id")
        subject = require_text(claims.get("sub"), "sub")
        token_jti = require_text(claims.get("jti"), "jti")
        assurance = self._assurance(claims)
        device_digest = _digest_text(require_text(device_id, "device_id"))
        session_id = secrets.token_hex(16)
        refresh_family = secrets.token_hex(16)
        expiry = datetime.fromtimestamp(expires_at, timezone.utc)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                nonce_row = self._db.execute(
                    "SELECT issuer,audience,expires_at,consumed_at FROM oidc_nonce WHERE nonce=?",
                    (expected_nonce,),
                ).fetchone()
                if (nonce_row is None or nonce_row[3] is not None
                        or nonce_row[0] != expected_issuer or nonce_row[1] != expected_audience
                        or parse_instant(nonce_row[2], "OIDC nonce expiry") <= now.astimezone(timezone.utc)):
                    raise ValidationError("OIDC nonce is unknown, expired, mismatched or consumed")
                if self._db.execute(
                    "SELECT 1 FROM oidc_token_jti WHERE issuer=? AND token_jti=?",
                    (expected_issuer, token_jti),
                ).fetchone():
                    raise ValidationError("OIDC token jti was replayed")
                if self._db.execute(
                    "SELECT 1 FROM holder_proof_replay WHERE proof_jti=?", (proof_jti,),
                ).fetchone():
                    raise ValidationError("holder proof jti was replayed")
                self._db.execute(
                    "UPDATE oidc_nonce SET consumed_at=? WHERE nonce=? AND consumed_at IS NULL",
                    (_utc(now), expected_nonce),
                )
                self._db.execute(
                    "INSERT INTO oidc_token_jti VALUES(?,?,?,?)",
                    (expected_issuer, token_jti, token_digest, _utc(now)),
                )
                self._db.execute(
                    "INSERT INTO holder_proof_replay VALUES(?,?,?)",
                    (proof_jti, proof_digest, _utc(now)),
                )
                self._db.execute(
                    "INSERT INTO identity_session VALUES(?,?,?,?,?,?,?,0,?,?,NULL)",
                    (session_id, tenant, subject, assurance, device_digest, holder_thumbprint,
                     refresh_family, _utc(now), _utc(expiry)),
                )
                self._audit(
                    tenant, "IDENTITY_SESSION_ISSUED", _digest_text(session_id), subject, now,
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return VerifiedPrincipal(tenant, subject, "HUMAN", assurance, device_digest,
                                 holder_thumbprint, session_id, expiry)

    def issue_oidc_nonce(self, issuer: str, audience: str, now: datetime) -> str:
        """Issue a short, durable one-use nonce for an exact trusted issuer/audience pair."""

        issuer_trust = self._oidc_issuer(issuer)
        audiences = {
            require_text(item, "trusted OIDC audience")
            for item in require_list(issuer_trust.get("audiences"), "trusted OIDC audiences")
        }
        if audience not in audiences:
            raise ValidationError("OIDC audience is not configured for the trusted issuer")
        oidc = require_mapping(self.policy.get("oidc"), "oidc policy")
        lifetime = int(oidc.get("nonceSeconds", 180))
        if not 30 <= lifetime <= 600:
            raise ValidationError("OIDC nonce lifetime is outside the safe bound")
        nonce = _b64url(secrets.token_bytes(32))
        self._db.execute(
            "INSERT INTO oidc_nonce VALUES(?,?,?,?,NULL)",
            (nonce, issuer, audience, _utc(now + timedelta(seconds=lifetime))),
        )
        return nonce

    def _oidc_issuer(self, issuer: str) -> Mapping[str, Any]:
        trust = self._receipt_trust()
        issuers = require_mapping(trust.get("oidcIssuers"), "identity trust oidcIssuers")
        configured = issuers.get(issuer)
        if configured is None:
            raise ValidationError("OIDC issuer is not in the trusted configuration")
        return require_mapping(configured, f"trusted OIDC issuer {issuer}")

    def _verify_holder_proof(
        self, proof: Mapping[str, Any], *, token_digest: str,
        expected_nonce: str, now: datetime,
    ) -> tuple[str, str, str]:
        value = require_mapping(proof, "holder proof")
        public_key = require_text(value.get("publicKeyPem"), "holder proof publicKeyPem")
        if "BEGIN PUBLIC KEY" not in public_key or len(public_key) > 16_384:
            raise ValidationError("holder proof public key is invalid")
        algorithm = require_text(value.get("algorithm"), "holder proof algorithm")
        if algorithm != "RS256":
            raise ValidationError("holder proof algorithm is not allowed")
        oidc = require_mapping(self.policy.get("oidc"), "oidc policy")
        method = require_text(value.get("method"), "holder proof method")
        uri = require_text(value.get("uri"), "holder proof uri")
        if method != oidc.get("holderProofMethod") or uri != oidc.get("holderProofUri"):
            raise ValidationError("holder proof request binding mismatch")
        if require_text(value.get("nonce"), "holder proof nonce") != expected_nonce:
            raise ValidationError("holder proof nonce mismatch")
        if require_text(value.get("tokenDigest"), "holder proof tokenDigest") != token_digest:
            raise ValidationError("holder proof token binding mismatch")
        proof_jti = require_text(value.get("jti"), "holder proof jti")
        if not __import__("re").fullmatch(r"[A-Za-z0-9._:-]{16,160}", proof_jti):
            raise ValidationError("holder proof jti is invalid")
        issued_at = parse_instant(value.get("issuedAt"), "holder proof issuedAt")
        skew = timedelta(seconds=int(self.policy.get("clockSkewSeconds", 0)))
        if not now.astimezone(timezone.utc) - skew <= issued_at <= now.astimezone(timezone.utc) + skew:
            raise ValidationError("holder proof is outside its validity window")
        unsigned = {key: item for key, item in value.items() if key != "signature"}
        signature = _b64url_decode(
            require_text(value.get("signature"), "holder proof signature"),
            "holder proof signature",
        )
        self._verify_rs256(public_key, canonical_json(unsigned), signature)
        proof_digest = hashlib.sha256(canonical_json(unsigned)).hexdigest()
        thumbprint = hashlib.sha256(public_key.encode("ascii")).hexdigest()
        return thumbprint, proof_jti, proof_digest

    def register_workload_identity(
        self, spiffe_id: str, service_name: str, certificate_thumbprint: str,
        issued_at: datetime, expires_at: datetime, actor: str,
    ) -> None:
        workload_policy = require_mapping(self.policy.get("workloadIdentity"), "workload policy")
        trust_domain = require_text(workload_policy.get("trustDomain"), "trustDomain")
        if not spiffe_id.startswith(trust_domain.rstrip("/") + "/"):
            raise ValidationError("SPIFFE identity is outside the trust domain")
        if expires_at <= issued_at or (expires_at - issued_at).total_seconds() > int(
            workload_policy["maximumCertificateSeconds"]
        ):
            raise ValidationError("workload certificate lifetime exceeds policy")
        if len(certificate_thumbprint) != 64:
            raise ValidationError("workload certificate thumbprint must be SHA-256 hex")
        self._db.execute(
            "INSERT INTO workload_identity VALUES(?,?,?,?,?,NULL)",
            (spiffe_id, service_name, certificate_thumbprint, _utc(issued_at), _utc(expires_at)),
        )
        self._audit(None, "WORKLOAD_IDENTITY_REGISTERED", _digest_text(spiffe_id), actor, issued_at)

    def authenticate_workload(
        self, spiffe_id: str, certificate_thumbprint: str, now: datetime,
    ) -> VerifiedPrincipal:
        row = self._db.execute(
            "SELECT service_name,certificate_thumbprint,expires_at,revoked_at FROM workload_identity "
            "WHERE spiffe_id=?", (spiffe_id,),
        ).fetchone()
        if row is None or row[3] is not None or not secrets.compare_digest(
            str(row[1]), certificate_thumbprint
        ):
            raise ValidationError("workload identity is unknown or revoked")
        expiry = parse_instant(row[2], "workload expiry")
        if expiry <= now.astimezone(timezone.utc):
            raise ValidationError("workload identity expired")
        return VerifiedPrincipal("platform", str(row[0]), "WORKLOAD", "PHISHING_RESISTANT",
                                 _digest_text(spiffe_id), certificate_thumbprint, spiffe_id, expiry)

    @staticmethod
    def _verify_rs256(public_key: str, message: bytes, signature: bytes) -> None:
        if "BEGIN PUBLIC KEY" not in public_key or len(public_key) > 16_384:
            raise ValidationError("OIDC public key is invalid")
        with tempfile.TemporaryDirectory(prefix="elmpay-oidc-") as directory:
            key_path = Path(directory) / "key.pem"
            signature_path = Path(directory) / "signature.bin"
            key_path.write_text(public_key, encoding="ascii")
            signature_path.write_bytes(signature)
            result = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", str(key_path),
                 "-signature", str(signature_path)],
                input=message, capture_output=True, timeout=5, check=False,
            )
        if result.returncode != 0:
            raise ValidationError("OIDC signature verification failed")

    @staticmethod
    def _assurance(claims: Mapping[str, Any]) -> str:
        methods = claims.get("amr", [])
        if not isinstance(methods, list):
            raise ValidationError("OIDC amr must be an array")
        normalized = {str(item).lower() for item in methods}
        acr = str(claims.get("acr", "")).lower()
        if {"webauthn", "hwk", "fido"} & normalized or "phishing" in acr:
            return "PHISHING_RESISTANT"
        if {"mfa", "otp"} & normalized:
            return "AAL2"
        return "AAL1"

    def register_webauthn_credential(
        self,
        *,
        tenant_id: str,
        user_id: str,
        credential_id: str,
        public_key_pem: str,
        rp_id: str,
        aaguid: str,
        sign_count: int,
        backup_eligible: bool,
        attestation_receipt: Mapping[str, Any],
        actor: str,
        now: datetime,
    ) -> str:
        """Persist a credential only after a trusted FIDO attestation verifier receipt."""

        webauthn = require_mapping(self.policy.get("webauthn"), "webauthn policy")
        if rp_id not in set(require_list(webauthn.get("rpIds"), "rpIds")):
            raise ValidationError("WebAuthn RP ID is not allowlisted")
        expected_key_digest = hashlib.sha256(public_key_pem.encode("ascii")).hexdigest()
        if "BEGIN PUBLIC KEY" not in public_key_pem or len(public_key_pem) > 16_384:
            raise ValidationError("WebAuthn public key must be bounded PEM")
        if isinstance(sign_count, bool) or not isinstance(sign_count, int) or sign_count < 0:
            raise ValidationError("WebAuthn sign count is invalid")
        receipt_digest, _signer = verify_downstream_receipt(
            attestation_receipt, self._receipt_trust(),
            receipt_type="WEBAUTHN_ATTESTATION", outcome="VERIFIED",
            fields={
                "tenantId": tenant_id, "userId": user_id,
                "credentialId": credential_id, "publicKeyDigest": expected_key_digest,
                "rpId": rp_id, "aaguid": aaguid, "signCount": sign_count,
                "backupEligible": backup_eligible, "metadataStatus": "TRUSTED",
            },
            required_role="webauthn_attestation_verifier", require_independent=True,
            now=now,
        )
        self._db.execute(
            "INSERT INTO webauthn_credential VALUES(?,?,?,?,?,?,?,?,?,?,NULL)",
            (tenant_id, user_id, credential_id, public_key_pem, rp_id, aaguid, sign_count,
             int(backup_eligible), receipt_digest, _utc(now)),
        )
        self._audit(tenant_id, "WEBAUTHN_CREDENTIAL_REGISTERED",
                    _digest_text(credential_id), actor, now)
        return receipt_digest

    def issue_webauthn_challenge(
        self,
        tenant_id: str,
        user_id: str,
        operation: str,
        origin: str,
        rp_id: str,
        session_binding: str,
        now: datetime,
    ) -> Mapping[str, str]:
        webauthn = require_mapping(self.policy.get("webauthn"), "webauthn policy")
        if origin not in set(require_list(webauthn.get("origins"), "origins")):
            raise ValidationError("WebAuthn origin is not allowlisted")
        if rp_id not in set(require_list(webauthn.get("rpIds"), "rpIds")):
            raise ValidationError("WebAuthn RP ID is not allowlisted")
        if not self._db.execute(
            "SELECT 1 FROM webauthn_credential WHERE tenant_id=? AND user_id=? "
            "AND rp_id=? AND revoked_at IS NULL", (tenant_id, user_id, rp_id),
        ).fetchone():
            raise ValidationError("user has no active WebAuthn credential for this RP")
        challenge_id = secrets.token_hex(16)
        challenge = _b64url(secrets.token_bytes(32))
        expiry = now.astimezone(timezone.utc) + timedelta(seconds=int(webauthn["challengeSeconds"]))
        binding_digest = _digest_text(require_text(session_binding, "session_binding"))
        self._db.execute(
            "INSERT INTO webauthn_challenge VALUES(?,?,?,?,?,?,?,?,?,NULL)",
            (challenge_id, tenant_id, user_id, operation, challenge, origin, rp_id,
             binding_digest, _utc(expiry)),
        )
        self._audit(tenant_id, "WEBAUTHN_CHALLENGE_ISSUED", _digest_text(challenge_id),
                    user_id, now)
        return {"challengeId": challenge_id, "challenge": challenge,
                "rpId": rp_id, "origin": origin, "expiresAt": _utc(expiry)}

    def verify_webauthn_assertion(
        self,
        *,
        tenant_id: str,
        challenge_id: str,
        credential_id: str,
        client_data_json: bytes,
        authenticator_data: bytes,
        signature: bytes,
        session_binding: str,
        now: datetime,
    ) -> WebAuthnResult:
        if len(client_data_json) > 16_384 or len(authenticator_data) < 37 or len(
            authenticator_data
        ) > 1_024 or not signature or len(signature) > 1_024:
            raise ValidationError("WebAuthn assertion component size is invalid")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                challenge = self._db.execute(
                    "SELECT user_id,operation,challenge,origin,rp_id,session_binding,expires_at,consumed_at "
                    "FROM webauthn_challenge WHERE tenant_id=? AND challenge_id=?",
                    (tenant_id, challenge_id),
                ).fetchone()
                if challenge is None or challenge[7] is not None:
                    raise ValidationError("WebAuthn challenge is unknown or already consumed")
                if parse_instant(challenge[6], "challenge expiry") <= now.astimezone(timezone.utc):
                    raise ValidationError("WebAuthn challenge expired")
                if not secrets.compare_digest(str(challenge[5]), _digest_text(session_binding)):
                    raise ValidationError("WebAuthn session binding mismatch")
                credential = self._db.execute(
                    "SELECT user_id,public_key_pem,rp_id,sign_count,revoked_at FROM "
                    "webauthn_credential WHERE tenant_id=? AND credential_id=?",
                    (tenant_id, credential_id),
                ).fetchone()
                if credential is None or credential[4] is not None or credential[0] != challenge[0]:
                    raise ValidationError("WebAuthn credential is unknown, revoked or user-mismatched")
                client = _strict_json(client_data_json, "clientDataJSON")
                if client.get("type") != "webauthn.get":
                    raise ValidationError("WebAuthn client data type mismatch")
                if not secrets.compare_digest(
                    require_text(client.get("challenge"), "client challenge"), str(challenge[2])
                ):
                    raise ValidationError("WebAuthn challenge mismatch")
                if require_text(client.get("origin"), "client origin") != challenge[3]:
                    raise ValidationError("WebAuthn origin mismatch")
                rp_id = str(challenge[4])
                if credential[2] != rp_id or not secrets.compare_digest(
                    authenticator_data[:32], hashlib.sha256(rp_id.encode("utf-8")).digest()
                ):
                    raise ValidationError("WebAuthn RP ID hash mismatch")
                flags = authenticator_data[32]
                if flags & 0x01 == 0:
                    raise ValidationError("WebAuthn user presence is required")
                if require_mapping(self.policy.get("webauthn"), "webauthn policy").get(
                    "requireUserVerification"
                ) is True and flags & 0x04 == 0:
                    raise ValidationError("WebAuthn user verification is required")
                new_count = int.from_bytes(authenticator_data[33:37], "big")
                previous_count = int(credential[3])
                if previous_count > 0 and new_count <= previous_count:
                    raise ValidationError("WebAuthn signature counter indicates a cloned credential")
                signed = authenticator_data + hashlib.sha256(client_data_json).digest()
                self._verify_webauthn_signature(str(credential[1]), signed, signature)
                self._db.execute(
                    "UPDATE webauthn_challenge SET consumed_at=? WHERE challenge_id=? "
                    "AND consumed_at IS NULL", (_utc(now), challenge_id),
                )
                self._db.execute(
                    "UPDATE webauthn_credential SET sign_count=? WHERE tenant_id=? AND credential_id=?",
                    (new_count, tenant_id, credential_id),
                )
                self._audit(tenant_id, "WEBAUTHN_ASSERTION_VERIFIED",
                            _digest_text(challenge_id), str(challenge[0]), now)
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return WebAuthnResult(tenant_id, str(challenge[0]), credential_id,
                              str(challenge[1]), new_count, True)

    @staticmethod
    def _verify_webauthn_signature(public_key: str, message: bytes, signature: bytes) -> None:
        with tempfile.TemporaryDirectory(prefix="elmpay-webauthn-") as directory:
            key_path = Path(directory) / "key.pem"
            signature_path = Path(directory) / "signature.bin"
            key_path.write_text(public_key, encoding="ascii")
            signature_path.write_bytes(signature)
            result = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", str(key_path),
                 "-signature", str(signature_path)],
                input=message, capture_output=True, timeout=5, check=False,
            )
        if result.returncode != 0:
            raise ValidationError("WebAuthn assertion signature is invalid")

    def propose_grant(
        self,
        tenant_id: str,
        subject_id: str,
        role_name: str,
        object_scope: str,
        field_scope: list[str],
        valid_from: datetime,
        valid_until: datetime,
        proposer: str,
        now: datetime,
    ) -> str:
        authorization = require_mapping(self.policy.get("authorization"), "authorization policy")
        if valid_until <= valid_from or valid_until <= now:
            raise ValidationError("authorization grant validity window is invalid")
        if (valid_until - valid_from).total_seconds() > int(authorization["maximumJitSeconds"]):
            raise ValidationError("JIT authorization exceeds maximum lifetime")
        fields = sorted({require_text(field, "field scope") for field in field_scope})
        if not fields:
            raise ValidationError("authorization field scope cannot be empty")
        self._assert_no_sod_conflict(tenant_id, subject_id, role_name, now)
        payload = {
            "tenantId": tenant_id,
            "subjectId": subject_id,
            "roleName": role_name,
            "objectScope": object_scope,
            "fieldScope": fields,
            "validFrom": _utc(valid_from),
            "validUntil": _utc(valid_until),
        }
        digest = hashlib.sha256(canonical_json(payload)).hexdigest()
        grant_id = hashlib.sha256(canonical_json({**payload, "proposer": proposer})).hexdigest()
        self._db.execute(
            "INSERT INTO authorization_grant VALUES(?,?,?,?,?,?,?,NULL,'PROPOSED',?,?,?,?)",
            (grant_id, tenant_id, subject_id, role_name, object_scope, canonical_json(fields),
             proposer, _utc(valid_from), _utc(valid_until), digest, _utc(now)),
        )
        self._audit(tenant_id, "AUTHORIZATION_GRANT_PROPOSED", digest, proposer, now)
        return grant_id

    def approve_grant(self, tenant_id: str, grant_id: str, approver: str, now: datetime) -> None:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT subject_id,role_name,proposed_by,state,valid_from,valid_until,payload_digest "
                    "FROM authorization_grant WHERE tenant_id=? AND grant_id=?",
                    (tenant_id, grant_id),
                ).fetchone()
                if row is None or row[3] != "PROPOSED":
                    raise ValidationError("authorization grant is not approvable")
                if row[2] == approver:
                    raise ValidationError("grant proposer cannot approve their own grant")
                if parse_instant(row[5], "grant expiry") <= now.astimezone(timezone.utc):
                    raise ValidationError("authorization grant expired before approval")
                self._assert_no_sod_conflict(tenant_id, str(row[0]), str(row[1]), now,
                                             ignore_grant=grant_id)
                state = "ACTIVE" if parse_instant(row[4], "grant start") <= now.astimezone(
                    timezone.utc
                ) else "PROPOSED"
                if state != "ACTIVE":
                    raise ValidationError("authorization grant cannot activate before valid_from")
                self._db.execute(
                    "UPDATE authorization_grant SET approved_by=?,state='ACTIVE' WHERE grant_id=?",
                    (approver, grant_id),
                )
                self._audit(tenant_id, "AUTHORIZATION_GRANT_ACTIVATED", str(row[6]), approver, now)
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def authorize(
        self,
        tenant_id: str,
        subject_id: str,
        role_name: str,
        object_id: str,
        requested_fields: list[str],
        now: datetime,
    ) -> GateReport:
        reasons: list[str] = []
        fields = set(requested_fields)
        rows = self._db.execute(
            "SELECT object_scope,field_scope,valid_from,valid_until FROM authorization_grant "
            "WHERE tenant_id=? AND subject_id=? AND role_name=? AND state='ACTIVE'",
            (tenant_id, subject_id, role_name),
        ).fetchall()
        for row in rows:
            start = parse_instant(row[2], "grant start")
            expiry = parse_instant(row[3], "grant expiry")
            if not start <= now.astimezone(timezone.utc) < expiry:
                continue
            if not self._scope_matches(str(row[0]), object_id):
                continue
            allowed_fields = set(json.loads(bytes(row[1])))
            if "*" in allowed_fields or fields <= allowed_fields:
                return GateReport(True, (), ("tenant", "object", "field", "jit"))
        reasons.append("authorization_grant_missing_or_out_of_scope")
        return GateReport.from_reasons(reasons)

    def propose_recovery(
        self, tenant_id: str, subject_id: str, proposer: str, reason: str,
        expires_at: datetime, now: datetime,
    ) -> str:
        if expires_at <= now or expires_at - now > timedelta(hours=1):
            raise ValidationError("account recovery approval window is invalid")
        payload = {"tenant": tenant_id, "subject": subject_id, "reason": reason,
                   "proposer": proposer, "expiresAt": _utc(expires_at)}
        recovery_id = hashlib.sha256(canonical_json(payload)).hexdigest()
        self._db.execute(
            "INSERT INTO identity_recovery VALUES(?,?,?,?,NULL,?,'PROPOSED',?,?,NULL)",
            (recovery_id, tenant_id, subject_id, proposer, reason, _utc(expires_at), _utc(now)),
        )
        self._audit(tenant_id, "ACCOUNT_RECOVERY_PROPOSED", recovery_id, proposer, now)
        return recovery_id

    def approve_recovery(self, tenant_id: str, recovery_id: str, approver: str,
                         now: datetime) -> int:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT subject_id,proposed_by,state,expires_at FROM identity_recovery "
                    "WHERE tenant_id=? AND recovery_id=?", (tenant_id, recovery_id),
                ).fetchone()
                if row is None or row[2] != "PROPOSED":
                    raise ValidationError("account recovery is not approvable")
                if row[1] == approver:
                    raise ValidationError("account recovery requires a distinct approver")
                if parse_instant(row[3], "recovery expiry") <= now.astimezone(timezone.utc):
                    raise ValidationError("account recovery approval expired")
                cursor = self._db.execute(
                    "UPDATE identity_session SET revoked_at=? WHERE tenant_id=? AND subject_id=? "
                    "AND revoked_at IS NULL", (_utc(now), tenant_id, row[0]),
                )
                self._db.execute(
                    "UPDATE identity_recovery SET approved_by=?,state='APPROVED',decided_at=? "
                    "WHERE recovery_id=?", (approver, _utc(now), recovery_id),
                )
                self._audit(tenant_id, "ACCOUNT_RECOVERY_APPROVED", recovery_id, approver, now)
                self._db.execute("COMMIT")
                return cursor.rowcount
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def require_session(
        self, tenant_id: str, session_id: str, device_id: str,
        holder_thumbprint: str, now: datetime,
    ) -> VerifiedPrincipal:
        row = self._db.execute(
            "SELECT subject_id,assurance_level,device_digest,holder_thumbprint,expires_at,revoked_at "
            "FROM identity_session WHERE tenant_id=? AND session_id=?", (tenant_id, session_id),
        ).fetchone()
        if row is None or row[5] is not None:
            raise ValidationError("identity session is unknown or revoked")
        expiry = parse_instant(row[4], "session expiry")
        if expiry <= now.astimezone(timezone.utc):
            raise ValidationError("identity session expired")
        if not secrets.compare_digest(str(row[2]), _digest_text(device_id)):
            raise ValidationError("identity session device binding mismatch")
        if not secrets.compare_digest(str(row[3]), holder_thumbprint):
            raise ValidationError("identity session holder binding mismatch")
        return VerifiedPrincipal(tenant_id, str(row[0]), "HUMAN", str(row[1]), str(row[2]),
                                 str(row[3]), session_id, expiry)

    def evaluate_zero_trust(self, request: Mapping[str, Any], now: datetime) -> GateReport:
        """Evaluate identity, device, network, risk, step-up and scoped authorization."""

        reasons: list[str] = []
        tenant = require_text(request.get("tenantId"), "tenantId")
        context_receipts = require_mapping(request.get("contextReceipts"), "contextReceipts")
        try:
            principal = self.require_session(
                tenant, require_text(request.get("sessionId"), "sessionId"),
                require_text(request.get("deviceId"), "deviceId"),
                require_text(request.get("holderThumbprint"), "holderThumbprint"), now,
            )
        except ValidationError as exc:
            reasons.append(f"identity_invalid:{exc}")
            return GateReport.from_reasons(reasons)
        action = require_text(request.get("action"), "action")
        object_id = require_text(request.get("objectId"), "objectId")
        device_posture = require_text(request.get("devicePosture"), "devicePosture")
        network_zone = require_text(request.get("networkZone"), "networkZone")
        risk_action = require_text(request.get("riskAction"), "riskAction")
        bindings = (
            ("device", "DEVICE_POSTURE", "device_attestation_verifier", {
                "tenantId": tenant, "sessionId": principal.session_id,
                "deviceDigest": principal.device_digest, "posture": device_posture,
            }),
            ("network", "NETWORK_ZONE", "network_context_verifier", {
                "tenantId": tenant, "sessionId": principal.session_id, "zone": network_zone,
            }),
            ("risk", "RISK_DECISION", "risk_decision_service", {
                "tenantId": tenant, "sessionId": principal.session_id, "action": action,
                "objectId": object_id, "decision": risk_action,
            }),
        )
        for receipt_name, receipt_type, role, fields in bindings:
            try:
                verify_downstream_receipt(
                    require_mapping(context_receipts.get(receipt_name), receipt_name),
                    self._receipt_trust(), receipt_type=receipt_type, outcome="VERIFIED",
                    fields=fields, required_role=role, now=now,
                )
            except ValidationError as exc:
                reasons.append(f"{receipt_name}_receipt_invalid:{exc}")
        if device_posture not in set(require_list(self.policy.get("allowedDevicePostures"),
                                                  "allowedDevicePostures")):
            reasons.append("device_posture_not_trusted")
        if network_zone not in set(require_list(self.policy.get("allowedNetworkZones"),
                                                "allowedNetworkZones")):
            reasons.append("network_zone_not_trusted")
        high_risk = action in set(require_list(self.policy.get("highRiskActions"),
                                               "highRiskActions"))
        if risk_action == "BLOCK":
            reasons.append("risk_decision_blocked")
        elif risk_action == "REVIEW" and principal.assurance_level != "PHISHING_RESISTANT":
            reasons.append("risk_review_requires_phishing_resistant_step_up")
        if high_risk:
            if principal.assurance_level != "PHISHING_RESISTANT":
                reasons.append("high_risk_action_requires_phishing_resistant_authentication")
            try:
                step_up_text = require_text(request.get("stepUpAt"), "stepUpAt")
                step_up = parse_instant(step_up_text, "stepUpAt")
                if not now.astimezone(timezone.utc) - timedelta(minutes=5) <= step_up <= now.astimezone(
                    timezone.utc
                ):
                    reasons.append("step_up_is_missing_or_stale")
                verify_downstream_receipt(
                    require_mapping(context_receipts.get("stepUp"), "stepUp"),
                    self._receipt_trust(), receipt_type="STEP_UP_AUTHENTICATION",
                    outcome="VERIFIED", fields={
                        "tenantId": tenant, "sessionId": principal.session_id,
                        "subjectId": principal.subject_id, "action": action,
                        "objectId": object_id, "performedAt": step_up_text,
                        "assuranceLevel": principal.assurance_level,
                    }, required_role="step_up_authenticator", now=now,
                )
            except ValidationError:
                reasons.append("step_up_is_missing_or_stale")
        authorization = self.authorize(
            tenant, principal.subject_id, require_text(request.get("role"), "role"),
            object_id,
            [require_text(item, "requested field") for item in require_list(
                request.get("requestedFields"), "requestedFields")], now,
        )
        reasons.extend(authorization.reasons)
        return GateReport.from_reasons(reasons, checks=(
            "identity", "holder_binding", "device", "network", "risk", "authorization",
        ))

    def _assert_no_sod_conflict(
        self, tenant_id: str, subject_id: str, role_name: str, now: datetime,
        *, ignore_grant: str | None = None,
    ) -> None:
        pairs = require_list(require_mapping(self.policy.get("authorization"),
                                             "authorization policy").get(
                                                 "separationOfDuties"
                                             ), "separationOfDuties")
        incompatible: set[str] = set()
        for raw_pair in pairs:
            pair = [require_text(item, "SoD role") for item in require_list(raw_pair, "SoD pair")]
            if len(pair) != 2:
                raise ValidationError("each separation-of-duties entry must contain two roles")
            if role_name == pair[0]:
                incompatible.add(pair[1])
            elif role_name == pair[1]:
                incompatible.add(pair[0])
        if not incompatible:
            return
        rows = self._db.execute(
            "SELECT grant_id,role_name,valid_until FROM authorization_grant WHERE tenant_id=? "
            "AND subject_id=? AND state='ACTIVE'", (tenant_id, subject_id),
        ).fetchall()
        for row in rows:
            if row[0] != ignore_grant and row[1] in incompatible and parse_instant(
                row[2], "grant expiry"
            ) > now.astimezone(timezone.utc):
                raise ValidationError("separation-of-duties role conflict")

    @staticmethod
    def _scope_matches(scope: str, object_id: str) -> bool:
        return scope == "*" or scope == object_id or (
            scope.endswith("*") and object_id.startswith(scope[:-1])
        )

    def propose_certificate(
        self,
        *,
        serial_number: str,
        subject_name: str,
        san_names: list[str],
        issuer_name: str,
        key_reference: str,
        overlap_group: str,
        not_before: datetime,
        not_after: datetime,
        proposer: str,
        ca_receipt: Mapping[str, Any],
        now: datetime,
    ) -> str:
        pki = require_mapping(self.policy.get("pki"), "pki policy")
        if issuer_name not in set(require_list(pki.get("trustedIssuers"), "trustedIssuers")):
            raise ValidationError("certificate issuer is not trusted")
        if not_after <= not_before or not_before > now + timedelta(minutes=5):
            raise ValidationError("certificate validity window is invalid")
        names = sorted({require_text(item, "certificate SAN") for item in san_names})
        if not names or subject_name not in names:
            raise ValidationError("certificate SANs must include the subject name")
        receipt_digest, _signer = verify_downstream_receipt(
            ca_receipt, self._receipt_trust(), receipt_type="CERTIFICATE_ISSUANCE",
            outcome="ISSUED", fields={
                "serialNumber": serial_number, "subjectName": subject_name,
                "sanNames": names, "issuerName": issuer_name,
                "keyReference": key_reference, "notBefore": _utc(not_before),
                "notAfter": _utc(not_after),
            }, required_role="certificate_authority", require_independent=True, now=now,
        )
        current = self._db.execute(
            "SELECT not_after FROM certificate_inventory WHERE overlap_group=? AND status='ACTIVE'",
            (overlap_group,),
        ).fetchone()
        if current is not None:
            overlap = parse_instant(current[0], "current certificate expiry") - not_before.astimezone(
                timezone.utc
            )
            if overlap.total_seconds() < int(pki["minimumOverlapSeconds"]):
                raise ValidationError("certificate rotation has insufficient verification overlap")
        self._db.execute(
            "INSERT INTO certificate_inventory VALUES(?,?,?,?,?,?,'PROPOSED',?,?,?,NULL,?,?,NULL)",
            (serial_number, subject_name, canonical_json(names), issuer_name, key_reference,
             overlap_group, _utc(not_before), _utc(not_after), proposer, receipt_digest, _utc(now)),
        )
        self._audit(None, "CERTIFICATE_PROPOSED", _digest_text(serial_number), proposer, now)
        return receipt_digest

    def approve_certificate(self, serial_number: str, approver: str, now: datetime) -> None:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT overlap_group,proposer,status,not_before,not_after FROM "
                    "certificate_inventory WHERE serial_number=?", (serial_number,),
                ).fetchone()
                if row is None or row[2] != "PROPOSED":
                    raise ValidationError("certificate is not approvable")
                if row[1] == approver:
                    raise ValidationError("certificate proposer cannot approve activation")
                if parse_instant(row[3], "certificate start") > now.astimezone(timezone.utc) + timedelta(
                    minutes=5
                ) or parse_instant(row[4], "certificate expiry") <= now.astimezone(timezone.utc):
                    raise ValidationError("certificate is not currently valid")
                self._db.execute(
                    "UPDATE certificate_inventory SET status='OVERLAP' WHERE overlap_group=? "
                    "AND status='ACTIVE'", (row[0],),
                )
                self._db.execute(
                    "UPDATE certificate_inventory SET status='ACTIVE',approver=? WHERE serial_number=?",
                    (approver, serial_number),
                )
                self._audit(None, "CERTIFICATE_ACTIVATED", _digest_text(serial_number), approver, now)
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def revoke_certificate(
        self, serial_number: str, reason: str, actor: str,
        ca_client: CertificateAuthorityClient, now: datetime,
    ) -> str:
        row = self._db.execute(
            "SELECT status FROM certificate_inventory WHERE serial_number=?", (serial_number,),
        ).fetchone()
        if row is None or row[0] not in {"ACTIVE", "OVERLAP"}:
            raise ValidationError("certificate is not revocable")
        receipt = require_mapping(ca_client.revoke(serial_number, reason), "CA revocation receipt")
        receipt_digest, _signer = verify_downstream_receipt(
            receipt, self._receipt_trust(), receipt_type="CERTIFICATE_REVOCATION",
            outcome="REVOKED", fields={"serialNumber": serial_number, "reason": reason},
            required_role="certificate_authority", require_independent=True, now=now,
        )
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute(
                    "UPDATE certificate_inventory SET status='REVOKED',revoked_at=? "
                    "WHERE serial_number=? AND status IN ('ACTIVE','OVERLAP')",
                    (_utc(now), serial_number),
                )
                self._audit(None, "CERTIFICATE_REVOKED", receipt_digest, actor, now)
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return receipt_digest

    def certificate_expiry_scan(self, now: datetime) -> tuple[Mapping[str, Any], ...]:
        warning_seconds = int(require_mapping(self.policy.get("pki"), "pki policy")[
            "expiryWarningSeconds"
        ])
        rows = self._db.execute(
            "SELECT serial_number,subject_name,status,not_after FROM certificate_inventory "
            "WHERE status IN ('ACTIVE','OVERLAP') ORDER BY not_after,serial_number"
        ).fetchall()
        alerts: list[Mapping[str, Any]] = []
        for row in rows:
            expiry = parse_instant(row[3], "certificate expiry")
            remaining = int((expiry - now.astimezone(timezone.utc)).total_seconds())
            if remaining <= 0:
                self._db.execute(
                    "UPDATE certificate_inventory SET status='EXPIRED' WHERE serial_number=?",
                    (row[0],),
                )
                severity = "EXPIRED"
            elif remaining <= warning_seconds:
                severity = "EXPIRING"
            else:
                continue
            alerts.append({"serialNumber": row[0], "subjectName": row[1],
                           "severity": severity, "secondsRemaining": remaining})
        return tuple(alerts)

    def _audit(
        self, tenant_id: str | None, event_type: str, object_digest: str,
        actor: str, now: datetime,
    ) -> None:
        previous = self._db.execute(
            "SELECT audit_hash FROM identity_security_audit ORDER BY sequence_no DESC LIMIT 1"
        ).fetchone()
        previous_hash = str(previous[0]) if previous else "GENESIS"
        payload = {
            "tenantId": tenant_id,
            "eventType": event_type,
            "objectDigest": object_digest,
            "actor": actor,
            "previousHash": previous_hash,
            "occurredAt": _utc(now),
        }
        audit_hash = hashlib.sha256(canonical_json(payload)).hexdigest()
        self._db.execute(
            "INSERT INTO identity_security_audit(tenant_id,event_type,object_digest,actor_id,"
            "previous_hash,audit_hash,occurred_at) VALUES(?,?,?,?,?,?,?)",
            (tenant_id, event_type, object_digest, actor, previous_hash, audit_hash, _utc(now)),
        )

    def _receipt_trust(self) -> Mapping[str, Any]:
        if self.receipt_trust is None:
            raise ValidationError("signed external receipt trust is not configured")
        return require_mapping(self.receipt_trust, "identity receipt trust")
