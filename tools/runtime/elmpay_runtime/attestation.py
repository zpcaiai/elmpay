"""Asymmetric, release-bound attestations for B119/B123/B124/B127.

The signed object is a DSSE envelope whose payload is the canonical JSON form of
the record outside the envelope.  Verification uses OpenSSL's Ed25519
implementation; private keys are never accepted by a verifier.  A durable nonce
store makes verification idempotent for the same payload while refusing nonce
reuse for a different payload.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import sqlite3
import subprocess
import tempfile
from typing import Any, Mapping

from .common import ValidationError, canonical_json, parse_instant, require_list, require_mapping, require_text


PAYLOAD_TYPE = "application/vnd.elmpay.attestation+json;version=1"
NONCE_PATTERN = __import__("re").compile(r"^[A-Za-z0-9._:-]{16,160}$")


def _pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 %d " % len(type_bytes) + type_bytes + b" %d " % len(payload) + payload


def _b64decode(value: object, field: str) -> bytes:
    text = require_text(value, field)
    try:
        decoded = base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValidationError(f"{field} must be canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != text:
        raise ValidationError(f"{field} must be canonical base64")
    return decoded


def _run_openssl(arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["openssl", *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise ValidationError("OpenSSL Ed25519 verifier is unavailable") from exc


def _verify_ed25519(public_key_pem: str, message: bytes, signature: bytes) -> bool:
    with tempfile.TemporaryDirectory(prefix="elmpay-ed25519-verify-") as directory:
        root = Path(directory)
        key = root / "public.pem"
        data = root / "payload.bin"
        sig = root / "signature.bin"
        key.write_text(public_key_pem, encoding="utf-8")
        data.write_bytes(message)
        sig.write_bytes(signature)
        completed = _run_openssl(
            [
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(key),
                "-rawin",
                "-in",
                str(data),
                "-sigfile",
                str(sig),
            ]
        )
        return completed.returncode == 0


def create_dsse_envelope(record: Mapping[str, Any], key_id: str, private_key_pem: str) -> dict[str, Any]:
    """Sign a record for tests or an external issuer process.

    Production verification never reads this private material.  The helper is
    intentionally explicit so callers cannot silently fall back to a shared
    HMAC secret.
    """

    require_text(key_id, "key_id")
    require_text(private_key_pem, "private_key_pem")
    payload = canonical_json(dict(record))
    message = _pae(PAYLOAD_TYPE, payload)
    with tempfile.TemporaryDirectory(prefix="elmpay-ed25519-sign-") as directory:
        root = Path(directory)
        key = root / "private.pem"
        data = root / "payload.bin"
        signature = root / "signature.bin"
        key.write_text(private_key_pem, encoding="utf-8")
        data.write_bytes(message)
        completed = _run_openssl(
            [
                "pkeyutl",
                "-sign",
                "-inkey",
                str(key),
                "-rawin",
                "-in",
                str(data),
                "-out",
                str(signature),
            ]
        )
        if completed.returncode != 0:
            raise ValidationError("OpenSSL refused the Ed25519 signature request")
        encoded_signature = base64.b64encode(signature.read_bytes()).decode("ascii")
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"keyid": key_id, "sig": encoded_signature}],
    }


def attach_dsse(record: Mapping[str, Any], key_id: str, private_key_pem: str) -> dict[str, Any]:
    unsigned = {key: value for key, value in record.items() if key != "dsse"}
    return {**unsigned, "dsse": create_dsse_envelope(unsigned, key_id, private_key_pem)}


def generate_ed25519_keypair() -> tuple[str, str]:
    """Generate an ephemeral Ed25519 pair, primarily for deterministic test setup."""

    with tempfile.TemporaryDirectory(prefix="elmpay-ed25519-keygen-") as directory:
        root = Path(directory)
        private = root / "private.pem"
        public = root / "public.pem"
        generated = _run_openssl(["genpkey", "-algorithm", "ED25519", "-out", str(private)])
        if generated.returncode != 0:
            raise ValidationError("OpenSSL could not generate an Ed25519 key")
        exported = _run_openssl(
            ["pkey", "-in", str(private), "-pubout", "-out", str(public)]
        )
        if exported.returncode != 0:
            raise ValidationError("OpenSSL could not export an Ed25519 public key")
        return private.read_text(encoding="utf-8"), public.read_text(encoding="utf-8")


@dataclass(frozen=True)
class VerifiedSigner:
    key_id: str
    identity: str
    role: str
    independent: bool
    payload_digest: str


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc, traceback))
        finally:
            self.close()


class NonceStore:
    """Durable, idempotent replay protection shared by release validators."""

    def __init__(self, database: str | Path) -> None:
        self.database = str(database)
        if self.database == ":memory:" or self.database.startswith("file::memory:"):
            raise ValidationError("attestation replay protection must use durable storage")
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS attestation_nonce (
                  issuer_key_id TEXT NOT NULL,
                  nonce TEXT NOT NULL,
                  payload_digest TEXT NOT NULL CHECK(length(payload_digest)=64),
                  first_seen_at TEXT NOT NULL,
                  PRIMARY KEY (issuer_key_id, nonce)
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database,
            timeout=10,
            isolation_level=None,
            factory=_ClosingConnection,
        )
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def accept(self, key_id: str, nonce: str, payload_digest: str, now: datetime) -> bool:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT payload_digest FROM attestation_nonce WHERE issuer_key_id=? AND nonce=?",
                (key_id, nonce),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO attestation_nonce VALUES (?,?,?,?)",
                    (key_id, nonce, payload_digest, now.astimezone(timezone.utc).isoformat()),
                )
                connection.commit()
                return True
            connection.commit()
            return row[0] == payload_digest


def nonce_store_from_trust(trust: Mapping[str, Any]) -> NonceStore:
    database = require_text(trust.get("replayDatabase"), "trust.replayDatabase")
    return NonceStore(database)


def verify_dsse_record(
    record: Mapping[str, Any],
    trust: Mapping[str, Any],
    expected_binding: str,
    *,
    now: datetime | None = None,
    nonce_store: NonceStore | None = None,
) -> VerifiedSigner:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if record.get("bindingDigest") != expected_binding:
        raise ValidationError("release_binding_mismatch")
    nonce = require_text(record.get("nonce"), "record.nonce")
    if not NONCE_PATTERN.fullmatch(nonce):
        raise ValidationError("attestation_nonce_invalid")
    issued_at = parse_instant(record.get("issuedAt"), "record.issuedAt")
    expires_at = parse_instant(record.get("expiresAt"), "record.expiresAt")
    if issued_at > current or expires_at <= current or expires_at <= issued_at:
        raise ValidationError("attestation_time_window_invalid")

    envelope = require_mapping(record.get("dsse"), "record.dsse")
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        raise ValidationError("dsse_payload_type_invalid")
    signatures = require_list(envelope.get("signatures"), "record.dsse.signatures")
    if len(signatures) != 1:
        raise ValidationError("dsse_requires_exactly_one_signature")
    signature = require_mapping(signatures[0], "record.dsse.signatures[0]")
    key_id = require_text(signature.get("keyid"), "signature.keyid")
    keys = require_mapping(trust.get("keys"), "trust.keys")
    if key_id not in keys:
        raise ValidationError("untrusted_key")
    key = require_mapping(keys[key_id], f"trust.keys.{key_id}")
    if key.get("algorithm") != "Ed25519":
        raise ValidationError("unsupported_signature_algorithm")
    if key.get("revoked") is True:
        raise ValidationError("revoked_key")
    key_not_before = parse_instant(key.get("notBefore"), f"trust.keys.{key_id}.notBefore")
    key_not_after = parse_instant(key.get("notAfter"), f"trust.keys.{key_id}.notAfter")
    if not key_not_before <= issued_at < key_not_after or current >= key_not_after:
        raise ValidationError("signing_key_outside_validity")

    payload = _b64decode(envelope.get("payload"), "record.dsse.payload")
    unsigned = {name: value for name, value in record.items() if name != "dsse"}
    expected_payload = canonical_json(unsigned)
    if payload != expected_payload:
        raise ValidationError("dsse_payload_record_mismatch")
    encoded_signature = _b64decode(signature.get("sig"), "record.dsse.signature")
    public_key = require_text(key.get("publicKeyPem"), f"trust.keys.{key_id}.publicKeyPem")
    if not _verify_ed25519(public_key, _pae(PAYLOAD_TYPE, payload), encoded_signature):
        raise ValidationError("signature_invalid")

    identity = require_text(record.get("actor", record.get("verifier")), "record.identity")
    role = require_text(record.get("role"), "record.role")
    if identity != key.get("identity"):
        raise ValidationError("identity_key_mismatch")
    if role != key.get("role"):
        raise ValidationError("role_key_mismatch")
    digest = hashlib.sha256(payload).hexdigest()
    replay = nonce_store or nonce_store_from_trust(trust)
    if not replay.accept(key_id, nonce, digest, current):
        raise ValidationError("attestation_nonce_reused_for_different_payload")
    return VerifiedSigner(
        key_id=key_id,
        identity=identity,
        role=role,
        independent=key.get("independent") is True,
        payload_digest=digest,
    )
