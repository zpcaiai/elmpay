"""B20 — an executable envelope-encryption reference.

**This is not real cryptography.** The confidentiality primitive here is a
SHA-256 keystream, not AES-GCM, and it exists so the *protocol* can be executed
and attacked: which value is bound to what, what the broker refuses, what a
rotation touches, and what a destroyed key makes impossible. The authenticity
half is a genuine HMAC-SHA-256, because the properties this module is meant to
prove — a ciphertext cannot be moved between tenants, a tampered ciphertext is
rejected — are authentication properties, and simulating those would prove
nothing at all.

The behaviour worth reading:

* ``decrypt`` builds the additional authenticated data from **the caller's**
  tenant and purpose, never from the envelope. If it trusted the envelope's own
  claims, moving a row between tenants would decrypt perfectly — which is
  precisely the attack AAD exists to stop. Note what the refusal does *not*
  say: an AEAD cannot tell a moved ciphertext from an edited one, so both come
  back as ``AUTH_FAILED``. Reporting a more specific reason would mean
  inventing information the primitive does not have.
* a data key is leased, not held: ``DataKeyLease`` expires, and using an expired
  lease raises rather than silently working.
* rotating a KEK rewraps data keys; the ciphertext is never rewritten. Old key
  versions stay usable for the overlap window and then stop.
* destroying a tenant's KEK makes every envelope under it permanently
  undecryptable, including the ones in yesterday's backup. That is the only
  deletion a system with backups can actually prove.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

# AEAD gives one answer, not a diagnosis: a moved ciphertext and an edited one
# both fail the same way, and pretending to distinguish them would be inventing
# information the primitive does not have.
AUTH_FAILED = "AUTH_FAILED"
NONCE_REUSE = "NONCE_REUSE"
LEASE_EXPIRED = "LEASE_EXPIRED"
KEY_DESTROYED = "KEY_DESTROYED"
KEY_VERSION_RETIRED = "KEY_VERSION_RETIRED"
UNKNOWN_KEY = "UNKNOWN_KEY"
WRAP_INVALID = "WRAP_INVALID"


class CryptoRefused(Exception):
    """Raised instead of returning plaintext. The code says which rule refused."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class Envelope:
    key_id: str
    key_version: int
    tenant_id: str
    purpose: str
    nonce: bytes
    wrapped_data_key: bytes
    ciphertext: bytes
    tag: bytes


@dataclass
class DataKeyLease:
    """A short-lived borrowing of decrypt capability, not ownership of a key."""

    key_id: str
    key_version: int
    plaintext: bytes
    wrapped: bytes
    expires_at: int

    def material(self, now: int) -> bytes:
        if now >= self.expires_at:
            raise CryptoRefused(LEASE_EXPIRED,
                                f"the plaintext data key expired at {self.expires_at}")
        return self.plaintext


def _stream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:length])


def _aad(tenant_id: str, purpose: str, key_id: str, key_version: int) -> bytes:
    # Order and separators are part of the contract: a concatenation without
    # separators lets ("ab", "c") and ("a", "bc") produce the same AAD.
    return "\x1f".join([tenant_id, purpose, key_id, str(key_version)]).encode("utf-8")


class KeyBroker:
    """The only way to obtain decrypt capability.

    Applications call this; they never see KEK material. Every call is recorded
    with the key version that served it, so "which key decrypted this, and when"
    is answerable after the fact.
    """

    def __init__(self, policy: dict, *, seed: bytes = b"reference-seed") -> None:
        self.policy = policy
        self.envelope_policy = policy["envelope"]
        self.lease_ttl = int(self.envelope_policy["plaintext_data_key_ttl_seconds"])
        self.overlap_days = int(policy["rotation"]["overlap_window_days"])
        self._seed = seed
        self._versions: dict[str, int] = {}
        self._retired: dict[tuple[str, int], int] = {}
        self._destroyed: set[str] = set()
        self._nonces: set[tuple[str, int, bytes]] = set()
        self.audit: list[dict] = []
        for entry in policy["keys"]:
            if entry["class"] in {"root", "kek"}:
                self._versions[entry["id"]] = 1

    # -- key material -----------------------------------------------------
    def _kek_material(self, key_id: str, version: int, tenant_id: str) -> bytes:
        if key_id not in self._versions:
            raise CryptoRefused(UNKNOWN_KEY, key_id)
        scope = tenant_id if self._tenant_scoped(key_id) else "-"
        if self._destroyed_id(key_id, scope) in self._destroyed:
            raise CryptoRefused(KEY_DESTROYED,
                                f"{key_id} for tenant {tenant_id} has been destroyed")
        return hashlib.sha256(self._seed + key_id.encode() + scope.encode()
                              + str(version).encode()).digest()

    def _tenant_scoped(self, key_id: str) -> bool:
        for entry in self.policy["keys"]:
            if entry["id"] == key_id:
                return bool(entry["tenant_scoped"])
        raise CryptoRefused(UNKNOWN_KEY, key_id)

    @staticmethod
    def _destroyed_id(key_id: str, scope: str) -> str:
        return f"{key_id}/{scope}"

    def kek_for(self, purpose: str) -> str:
        for entry in self.policy["keys"]:
            if entry["class"] == "kek" and entry["purpose"] == purpose:
                return entry["id"]
        raise CryptoRefused(UNKNOWN_KEY, f"no KEK for purpose {purpose!r}")

    # -- leases -----------------------------------------------------------
    def lease(self, *, purpose: str, tenant_id: str, now: int,
              wrapped: bytes | None = None, key_version: int | None = None) -> DataKeyLease:
        key_id = self.kek_for(purpose)
        version = self._versions[key_id] if key_version is None else key_version
        self._check_version(key_id, version, now)
        kek = self._kek_material(key_id, version, tenant_id)
        if wrapped is None:
            material = hashlib.sha256(kek + b"|dek|" + str(len(self.audit)).encode()).digest()
            wrapped = self._wrap(kek, material)
        else:
            material = self._unwrap(kek, wrapped)
        self.audit.append({"action": "lease", "key_id": key_id, "key_version": version,
                           "tenant_id": tenant_id, "purpose": purpose, "at": now})
        return DataKeyLease(key_id=key_id, key_version=version, plaintext=material,
                            wrapped=wrapped, expires_at=now + self.lease_ttl)

    def _check_version(self, key_id: str, version: int, now: int) -> None:
        current = self._versions.get(key_id)
        if current is None:
            raise CryptoRefused(UNKNOWN_KEY, key_id)
        if version > current:
            raise CryptoRefused(UNKNOWN_KEY, f"{key_id} has no version {version}")
        retired_at = self._retired.get((key_id, version))
        if retired_at is not None and now >= retired_at:
            raise CryptoRefused(KEY_VERSION_RETIRED,
                                f"{key_id} v{version} left its overlap window at {retired_at}")

    @staticmethod
    def _wrap(kek: bytes, material: bytes) -> bytes:
        """Key wrapping is authenticated, exactly like the policy says.

        This is what makes unwrapping under the wrong KEK — a tenant's row
        pasted into another tenant's table, when the KEK is per tenant — fail
        loudly instead of yielding a wrong-but-plausible key.
        """
        body = bytes(a ^ b for a, b in zip(material, _stream(kek, b"wrap", len(material))))
        return body + hmac.new(kek, body, hashlib.sha256).digest()

    @staticmethod
    def _unwrap(kek: bytes, wrapped: bytes) -> bytes:
        body, tag = wrapped[:-32], wrapped[-32:]
        if not hmac.compare_digest(hmac.new(kek, body, hashlib.sha256).digest(), tag):
            raise CryptoRefused(WRAP_INVALID,
                                "the wrapped data key does not belong to this key")
        return bytes(a ^ b for a, b in zip(body, _stream(kek, b"wrap", len(body))))

    # -- rotation and destruction ----------------------------------------
    def rotate(self, key_id: str, now: int) -> int:
        """New KEK version. Data keys get rewrapped; ciphertext is untouched."""
        current = self._versions.get(key_id)
        if current is None:
            raise CryptoRefused(UNKNOWN_KEY, key_id)
        self._retired[(key_id, current)] = now + self.overlap_days * 86400
        self._versions[key_id] = current + 1
        self.audit.append({"action": "rotate", "key_id": key_id,
                           "key_version": current + 1, "at": now})
        return current + 1

    def rewrap(self, envelope: Envelope, now: int) -> Envelope:
        old = self._kek_material(envelope.key_id, envelope.key_version, envelope.tenant_id)
        material = self._unwrap(old, envelope.wrapped_data_key)
        version = self._versions[envelope.key_id]
        new = self._kek_material(envelope.key_id, version, envelope.tenant_id)
        self.audit.append({"action": "rewrap", "key_id": envelope.key_id,
                           "key_version": version, "at": now})
        # Only the wrapped data key and the version change. The AAD binds the
        # key version, so the tag is recomputed over the same plaintext key.
        aad = _aad(envelope.tenant_id, envelope.purpose, envelope.key_id, version)
        tag = hmac.new(material, envelope.nonce + envelope.ciphertext + aad,
                       hashlib.sha256).digest()
        return Envelope(key_id=envelope.key_id, key_version=version,
                        tenant_id=envelope.tenant_id, purpose=envelope.purpose,
                        nonce=envelope.nonce, wrapped_data_key=self._wrap(new, material),
                        ciphertext=envelope.ciphertext, tag=tag)

    def destroy(self, key_id: str, tenant_id: str = "-") -> None:
        scope = tenant_id if self._tenant_scoped(key_id) else "-"
        self._destroyed.add(self._destroyed_id(key_id, scope))
        self.audit.append({"action": "destroy", "key_id": key_id, "key_version": None,
                           "tenant_id": tenant_id, "at": None})

    # -- record encryption ------------------------------------------------
    def encrypt(self, plaintext: bytes, *, tenant_id: str, purpose: str, now: int,
                nonce: bytes) -> Envelope:
        if len(nonce) < int(self.envelope_policy["nonce_bytes"]):
            raise CryptoRefused(AUTH_FAILED, "nonce too short")
        lease = self.lease(purpose=purpose, tenant_id=tenant_id, now=now)
        seen = (lease.key_id, lease.key_version, nonce)
        if self.envelope_policy["nonce_reuse_forbidden"] and seen in self._nonces:
            raise CryptoRefused(NONCE_REUSE,
                                "this nonce has already been used under this key version")
        self._nonces.add(seen)
        material = lease.material(now)
        aad = _aad(tenant_id, purpose, lease.key_id, lease.key_version)
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, _stream(material, nonce,
                                                                   len(plaintext))))
        tag = hmac.new(material, nonce + ciphertext + aad, hashlib.sha256).digest()
        self.audit.append({"action": "encrypt", "key_id": lease.key_id,
                           "key_version": lease.key_version, "tenant_id": tenant_id,
                           "purpose": purpose, "at": now})
        return Envelope(key_id=lease.key_id, key_version=lease.key_version, tenant_id=tenant_id,
                        purpose=purpose, nonce=nonce, wrapped_data_key=lease.wrapped,
                        ciphertext=ciphertext, tag=tag)

    def decrypt(self, envelope: Envelope, *, tenant_id: str, purpose: str, now: int) -> bytes:
        """Decrypt, using the *caller's* tenant and purpose to rebuild the AAD."""
        lease = self.lease(purpose=purpose, tenant_id=tenant_id, now=now,
                           wrapped=envelope.wrapped_data_key, key_version=envelope.key_version)
        material = lease.material(now)
        aad = _aad(tenant_id, purpose, envelope.key_id, envelope.key_version)
        expected = hmac.new(material, envelope.nonce + envelope.ciphertext + aad,
                            hashlib.sha256).digest()
        if not hmac.compare_digest(expected, envelope.tag):
            self.audit.append({"action": "decrypt-refused", "key_id": envelope.key_id,
                               "key_version": envelope.key_version, "tenant_id": tenant_id,
                               "purpose": purpose, "at": now})
            raise CryptoRefused(AUTH_FAILED,
                                "the ciphertext is not authentic under this tenant, purpose and "
                                "key version")
        self.audit.append({"action": "decrypt", "key_id": envelope.key_id,
                           "key_version": envelope.key_version, "tenant_id": tenant_id,
                           "purpose": purpose, "at": now})
        return bytes(a ^ b for a, b in zip(envelope.ciphertext,
                                           _stream(material, envelope.nonce,
                                                   len(envelope.ciphertext))))
