"""B26 — an executable provider-account binding and callback attribution model.

The interesting method is :meth:`Bindings.attribute`. Everything else in this
file exists to make its three answers possible:

* **exactly one binding matches** — deliver it;
* **no binding matches** — quarantine;
* **more than one binding matches** — quarantine.

There is deliberately no fourth answer. The tempting one is "pick the closest
match by amount and timestamp", and it passes every test anyone writes, because
tests do not run two tenants taking ¥99.00 in the same second. Production does,
and then one merchant's money is booked against another with nothing in the
record to show which way round it went. :meth:`attribute` raises
``ATTRIBUTION_AMBIGUOUS`` instead, and the caller cannot make it guess.

Signature verification here is a stand-in — a shared-secret HMAC over the
canonical payload — because the point being modelled is *when* a signature is
checked (before attribution, before any state change), not which curve it uses.

Time is an integer second supplied by the caller; nothing reads the clock.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field

PENDING = "pending"
ACTIVE = "active"
SUSPENDED = "suspended"
REVOKED = "revoked"

DENY_UNKNOWN = "DENY_UNKNOWN"
DENY_DUPLICATE_BINDING = "DENY_DUPLICATE_BINDING"
DENY_IMMUTABLE = "DENY_IMMUTABLE"
DENY_SHARED_CREDENTIAL = "DENY_SHARED_CREDENTIAL"
DENY_NOT_ALLOWED = "DENY_NOT_ALLOWED"
DENY_TRANSITION = "DENY_TRANSITION"
DENY_REQUIREMENT = "DENY_REQUIREMENT"
DENY_SELF_APPROVAL = "DENY_SELF_APPROVAL"
DENY_LEASE_EXPIRED = "DENY_LEASE_EXPIRED"
DENY_CREDENTIAL_DESTROYED = "DENY_CREDENTIAL_DESTROYED"
SIGNATURE_INVALID = "SIGNATURE_INVALID"
CALLBACK_STALE = "CALLBACK_STALE"
ATTRIBUTION_NONE = "ATTRIBUTION_NONE"
ATTRIBUTION_AMBIGUOUS = "ATTRIBUTION_AMBIGUOUS"
DENY_CROSS_TENANT = "DENY_CROSS_TENANT"
DENY_RETURN_PAGE = "DENY_RETURN_PAGE"
DENY_BLIND_REPLAY = "DENY_BLIND_REPLAY"


class BindingRefused(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class Credential:
    """A provider credential. The secret never leaves this object in the clear."""

    id: str
    secret: bytes
    issued_at: int
    rotates_after: int


@dataclass
class Binding:
    tenant_id: str
    project_id: str
    environment: str
    provider: str
    provider_merchant_id: str
    endpoint_id: str
    state: str = PENDING
    credential: Credential | None = None
    previous_credential: Credential | None = None
    previous_valid_until: int = 0
    history: list[dict] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.tenant_id, self.project_id, self.environment, self.provider)


@dataclass(frozen=True)
class Callback:
    provider: str
    environment: str
    provider_event_id: str
    payload: dict
    signature: str
    sent_at: int
    attribution: dict          # the provider's own identifiers, echoed back
    source: str = "provider"   # "provider" or "client_return_page"


@dataclass(frozen=True)
class Quarantined:
    reason: str
    callback: Callback
    at: int


def sign(secret: bytes, payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(secret, canonical, hashlib.sha256).hexdigest()


class Bindings:
    """The binding registry as the platform would enforce it, minus the storage."""

    def __init__(self, model: dict) -> None:
        self.model = model
        self.binding_rules = model["binding"]
        self.credentials = model["credentials"]
        self.callback_rules = model["callback"]
        self.quarantine_rules = model["quarantine"]
        self.lifecycle = model["lifecycle"]
        self.transitions = {(t["from"], t["to"]): set(t["requires"])
                            for t in self.lifecycle["transitions"]}
        self.capabilities = {row["state"]: row for row in model["capability_matrix"]}
        self.providers = {p["id"]: p for p in model["providers"]}
        self.bindings: list[Binding] = []
        self.quarantine: list[Quarantined] = []
        self.delivered: dict[str, tuple[Binding, str]] = {}

    # -- registration -----------------------------------------------------
    def bind(self, binding: Binding) -> Binding:
        provider = self.providers.get(binding.provider)
        if provider is None:
            raise BindingRefused(DENY_UNKNOWN, f"provider {binding.provider}")
        if binding.environment not in provider["environments"]:
            raise BindingRefused(DENY_UNKNOWN, f"environment {binding.environment}")
        if any(b.key == binding.key for b in self.bindings):
            raise BindingRefused(DENY_DUPLICATE_BINDING, str(binding.key))
        self.bindings.append(binding)
        return binding

    def get(self, tenant_id: str, project_id: str, environment: str, provider: str) -> Binding:
        for binding in self.bindings:
            if binding.key == (tenant_id, project_id, environment, provider):
                return binding
        raise BindingRefused(DENY_UNKNOWN, f"{tenant_id}/{project_id}/{environment}/{provider}")

    def rebind(self, binding: Binding, **changes) -> Binding:
        for name in changes:
            if name in self.binding_rules["immutable_fields"]:
                # Editing a binding in place would move a merchant's money with
                # no trace. Revoke and create a new one instead.
                raise BindingRefused(DENY_IMMUTABLE, name)
        for name, value in changes.items():
            setattr(binding, name, value)
        return binding

    # -- credentials ------------------------------------------------------
    def install(self, binding: Binding, credential: Credential) -> Binding:
        for other in self.bindings:
            if other is binding or other.credential is None:
                continue
            if other.credential.secret == credential.secret:
                raise BindingRefused(DENY_SHARED_CREDENTIAL,
                                     f"already installed on {other.key}")
        binding.credential = credential
        return binding

    def rotate(self, binding: Binding, credential: Credential, *, now: int,
               actor: str, approver: str) -> Binding:
        if actor == approver:
            raise BindingRefused(DENY_SELF_APPROVAL, actor)
        self.require(binding, "rotate_credential")
        overlap = int(self.credentials["rotation_overlap_days"]) * 86400
        binding.previous_credential = binding.credential
        binding.previous_valid_until = now + overlap
        self.install(binding, credential)
        binding.history.append({"event": "rotated", "at": now, "actor": actor})
        return binding

    def lease(self, binding: Binding, *, now: int) -> tuple[bytes, int]:
        """Hand out a decrypted credential with an expiry attached to it."""
        if binding.credential is None:
            raise BindingRefused(DENY_CREDENTIAL_DESTROYED, str(binding.key))
        expires = now + int(self.credentials["max_decrypt_lease_seconds"])
        return binding.credential.secret, expires

    def use_lease(self, expires_at: int, *, now: int) -> str:
        if now >= expires_at:
            raise BindingRefused(DENY_LEASE_EXPIRED, str(expires_at))
        return "OK"

    # -- lifecycle --------------------------------------------------------
    def transition(self, binding: Binding, target: str, *, satisfied: set[str],
                   actor: str) -> Binding:
        required = self.transitions.get((binding.state, target))
        if required is None:
            raise BindingRefused(DENY_TRANSITION, f"{binding.state} -> {target}")
        missing = required - satisfied
        if missing:
            raise BindingRefused(DENY_REQUIREMENT, f"missing {sorted(missing)}")
        binding.history.append({"from": binding.state, "to": target, "actor": actor})
        binding.state = target
        if target == REVOKED:
            binding.credential = None
            binding.previous_credential = None
        return binding

    def activate(self, binding: Binding, *, test_transaction_settled: bool,
                 callback_roundtrip_verified: bool, actor: str) -> Binding:
        satisfied = set()
        if test_transaction_settled:
            satisfied.add("test_transaction_settled")
        if callback_roundtrip_verified:
            satisfied.add("callback_roundtrip_verified")
        return self.transition(binding, ACTIVE, satisfied=satisfied, actor=actor)

    def may(self, binding: Binding, capability: str) -> bool:
        row = self.capabilities.get(binding.state)
        if row is None or capability not in row:
            raise BindingRefused(DENY_UNKNOWN, f"{binding.state}/{capability}")
        return bool(row[capability])

    def require(self, binding: Binding, capability: str) -> str:
        if not self.may(binding, capability):
            raise BindingRefused(DENY_NOT_ALLOWED,
                                 f"{capability} is not allowed while {binding.state}")
        return "OK"

    # -- callbacks --------------------------------------------------------
    def candidates(self, callback: Callback) -> list[Binding]:
        provider = self.providers.get(callback.provider)
        if provider is None:
            return []
        field_name = provider["callback_attribution_field"]
        value = callback.attribution.get(field_name)
        if value in (None, ""):
            return []
        return [b for b in self.bindings
                if b.provider == callback.provider
                and b.environment == callback.environment
                and getattr(b, field_name, None) == value]

    def verify_signature(self, binding: Binding, callback: Callback, *, now: int) -> str:
        secrets = []
        if binding.credential is not None:
            secrets.append(binding.credential.secret)
        if binding.previous_credential is not None and now < binding.previous_valid_until:
            # The overlap window: a callback signed just before the rotation is
            # still the provider telling us it took the money.
            secrets.append(binding.previous_credential.secret)
        if not secrets:
            raise BindingRefused(DENY_CREDENTIAL_DESTROYED, str(binding.key))
        for secret in secrets:
            if hmac.compare_digest(sign(secret, callback.payload), callback.signature):
                return "OK"
        raise BindingRefused(SIGNATURE_INVALID, callback.provider_event_id)

    def attribute(self, callback: Callback, *, now: int) -> Binding:
        """Return the one binding this callback belongs to, or refuse.

        Order matters: a callback that cannot be attributed is quarantined
        *before* anything downstream sees it, and a signature is checked
        against that one binding's own credential — never against every
        credential on file, which would let a leaked key from tenant A be used
        to inject a payment for tenant B.
        """
        if callback.source != "provider":
            # A browser redirect is a request from the payer's own machine.
            raise BindingRefused(DENY_RETURN_PAGE, callback.source)
        if now - callback.sent_at > int(self.callback_rules["replay_window_seconds"]):
            raise BindingRefused(CALLBACK_STALE, str(callback.sent_at))
        matches = self.candidates(callback)
        if not matches:
            self._quarantine(ATTRIBUTION_NONE, callback, now)
            raise BindingRefused(ATTRIBUTION_NONE, callback.provider_event_id)
        if len(matches) > 1:
            self._quarantine(ATTRIBUTION_AMBIGUOUS, callback, now)
            raise BindingRefused(ATTRIBUTION_AMBIGUOUS,
                                 f"{len(matches)} bindings match")
        return matches[0]

    def deliver(self, callback: Callback, *, now: int, to_tenant: str | None = None) -> str:
        """Attribute, verify, de-duplicate, then hand over. In that order."""
        binding = self.attribute(callback, now=now)
        if to_tenant is not None and to_tenant != binding.tenant_id:
            raise BindingRefused(DENY_CROSS_TENANT, to_tenant)
        self.verify_signature(binding, callback, now=now)
        self.require(binding, "receive_callback")
        key = callback.provider_event_id
        if key in self.delivered:
            # Providers retry. A retry must not book the money a second time.
            return "DUPLICATE"
        self.delivered[key] = (binding, key)
        return "DELIVERED"

    def _quarantine(self, reason: str, callback: Callback, now: int) -> None:
        self.quarantine.append(Quarantined(reason=reason, callback=callback, at=now))

    def replay(self, quarantined: Quarantined, *, binding: Binding | None, now: int) -> str:
        """Manual replay only, and only with a binding named by a human."""
        if binding is None:
            raise BindingRefused(DENY_BLIND_REPLAY, quarantined.reason)
        self.verify_signature(binding, quarantined.callback, now=now)
        self.require(binding, "receive_callback")
        key = quarantined.callback.provider_event_id
        if key in self.delivered:
            return "DUPLICATE"
        self.delivered[key] = (binding, key)
        self.quarantine.remove(quarantined)
        return "DELIVERED"
