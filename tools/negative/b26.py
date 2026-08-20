"""B26 negative controls — the four ways a provider binding stops isolating."""
from __future__ import annotations

from . import EXIT_PROBLEMS

REL = "governance/provider-accounts.json"
KEYS = "governance/key-management.json"
AUTHZ = "governance/authorization.json"


def _row(d, state):
    return next(r for r in d["capability_matrix"] if r["state"] == state)


def _transition(d, source, target):
    return next(t for t in d["lifecycle"]["transitions"]
                if t["from"] == source and t["to"] == target)


EXPECTED_CODES = {
    "B26 an ambiguous callback is resolved by best match": "ACCOUNT_CALLBACK_GUESSED",
    "B26 attribution must no longer be deterministic": "ACCOUNT_CALLBACK_GUESSED",
    "B26 unattributable callbacks are dropped instead of quarantined":
        "ACCOUNT_NO_QUARANTINE",
    "B26 quarantined callbacks replay themselves": "ACCOUNT_QUARANTINE_AUTO_REPLAY",
    "B26 attribution by amount and time is allowed": "ACCOUNT_ATTRIBUTION_HEURISTIC",
    "B26 provider callbacks stop being signed": "ACCOUNT_CALLBACK_UNSIGNED",
    "B26 the client return page becomes evidence": "ACCOUNT_RETURN_PAGE_EVIDENCE",
    "B26 callbacks lose their idempotency key": "ACCOUNT_NO_IDEMPOTENCY_KEY",
    "B26 callbacks may be delivered to another tenant": "ACCOUNT_CROSS_TENANT_CALLBACK",
    "B26 one credential is shared across tenants": "ACCOUNT_SHARED_CREDENTIAL",
    "B26 credentials are stored in plaintext": "ACCOUNT_PLAINTEXT_CREDENTIAL",
    "B26 a decrypted credential never expires": "ACCOUNT_LEASE_UNBOUNDED",
    "B26 rotation loses its overlap window": "ACCOUNT_ROTATION_NO_OVERLAP",
    "B26 credentials outlive the key that wraps them": "ACCOUNT_ROTATION_SLOWER_THAN_KEY",
    "B26 the binding stops being scoped by environment": "ACCOUNT_BINDING_DIMENSIONS",
    "B26 the binding becomes editable in place": "ACCOUNT_BINDING_MUTABLE",
    "B26 a settlement currency leaves the money model": "ACCOUNT_CURRENCY_UNKNOWN",
    "B26 a provider names a key that does not exist": "ACCOUNT_PROVIDER_KEY_UNKNOWN",
    "B26 activation no longer needs a callback round trip": "ACCOUNT_ACTIVATION_UNPROVEN",
    "B26 a suspended binding has its callbacks switched off":
        "ACCOUNT_SUSPENDED_BLOCKS_CALLBACKS",
    "B26 a suspended binding takes new payments": "ACCOUNT_SUSPENDED_TAKES_MONEY",
    "B26 a revoked binding still receives callbacks": "ACCOUNT_REVOKED_ACTIVE",
    "B26 revocation stops waiting for settlement": "ACCOUNT_REVOKE_BEFORE_SETTLEMENT",
    "B26 one person reinstates a suspended binding": "ACCOUNT_REINSTATE_SINGLE_PERSON",
    "B26 credential rotation drops dual control": "ACCOUNT_ROTATION_SINGLE_PERSON",
    "B26 binding changes map to a nonexistent audit class": "ACCOUNT_AUDIT_CLASS_UNKNOWN",
    "B26 provider account document hand-edited": "ACCOUNT_GENERATED_DRIFT",
}

SCENARIOS = [
    ("B26 an ambiguous callback is resolved by best match", REL,
     lambda d: d["callback"].__setitem__("guess_on_ambiguity", True), EXIT_PROBLEMS),
    ("B26 attribution must no longer be deterministic", REL,
     lambda d: d["callback"].__setitem__("attribution_must_be_deterministic", False),
     EXIT_PROBLEMS),
    ("B26 unattributable callbacks are dropped instead of quarantined", REL,
     lambda d: d["callback"].__setitem__("quarantine_on_unattributable", False), EXIT_PROBLEMS),
    ("B26 quarantined callbacks replay themselves", REL,
     lambda d: d["quarantine"].__setitem__("auto_replay_allowed", True), EXIT_PROBLEMS),
    ("B26 attribution by amount and time is allowed", REL,
     lambda d: d["forbidden"].__setitem__("attribution_by_amount_or_time", False),
     EXIT_PROBLEMS),
    ("B26 provider callbacks stop being signed", REL,
     lambda d: d["callback"].__setitem__("signature_required", False), EXIT_PROBLEMS),
    ("B26 the client return page becomes evidence", REL,
     lambda d: d["callback"].__setitem__("client_return_page_is_evidence", True),
     EXIT_PROBLEMS),
    ("B26 callbacks lose their idempotency key", REL,
     lambda d: d["callback"].__setitem__("idempotency_key_field", ""), EXIT_PROBLEMS),
    ("B26 callbacks may be delivered to another tenant", REL,
     lambda d: d["callback"].__setitem__("cross_tenant_delivery_allowed", True), EXIT_PROBLEMS),
    ("B26 one credential is shared across tenants", REL,
     lambda d: d["credentials"].__setitem__("shared_across_tenants", True), EXIT_PROBLEMS),
    ("B26 credentials are stored in plaintext", REL,
     lambda d: d["credentials"].__setitem__("plaintext_at_rest", True), EXIT_PROBLEMS),
    ("B26 a decrypted credential never expires", REL,
     lambda d: d["credentials"].__setitem__("max_decrypt_lease_seconds", 0), EXIT_PROBLEMS),
    ("B26 rotation loses its overlap window", REL,
     lambda d: d["credentials"].__setitem__("rotation_overlap_days", 0), EXIT_PROBLEMS),
    ("B26 credentials outlive the key that wraps them", KEYS,
     lambda d: next(k for k in d["keys"] if k["id"] == "kek-provider-credentials")
     .__setitem__("rotation_days", 30), EXIT_PROBLEMS),
    ("B26 the binding stops being scoped by environment", REL,
     lambda d: d["binding"].__setitem__("identity_fields",
                                        ["tenant_id", "project_id", "provider"]),
     EXIT_PROBLEMS),
    ("B26 the binding becomes editable in place", REL,
     lambda d: d["binding"].__setitem__("immutable_fields", ["provider"]), EXIT_PROBLEMS),
    ("B26 a settlement currency leaves the money model", REL,
     lambda d: d["providers"][0].__setitem__("settlement_currencies", ["XYZ"]), EXIT_PROBLEMS),
    ("B26 a provider names a key that does not exist", REL,
     lambda d: d["providers"][0].__setitem__("key_id", "kek-imaginary"), EXIT_PROBLEMS),
    ("B26 activation no longer needs a callback round trip", REL,
     lambda d: _transition(d, "pending", "active").__setitem__(
         "requires", ["test_transaction_settled"]), EXIT_PROBLEMS),
    ("B26 a suspended binding has its callbacks switched off", REL,
     lambda d: _row(d, "suspended").__setitem__("receive_callback", False), EXIT_PROBLEMS),
    ("B26 a suspended binding takes new payments", REL,
     lambda d: _row(d, "suspended").__setitem__("initiate_payment", True), EXIT_PROBLEMS),
    ("B26 a revoked binding still receives callbacks", REL,
     lambda d: _row(d, "revoked").__setitem__("receive_callback", True), EXIT_PROBLEMS),
    ("B26 revocation stops waiting for settlement", REL,
     lambda d: _transition(d, "suspended", "revoked").__setitem__(
         "requires", ["credential_destroyed"]), EXIT_PROBLEMS),
    ("B26 one person reinstates a suspended binding", REL,
     lambda d: _transition(d, "suspended", "active").__setitem__("requires",
                                                                 ["reason", "actor"]),
     EXIT_PROBLEMS),
    ("B26 credential rotation drops dual control", AUTHZ,
     lambda d: next(p for p in d["permissions"] if p["id"] == "config.write")
     .__setitem__("dual_control", False), EXIT_PROBLEMS),
    ("B26 binding changes map to a nonexistent audit class", REL,
     lambda d: d.__setitem__("audit_event_class", "binding.vanished"), EXIT_PROBLEMS),
]

TEXT_SCENARIOS = [
    ("B26 provider account document hand-edited",
     "docs/provider/PROVIDER_ACCOUNTS.md", "隔离并告警", "取最像的一个", EXIT_PROBLEMS),
]
