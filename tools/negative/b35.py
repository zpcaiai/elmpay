"""B35 negative controls — the ways a card-data boundary quietly stops holding.

None of these edits look like an attack. Every one of them is something a
reasonable person does on a Tuesday: tidying an alias list, making a fingerprint
comparable across tenants so support can answer a question, letting a token be a
URL because that was easier to debug.
"""
from __future__ import annotations

from . import EXIT_PROBLEMS

MODEL = "governance/payment-method.json"
CONTRACT = "contracts/payment-method/sensitive-fields.json"


def _family(d, name):
    return next(f for f in d["forbidden_fields"] if f["canonical"] == name)


def _drop_family(d, name):
    d["forbidden_fields"] = [f for f in d["forbidden_fields"] if f["canonical"] != name]


def _drop_alias(d, family, alias):
    entry = _family(d, family)
    entry["aliases"] = [a for a in entry["aliases"] if a != alias]


EXPECTED_CODES = {
    "B35 the PAN family disappears": "PMETHOD_FAMILY_MISSING",
    "B35 the wallet cleartext family disappears": "PMETHOD_FAMILY_MISSING",
    "B35 card_pan drops out of the PAN aliases": "PMETHOD_ALIAS_GAP",
    "B35 cvv2 drops out of the CVV aliases": "PMETHOD_ALIAS_GAP",
    "B35 apple_pay_token drops out of the wallet aliases": "PMETHOD_ALIAS_GAP",
    "B35 comparison becomes case sensitive": "PMETHOD_NORMALIZATION_WEAK",
    "B35 separators stop being stripped": "PMETHOD_NORMALIZATION_WEAK",
    "B35 the platform claims to hold the PAN": "PMETHOD_CUSTODY_CLAIMED",
    "B35 the platform becomes the vault": "PMETHOD_CUSTODY_CLAIMED",
    "B35 the platform stops promising never to hold the CVV": "PMETHOD_CUSTODY_CLAIMED",
    "B35 an https reference counts as a token": "PMETHOD_TOKEN_SCHEME",
    "B35 the token stops being opaque": "PMETHOD_TOKEN_SCHEME",
    "B35 the scheme allowlist is emptied": "PMETHOD_TOKEN_SCHEME",
    "B35 a token may be reused across providers": "PMETHOD_TOKEN_NOT_PROVIDER_SCOPED",
    "B35 the fingerprint loses its key": "PMETHOD_FINGERPRINT_REVERSIBLE",
    "B35 the fingerprint stops being one-way": "PMETHOD_FINGERPRINT_REVERSIBLE",
    "B35 the fingerprint is shared across tenants": "PMETHOD_FINGERPRINT_CROSS_TENANT",
    "B35 the fingerprint key is defined locally": "PMETHOD_KEY_SOURCE",
    "B35 the CVV becomes displayable": "PMETHOD_DISPLAY_FIELD_UNSAFE",
    "B35 the display allowlist is emptied": "PMETHOD_DISPLAY_FIELD_UNSAFE",
    "B35 retention loses its bound": "PMETHOD_RETENTION_UNBOUNDED",
    "B35 fingerprints are kept for a century": "PMETHOD_RETENTION_UNBOUNDED",
    "B35 references stop being tenant scoped": "PMETHOD_TENANT_UNSCOPED",
    "B35 the fingerprint lookup drops the tenant": "PMETHOD_TENANT_UNSCOPED",
    "B35 referencing a method stops being audited": "PMETHOD_UNAUDITED",
    "B35 no implementation is bound to the catalogue": "PMETHOD_CATALOG_UNBOUND",
    "B35 the model loses its schema version": "PMETHOD_VERSION_FIELD",
    "B35 the principle is emptied": "PMETHOD_PRINCIPLE",
    "B35 the generated catalogue is hand-edited": "PMETHOD_GENERATED_DRIFT",
}

SCENARIOS = [
    ("B35 the PAN family disappears", MODEL,
     lambda d: _drop_family(d, "pan"), EXIT_PROBLEMS),
    ("B35 the wallet cleartext family disappears", MODEL,
     lambda d: _drop_family(d, "wallet_cleartext"), EXIT_PROBLEMS),
    ("B35 card_pan drops out of the PAN aliases", MODEL,
     lambda d: _drop_alias(d, "pan", "card_pan"), EXIT_PROBLEMS),
    ("B35 cvv2 drops out of the CVV aliases", MODEL,
     lambda d: _drop_alias(d, "cvv", "cvv2"), EXIT_PROBLEMS),
    ("B35 apple_pay_token drops out of the wallet aliases", MODEL,
     lambda d: _drop_alias(d, "wallet_cleartext", "apple_pay_token"), EXIT_PROBLEMS),
    ("B35 comparison becomes case sensitive", MODEL,
     lambda d: d["normalization"].__setitem__("lowercase", False), EXIT_PROBLEMS),
    ("B35 separators stop being stripped", MODEL,
     lambda d: d["normalization"].__setitem__("strip_characters", [" "]), EXIT_PROBLEMS),
    ("B35 the platform claims to hold the PAN", MODEL,
     lambda d: d["custody"]["platform_holds"].append("pan"), EXIT_PROBLEMS),
    ("B35 the platform becomes the vault", MODEL,
     lambda d: d["custody"].__setitem__("vault_holder", "platform"), EXIT_PROBLEMS),
    ("B35 the platform stops promising never to hold the CVV", MODEL,
     lambda d: d["custody"].__setitem__(
         "platform_never_holds",
         [x for x in d["custody"]["platform_never_holds"] if x != "cvv"]), EXIT_PROBLEMS),
    ("B35 an https reference counts as a token", MODEL,
     lambda d: d["token_reference"]["schemes"].append("https"), EXIT_PROBLEMS),
    ("B35 the token stops being opaque", MODEL,
     lambda d: d["token_reference"].__setitem__("opaque", False), EXIT_PROBLEMS),
    ("B35 the scheme allowlist is emptied", MODEL,
     lambda d: d["token_reference"].__setitem__("schemes", []), EXIT_PROBLEMS),
    ("B35 a token may be reused across providers", MODEL,
     lambda d: d["token_reference"].__setitem__("provider_scoped", False), EXIT_PROBLEMS),
    ("B35 the fingerprint loses its key", MODEL,
     lambda d: d["fingerprint"].__setitem__("keyed", False), EXIT_PROBLEMS),
    ("B35 the fingerprint stops being one-way", MODEL,
     lambda d: d["fingerprint"].__setitem__("one_way", False), EXIT_PROBLEMS),
    ("B35 the fingerprint is shared across tenants", MODEL,
     lambda d: d["fingerprint"].__setitem__("tenant_scoped", False), EXIT_PROBLEMS),
    ("B35 the fingerprint key is defined locally", MODEL,
     lambda d: d["fingerprint"].__setitem__("key_source", "governance/payment-method.json"),
     EXIT_PROBLEMS),
    ("B35 the CVV becomes displayable", MODEL,
     lambda d: d["display_allowlist"].append("cvv"), EXIT_PROBLEMS),
    ("B35 the display allowlist is emptied", MODEL,
     lambda d: d.__setitem__("display_allowlist", []), EXIT_PROBLEMS),
    ("B35 retention loses its bound", MODEL,
     lambda d: d["retention"].__setitem__("bounded", False), EXIT_PROBLEMS),
    ("B35 fingerprints are kept for a century", MODEL,
     lambda d: d["retention"].__setitem__("fingerprint_days", 36500), EXIT_PROBLEMS),
    ("B35 references stop being tenant scoped", MODEL,
     lambda d: d["tenant_scope"].__setitem__("tenant_id_required", False), EXIT_PROBLEMS),
    ("B35 the fingerprint lookup drops the tenant", MODEL,
     lambda d: d["tenant_scope"].__setitem__("lookup_key", ["fingerprint"]), EXIT_PROBLEMS),
    ("B35 referencing a method stops being audited", MODEL,
     lambda d: d.__setitem__("audit_event", ""), EXIT_PROBLEMS),
    ("B35 no implementation is bound to the catalogue", MODEL,
     lambda d: d["conformance"].__setitem__("derived_implementations", []), EXIT_PROBLEMS),
    ("B35 the model loses its schema version", MODEL,
     lambda d: d.__setitem__("schema_version", "v1"), EXIT_PROBLEMS),
    ("B35 the principle is emptied", MODEL,
     lambda d: d.__setitem__("principle", ""), EXIT_PROBLEMS),
]

TEXT_SCENARIOS = [
    ("B35 the generated catalogue is hand-edited", CONTRACT,
     "由 governance/payment-method.json 派生", "手工维护，请勿再生成", EXIT_PROBLEMS),
]
