"""B25 negative controls — the four places KYB stops meaning anything."""
from __future__ import annotations

from . import EXIT_PROBLEMS

REL = "governance/merchant-profile.json"
AUTHZ = "governance/authorization.json"


def _doc(d, did):
    return next(x for x in d["documents"] if x["id"] == did)


def _change(d, cid):
    return next(x for x in d["material_changes"] if x["id"] == cid)


def _risk(d, rid):
    return next(x for x in d["risk_levels"] if x["id"] == rid)


EXPECTED_CODES = {
    "B25 the platform declares itself a licensed verifier": "MERCHANT_SELF_VERIFIED",
    "B25 verification stops needing an external authority": "MERCHANT_SELF_VERIFIED",
    "B25 the authority record loses its expiry field": "MERCHANT_AUTHORITY_INCOMPLETE",
    "B25 a verification decision never expires": "MERCHANT_VERIFICATION_FOREVER",
    "B25 the merchant may self-attest its legal name": "MERCHANT_SELF_ATTESTED_FACT",
    "B25 a KYB document never expires": "MERCHANT_DOC_NO_EXPIRY",
    "B25 the payout account proof outlives the other documents":
        "MERCHANT_ACCOUNT_PROOF_STALE",
    "B25 a company no longer declares its owners": "MERCHANT_COMPANY_NO_UBO",
    "B25 ownership is traced one layer deep": "MERCHANT_UBO_DEPTH",
    "B25 a sanctions hit is auto-approved": "MERCHANT_SANCTIONS_AUTO",
    "B25 screening happens once at signup": "MERCHANT_SCREENING_ONCE",
    "B25 a prohibited category is still allowed": "MERCHANT_PROHIBITED_CATEGORY_ALLOWED",
    "B25 a settlement currency leaves the money model": "MERCHANT_CURRENCY_UNKNOWN",
    "B25 high risk buys a higher daily limit": "MERCHANT_RISK_LIMITS_INVERTED",
    "B25 one person onboards a high-risk merchant": "MERCHANT_HIGH_RISK_SINGLE_APPROVER",
    "B25 a payout account change keeps paying out": "MERCHANT_ACCOUNT_CHANGE_NO_HOLD",
    "B25 the payout account permission drops dual control":
        "MERCHANT_ACCOUNT_CHANGE_SINGLE_PERSON",
    "B25 a material change no longer reopens verification": "MERCHANT_CHANGE_NO_REVERIFY",
    "B25 KYB records are dropped before the regulator allows": "MERCHANT_RETENTION_SHORT",
    "B25 a rejection cannot be appealed": "MERCHANT_NO_APPEAL",
    "B25 profile decisions map to a nonexistent audit class": "MERCHANT_AUDIT_CLASS_UNKNOWN",
    "B25 merchant profile document hand-edited": "MERCHANT_GENERATED_DRIFT",
}

SCENARIOS = [
    ("B25 the platform declares itself a licensed verifier", REL,
     lambda d: d["verification"].__setitem__("platform_is_licensed_verifier", True),
     EXIT_PROBLEMS),
    ("B25 verification stops needing an external authority", REL,
     lambda d: d["verification"].__setitem__("authority_required", False), EXIT_PROBLEMS),
    ("B25 the authority record loses its expiry field", REL,
     lambda d: d["verification"].__setitem__(
         "authority_fields", ["authority", "decision_reference", "decided_at"]), EXIT_PROBLEMS),
    ("B25 a verification decision never expires", REL,
     lambda d: d["verification"].__setitem__("max_validity_days", 0), EXIT_PROBLEMS),
    ("B25 the merchant may self-attest its legal name", REL,
     lambda d: d["verification"]["self_attestation_allowed_for"].append("legal_name"),
     EXIT_PROBLEMS),
    ("B25 a KYB document never expires", REL,
     lambda d: _doc(d, "business_licence").__setitem__("expires_days", 0), EXIT_PROBLEMS),
    ("B25 the payout account proof outlives the other documents", REL,
     lambda d: _doc(d, "bank_account_proof").__setitem__("expires_days", 400), EXIT_PROBLEMS),
    ("B25 a company no longer declares its owners", REL,
     lambda d: next(e for e in d["entity_kinds"] if e["id"] == "company").__setitem__(
         "required_documents", ["business_licence", "director_identity", "bank_account_proof"]),
     EXIT_PROBLEMS),
    ("B25 ownership is traced one layer deep", REL,
     lambda d: d["ubo"].__setitem__("max_ownership_depth", 1), EXIT_PROBLEMS),
    ("B25 a sanctions hit is auto-approved", REL,
     lambda d: d["screening"].__setitem__("auto_approve_on_hit", True), EXIT_PROBLEMS),
    ("B25 screening happens once at signup", REL,
     lambda d: d["screening"].__setitem__("rescreen_interval_days", 0), EXIT_PROBLEMS),
    ("B25 a prohibited category is still allowed", REL,
     lambda d: next(c for c in d["business_categories"]
                    if c["risk"] == "prohibited").__setitem__("allowed", True), EXIT_PROBLEMS),
    ("B25 a settlement currency leaves the money model", REL,
     lambda d: d["operating_regions"][0].__setitem__("settlement_currencies", ["XYZ"]),
     EXIT_PROBLEMS),
    ("B25 high risk buys a higher daily limit", REL,
     lambda d: _risk(d, "high").__setitem__("daily_limit_minor", 10 ** 12), EXIT_PROBLEMS),
    ("B25 one person onboards a high-risk merchant", REL,
     lambda d: _risk(d, "high").__setitem__("approvers_required", 1), EXIT_PROBLEMS),
    ("B25 a payout account change keeps paying out", REL,
     lambda d: _change(d, "payout_account_change").__setitem__("holds_settlement", False),
     EXIT_PROBLEMS),
    ("B25 the payout account permission drops dual control", AUTHZ,
     lambda d: next(p for p in d["permissions"]
                    if p["id"] == "payout_account.write").__setitem__("dual_control", False),
     EXIT_PROBLEMS),
    ("B25 a material change no longer reopens verification", REL,
     lambda d: _change(d, "ubo_change").__setitem__("requires_reverification", False),
     EXIT_PROBLEMS),
    ("B25 KYB records are dropped before the regulator allows", REL,
     lambda d: d["retention"].__setitem__("after_offboarding_days", 30), EXIT_PROBLEMS),
    ("B25 a rejection cannot be appealed", REL,
     lambda d: d["appeal"].__setitem__("available", False), EXIT_PROBLEMS),
    ("B25 profile decisions map to a nonexistent audit class", REL,
     lambda d: d.__setitem__("audit_event_class", "merchant.vanished"), EXIT_PROBLEMS),
]

TEXT_SCENARIOS = [
    ("B25 merchant profile document hand-edited",
     "docs/merchant/MERCHANT_PROFILE.md", "不是持牌核验机构", "就是持牌核验机构", EXIT_PROBLEMS),
]
