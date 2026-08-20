"""B27 negative controls — the four ways a capability matrix stops limiting."""
from __future__ import annotations

from . import EXIT_PROBLEMS

REL = "governance/provider-capabilities.json"


def _row(d, provider, method):
    return next(r for r in d["capabilities"]
                if r["provider"] == provider and r["method"] == method)


def _region(d, code):
    return next(r for r in d["region_policy"] if r["region"] == code)


def _availability(d, provider):
    return next(a for a in d["availability"] if a["provider"] == provider)


EXPECTED_CODES = {
    "B27 the matrix allows by default": "CAP_IMPLICIT_ALLOW",
    "B27 an undeclared combination is attempted anyway": "CAP_IMPLICIT_ALLOW",
    "B27 the platform silently switches provider": "CAP_SILENT_FALLBACK",
    "B27 a provider reroutes while it is down": "CAP_SILENT_FALLBACK",
    "B27 an authorisation never expires": "CAP_AUTH_NEVER_EXPIRES",
    "B27 an expired authorisation may still be captured": "CAP_CAPTURE_AFTER_EXPIRY",
    "B27 an expired authorisation is reused instead of retaken": "CAP_NO_REAUTHORIZATION",
    "B27 capture exceeds the authorised amount": "CAP_OVER_CAPTURE",
    "B27 a wallet declares an authorisation window it does not have":
        "CAP_AUTH_WINDOW_WITHOUT_AUTH",
    "B27 the refund window never closes": "CAP_REFUND_NO_WINDOW",
    "B27 a refund is promised beyond the window": "CAP_REFUND_PROMISED_BEYOND_WINDOW",
    "B27 a refund may exceed what was captured": "CAP_OVER_REFUND",
    "B27 a refund may go somewhere other than the original instrument":
        "CAP_REFUND_ELSEWHERE",
    "B27 the dispute deadline becomes our own SLA": "CAP_DISPUTE_DEADLINE_INTERNAL",
    "B27 disputes are conceded automatically": "CAP_DISPUTE_AUTO_ACCEPT",
    "B27 the dispute evidence pack loses the delivery proof": "CAP_DISPUTE_NO_EVIDENCE",
    "B27 a dispute deadline falls outside its own window": "CAP_DISPUTE_DEADLINE_INVERTED",
    "B27 a currency can be charged but not settled": "CAP_CURRENCY_UNSETTLEABLE",
    "B27 a capability names a provider that has no binding": "CAP_PROVIDER_UNKNOWN",
    "B27 a region promises a method the matrix cannot deliver":
        "CAP_REGION_METHOD_UNSUPPORTED",
    "B27 strong customer authentication is switched off in the EU": "CAP_SCA_DISABLED",
    "B27 a provider loses its availability row": "CAP_AVAILABILITY_MISSING",
    "B27 scheduled maintenance has no declared window": "CAP_MAINTENANCE_UNDECLARED",
    "B27 matrix changes map to a nonexistent audit class": "CAP_AUDIT_CLASS_UNKNOWN",
    "B27 capability document hand-edited": "CAP_GENERATED_DRIFT",
}

SCENARIOS = [
    ("B27 the matrix allows by default", REL,
     lambda d: d["resolution"].__setitem__("default", "allow"), EXIT_PROBLEMS),
    ("B27 an undeclared combination is attempted anyway", REL,
     lambda d: d["resolution"].__setitem__("unknown_combination", "attempt"), EXIT_PROBLEMS),
    ("B27 the platform silently switches provider", REL,
     lambda d: d["resolution"].__setitem__("silent_fallback_to_another_provider", True),
     EXIT_PROBLEMS),
    ("B27 a provider reroutes while it is down", REL,
     lambda d: _availability(d, "stripe").__setitem__("silent_fallback_allowed", True),
     EXIT_PROBLEMS),
    ("B27 an authorisation never expires", REL,
     lambda d: _row(d, "stripe", "card").__setitem__("authorization_valid_hours", 0),
     EXIT_PROBLEMS),
    ("B27 an expired authorisation may still be captured", REL,
     lambda d: d["authorization"].__setitem__("capture_after_expiry_allowed", True),
     EXIT_PROBLEMS),
    ("B27 an expired authorisation is reused instead of retaken", REL,
     lambda d: d["authorization"].__setitem__("reauthorization_required", False),
     EXIT_PROBLEMS),
    ("B27 capture exceeds the authorised amount", REL,
     lambda d: _row(d, "stripe", "card").__setitem__("capture_max_percent", 115),
     EXIT_PROBLEMS),
    ("B27 a wallet declares an authorisation window it does not have", REL,
     lambda d: _row(d, "wechat", "wechat_pay").__setitem__("authorization_valid_hours", 48),
     EXIT_PROBLEMS),
    ("B27 the refund window never closes", REL,
     lambda d: _row(d, "stripe", "card").__setitem__("refund_window_days", 0), EXIT_PROBLEMS),
    ("B27 a refund is promised beyond the window", REL,
     lambda d: d["refund"].__setitem__("promise_beyond_window", True), EXIT_PROBLEMS),
    ("B27 a refund may exceed what was captured", REL,
     lambda d: d["refund"].__setitem__("refund_exceeding_capture_allowed", True),
     EXIT_PROBLEMS),
    ("B27 a refund may go somewhere other than the original instrument", REL,
     lambda d: _row(d, "stripe", "card").__setitem__("refund_to_original_instrument_only",
                                                     False), EXIT_PROBLEMS),
    ("B27 the dispute deadline becomes our own SLA", REL,
     lambda d: d["dispute"].__setitem__("deadline_is_external", False), EXIT_PROBLEMS),
    ("B27 disputes are conceded automatically", REL,
     lambda d: d["dispute"].__setitem__("auto_accept_allowed", True), EXIT_PROBLEMS),
    ("B27 the dispute evidence pack loses the delivery proof", REL,
     lambda d: d["dispute"].__setitem__("evidence_required",
                                        ["order_record", "authorization_record"]),
     EXIT_PROBLEMS),
    ("B27 a dispute deadline falls outside its own window", REL,
     lambda d: _row(d, "stripe", "card").__setitem__("dispute_window_days", 10),
     EXIT_PROBLEMS),
    ("B27 a currency can be charged but not settled", REL,
     lambda d: _row(d, "stripe", "card")["currencies"].append("CNY"), EXIT_PROBLEMS),
    ("B27 a capability names a provider that has no binding", REL,
     lambda d: _row(d, "stripe", "card").__setitem__("provider", "klarna"), EXIT_PROBLEMS),
    ("B27 a region promises a method the matrix cannot deliver", REL,
     lambda d: _region(d, "SG")["allowed_methods"].append("wechat_pay"), EXIT_PROBLEMS),
    ("B27 strong customer authentication is switched off in the EU", REL,
     lambda d: _region(d, "EU").__setitem__("strong_customer_authentication", False),
     EXIT_PROBLEMS),
    ("B27 a provider loses its availability row", REL,
     lambda d: d.__setitem__("availability", [a for a in d["availability"]
                                              if a["provider"] != "stripe"]), EXIT_PROBLEMS),
    ("B27 scheduled maintenance has no declared window", REL,
     lambda d: _availability(d, "stripe").__setitem__("scheduled_maintenance", True),
     EXIT_PROBLEMS),
    ("B27 matrix changes map to a nonexistent audit class", REL,
     lambda d: d.__setitem__("audit_event_class", "matrix.vanished"), EXIT_PROBLEMS),
]

TEXT_SCENARIOS = [
    ("B27 capability document hand-edited",
     "docs/provider/PROVIDER_CAPABILITIES.md", "默认拒绝", "默认放行", EXIT_PROBLEMS),
]
