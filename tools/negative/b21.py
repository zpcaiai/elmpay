"""B21 negative controls — the ways a certificate estate quietly stops working."""
from __future__ import annotations

from . import EXIT_PROBLEMS

CERTS = "governance/certificates.json"

EXPECTED_CODES = {
    "B21 renewal margin shrunk to two days": "CERT_RENEW_MARGIN",
    "B21 rotation loses its overlap window": "CERT_NO_OVERLAP",
    "B21 seven-day certificates renewed by hand": "CERT_MANUAL_SHORT_LIVED",
    "B21 a material loses its revocation route": "CERT_NO_REVOCATION",
    "B21 renewal failures stop escalating": "CERT_NO_ESCALATION",
    "B21 certificate transparency monitoring switched off": "CERT_NO_CT_MONITORING",
    "B21 the registrar lock is removed": "DOMAIN_NO_LOCK",
    "B21 CAA records dropped": "DOMAIN_NO_CAA",
    "B21 DNSSEC switched off": "DOMAIN_NO_DNSSEC",
    "B21 recovery is no longer rehearsed": "CERT_UNREHEARSED_RECOVERY",
    "B21 recovery no longer needs a quorum": "CERT_RECOVERY_QUORUM",
    "B21 a certificate points at an unmanaged key": "CERT_KEY_UNMANAGED",
    "B21 an HSM-backed provider key loses its expiry date": "CERT_PROVIDER_UNTRACKED",
    "B21 the lifecycle stops before revocation": "CERT_STAGES",
    "B21 certificate document hand-edited": "CERT_GENERATED_DRIFT",
}

SCENARIOS = [
    ("B21 renewal margin shrunk to two days", CERTS,
     lambda d: next(m for m in d["materials"] if m["id"] == "edge-tls")
     .__setitem__("renew_before_days", 2), EXIT_PROBLEMS),
    ("B21 rotation loses its overlap window", CERTS,
     lambda d: next(m for m in d["materials"] if m["id"] == "token-signing")
     .__setitem__("overlap_days", 0), EXIT_PROBLEMS),
    ("B21 seven-day certificates renewed by hand", CERTS,
     lambda d: next(m for m in d["materials"] if m["id"] == "internal-mtls")
     .__setitem__("automated_renewal", False), EXIT_PROBLEMS),
    ("B21 a material loses its revocation route", CERTS,
     lambda d: next(m for m in d["materials"] if m["id"] == "edge-tls")
     .__setitem__("revocation", ""), EXIT_PROBLEMS),
    ("B21 renewal failures stop escalating", CERTS,
     lambda d: d["alerting"].__setitem__("escalate_after_failed_renewals", 0), EXIT_PROBLEMS),
    ("B21 certificate transparency monitoring switched off", CERTS,
     lambda d: d["alerting"].__setitem__("certificate_transparency_monitoring", False),
     EXIT_PROBLEMS),
    ("B21 the registrar lock is removed", CERTS,
     lambda d: next(x for x in d["domains"] if x["name"] == "pay.example.invalid")
     .__setitem__("registrar_lock", False), EXIT_PROBLEMS),
    ("B21 CAA records dropped", CERTS,
     lambda d: next(x for x in d["domains"] if x["name"] == "internal.pay.example.invalid")
     .__setitem__("caa_records", []), EXIT_PROBLEMS),
    ("B21 DNSSEC switched off", CERTS,
     lambda d: next(x for x in d["domains"] if x["name"] == "api.pay.example.invalid")
     .__setitem__("dnssec", False), EXIT_PROBLEMS),
    ("B21 recovery is no longer rehearsed", CERTS,
     lambda d: d["recovery"].__setitem__("rehearsed", False), EXIT_PROBLEMS),
    ("B21 recovery no longer needs a quorum", CERTS,
     lambda d: d["recovery"].__setitem__("quorum_required", False), EXIT_PROBLEMS),
    ("B21 a certificate points at an unmanaged key", CERTS,
     lambda d: next(m for m in d["materials"] if m["id"] == "edge-tls")
     .__setitem__("key_id", "ghost-key"), EXIT_PROBLEMS),
    ("B21 an HSM-backed provider key loses its expiry date", CERTS,
     lambda d: d.__setitem__("materials",
                             [m for m in d["materials"] if "apple" not in m["id"]]),
     EXIT_PROBLEMS),
    ("B21 the lifecycle stops before revocation", CERTS,
     lambda d: d.__setitem__("lifecycle_stages",
                             ["generate", "distribute", "activate", "overlap", "rotate"]),
     EXIT_PROBLEMS),
]

TEXT_SCENARIOS = [
    ("B21 certificate document hand-edited",
     "docs/security/CERTIFICATE_LIFECYCLE.md", "重叠期", "重叠区", EXIT_PROBLEMS),
]
