"""B23 negative controls — the ways an audit log stops being evidence."""
from __future__ import annotations

from . import EXIT_PROBLEMS

AUDIT = "governance/audit-log.json"

EXPECTED_CODES = {
    "B23 the hash chain stops covering its predecessor": "AUDIT_NO_CHAIN",
    "B23 sequence numbers dropped from the hash": "AUDIT_NO_SEQUENCE",
    "B23 anchoring switched off": "AUDIT_NO_ANCHOR",
    "B23 the anchor interval becomes a week": "AUDIT_ANCHOR_INTERVAL",
    "B23 anchors lose their external witness": "AUDIT_NO_WITNESS",
    "B23 the anchor signing key is not managed": "AUDIT_ANCHOR_KEY_UNMANAGED",
    "B23 the rule version is dropped from records": "AUDIT_MISSING_FIELD",
    "B23 card data allowed into the audit log": "AUDIT_FORBIDDEN_FIELD",
    "B23 denials stop being recorded": "AUDIT_NO_DENIALS",
    "B23 audit storage becomes mutable": "AUDIT_MUTABLE_STORAGE",
    "B23 the application regains delete rights": "AUDIT_SHARED_CREDENTIALS",
    "B23 crypto-shredding removed while PII stays": "AUDIT_NO_SHREDDING",
    "B23 the auditor becomes elevatable": "AUDIT_READER_ELEVATABLE",
    "B23 a money action drops off the audited list": "AUDIT_ACTION_UNLOGGED",
    "B23 chain verification is never rehearsed": "AUDIT_UNREHEARSED",
    "B23 audit document hand-edited": "AUDIT_GENERATED_DRIFT",
}

SCENARIOS = [
    ("B23 the hash chain stops covering its predecessor", AUDIT,
     lambda d: d["hash_chain"].__setitem__("includes_previous_hash", False), EXIT_PROBLEMS),
    ("B23 sequence numbers dropped from the hash", AUDIT,
     lambda d: d["hash_chain"].__setitem__("includes_sequence", False), EXIT_PROBLEMS),
    ("B23 anchoring switched off", AUDIT,
     lambda d: d["anchoring"].__setitem__("required", False), EXIT_PROBLEMS),
    ("B23 the anchor interval becomes a week", AUDIT,
     lambda d: d["anchoring"].__setitem__("interval_minutes", 10080), EXIT_PROBLEMS),
    ("B23 anchors lose their external witness", AUDIT,
     lambda d: d["anchoring"].__setitem__("witness", ""), EXIT_PROBLEMS),
    ("B23 the anchor signing key is not managed", AUDIT,
     lambda d: d["anchoring"].__setitem__("signed_by_key", "ghost-key"), EXIT_PROBLEMS),
    ("B23 the rule version is dropped from records", AUDIT,
     lambda d: d["records"].__setitem__(
         "required_fields", [f for f in d["records"]["required_fields"]
                             if f != "rule_version"]), EXIT_PROBLEMS),
    ("B23 card data allowed into the audit log", AUDIT,
     lambda d: d["records"].__setitem__("forbidden_fields", ["password"]), EXIT_PROBLEMS),
    ("B23 denials stop being recorded", AUDIT,
     lambda d: d["records"].__setitem__("records_denials", False), EXIT_PROBLEMS),
    ("B23 audit storage becomes mutable", AUDIT,
     lambda d: d["storage"].__setitem__("append_only", False), EXIT_PROBLEMS),
    ("B23 the application regains delete rights", AUDIT,
     lambda d: d["storage"].__setitem__("separate_credentials_from_application", False),
     EXIT_PROBLEMS),
    ("B23 crypto-shredding removed while PII stays", AUDIT,
     lambda d: d["redaction"].__setitem__("payload_crypto_shredding", False), EXIT_PROBLEMS),
    ("B23 the auditor becomes elevatable", AUDIT,
     lambda d: d["access"].__setitem__("reader_cannot_be_elevated", False), EXIT_PROBLEMS),
    ("B23 a money action drops off the audited list", AUDIT,
     lambda d: d.__setitem__("audited_actions",
                             [a for a in d["audited_actions"] if a != "ledger.adjust"]),
     EXIT_PROBLEMS),
    ("B23 chain verification is never rehearsed", AUDIT,
     lambda d: d["verification"].__setitem__("rehearsed", False), EXIT_PROBLEMS),
]

TEXT_SCENARIOS = [
    ("B23 audit document hand-edited",
     "docs/security/AUDIT_LOG.md", "可被否认窗口", "无所谓的窗口", EXIT_PROBLEMS),
]
