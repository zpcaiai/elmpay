"""B24 negative controls — the three edges where multi-tenancy breaks."""
from __future__ import annotations

from . import EXIT_PROBLEMS

REG = "governance/tenant-registry.json"


def _row(d, state):
    return next(r for r in d["capability_matrix"] if r["state"] == state)


def _transition(d, source, target):
    return next(t for t in d["lifecycle"]["transitions"]
                if t["from"] == source and t["to"] == target)


EXPECTED_CODES = {
    "B24 a suspended tenant can no longer refund": "TENANT_SUSPENDED_BLOCKS_REFUNDS",
    "B24 a suspended tenant keeps taking payments": "TENANT_SUSPENDED_TAKES_MONEY",
    "B24 a draft tenant may take payments": "TENANT_DRAFT_TAKES_MONEY",
    "B24 a closed tenant can still read its data": "TENANT_CLOSED_ACTIVE",
    "B24 test and live share keys": "TENANT_ENV_SHARES_KEYS",
    "B24 identifiers stop being opaque": "TENANT_ID_NOT_OPAQUE",
    "B24 activation no longer requires KYB": "TENANT_ACTIVATION_UNVERIFIED",
    "B24 one person can reinstate a suspended tenant": "TENANT_UNSUSPEND_SINGLE_PERSON",
    "B24 closure no longer waits for settlement": "TENANT_CLOSE_BEFORE_SETTLEMENT",
    "B24 offboarding stops retaining the ledger": "TENANT_LEDGER_NOT_RETAINED",
    "B24 the per-tenant KEK becomes shared": "TENANT_KEK_NOT_SCOPED",
    "B24 cross-tenant references allowed": "TENANT_CROSS_REFERENCE",
    "B24 quota ceilings fall below their defaults": "TENANT_QUOTA_CEILING",
    "B24 lifecycle changes map to a nonexistent audit class": "TENANT_AUDIT_CLASS_UNKNOWN",
    "B24 tenant registry document hand-edited": "TENANT_GENERATED_DRIFT",
}

SCENARIOS = [
    ("B24 a suspended tenant can no longer refund", REG,
     lambda d: _row(d, "suspended").__setitem__("issue_refunds", False), EXIT_PROBLEMS),
    ("B24 a suspended tenant keeps taking payments", REG,
     lambda d: _row(d, "suspended").__setitem__("accept_payments", True), EXIT_PROBLEMS),
    ("B24 a draft tenant may take payments", REG,
     lambda d: _row(d, "draft").__setitem__("accept_payments", True), EXIT_PROBLEMS),
    ("B24 a closed tenant can still read its data", REG,
     lambda d: _row(d, "closed").__setitem__("read_data", True), EXIT_PROBLEMS),
    ("B24 test and live share keys", REG,
     lambda d: next(e for e in d["environments"] if e["id"] == "test")
     .__setitem__("shares_keys_with", ["live"]), EXIT_PROBLEMS),
    ("B24 identifiers stop being opaque", REG,
     lambda d: d["identifier"].__setitem__("opaque", False), EXIT_PROBLEMS),
    ("B24 activation no longer requires KYB", REG,
     lambda d: _transition(d, "draft", "active").__setitem__("requires", ["contract_signed"]),
     EXIT_PROBLEMS),
    ("B24 one person can reinstate a suspended tenant", REG,
     lambda d: _transition(d, "suspended", "active").__setitem__("requires",
                                                                 ["reason", "actor"]),
     EXIT_PROBLEMS),
    ("B24 closure no longer waits for settlement", REG,
     lambda d: _transition(d, "offboarding", "closed").__setitem__(
         "requires", ["kek_destroyed", "retention_period_started"]), EXIT_PROBLEMS),
    ("B24 offboarding stops retaining the ledger", REG,
     lambda d: d["offboarding"].__setitem__("ledger_retained", False), EXIT_PROBLEMS),
    ("B24 the per-tenant KEK becomes shared", REG,
     lambda d: d["isolation"].__setitem__("per_tenant_kek", "kek-provider-credentials"),
     EXIT_PROBLEMS),
    ("B24 cross-tenant references allowed", REG,
     lambda d: d["isolation"].__setitem__("cross_tenant_reference_allowed", True),
     EXIT_PROBLEMS),
    ("B24 quota ceilings fall below their defaults", REG,
     lambda d: d["quotas"][0].__setitem__("hard_ceiling", 1), EXIT_PROBLEMS),
    ("B24 lifecycle changes map to a nonexistent audit class", REG,
     lambda d: d.__setitem__("audit_event_class", "tenant.vanished"), EXIT_PROBLEMS),
]

TEXT_SCENARIOS = [
    ("B24 tenant registry document hand-edited",
     "docs/tenancy/TENANT_REGISTRY.md", "停用不等于断电", "停用就是断电", EXIT_PROBLEMS),
]
