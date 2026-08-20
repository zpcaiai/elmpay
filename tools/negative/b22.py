"""B22 negative controls — the ways a compliance matrix turns into fiction."""
from __future__ import annotations

from . import EXIT_PROBLEMS

BASE = "governance/security-baseline.json"


def _req(d, rid):
    return next(r for r in d["requirements"] if r["id"] == rid)


EXPECTED_CODES = {
    "B22 a requirement maps to a rule code nobody emits": "BASE_RULE_UNKNOWN",
    "B22 a requirement maps to a deleted test": "BASE_TEST_MISSING",
    "B22 an accepted gap loses its owner": "BASE_GAP_NO_OWNER",
    "B22 an accepted gap loses its review batch": "BASE_GAP_NO_REVIEW",
    "B22 a gap claims enforcement as well": "BASE_GAP_WITH_REFS",
    "B22 mobile requirements claim compliance": "BASE_FALSE_COMPLIANCE",
    "B22 the gap cap is removed": "BASE_COVERAGE_POLICY",
    "B22 enforcement references are emptied": "BASE_NO_ENFORCEMENT",
    "B22 a standard loses its version": "BASE_STANDARD_VERSION",
    "B22 a requirement cites an unregistered standard": "BASE_STANDARD_UNKNOWN",
    "B22 baseline document hand-edited": "BASE_GENERATED_DRIFT",
}

SCENARIOS = [
    ("B22 a requirement maps to a rule code nobody emits", BASE,
     lambda d: _req(d, "ASVS-1.4.1")["enforcement"].__setitem__(
         "refs", ["AUTHZ_IMAGINARY_RULE"]), EXIT_PROBLEMS),
    ("B22 a requirement maps to a deleted test", BASE,
     lambda d: _req(d, "ASVS-7.1.2")["enforcement"].__setitem__(
         "refs", ["tools/tests/test_b22_baseline.py::HardeningReference::test_deleted"]),
     EXIT_PROBLEMS),
    ("B22 an accepted gap loses its owner", BASE,
     lambda d: _req(d, "ASVS-5.3.4")["enforcement"].__setitem__("owner", ""), EXIT_PROBLEMS),
    ("B22 an accepted gap loses its review batch", BASE,
     lambda d: _req(d, "ASVS-5.3.4")["enforcement"].__setitem__("review_batch", "later"),
     EXIT_PROBLEMS),
    ("B22 a gap claims enforcement as well", BASE,
     lambda d: _req(d, "ASVS-5.3.4")["enforcement"].__setitem__(
         "refs", ["AUTHZ_DEFAULT_DECISION"]), EXIT_PROBLEMS),
    ("B22 mobile requirements claim compliance", BASE,
     lambda d: _req(d, "MASVS-STORAGE-1").__setitem__(
         "enforcement", {"kind": "gate_rule", "refs": ["AUTHZ_FIELD_MASK"]}), EXIT_PROBLEMS),
    ("B22 the gap cap is removed", BASE,
     lambda d: d["coverage_policy"].__setitem__("max_accepted_gaps", 0), EXIT_PROBLEMS),
    ("B22 enforcement references are emptied", BASE,
     lambda d: _req(d, "ASVS-2.2.1")["enforcement"].__setitem__("refs", []), EXIT_PROBLEMS),
    ("B22 a standard loses its version", BASE,
     lambda d: d["standards"][0].__setitem__("version", ""), EXIT_PROBLEMS),
    ("B22 a requirement cites an unregistered standard", BASE,
     lambda d: _req(d, "ASVS-1.4.1").__setitem__("standard", "NIST"), EXIT_PROBLEMS),
]

TEXT_SCENARIOS = [
    ("B22 baseline document hand-edited",
     "docs/security/SECURITY_BASELINE.md", "明确记录的缺口", "已知问题", EXIT_PROBLEMS),
]
