"""Scenarios for the programme-hygiene rules added alongside the registry split.

These cover the two places where "adding a batch" used to mean "editing a file
every earlier batch is pinned to": the validator registry and the SSOT
registry. The controls that replaced the pinning have to be attackable, or the
refactor traded a slow-but-honest arrangement for a fast dishonest one.
"""
from __future__ import annotations

from . import EXIT_PROBLEMS

EXPECTED_CODES = {
    "hygiene an SSOT entry lies about which batch owns it": "SSOT_BATCH_MISMATCH",
}

SCENARIOS = [
    ("hygiene an SSOT entry lies about which batch owns it", "governance/ssot-registry.json",
     lambda d: next(s for s in d["sources"] if s["id"] == "mfa").__setitem__("batch", "B03"),
     EXIT_PROBLEMS),
]
