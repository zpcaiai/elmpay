"""B34 negative controls — the ways an authorisation stops being released.

Every scenario here is a plausible edit. That is the point: nobody deletes the
close operation on purpose. It goes missing because the partial-capture story
ends at "we took 600" and nobody asks what happened to the other 400.
"""
from __future__ import annotations

from . import EXIT_PROBLEMS

MODEL = "governance/capture-lifecycle.json"


def _op(d, name):
    return next(o for o in d["operations"] if o["id"] == name)


def _mode(d, name):
    return next(m for m in d["capture_modes"] if m["id"] == name)


def _inv(d, name):
    return next(i for i in d["invariants"] if i["id"] == name)


def _drop_op(d, name):
    d["operations"] = [o for o in d["operations"] if o["id"] != name]


EXPECTED_CODES = {
    "B34 the close operation disappears": "CAPTURE_NO_EXPLICIT_CLOSE",
    "B34 close stops releasing the remainder": "CAPTURE_NO_EXPLICIT_CLOSE",
    "B34 close stops requiring that anything was captured": "CAPTURE_NO_EXPLICIT_CLOSE",
    "B34 partial capture stops requiring a close": "CAPTURE_NO_EXPLICIT_CLOSE",
    "B34 expiry becomes the release path": "CAPTURE_EXPIRY_AS_RELEASE",
    "B34 reaching expiry stops raising exposure": "CAPTURE_EXPIRY_AS_RELEASE",
    "B34 a void is allowed after money moved": "CAPTURE_VOID_AFTER_CAPTURE",
    "B34 a void stops releasing the whole authorisation": "CAPTURE_VOID_AFTER_CAPTURE",
    "B34 close stops being terminal": "CAPTURE_AFTER_TERMINAL",
    "B34 the cumulative ceiling loses its rule": "CAPTURE_EXCEEDS_AUTHORIZED",
    "B34 the cumulative ceiling stops being an integer invariant": "CAPTURE_EXCEEDS_AUTHORIZED",
    "B34 a query settles success": "CAPTURE_UNKNOWN_IS_SUCCESS",
    "B34 capture stops carrying an idempotency key": "CAPTURE_NOT_IDEMPOTENT",
    "B34 closing stops being audited": "CAPTURE_UNAUDITED",
    "B34 partial capture stops checking provider capability": "CAPTURE_CAPABILITY_UNCHECKED",
    "B34 the authorisation window gets a second source": "CAPTURE_CAPABILITY_SOURCE",
    "B34 a capture may be settled by the client return page": "CAPTURE_AUTHORITY_WEAK",
    "B34 an invariant delegates to a rule nobody emits": "CAPTURE_INVARIANT_UNENFORCED",
    "B34 the closed-after-partial ending loses its state": "CAPTURE_TERMINAL_OUTCOME",
    "B34 an operation is dropped from the lifecycle": "CAPTURE_OPERATION_MISSING",
    "B34 the vectors are bound to another file": "CAPTURE_VECTORS_DRIFT",
    "B34 the Java conformance test is unbound": "CAPTURE_JAVA_UNBOUND",
    "B34 the model loses its schema version": "CAPTURE_VERSION_FIELD",
    "B34 the principle is emptied": "CAPTURE_PRINCIPLE",
}

SCENARIOS = [
    ("B34 the close operation disappears", MODEL,
     lambda d: _drop_op(d, "close"), EXIT_PROBLEMS),
    ("B34 close stops releasing the remainder", MODEL,
     lambda d: _op(d, "close").__setitem__("releases", "none"), EXIT_PROBLEMS),
    ("B34 close stops requiring that anything was captured", MODEL,
     lambda d: _op(d, "close").__setitem__("preconditions", ["authorization_active"]),
     EXIT_PROBLEMS),
    ("B34 partial capture stops requiring a close", MODEL,
     lambda d: _mode(d, "partial").__setitem__("requires_close_for_remainder", False),
     EXIT_PROBLEMS),
    ("B34 expiry becomes the release path", MODEL,
     lambda d: d["authorization"].__setitem__("expiry_is_release_path", True), EXIT_PROBLEMS),
    ("B34 reaching expiry stops raising exposure", MODEL,
     lambda d: d["authorization"].__setitem__("expiry_requires_exposure_alert", False),
     EXIT_PROBLEMS),
    ("B34 a void is allowed after money moved", MODEL,
     lambda d: _op(d, "void").__setitem__("preconditions", ["authorization_active"]),
     EXIT_PROBLEMS),
    ("B34 a void stops releasing the whole authorisation", MODEL,
     lambda d: _op(d, "void").__setitem__("releases", "remainder"), EXIT_PROBLEMS),
    ("B34 close stops being terminal", MODEL,
     lambda d: _op(d, "close").__setitem__("terminal", False), EXIT_PROBLEMS),
    ("B34 the cumulative ceiling loses its rule", MODEL,
     lambda d: _inv(d, "CAP-I1").__setitem__("enforced_by", []), EXIT_PROBLEMS),
    ("B34 the cumulative ceiling stops being an integer invariant", MODEL,
     lambda d: _inv(d, "CAP-I1").__setitem__("unit", "decimal"), EXIT_PROBLEMS),
    ("B34 a query settles success", MODEL,
     lambda d: _op(d, "query").__setitem__("settles_success", True), EXIT_PROBLEMS),
    ("B34 capture stops carrying an idempotency key", MODEL,
     lambda d: _op(d, "capture").__setitem__("requires_idempotency_key", False), EXIT_PROBLEMS),
    ("B34 closing stops being audited", MODEL,
     lambda d: _op(d, "close").__setitem__("audit_event", ""), EXIT_PROBLEMS),
    ("B34 partial capture stops checking provider capability", MODEL,
     lambda d: _mode(d, "partial").__setitem__("requires_capability", None), EXIT_PROBLEMS),
    ("B34 the authorisation window gets a second source", MODEL,
     lambda d: d["authorization"].__setitem__("validity_source", "docs/payment/CAPTURE.md"),
     EXIT_PROBLEMS),
    ("B34 a capture may be settled by the client return page", MODEL,
     lambda d: _op(d, "capture").__setitem__("authority", ["client_return_page"]), EXIT_PROBLEMS),
    ("B34 an invariant delegates to a rule nobody emits", MODEL,
     lambda d: _inv(d, "CAP-I3").__setitem__("enforced_by", ["CAPTURE_IMAGINARY_RULE"]),
     EXIT_PROBLEMS),
    ("B34 the closed-after-partial ending loses its state", MODEL,
     lambda d: d["terminal_outcomes"].__setitem__("closed_after_partial", ""), EXIT_PROBLEMS),
    ("B34 an operation is dropped from the lifecycle", MODEL,
     lambda d: _drop_op(d, "query"), EXIT_PROBLEMS),
    ("B34 the vectors are bound to another file", MODEL,
     lambda d: d["conformance"].__setitem__("vectors", "contracts/money/vectors.json"),
     EXIT_PROBLEMS),
    ("B34 the Java conformance test is unbound", MODEL,
     lambda d: d["conformance"].__setitem__("java_test", ""), EXIT_PROBLEMS),
    ("B34 the model loses its schema version", MODEL,
     lambda d: d.__setitem__("schema_version", "1.0"), EXIT_PROBLEMS),
    ("B34 the principle is emptied", MODEL,
     lambda d: d.__setitem__("principle", ""), EXIT_PROBLEMS),
]
