"""B34 / AT-B34-01 — executable coverage for the capture lifecycle contract.

Each rejection below mutates one field in an isolated governance fixture and
asserts the rule that must stop the change.  Keeping the mutations executable
means the rule-coverage gate cannot be satisfied by a list of rule names that
no test can actually trigger.
"""
from __future__ import annotations

from tools.paygov import capture
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase

REL = "governance/capture-lifecycle.json"


def _operation(model: dict, name: str) -> dict:
    return next(entry for entry in model["operations"] if entry.get("id") == name)


class CaptureModelHappyPath(FixtureTestCase):
    def test_real_model_passes(self):
        problems = capture.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(problem) for problem in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("capture-lifecycle", registry.names())

    def test_model_declares_all_money_safety_properties(self):
        model = self.fixture.read(REL)
        self.assertEqual({entry["id"] for entry in model["operations"]},
                         set(capture.REQUIRED_OPERATIONS))
        self.assertTrue(_operation(model, "capture")["requires_idempotency_key"])
        self.assertTrue(_operation(model, "close")["terminal"])
        self.assertFalse(_operation(model, "query")["mutates_money_state"])


class CaptureModelRejects(FixtureTestCase):
    def _validate(self):
        return capture.validate(self.fixture.root, Budget(seconds=60).start())

    def test_rejects_unreadable_model(self):
        self.fixture.write(REL, "{ broken")
        self.assertIn("CAPTURE_UNREADABLE", self.codes(self._validate()))

    def test_rejects_non_object_model(self):
        self.fixture.write(REL, [])
        self.assertIn("CAPTURE_SHAPE", self.codes(self._validate()))

    def test_rejects_invalid_schema_version(self):
        self.fixture.mutate(REL, lambda d: d.__setitem__("schema_version", "next"))
        self.assertIn("CAPTURE_VERSION_FIELD", self.codes(self._validate()))

    def test_rejects_a_vague_principle(self):
        self.fixture.mutate(REL, lambda d: d.__setitem__("principle", "short"))
        self.assertIn("CAPTURE_PRINCIPLE", self.codes(self._validate()))

    def test_rejects_a_lifecycle_missing_an_operation(self):
        self.fixture.mutate(REL, lambda d: d["operations"].remove(_operation(d, "query")))
        self.assertIn("CAPTURE_OPERATION_MISSING", self.codes(self._validate()))

    def test_requires_an_explicit_close_for_the_remainder(self):
        self.fixture.mutate(REL, lambda d: _operation(d, "close").__setitem__("releases", "none"))
        self.assertIn("CAPTURE_NO_EXPLICIT_CLOSE", self.codes(self._validate()))

    def test_expiry_is_not_a_release_policy(self):
        self.fixture.mutate(
            REL, lambda d: d["authorization"].__setitem__("expiry_is_release_path", True))
        self.assertIn("CAPTURE_EXPIRY_AS_RELEASE", self.codes(self._validate()))

    def test_void_is_refused_after_capture(self):
        self.fixture.mutate(
            REL, lambda d: _operation(d, "void")["preconditions"].remove("captured_amount_is_zero"))
        self.assertIn("CAPTURE_VOID_AFTER_CAPTURE", self.codes(self._validate()))

    def test_release_operations_are_terminal(self):
        self.fixture.mutate(REL, lambda d: _operation(d, "void").__setitem__("terminal", False))
        self.assertIn("CAPTURE_AFTER_TERMINAL", self.codes(self._validate()))

    def test_query_unknown_never_settles_or_moves_money(self):
        self.fixture.mutate(REL, lambda d: _operation(d, "query").__setitem__("settles_success", True))
        self.assertIn("CAPTURE_UNKNOWN_IS_SUCCESS", self.codes(self._validate()))

    def test_money_operations_require_idempotency(self):
        self.fixture.mutate(
            REL, lambda d: _operation(d, "capture").__setitem__("requires_idempotency_key", False))
        self.assertIn("CAPTURE_NOT_IDEMPOTENT", self.codes(self._validate()))

    def test_money_operations_are_audited(self):
        self.fixture.mutate(REL, lambda d: _operation(d, "authorize").__setitem__("audit_event", ""))
        self.assertIn("CAPTURE_UNAUDITED", self.codes(self._validate()))

    def test_money_operations_need_provider_authority(self):
        self.fixture.mutate(REL, lambda d: _operation(d, "capture").__setitem__("authority", []))
        self.assertIn("CAPTURE_AUTHORITY_WEAK", self.codes(self._validate()))

    def test_partial_modes_are_capability_gated(self):
        self.fixture.mutate(
            REL,
            lambda d: next(m for m in d["capture_modes"] if m["id"] == "partial")
            .__setitem__("requires_capability", None),
        )
        self.assertIn("CAPTURE_CAPABILITY_UNCHECKED", self.codes(self._validate()))

    def test_capability_source_is_the_provider_matrix(self):
        self.fixture.mutate(
            REL,
            lambda d: d["authorization"].__setitem__(
                "validity_source", "governance/other-capabilities.json"),
        )
        self.assertIn("CAPTURE_CAPABILITY_SOURCE", self.codes(self._validate()))

    def test_cumulative_capture_ceiling_is_declared_and_enforced(self):
        self.fixture.mutate(
            REL,
            lambda d: d["invariants"][0].__setitem__("statement", "capture is bounded"),
        )
        self.assertIn("CAPTURE_EXCEEDS_AUTHORIZED", self.codes(self._validate()))

    def test_invariants_cannot_delegate_to_an_unknown_rule(self):
        self.fixture.mutate(
            REL,
            lambda d: d["invariants"][0]["enforced_by"].append("CAPTURE_UNKNOWN_RULE"),
        )
        self.assertIn("CAPTURE_INVARIANT_UNENFORCED", self.codes(self._validate()))

    def test_terminal_outcomes_are_complete(self):
        self.fixture.mutate(REL, lambda d: d["terminal_outcomes"].pop("closed_after_partial"))
        self.assertIn("CAPTURE_TERMINAL_OUTCOME", self.codes(self._validate()))

    def test_terminal_outcomes_use_the_payment_state_machine(self):
        self.fixture.mutate(
            REL,
            lambda d: d["terminal_outcomes"].__setitem__("captured_in_full", "not-a-state"),
        )
        self.assertIn("CAPTURE_TERMINAL_OUTCOME", self.codes(self._validate()))

    def test_java_conformance_binding_cannot_be_missing(self):
        self.fixture.mutate(
            REL,
            lambda d: d["conformance"].__setitem__("java_test", "services/missing.java"),
        )
        self.assertIn("CAPTURE_JAVA_UNBOUND", self.codes(self._validate()))

    def test_vectors_must_follow_the_model(self):
        # CAPTURE_VECTORS_DRIFT is emitted when the model changes without a
        # regenerated vector contract; CAPTURE_PRINCIPLE remains valid here.
        self.fixture.mutate(
            REL,
            lambda d: d.__setitem__("principle", d["principle"] + "追加约束"),
        )
        self.assertIn("CAPTURE_VECTORS_DRIFT", self.codes(self._validate()))
