"""B22 / AT-B22-01 — ASVS, API Security and MASVS mapped to running code.

The test that gives this batch its point is
``test_a_mapping_to_a_nonexistent_rule_is_rejected``. Every compliance matrix
starts honest and rots the same way: a rule gets renamed, a test gets deleted,
and the row still says "covered". Here the mapping is resolved — rule codes
against the codes validators actually emit, test references down to the method
name — so rot becomes a failing build rather than a green spreadsheet.

``HardeningReference`` holds the four rows that are enforced by running code
rather than by another rule: redaction, security headers, CORS, and money
parsing. They are cited by id from ``governance/security-baseline.json``, which
means renaming one of these methods breaks the gate — deliberately.
"""
from __future__ import annotations

import json

from libs.appsec.reference import hardening as H
from tools.paygov import baseline, baselinegen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


def _model(root=REAL_ROOT) -> dict:
    return json.loads((root / "governance/security-baseline.json").read_text(encoding="utf-8"))


class BaselineHappyPath(FixtureTestCase):
    def test_real_baseline_passes(self):
        problems = baseline.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("security-baseline", registry.names())

    def test_every_gate_rule_reference_is_a_code_we_emit(self):
        from pathlib import Path

        from tools.paygov import rulecov
        emitted = set(rulecov.emitted_codes(Path(REAL_ROOT)))
        for entry in _model()["requirements"]:
            if entry["enforcement"]["kind"] == "gate_rule":
                for ref in entry["enforcement"]["refs"]:
                    self.assertIn(ref, emitted, f"{entry['id']} -> {ref}")

    def test_every_test_reference_resolves_to_a_real_method(self):
        import ast
        for entry in _model()["requirements"]:
            if entry["enforcement"]["kind"] != "test":
                continue
            for ref in entry["enforcement"]["refs"]:
                path, *parts = ref.split("::")
                source = (REAL_ROOT / path).read_text(encoding="utf-8")
                tree = ast.parse(source)
                node = tree
                for part in parts:
                    node = next(child for child in ast.iter_child_nodes(node)
                                if isinstance(child, (ast.ClassDef, ast.FunctionDef))
                                and child.name == part)

    def test_mobile_requirements_are_recorded_as_gaps_not_as_compliance(self):
        for entry in _model()["requirements"]:
            if entry["applicability"] == "mobile":
                self.assertEqual(entry["enforcement"]["kind"], "accepted_gap", entry["id"])

    def test_every_gap_has_an_owner_and_a_review_batch(self):
        for entry in _model()["requirements"]:
            enforcement = entry["enforcement"]
            if enforcement["kind"] == "accepted_gap":
                self.assertTrue(enforcement["owner"], entry["id"])
                self.assertRegex(enforcement["review_batch"], r"^B\d{2}$")
                self.assertGreaterEqual(len(entry["notes"]), 12, entry["id"])

    def test_coverage_is_above_the_declared_floor(self):
        model = _model()
        applicable = [r for r in model["requirements"] if r["applicability"] != "mobile"]
        enforced = [r for r in applicable
                    if r["enforcement"]["kind"] in {"gate_rule", "test"}]
        self.assertGreaterEqual(len(enforced) / len(applicable),
                                model["coverage_policy"]["minimum_covered_ratio"])

    def test_gaps_stay_under_the_cap(self):
        model = _model()
        gaps = [r for r in model["requirements"]
                if r["enforcement"]["kind"] == "accepted_gap"]
        self.assertLessEqual(len(gaps), model["coverage_policy"]["max_accepted_gaps"])

    def test_every_standard_is_versioned_and_used(self):
        model = _model()
        cited = {r["standard"] for r in model["requirements"]}
        for standard in model["standards"]:
            self.assertTrue(standard["version"], standard["id"])
            self.assertIn(standard["id"], cited)


class HardeningReference(FixtureTestCase):
    """The baseline rows that are enforced by code, not by another rule."""

    def test_redaction_strips_card_numbers_and_credentials(self):
        trace = ("Traceback (most recent call last):\n"
                 "  File \"charge.py\", line 42, in capture\n"
                 "    raise ProviderError(card='4111 1111 1111 1111', "
                 "api_key=sk_live_51H8xQ2eZvKYlo2C, msg='declined')\n"  # paygov:allow-secret-pattern
                 "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature\n")
        cleaned = H.redact(trace)
        self.assertNotIn("4111 1111 1111 1111", cleaned)
        self.assertNotIn("sk_live_51H8xQ2eZvKYlo2C", cleaned)  # paygov:allow-secret-pattern
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", cleaned)
        self.assertIn(H.MASKED_CARD, cleaned)
        self.assertIn("declined", cleaned)  # the useful part survives

    def test_redaction_leaves_ordinary_numbers_alone(self):
        text = "order 1234567890123 failed after 3 retries"
        self.assertEqual(H.redact(text), text)

    def test_luhn_distinguishes_a_card_from_a_long_id(self):
        self.assertTrue(H.luhn("4111111111111111"))
        self.assertFalse(H.luhn("4111111111111112"))
        self.assertFalse(H.luhn("123"))

    def test_missing_security_headers_are_reported(self):
        problems = H.security_headers({"content-type": "application/json"})
        self.assertTrue(problems)
        self.assertTrue(any("strict-transport-security" in p for p in problems))
        self.assertTrue(any("content-security-policy" in p for p in problems))

    def test_a_complete_header_set_passes(self):
        self.assertEqual(H.security_headers({
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }), [])

    def test_disabled_hsts_and_stack_advertising_are_reported(self):
        problems = H.security_headers({
            "Strict-Transport-Security": "max-age=0",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "X-Powered-By": "Express",
        })
        self.assertTrue(any("max-age=0" in p for p in problems))
        self.assertTrue(any("x-powered-by" in p for p in problems))

    def test_wildcard_cors_with_credentials_is_rejected(self):
        problems = H.check_cors({"Access-Control-Allow-Origin": "*",
                                 "Access-Control-Allow-Credentials": "true"})
        self.assertTrue(problems)
        self.assertIn("wildcard", problems[0])

    def test_wildcard_cors_without_credentials_is_allowed(self):
        self.assertEqual(H.check_cors({"Access-Control-Allow-Origin": "*"}), [])

    def test_null_origin_is_rejected(self):
        self.assertTrue(H.check_cors({"Access-Control-Allow-Origin": "null"}))

    def test_amount_parsing_rejects_floats_and_junk(self):
        for bad in (12.5, "12.5", "1e3", "", "  ", "12 34", None, True):
            with self.subTest(bad=bad):
                with self.assertRaises(H.ValidationError) as caught:
                    H.parse_amount(bad, currency_exponent=2)
                self.assertEqual(caught.exception.code, "AMOUNT_NOT_INTEGER")

    def test_amount_parsing_accepts_integers_and_integer_strings(self):
        self.assertEqual(H.parse_amount(1250, currency_exponent=2), 1250)
        self.assertEqual(H.parse_amount(" 1250 ", currency_exponent=2), 1250)
        self.assertEqual(H.parse_amount(0, currency_exponent=0), 0)

    def test_amount_parsing_refuses_negative_and_oversized_values(self):
        with self.assertRaises(H.ValidationError) as negative:
            H.parse_amount(-1, currency_exponent=2)
        self.assertEqual(negative.exception.code, "AMOUNT_NEGATIVE")
        with self.assertRaises(H.ValidationError) as large:
            H.parse_amount(10 ** 13, currency_exponent=2)
        self.assertEqual(large.exception.code, "AMOUNT_TOO_LARGE")

    def test_amount_parsing_refuses_impossible_currency_exponents(self):
        with self.assertRaises(H.ValidationError) as caught:
            H.parse_amount(100, currency_exponent=9)
        self.assertEqual(caught.exception.code, "CURRENCY_EXPONENT")

    def test_a_mutating_request_needs_an_idempotency_key(self):
        problems = H.check_request("POST", {"Authorization": "Bearer x",
                                            "Content-Type": "application/json"})
        self.assertTrue(any("idempotency" in p for p in problems))

    def test_a_complete_mutating_request_passes(self):
        self.assertEqual(H.check_request("POST", {
            "Authorization": "Bearer x", "Idempotency-Key": "abc",
            "Content-Type": "application/json"}), [])

    def test_an_unauthenticated_request_is_reported(self):
        self.assertTrue(any("authorization" in p for p in H.check_request("GET", {})))

    def test_an_unexpected_content_type_is_reported(self):
        problems = H.check_request("POST", {"Authorization": "Bearer x",
                                            "Idempotency-Key": "abc",
                                            "Content-Type": "text/xml"})
        self.assertTrue(any("content type" in p for p in problems))


class BaselineGeneratedArtefacts(FixtureTestCase):
    def test_generated_artefacts_match_the_model(self):
        for rel, content in baselinegen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)

    def test_matrix_reports_real_coverage_numbers(self):
        matrix = json.loads(baselinegen.matrix_json(REAL_ROOT))
        model = _model()
        applicable = [r for r in model["requirements"] if r["applicability"] != "mobile"]
        self.assertEqual(matrix["coverage"]["applicable"], len(applicable))
        self.assertLessEqual(matrix["coverage"]["enforced"], matrix["coverage"]["applicable"])

    def test_document_lists_every_requirement_and_gap(self):
        text = baselinegen.baseline_markdown(REAL_ROOT)
        for entry in _model()["requirements"]:
            self.assertIn(entry["id"], text)

    def test_drift_is_reported(self):
        self.fixture.write("docs/security/SECURITY_BASELINE.md", "hand written\n")
        codes = self.codes(baseline.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("BASE_GENERATED_DRIFT", codes)

    def test_missing_generated_artefact_is_reported(self):
        self.fixture.remove("contracts/security/baseline-matrix.json")
        codes = self.codes(baseline.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("BASE_GENERATED_MISSING", codes)

    def test_unrenderable_model_fails_closed(self):
        self.fixture.mutate("governance/security-baseline.json",
                            lambda d: d.__setitem__("requirements", [{"id": "x"}]))
        codes = self.codes(baseline.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("BASE_GENERATED", codes)


class BaselineGateRejects(FixtureTestCase):
    REL = "governance/security-baseline.json"

    def _validate(self):
        return baseline.validate(self.fixture.root, Budget(seconds=60).start())

    def _req(self, d, rid):
        return next(r for r in d["requirements"] if r["id"] == rid)

    def test_rejects_unreadable_baseline(self):
        self.fixture.write(self.REL, "{ broken")
        self.assertIn("BASE_UNREADABLE", self.codes(self._validate()))

    def test_rejects_non_object_baseline(self):
        self.fixture.write(self.REL, [1])
        self.assertIn("BASE_SHAPE", self.codes(self._validate()))

    def test_rejects_bad_schema_version(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("schema_version", "one"))
        self.assertIn("BASE_VERSION_FIELD", self.codes(self._validate()))

    def test_rejects_missing_principle(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("principle", ""))
        self.assertIn("BASE_PRINCIPLE", self.codes(self._validate()))

    def test_rejects_an_unversioned_standard(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["standards"][0].__setitem__("version", ""))
        self.assertIn("BASE_STANDARD_VERSION", self.codes(self._validate()))

    def test_rejects_a_standard_with_no_id(self):
        self.fixture.mutate(self.REL, lambda d: d["standards"][0].__setitem__("id", ""))
        self.assertIn("BASE_STANDARD_ID", self.codes(self._validate()))

    def test_rejects_a_standard_without_notes(self):
        self.fixture.mutate(self.REL, lambda d: d["standards"][0].__setitem__("notes", ""))
        self.assertIn("BASE_STANDARD_NOTES", self.codes(self._validate()))

    def test_rejects_a_standard_nobody_cites(self):
        self.fixture.mutate(self.REL, lambda d: d["standards"].append(
            {"id": "PCI", "version": "4.0", "notes": "登记了却没有任何要求引用它。"}))
        self.assertIn("BASE_STANDARD_UNUSED", self.codes(self._validate()))

    def test_rejects_a_requirement_from_an_unregistered_standard(self):
        self.fixture.mutate(self.REL, lambda d: self._req(d, "ASVS-1.4.1")
                            .__setitem__("standard", "NIST"))
        self.assertIn("BASE_STANDARD_UNKNOWN", self.codes(self._validate()))

    def test_rejects_a_bad_requirement_id(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._req(d, "ASVS-1.4.1").__setitem__("id", "asvs one"))
        self.assertIn("BASE_REQUIREMENT_ID", self.codes(self._validate()))

    def test_rejects_a_duplicate_requirement(self):
        self.fixture.mutate(self.REL, lambda d: d["requirements"].append(
            dict(self._req(d, "ASVS-1.4.1"))))
        self.assertIn("BASE_REQUIREMENT_DUPLICATE", self.codes(self._validate()))

    def test_rejects_an_unknown_level(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._req(d, "ASVS-1.4.1").__setitem__("level", "L9"))
        self.assertIn("BASE_LEVEL", self.codes(self._validate()))

    def test_rejects_an_unknown_applicability(self):
        self.fixture.mutate(self.REL, lambda d: self._req(d, "ASVS-1.4.1")
                            .__setitem__("applicability", "vibes"))
        self.assertIn("BASE_APPLICABILITY", self.codes(self._validate()))

    def test_rejects_a_requirement_without_a_title(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._req(d, "ASVS-1.4.1").__setitem__("title", ""))
        self.assertIn("BASE_TITLE", self.codes(self._validate()))

    def test_rejects_a_requirement_without_notes(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._req(d, "ASVS-1.4.1").__setitem__("notes", ""))
        self.assertIn("BASE_NOTES", self.codes(self._validate()))

    def test_rejects_an_unknown_enforcement_kind(self):
        self.fixture.mutate(self.REL, lambda d: self._req(d, "ASVS-1.4.1")["enforcement"]
                            .__setitem__("kind", "hope"))
        self.assertIn("BASE_ENFORCEMENT_KIND", self.codes(self._validate()))

    def test_a_mapping_to_a_nonexistent_rule_is_rejected(self):
        self.fixture.mutate(self.REL, lambda d: self._req(d, "ASVS-1.4.1")["enforcement"]
                            .__setitem__("refs", ["AUTHZ_TOTALLY_MADE_UP"]))
        self.assertIn("BASE_RULE_UNKNOWN", self.codes(self._validate()))

    def test_rejects_enforcement_with_no_references(self):
        self.fixture.mutate(self.REL, lambda d: self._req(d, "ASVS-1.4.1")["enforcement"]
                            .__setitem__("refs", []))
        self.assertIn("BASE_NO_ENFORCEMENT", self.codes(self._validate()))

    def test_rejects_a_reference_to_a_missing_test_file(self):
        self.fixture.mutate(self.REL, lambda d: self._req(d, "ASVS-5.1.3")["enforcement"]
                            .__setitem__("refs", ["tools/tests/test_ghost.py"]))
        self.assertIn("BASE_TEST_MISSING", self.codes(self._validate()))

    def test_rejects_a_reference_to_a_renamed_test_method(self):
        self.fixture.mutate(self.REL, lambda d: self._req(d, "ASVS-5.1.3")["enforcement"]
                            .__setitem__("refs", ["tools/tests/test_b22_baseline.py::"
                                                  "HardeningReference::test_renamed_away"]))
        self.assertIn("BASE_TEST_MISSING", self.codes(self._validate()))

    def test_rejects_a_gap_that_also_claims_enforcement(self):
        self.fixture.mutate(self.REL, lambda d: self._req(d, "ASVS-5.3.4")["enforcement"]
                            .__setitem__("refs", ["AUTHZ_DEFAULT_DECISION"]))
        self.assertIn("BASE_GAP_WITH_REFS", self.codes(self._validate()))

    def test_rejects_a_gap_without_an_owner(self):
        self.fixture.mutate(self.REL, lambda d: self._req(d, "ASVS-5.3.4")["enforcement"]
                            .__setitem__("owner", ""))
        self.assertIn("BASE_GAP_NO_OWNER", self.codes(self._validate()))

    def test_rejects_a_gap_with_no_review_batch(self):
        self.fixture.mutate(self.REL, lambda d: self._req(d, "ASVS-5.3.4")["enforcement"]
                            .__setitem__("review_batch", "someday"))
        self.assertIn("BASE_GAP_NO_REVIEW", self.codes(self._validate()))

    def test_rejects_a_gap_with_no_reason(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._req(d, "ASVS-5.3.4").__setitem__("notes", "n/a"))
        self.assertIn("BASE_GAP_NO_REASON", self.codes(self._validate()))

    def test_rejects_claiming_compliance_for_a_mobile_app_we_do_not_have(self):
        def claim(d):
            entry = self._req(d, "MASVS-STORAGE-1")
            entry["enforcement"] = {"kind": "gate_rule", "refs": ["AUTHZ_FIELD_MASK"]}
        self.fixture.mutate(self.REL, claim)
        self.assertIn("BASE_FALSE_COMPLIANCE", self.codes(self._validate()))

    def test_rejects_coverage_falling_below_the_floor(self):
        def gut(d):
            for entry in d["requirements"]:
                if entry["applicability"] != "mobile":
                    entry["enforcement"] = {"kind": "accepted_gap", "refs": [],
                                            "owner": "platform-security",
                                            "review_batch": "B99"}
                    entry["notes"] = "刻意把所有要求都改成缺口，用来验证覆盖率下限真的会拦。"
        self.fixture.mutate(self.REL, gut)
        codes = self.codes(self._validate())
        self.assertIn("BASE_COVERAGE_BELOW_FLOOR", codes)
        self.assertIn("BASE_TOO_MANY_GAPS", codes)

    def test_rejects_removing_the_gap_cap(self):
        self.fixture.mutate(self.REL, lambda d: d["coverage_policy"]
                            .__setitem__("max_accepted_gaps", 0))
        self.assertIn("BASE_COVERAGE_POLICY", self.codes(self._validate()))

    def test_rejects_gaps_without_owners_in_policy(self):
        self.fixture.mutate(self.REL, lambda d: d["coverage_policy"]
                            .__setitem__("gap_requires_owner", False))
        self.assertIn("BASE_COVERAGE_POLICY", self.codes(self._validate()))

    def test_budget_exhaustion_is_reraised(self):
        from tools.paygov.errors import BudgetExceeded
        with self.assertRaises(BudgetExceeded):
            baseline.validate(self.fixture.root, Budget(seconds=0).start())
