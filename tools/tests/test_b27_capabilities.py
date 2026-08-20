"""B27 / AT-B27-01 — provider capability and regional policy matrix.

``test_an_undeclared_combination_is_refused_before_the_payer_commits`` is the
test this batch exists for. A matrix whose default is "probably fine, ask the
provider" has restricted nothing; it has only moved the refusal to the moment
after the payer entered their card details, where it arrives as a third-party
error code.

``test_capturing_an_expired_authorisation_is_refused`` is the other one. A real
acquirer may well accept that capture. The cardholder may still take it back,
and the burden of proof is ours — so the model refuses what the network would
have allowed.
"""
from __future__ import annotations

import json

from libs.capability.reference import matrix as M
from tools.paygov import capabilities, capabilitiesgen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase

REL = "governance/provider-capabilities.json"
HOUR = 1000
DAY = 500


def _row(model, provider, method):
    return next(r for r in model["capabilities"]
                if r["provider"] == provider and r["method"] == method)


def _region(model, code):
    return next(r for r in model["region_policy"] if r["region"] == code)


def _availability(model, provider):
    return next(a for a in model["availability"] if a["provider"] == provider)


class CapabilityMatrixHappyPath(FixtureTestCase):
    def test_real_model_passes(self):
        problems = capabilities.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("provider-capabilities", registry.names())

    def test_the_matrix_denies_by_default(self):
        resolution = self.fixture.read(REL)["resolution"]
        self.assertEqual(resolution["default"], "deny")
        self.assertEqual(resolution["unknown_combination"], "unsupported")

    def test_nothing_may_be_silently_substituted(self):
        resolution = self.fixture.read(REL)["resolution"]
        self.assertFalse(resolution["silent_fallback_to_another_method"])
        self.assertFalse(resolution["silent_fallback_to_another_provider"])
        for entry in self.fixture.read(REL)["availability"]:
            self.assertFalse(entry["silent_fallback_allowed"], entry["provider"])

    def test_every_capability_names_a_provider_the_binding_model_defines(self):
        providers = {p["id"] for p in
                     self.fixture.read("governance/provider-accounts.json")["providers"]}
        for row in self.fixture.read(REL)["capabilities"]:
            self.assertIn(row["provider"], providers, row["provider"])

    def test_every_capability_region_is_an_operating_region(self):
        regions = {r["code"] for r in
                   self.fixture.read("governance/merchant-profile.json")["operating_regions"]}
        for row in self.fixture.read(REL)["capabilities"]:
            for code in row["regions"]:
                self.assertIn(code, regions, row["provider"])

    def test_every_chargeable_currency_can_also_be_settled(self):
        accounts = {p["id"]: p for p in
                    self.fixture.read("governance/provider-accounts.json")["providers"]}
        for row in self.fixture.read(REL)["capabilities"]:
            settle = set(accounts[row["provider"]]["settlement_currencies"])
            self.assertTrue(set(row["currencies"]) <= settle,
                            f"{row['provider']}: {set(row['currencies']) - settle}")

    def test_every_currency_exists_in_the_currency_metadata(self):
        known = {c["code"] for c in
                 self.fixture.read("governance/currency-metadata.json")["currencies"]}
        for row in self.fixture.read(REL)["capabilities"]:
            for code in row["currencies"]:
                self.assertIn(code, known, row["provider"])

    def test_every_authorisation_expires(self):
        for row in self.fixture.read(REL)["capabilities"]:
            if row["supports_authorization_capture"]:
                self.assertGreater(row["authorization_valid_hours"], 0, row["provider"])
                self.assertLessEqual(row["authorization_valid_hours"], capabilities.MAX_AUTH_HOURS)
            else:
                self.assertEqual(row["authorization_valid_hours"], 0, row["provider"])

    def test_capture_is_capped_at_the_authorised_amount(self):
        model = self.fixture.read(REL)
        self.assertFalse(model["authorization"]["over_capture_allowed"])
        self.assertFalse(model["authorization"]["capture_after_expiry_allowed"])
        self.assertTrue(model["authorization"]["reauthorization_required"])
        for row in model["capabilities"]:
            self.assertEqual(row["capture_max_percent"], 100, row["provider"])

    def test_refunds_have_a_window_and_a_direction(self):
        model = self.fixture.read(REL)
        self.assertFalse(model["refund"]["promise_beyond_window"])
        self.assertFalse(model["refund"]["refund_exceeding_capture_allowed"])
        for row in model["capabilities"]:
            self.assertGreater(row["refund_window_days"], 0, row["provider"])
            self.assertTrue(row["refund_to_original_instrument_only"], row["provider"])

    def test_the_dispute_clock_belongs_to_the_network(self):
        dispute = self.fixture.read(REL)["dispute"]
        self.assertTrue(dispute["deadline_is_external"])
        self.assertTrue(dispute["missing_response_loses_by_default"])
        self.assertFalse(dispute["auto_accept_allowed"])
        self.assertTrue(capabilities.EVIDENCE_REQUIRED <= set(dispute["evidence_required"]))

    def test_every_dispute_deadline_falls_inside_its_window(self):
        for row in self.fixture.read(REL)["capabilities"]:
            self.assertLess(row["dispute_response_days"], row["dispute_window_days"],
                            row["provider"])
            self.assertLessEqual(row["dispute_response_days"],
                                 capabilities.MAX_DISPUTE_RESPONSE_DAYS, row["provider"])

    def test_every_provider_says_what_happens_when_it_is_down(self):
        model = self.fixture.read(REL)
        covered = {a["provider"] for a in model["availability"]}
        self.assertEqual(covered, {r["provider"] for r in model["capabilities"]})
        for entry in model["availability"]:
            self.assertIn(entry["degraded_behaviour"], capabilities.DEGRADED)
            if entry["scheduled_maintenance"]:
                self.assertTrue(entry["maintenance_window_utc"], entry["provider"])

    def test_every_region_policy_is_backed_by_a_capability_row(self):
        model = self.fixture.read(REL)
        for policy in model["region_policy"]:
            for method in policy["allowed_methods"]:
                self.assertTrue(any(r["method"] == method and policy["region"] in r["regions"]
                                    for r in model["capabilities"]),
                                f"{policy['region']}/{method}")

    def test_strong_customer_authentication_is_mandatory_in_the_eu(self):
        self.assertTrue(_region(self.fixture.read(REL), "EU")
                        ["strong_customer_authentication"])

    def test_matrix_changes_map_to_a_real_audit_class(self):
        audit = self.fixture.read("governance/audit-log.json")
        self.assertIn(self.fixture.read(REL)["audit_event_class"],
                      {c["id"] for c in audit["event_classes"]})


class CapabilityGeneratedArtefacts(FixtureTestCase):
    def _validate(self):
        return capabilities.validate(self.fixture.root, Budget(seconds=60).start())

    def test_generated_artefacts_match_the_model(self):
        for rel, content in capabilitiesgen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)

    def test_contract_carries_every_row(self):
        contract = json.loads(capabilitiesgen.contract_json(REAL_ROOT))
        model = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))
        self.assertEqual({(r["provider"], r["method"]) for r in contract["capabilities"]},
                         {(r["provider"], r["method"]) for r in model["capabilities"]})

    def test_document_shows_every_region(self):
        text = capabilitiesgen.capabilities_markdown(REAL_ROOT)
        model = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))
        for policy in model["region_policy"]:
            self.assertIn(policy["region"], text)

    def test_drift_is_reported(self):
        self.fixture.write("docs/provider/PROVIDER_CAPABILITIES.md", "hand written\n")
        self.assertIn("CAP_GENERATED_DRIFT", self.codes(self._validate()))

    def test_missing_generated_artefact_is_reported(self):
        self.fixture.remove("contracts/provider/capability-matrix.json")
        self.assertIn("CAP_GENERATED_MISSING", self.codes(self._validate()))

    def test_unrenderable_model_fails_closed(self):
        self.fixture.mutate(REL, lambda d: d.__setitem__(
            "capabilities", [{"provider": "stripe", "method": "card"}]))
        self.assertIn("CAP_GENERATED", self.codes(self._validate()))


class CapabilityGateRejects(FixtureTestCase):
    def _validate(self):
        return capabilities.validate(self.fixture.root, Budget(seconds=60).start())

    def _assert(self, code):
        self.assertIn(code, self.codes(self._validate()))

    def _mutate(self, fn, code, rel=REL):
        self.fixture.mutate(rel, fn)
        self._assert(code)

    # -- shape ------------------------------------------------------------
    def test_rejects_unreadable_model(self):
        self.fixture.write(REL, "{ broken")
        self._assert("CAP_UNREADABLE")

    def test_rejects_non_object_model(self):
        self.fixture.write(REL, [1])
        self._assert("CAP_SHAPE")

    def test_rejects_a_bad_schema_version(self):
        self._mutate(lambda d: d.__setitem__("schema_version", "one"), "CAP_VERSION_FIELD")

    def test_rejects_a_missing_principle(self):
        self._mutate(lambda d: d.__setitem__("principle", ""), "CAP_PRINCIPLE")

    def test_rejects_an_empty_method_list(self):
        self._mutate(lambda d: d.__setitem__("payment_methods", []), "CAP_SHAPE")

    def test_rejects_a_non_object_method(self):
        self._mutate(lambda d: d["payment_methods"].append("card"), "CAP_SHAPE")

    def test_rejects_an_empty_device_list(self):
        self._mutate(lambda d: d.__setitem__("device_kinds", []), "CAP_SHAPE")

    def test_rejects_a_non_object_capability(self):
        self._mutate(lambda d: d["capabilities"].append("stripe/card"), "CAP_SHAPE")

    def test_rejects_a_non_object_authorization_block(self):
        self._mutate(lambda d: d.__setitem__("authorization", []), "CAP_SHAPE")

    def test_rejects_a_non_object_refund_block(self):
        self._mutate(lambda d: d.__setitem__("refund", []), "CAP_SHAPE")

    def test_rejects_a_non_object_dispute_block(self):
        self._mutate(lambda d: d.__setitem__("dispute", []), "CAP_SHAPE")

    def test_rejects_an_empty_availability_list(self):
        self._mutate(lambda d: d.__setitem__("availability", []), "CAP_SHAPE")

    def test_rejects_a_non_object_availability_row(self):
        self._mutate(lambda d: d["availability"].append("stripe"), "CAP_SHAPE")

    def test_rejects_an_empty_region_policy(self):
        self._mutate(lambda d: d.__setitem__("region_policy", []), "CAP_SHAPE")

    def test_rejects_a_non_object_region_policy(self):
        self._mutate(lambda d: d["region_policy"].append("EU"), "CAP_SHAPE")

    # -- the central claim ------------------------------------------------
    def test_rejects_a_matrix_that_allows_by_default(self):
        self._mutate(lambda d: d["resolution"].__setitem__("default", "allow"),
                     "CAP_IMPLICIT_ALLOW")

    def test_rejects_attempting_an_undeclared_combination(self):
        self._mutate(lambda d: d["resolution"].__setitem__("unknown_combination", "attempt"),
                     "CAP_IMPLICIT_ALLOW")

    def test_rejects_a_missing_resolution_policy(self):
        self._mutate(lambda d: d.__setitem__("resolution", []), "CAP_IMPLICIT_ALLOW")

    def test_rejects_silently_switching_provider(self):
        self._mutate(lambda d: d["resolution"].__setitem__(
            "silent_fallback_to_another_provider", True), "CAP_SILENT_FALLBACK")

    def test_rejects_silently_switching_method(self):
        self._mutate(lambda d: d["resolution"].__setitem__(
            "silent_fallback_to_another_method", True), "CAP_SILENT_FALLBACK")

    def test_rejects_a_provider_that_falls_back_while_down(self):
        self._mutate(lambda d: _availability(d, "stripe").__setitem__(
            "silent_fallback_allowed", True), "CAP_SILENT_FALLBACK")

    def test_rejects_an_unexplained_resolution_policy(self):
        self._mutate(lambda d: d["resolution"].__setitem__("notes", ""),
                     "CAP_RESOLUTION_NOTES")

    # -- methods and devices ----------------------------------------------
    def test_rejects_a_non_snake_case_method_id(self):
        self._mutate(lambda d: d["payment_methods"][0].__setitem__("id", "WeChat Pay"),
                     "CAP_METHOD_ID")

    def test_rejects_a_duplicate_method(self):
        self._mutate(lambda d: d["payment_methods"].append(dict(d["payment_methods"][0])),
                     "CAP_METHOD_DUPLICATE")

    def test_rejects_an_unknown_method_kind(self):
        self._mutate(lambda d: d["payment_methods"][0].__setitem__("kind", "vibes"),
                     "CAP_METHOD_KIND")

    def test_rejects_an_unexplained_method(self):
        self._mutate(lambda d: d["payment_methods"][0].__setitem__("notes", ""),
                     "CAP_METHOD_NOTES")

    def test_rejects_an_unknown_device_kind(self):
        self._mutate(lambda d: d["device_kinds"].append("smart_fridge"),
                     "CAP_DEVICE_UNKNOWN")

    def test_rejects_a_row_using_an_undeclared_device(self):
        # "pos" is a real device kind but this model does not declare it for
        # cards; the row may only use kinds the model lists.
        self._mutate(lambda d: (d["device_kinds"].remove("pos"),
                                _row(d, "stripe", "card")["devices"].append("pos")),
                     "CAP_DEVICE_UNKNOWN")

    # -- capability rows --------------------------------------------------
    def test_rejects_an_empty_matrix(self):
        self._mutate(lambda d: d.__setitem__("capabilities", []), "CAP_NO_MATRIX")

    def test_rejects_a_provider_the_binding_model_does_not_define(self):
        self._mutate(lambda d: _row(d, "stripe", "card").__setitem__("provider", "klarna"),
                     "CAP_PROVIDER_UNKNOWN")

    def test_rejects_an_undeclared_method(self):
        self._mutate(lambda d: _row(d, "stripe", "card").__setitem__("method", "crypto"),
                     "CAP_METHOD_UNKNOWN")

    def test_rejects_two_rows_for_one_pair(self):
        self._mutate(lambda d: d["capabilities"].append(dict(_row(d, "stripe", "card"))),
                     "CAP_ROW_DUPLICATE")

    def test_rejects_a_row_with_no_region(self):
        self._mutate(lambda d: _row(d, "stripe", "card").__setitem__("regions", []),
                     "CAP_ROW_NO_REGION")

    def test_rejects_a_region_that_is_not_an_operating_region(self):
        self._mutate(lambda d: _row(d, "stripe", "card")["regions"].append("US"),
                     "CAP_REGION_UNKNOWN")

    def test_rejects_a_row_with_no_currency(self):
        self._mutate(lambda d: _row(d, "stripe", "card").__setitem__("currencies", []),
                     "CAP_ROW_NO_CURRENCY")

    def test_rejects_a_currency_the_money_model_does_not_know(self):
        self._mutate(lambda d: _row(d, "stripe", "card")["currencies"].append("XYZ"),
                     "CAP_CURRENCY_UNKNOWN")

    def test_rejects_a_currency_that_can_be_charged_but_not_settled(self):
        self._mutate(lambda d: _row(d, "stripe", "card")["currencies"].append("CNY"),
                     "CAP_CURRENCY_UNSETTLEABLE")

    def test_rejects_a_row_with_no_device(self):
        self._mutate(lambda d: _row(d, "stripe", "card").__setitem__("devices", []),
                     "CAP_ROW_NO_DEVICE")

    def test_rejects_an_unstated_authorisation_capability(self):
        self._mutate(lambda d: _row(d, "stripe", "card").__setitem__(
            "supports_authorization_capture", "yes"), "CAP_AUTH_UNSTATED")

    def test_rejects_an_authorisation_that_never_expires(self):
        self._mutate(lambda d: _row(d, "stripe", "card").__setitem__(
            "authorization_valid_hours", 0), "CAP_AUTH_NEVER_EXPIRES")

    def test_rejects_an_authorisation_window_without_an_authorisation_step(self):
        self._mutate(lambda d: _row(d, "wechat", "wechat_pay").__setitem__(
            "authorization_valid_hours", 48), "CAP_AUTH_WINDOW_WITHOUT_AUTH")

    def test_rejects_over_capture_in_a_row(self):
        self._mutate(lambda d: _row(d, "stripe", "card").__setitem__("capture_max_percent", 115),
                     "CAP_OVER_CAPTURE")

    def test_rejects_a_refund_window_that_never_closes(self):
        self._mutate(lambda d: _row(d, "stripe", "card").__setitem__("refund_window_days", 0),
                     "CAP_REFUND_NO_WINDOW")

    def test_rejects_an_unstated_partial_refund_capability(self):
        self._mutate(lambda d: _row(d, "stripe", "card").__setitem__("partial_refund", "yes"),
                     "CAP_REFUND_UNSTATED")

    def test_rejects_refunding_to_a_different_instrument(self):
        self._mutate(lambda d: _row(d, "stripe", "card").__setitem__(
            "refund_to_original_instrument_only", False), "CAP_REFUND_ELSEWHERE")

    def test_rejects_a_row_with_no_dispute_window(self):
        self._mutate(lambda d: _row(d, "stripe", "card").__setitem__("dispute_window_days", 0),
                     "CAP_DISPUTE_NO_WINDOW")

    def test_rejects_a_row_with_no_dispute_deadline(self):
        self._mutate(lambda d: _row(d, "stripe", "card").__setitem__("dispute_response_days", 0),
                     "CAP_DISPUTE_NO_DEADLINE")

    def test_rejects_a_deadline_outside_its_dispute_window(self):
        self._mutate(lambda d: _row(d, "stripe", "card").__setitem__("dispute_window_days",
                                                                     10),
                     "CAP_DISPUTE_DEADLINE_INVERTED")

    def test_rejects_an_unstated_subscription_capability(self):
        self._mutate(lambda d: _row(d, "stripe", "card").__setitem__("supports_subscription",
                                                                     "maybe"),
                     "CAP_SUBSCRIPTION_UNSTATED")

    def test_rejects_an_unexplained_row(self):
        self._mutate(lambda d: _row(d, "stripe", "card").__setitem__("notes", ""),
                     "CAP_ROW_NOTES")

    # -- authorisation, refund, dispute blocks ----------------------------
    def test_rejects_an_unbounded_global_authorisation_ceiling(self):
        self._mutate(lambda d: d["authorization"].__setitem__("max_valid_hours", 0),
                     "CAP_AUTH_NEVER_EXPIRES")

    def test_rejects_capturing_after_expiry(self):
        self._mutate(lambda d: d["authorization"].__setitem__("capture_after_expiry_allowed",
                                                              True),
                     "CAP_CAPTURE_AFTER_EXPIRY")

    def test_rejects_reusing_an_expired_authorisation(self):
        self._mutate(lambda d: d["authorization"].__setitem__("reauthorization_required", False),
                     "CAP_NO_REAUTHORIZATION")

    def test_rejects_global_over_capture(self):
        self._mutate(lambda d: d["authorization"].__setitem__("over_capture_allowed", True),
                     "CAP_OVER_CAPTURE")

    def test_rejects_an_unexplained_authorisation_policy(self):
        self._mutate(lambda d: d["authorization"].__setitem__("notes", ""), "CAP_AUTH_NOTES")

    def test_rejects_promising_a_refund_beyond_the_window(self):
        self._mutate(lambda d: d["refund"].__setitem__("promise_beyond_window", True),
                     "CAP_REFUND_PROMISED_BEYOND_WINDOW")

    def test_rejects_saying_nothing_about_life_after_the_window(self):
        self._mutate(lambda d: d["refund"].__setitem__("beyond_window_action", "shrug"),
                     "CAP_REFUND_NO_FALLBACK")

    def test_rejects_refunding_more_than_was_captured(self):
        self._mutate(lambda d: d["refund"].__setitem__("refund_exceeding_capture_allowed", True),
                     "CAP_OVER_REFUND")

    def test_rejects_an_unexplained_refund_policy(self):
        self._mutate(lambda d: d["refund"].__setitem__("notes", ""), "CAP_REFUND_NOTES")

    def test_rejects_treating_the_dispute_deadline_as_ours(self):
        self._mutate(lambda d: d["dispute"].__setitem__("deadline_is_external", False),
                     "CAP_DISPUTE_DEADLINE_INTERNAL")

    def test_rejects_pretending_a_missed_deadline_is_survivable(self):
        self._mutate(lambda d: d["dispute"].__setitem__("missing_response_loses_by_default",
                                                        False),
                     "CAP_DISPUTE_NO_DEADLINE")

    def test_rejects_automatic_concession(self):
        self._mutate(lambda d: d["dispute"].__setitem__("auto_accept_allowed", True),
                     "CAP_DISPUTE_AUTO_ACCEPT")

    def test_rejects_an_incomplete_evidence_pack(self):
        self._mutate(lambda d: d["dispute"].__setitem__("evidence_required", ["order_record"]),
                     "CAP_DISPUTE_NO_EVIDENCE")

    def test_rejects_an_unexplained_dispute_policy(self):
        self._mutate(lambda d: d["dispute"].__setitem__("notes", ""), "CAP_DISPUTE_NOTES")

    # -- availability -----------------------------------------------------
    def test_rejects_an_availability_row_for_an_unknown_provider(self):
        self._mutate(lambda d: _availability(d, "stripe").__setitem__("provider", "klarna"),
                     "CAP_PROVIDER_UNKNOWN")

    def test_rejects_a_provider_with_no_availability_row(self):
        self._mutate(lambda d: d.__setitem__(
            "availability", [a for a in d["availability"] if a["provider"] != "stripe"]),
            "CAP_AVAILABILITY_MISSING")

    def test_rejects_an_undefined_degraded_behaviour(self):
        self._mutate(lambda d: _availability(d, "stripe").__setitem__("degraded_behaviour",
                                                                      "improvise"),
                     "CAP_DEGRADED_UNDEFINED")

    def test_rejects_scheduled_maintenance_with_no_window(self):
        self._mutate(lambda d: _availability(d, "stripe").__setitem__("scheduled_maintenance",
                                                                      True),
                     "CAP_MAINTENANCE_UNDECLARED")

    def test_rejects_an_unexplained_availability_row(self):
        self._mutate(lambda d: _availability(d, "stripe").__setitem__("notes", ""),
                     "CAP_AVAILABILITY_NOTES")

    # -- region policy ----------------------------------------------------
    def test_rejects_a_policy_for_a_region_we_do_not_operate_in(self):
        self._mutate(lambda d: _region(d, "SG").__setitem__("region", "US"),
                     "CAP_REGION_UNKNOWN")

    def test_rejects_a_duplicate_region_policy(self):
        self._mutate(lambda d: d["region_policy"].append(dict(_region(d, "SG"))),
                     "CAP_REGION_DUPLICATE")

    def test_rejects_a_region_that_allows_nothing(self):
        self._mutate(lambda d: _region(d, "SG").__setitem__("allowed_methods", []),
                     "CAP_REGION_NO_METHOD")

    def test_rejects_a_region_allowing_an_unknown_method(self):
        self._mutate(lambda d: _region(d, "SG")["allowed_methods"].append("crypto"),
                     "CAP_METHOD_UNKNOWN")

    def test_rejects_a_policy_promising_what_the_matrix_cannot_deliver(self):
        self._mutate(lambda d: _region(d, "SG")["allowed_methods"].append("wechat_pay"),
                     "CAP_REGION_METHOD_UNSUPPORTED")

    def test_rejects_an_unstated_acquirer_rule(self):
        self._mutate(lambda d: _region(d, "SG").__setitem__("requires_local_acquirer", "yes"),
                     "CAP_REGION_ACQUIRER_UNSTATED")

    def test_rejects_an_unstated_sca_rule(self):
        self._mutate(lambda d: _region(d, "SG").__setitem__("strong_customer_authentication",
                                                            "maybe"), "CAP_SCA_UNSTATED")

    def test_rejects_switching_off_strong_customer_authentication_in_the_eu(self):
        self._mutate(lambda d: _region(d, "EU").__setitem__("strong_customer_authentication",
                                                            False), "CAP_SCA_DISABLED")

    def test_rejects_an_unexplained_region_policy(self):
        self._mutate(lambda d: _region(d, "SG").__setitem__("notes", ""), "CAP_REGION_NOTES")

    def test_rejects_an_unknown_audit_class(self):
        self._mutate(lambda d: d.__setitem__("audit_event_class", "matrix.vanished"),
                     "CAP_AUDIT_CLASS_UNKNOWN")


class CapabilityReferenceModel(FixtureTestCase):
    MODEL = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))

    def matrix(self) -> M.Matrix:
        return M.Matrix(self.MODEL)

    def card(self) -> M.Request:
        return M.Request("stripe", "card", "SG", "USD", "web")

    def refused(self, fn, code):
        with self.assertRaises(M.CapabilityRefused) as ctx:
            fn()
        self.assertEqual(ctx.exception.code, code)

    # -- resolution -------------------------------------------------------
    def test_a_declared_combination_resolves(self):
        row = self.matrix().resolve(self.card())
        self.assertEqual((row["provider"], row["method"]), ("stripe", "card"))

    def test_an_undeclared_combination_is_refused_before_the_payer_commits(self):
        matrix = self.matrix()
        # Every one of these would have been a provider-side error after the
        # payer entered their details.
        self.refused(lambda: matrix.resolve(M.Request("paypal", "card", "EU", "EUR", "web")),
                     M.UNSUPPORTED)
        self.refused(lambda: matrix.resolve(M.Request("stripe", "card", "SG", "CNY", "web")),
                     M.CURRENCY_UNSUPPORTED)
        self.refused(lambda: matrix.resolve(M.Request("stripe", "apple_pay", "SG", "USD",
                                                      "android")), M.DEVICE_UNSUPPORTED)
        self.assertFalse(matrix.supports(M.Request("stripe", "card", "SG", "CNY", "web")))

    def test_an_unknown_provider_method_or_region_is_refused(self):
        matrix = self.matrix()
        self.refused(lambda: matrix.resolve(M.Request("klarna", "card", "EU", "EUR", "web")),
                     M.UNKNOWN_PROVIDER)
        self.refused(lambda: matrix.resolve(M.Request("stripe", "crypto", "EU", "EUR", "web")),
                     M.UNKNOWN_METHOD)
        self.refused(lambda: matrix.resolve(M.Request("stripe", "card", "US", "USD", "web")),
                     M.UNSUPPORTED)

    def test_a_region_that_forbids_a_method_wins_over_the_row(self):
        self.refused(lambda: self.matrix().resolve(
            M.Request("wechat", "wechat_pay", "SG", "SGD", "web")), M.REGION_FORBIDS_METHOD)

    def test_a_supported_pair_in_an_unsupported_region_is_refused(self):
        self.refused(lambda: self.matrix().resolve(
            M.Request("paypal", "paypal_wallet", "CN", "USD", "web")), M.REGION_FORBIDS_METHOD)

    def test_nothing_is_substituted_behind_the_payers_back(self):
        matrix = self.matrix()
        self.refused(lambda: matrix.fallback(
            self.card(), M.Request("paypal", "paypal_wallet", "SG", "USD", "web")),
            M.SILENT_FALLBACK)
        self.refused(lambda: matrix.fallback(
            self.card(), M.Request("stripe", "apple_pay", "SG", "USD", "web")),
            M.SILENT_FALLBACK)

    def test_an_unavailable_provider_rejects_rather_than_reroutes(self):
        matrix = self.matrix()
        self.assertEqual(matrix.check_available("wechat", in_maintenance=False), "OK")
        self.refused(lambda: matrix.check_available("wechat", in_maintenance=True),
                     M.PROVIDER_UNAVAILABLE)
        self.refused(lambda: matrix.check_available("klarna", in_maintenance=False),
                     M.UNKNOWN_PROVIDER)

    def test_strong_customer_authentication_follows_the_region(self):
        matrix = self.matrix()
        self.assertTrue(matrix.requires_strong_customer_authentication("EU"))
        self.assertFalse(matrix.requires_strong_customer_authentication("CN"))
        self.refused(lambda: matrix.requires_strong_customer_authentication("US"),
                     M.UNSUPPORTED)

    # -- authorisation and capture ----------------------------------------
    def test_a_wallet_has_no_authorisation_step(self):
        self.refused(lambda: self.matrix().authorize(
            M.Request("wechat", "wechat_pay", "CN", "CNY", "ios"), 9900, hour=HOUR),
            M.NO_AUTHORIZATION_STEP)

    def test_an_authorisation_expires_at_the_declared_hour(self):
        matrix = self.matrix()
        auth = matrix.authorize(self.card(), 10000, hour=HOUR)
        row = _row(self.MODEL, "stripe", "card")
        self.assertEqual(matrix.authorization_expires_at(auth),
                         HOUR + row["authorization_valid_hours"])

    def test_capturing_an_expired_authorisation_is_refused(self):
        matrix = self.matrix()
        auth = matrix.authorize(self.card(), 10000, hour=HOUR)
        expires = matrix.authorization_expires_at(auth)
        # An acquirer might well accept this. The cardholder can still reverse
        # it, and we would be the ones explaining why we captured late.
        self.refused(lambda: matrix.capture(auth, 10000, hour=expires), M.AUTH_EXPIRED)
        self.assertEqual(matrix.capture(auth, 10000, hour=expires - 1), 10000)

    def test_capturing_more_than_authorised_is_refused(self):
        matrix = self.matrix()
        auth = matrix.authorize(self.card(), 10000, hour=HOUR)
        self.refused(lambda: matrix.capture(auth, 10001, hour=HOUR + 1), M.OVER_CAPTURE)

    def test_capturing_twice_is_refused(self):
        matrix = self.matrix()
        auth = matrix.authorize(self.card(), 10000, hour=HOUR)
        matrix.capture(auth, 10000, hour=HOUR + 1)
        self.refused(lambda: matrix.capture(auth, 1, hour=HOUR + 2), M.ALREADY_CAPTURED)

    def test_partial_capture_follows_the_row(self):
        matrix = self.matrix()
        auth = matrix.authorize(self.card(), 10000, hour=HOUR)
        self.assertEqual(matrix.capture(auth, 4000, hour=HOUR + 1), 4000)
        apple = matrix.authorize(M.Request("apple_pay", "apple_pay", "CN", "CNY", "ios"),
                                 10000, hour=HOUR)
        self.refused(lambda: matrix.capture(apple, 5000, hour=HOUR + 1),
                     M.PARTIAL_CAPTURE_UNSUPPORTED)

    def test_reauthorisation_only_happens_after_expiry(self):
        matrix = self.matrix()
        auth = matrix.authorize(self.card(), 10000, hour=HOUR)
        self.assertIs(matrix.reauthorize(auth, hour=HOUR + 1), auth)
        self.assertIsNot(matrix.reauthorize(auth, hour=HOUR + 1000), auth)

    # -- refunds ----------------------------------------------------------
    def test_a_refund_inside_the_window_is_allowed(self):
        matrix = self.matrix()
        auth = matrix.authorize(self.card(), 10000, hour=HOUR)
        matrix.capture(auth, 10000, hour=HOUR + 1)
        self.assertEqual(matrix.refund(auth, 4000, paid_on_day=DAY, day=DAY + 1), 4000)

    def test_a_refund_after_the_window_is_refused_with_a_route_out(self):
        matrix = self.matrix()
        auth = matrix.authorize(self.card(), 10000, hour=HOUR)
        matrix.capture(auth, 10000, hour=HOUR + 1)
        closes = matrix.refund_closes_on(self.card(), DAY)
        self.assertFalse(matrix.may_offer_refund(self.card(), paid_on_day=DAY, day=closes))
        with self.assertRaises(M.CapabilityRefused) as ctx:
            matrix.refund(auth, 100, paid_on_day=DAY, day=closes)
        self.assertEqual(ctx.exception.code, M.REFUND_WINDOW_CLOSED)
        self.assertIn(self.MODEL["refund"]["beyond_window_action"], str(ctx.exception))

    def test_refunding_more_than_was_captured_is_refused(self):
        matrix = self.matrix()
        auth = matrix.authorize(self.card(), 10000, hour=HOUR)
        matrix.capture(auth, 6000, hour=HOUR + 1)
        self.refused(lambda: matrix.refund(auth, 6001, paid_on_day=DAY, day=DAY + 1),
                     M.OVER_REFUND)

    def test_a_refund_must_return_the_way_it_came(self):
        matrix = self.matrix()
        auth = matrix.authorize(self.card(), 10000, hour=HOUR)
        matrix.capture(auth, 10000, hour=HOUR + 1)
        self.refused(lambda: matrix.refund(auth, 100, paid_on_day=DAY, day=DAY + 1,
                                           to_original_instrument=False), M.REFUND_ELSEWHERE)

    # -- disputes ---------------------------------------------------------
    def test_a_dispute_opens_inside_its_window_and_sets_an_external_clock(self):
        matrix = self.matrix()
        row = _row(self.MODEL, "stripe", "card")
        due = matrix.open_dispute(self.card(), paid_on_day=DAY, day=DAY + 30)
        self.assertEqual(due, DAY + 30 + row["dispute_response_days"])
        self.refused(lambda: matrix.open_dispute(self.card(), paid_on_day=DAY,
                                                 day=DAY + row["dispute_window_days"] + 1),
                     M.DISPUTE_WINDOW_CLOSED)

    def test_missing_the_deadline_loses_the_case(self):
        matrix = self.matrix()
        due = matrix.dispute_response_due(self.card(), DAY)
        self.refused(lambda: matrix.respond_to_dispute(
            self.card(), opened_on_day=DAY, day=due + 1,
            evidence=set(self.MODEL["dispute"]["evidence_required"])),
            M.DISPUTE_DEADLINE_PASSED)

    def test_an_incomplete_evidence_pack_cannot_contest(self):
        matrix = self.matrix()
        self.refused(lambda: matrix.respond_to_dispute(self.card(), opened_on_day=DAY,
                                                       day=DAY + 1,
                                                       evidence={"order_record"}),
                     M.DISPUTE_EVIDENCE_INCOMPLETE)
        self.assertEqual(matrix.respond_to_dispute(
            self.card(), opened_on_day=DAY, day=DAY + 1,
            evidence=set(self.MODEL["dispute"]["evidence_required"])), "CONTESTED")

    def test_conceding_automatically_is_refused_but_a_person_may_concede(self):
        matrix = self.matrix()
        self.refused(lambda: matrix.respond_to_dispute(self.card(), opened_on_day=DAY,
                                                       day=DAY + 1, evidence=set(),
                                                       accept=True, automated=True),
                     M.DISPUTE_AUTO_ACCEPT)
        self.assertEqual(matrix.respond_to_dispute(self.card(), opened_on_day=DAY, day=DAY + 1,
                                                   evidence=set(), accept=True), "ACCEPTED")

    # -- subscriptions ----------------------------------------------------
    def test_subscriptions_follow_the_row(self):
        matrix = self.matrix()
        self.assertEqual(matrix.start_subscription(
            M.Request("paypal", "paypal_wallet", "EU", "EUR", "web")), "OK")
        self.refused(lambda: matrix.start_subscription(
            M.Request("stripe", "apple_pay", "EU", "EUR", "ios")), M.SUBSCRIPTION_UNSUPPORTED)
