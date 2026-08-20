"""B29 / AT-B29-01 — fee, cost, commission and metering model.

``test_a_settlement_that_disagrees_does_not_overwrite_the_estimate`` is the test
this batch exists for. The brief forbids substituting a book model for real
settlement, and the way that happens is never a decision — it is one line that
writes the provider's figure over ours because then the numbers agree. What is
lost is the answer to "what did we believe we were charging", which is the whole
content of a fee dispute.

``test_tax_is_levied_on_the_service_fee_not_the_payment`` is the other one. It
looks like a detail and it is a factor of a hundred in what we tell an authority
we owe.
"""
from __future__ import annotations

import json

from libs.pricing.reference import fees as F
from tools.paygov import fees, feesgen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase

REL = "governance/fee-model.json"
DAY = 500


def _schedule(model, sid):
    return next(s for s in model["schedules"] if s["id"] == sid)


def _category(model, cid):
    return next(c for c in model["categories"] if c["id"] == cid)


class FeeModelHappyPath(FixtureTestCase):
    def test_real_model_passes(self):
        problems = fees.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("fee-model", registry.names())

    def test_all_four_categories_exist_and_are_distinguished(self):
        model = self.fixture.read(REL)
        self.assertEqual({c["id"] for c in model["categories"]}, fees.CATEGORIES)
        self.assertFalse(_category(model, "tax")["is_revenue"])
        self.assertTrue(_category(model, "tax")["remitted_to_authority"])
        self.assertFalse(_category(model, "provider_cost")["is_revenue"])
        self.assertTrue(_category(model, "platform_service_fee")["is_revenue"])
        self.assertFalse(_category(model, "internal_cost")["charged_to_merchant"])

    def test_rounding_is_declared_with_an_owner_for_the_remainder(self):
        rounding = self.fixture.read(REL)["rounding"]
        self.assertIn(rounding["mode"], fees.ROUNDING_MODES)
        self.assertEqual(rounding["unit"], "minor")
        self.assertTrue(rounding["declared"])
        self.assertTrue(rounding["sum_must_equal_total"])
        self.assertIn(rounding["remainder_owner"], fees.PARTIES)

    def test_every_amount_in_the_model_is_an_integer(self):
        for schedule in self.fixture.read(REL)["schedules"]:
            for field in ("percentage_bp", "fixed_minor", "min_minor", "max_minor"):
                self.assertIsInstance(schedule[field], int, f"{schedule['id']}.{field}")

    def test_every_schedule_says_what_it_is_a_percentage_of(self):
        for schedule in self.fixture.read(REL)["schedules"]:
            self.assertIn(schedule["basis"], fees.BASIS_KINDS, schedule["id"])

    def test_tax_is_levied_on_the_service_fee(self):
        for schedule in self.fixture.read(REL)["schedules"]:
            if schedule["category"] == "tax":
                self.assertEqual(schedule["basis"], "platform_service_fee", schedule["id"])

    def test_every_bound_provider_has_a_cost_schedule(self):
        providers = {p["id"] for p in
                     self.fixture.read("governance/provider-accounts.json")["providers"]}
        priced = {s["provider"] for s in self.fixture.read(REL)["schedules"]
                  if s["category"] == "provider_cost"}
        self.assertEqual(providers - priced, set())

    def test_every_schedule_prices_a_payment_that_can_actually_happen(self):
        caps = self.fixture.read("governance/provider-capabilities.json")
        for schedule in self.fixture.read(REL)["schedules"]:
            self.assertTrue(
                any(row["provider"] == schedule["provider"]
                    and row["method"] == schedule["method"]
                    and schedule["region"] in row["regions"]
                    and schedule["currency"] in row["currencies"]
                    for row in caps["capabilities"]), schedule["id"])

    def test_every_currency_exists_in_the_currency_metadata(self):
        known = {c["code"] for c in
                 self.fixture.read("governance/currency-metadata.json")["currencies"]}
        for schedule in self.fixture.read(REL)["schedules"]:
            self.assertIn(schedule["currency"], known, schedule["id"])

    def test_percentage_service_fees_are_capped(self):
        for schedule in self.fixture.read(REL)["schedules"]:
            if schedule["category"] == "platform_service_fee" and schedule["percentage_bp"]:
                self.assertGreater(schedule["max_minor"], 0, schedule["id"])

    def test_the_book_value_is_an_estimate_until_settlement(self):
        settlement = self.fixture.read(REL)["settlement"]
        self.assertTrue(settlement["book_value_is_estimate"])
        self.assertEqual(settlement["authoritative_source"], "provider_settlement_report")
        self.assertTrue(settlement["mismatch_opens_reconciliation"])
        self.assertFalse(settlement["silent_overwrite_allowed"])
        self.assertEqual(settlement["tolerance_minor"], 0)
        self.assertLessEqual(settlement["max_settle_lag_days"], fees.MAX_SETTLE_LAG_DAYS)

    def test_the_split_names_every_party_and_the_residue_owner(self):
        split = self.fixture.read(REL)["split"]
        self.assertTrue(fees.PARTIES <= set(split["parties"]))
        self.assertTrue(split["must_sum_to_total"])
        self.assertIn(split["residue_to"], fees.PARTIES)

    def test_currency_conversion_needs_a_rate_record(self):
        currency = self.fixture.read(REL)["currency"]
        self.assertTrue(currency["fee_currency_equals_payment_currency"])
        self.assertFalse(currency["implicit_conversion_allowed"])
        self.assertTrue(currency["conversion_requires_rate_record"])
        self.assertTrue(fees.RATE_RECORD_FIELDS <= set(currency["rate_record_fields"]))

    def test_metering_is_idempotent_and_recomputable(self):
        metering = self.fixture.read(REL)["metering"]
        self.assertEqual(metering["event_key"], "payment_id")
        self.assertTrue(metering["idempotent"])
        self.assertTrue(metering["recomputable"])
        self.assertGreaterEqual(metering["retention_days"], 365)

    def test_fee_events_are_money_events(self):
        audit = self.fixture.read("governance/audit-log.json")
        model = self.fixture.read(REL)
        self.assertEqual(model["audit_event_class"], "money.movement")
        self.assertIn(model["audit_event_class"], {c["id"] for c in audit["event_classes"]})


class FeeGeneratedArtefacts(FixtureTestCase):
    def _validate(self):
        return fees.validate(self.fixture.root, Budget(seconds=60).start())

    def test_generated_artefacts_match_the_model(self):
        for rel, content in feesgen.render_all(REAL_ROOT).items():
            self.assertEqual((REAL_ROOT / rel).read_text(encoding="utf-8"), content, rel)
            self.assertIn("GENERATED FILE", content, rel)

    def test_contract_carries_every_schedule_with_its_basis(self):
        contract = json.loads(feesgen.contract_json(REAL_ROOT))
        model = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))
        self.assertEqual({s["id"] for s in contract["schedules"]},
                         {s["id"] for s in model["schedules"]})
        for schedule in contract["schedules"]:
            self.assertIn("basis", schedule)

    def test_document_shows_every_category(self):
        text = feesgen.fees_markdown(REAL_ROOT)
        for category in fees.CATEGORIES:
            self.assertIn(category, text)

    def test_drift_is_reported(self):
        self.fixture.write("docs/pricing/FEE_MODEL.md", "hand written\n")
        self.assertIn("FEE_GENERATED_DRIFT", self.codes(self._validate()))

    def test_missing_generated_artefact_is_reported(self):
        self.fixture.remove("contracts/pricing/fee-model.json")
        self.assertIn("FEE_GENERATED_MISSING", self.codes(self._validate()))

    def test_unrenderable_model_fails_closed(self):
        self.fixture.mutate(REL, lambda d: d.__setitem__("schedules", [{"id": "x"}]))
        self.assertIn("FEE_GENERATED", self.codes(self._validate()))


class FeeGateRejects(FixtureTestCase):
    def _validate(self):
        return fees.validate(self.fixture.root, Budget(seconds=60).start())

    def _assert(self, code):
        self.assertIn(code, self.codes(self._validate()))

    def _mutate(self, fn, code, rel=REL):
        self.fixture.mutate(rel, fn)
        self._assert(code)

    # -- shape ------------------------------------------------------------
    def test_rejects_unreadable_model(self):
        self.fixture.write(REL, "{ broken")
        self._assert("FEE_UNREADABLE")

    def test_rejects_non_object_model(self):
        self.fixture.write(REL, [1])
        self._assert("FEE_SHAPE")

    def test_rejects_a_bad_schema_version(self):
        self._mutate(lambda d: d.__setitem__("schema_version", "one"), "FEE_VERSION_FIELD")

    def test_rejects_a_missing_principle(self):
        self._mutate(lambda d: d.__setitem__("principle", ""), "FEE_PRINCIPLE")

    def test_rejects_an_empty_category_list(self):
        self._mutate(lambda d: d.__setitem__("categories", []), "FEE_SHAPE")

    def test_rejects_a_non_object_category(self):
        self._mutate(lambda d: d["categories"].append("tax"), "FEE_SHAPE")

    def test_rejects_a_non_object_schedule(self):
        self._mutate(lambda d: d["schedules"].append("stripe_eu_cost"), "FEE_SHAPE")

    def test_rejects_a_non_object_metering_block(self):
        self._mutate(lambda d: d.__setitem__("metering", []), "FEE_SHAPE")

    # -- categories -------------------------------------------------------
    def test_rejects_an_unknown_category(self):
        self._mutate(lambda d: _category(d, "tax").__setitem__("id", "surcharge"),
                     "FEE_CATEGORY_UNKNOWN")

    def test_rejects_a_duplicate_category(self):
        self._mutate(lambda d: d["categories"].append(dict(_category(d, "tax"))),
                     "FEE_CATEGORY_DUPLICATE")

    def test_rejects_an_unstated_category_flag(self):
        self._mutate(lambda d: _category(d, "tax").__setitem__("is_revenue", "no"),
                     "FEE_CATEGORY_UNSTATED")

    def test_rejects_a_missing_category(self):
        self._mutate(lambda d: d.__setitem__(
            "categories", [c for c in d["categories"] if c["id"] != "internal_cost"]),
            "FEE_CATEGORY_MISSING")

    def test_rejects_counting_tax_as_revenue(self):
        self._mutate(lambda d: _category(d, "tax").__setitem__("is_revenue", True),
                     "FEE_TAX_AS_REVENUE")

    def test_rejects_tax_that_is_not_remitted(self):
        self._mutate(lambda d: _category(d, "tax").__setitem__("remitted_to_authority", False),
                     "FEE_TAX_NOT_REMITTED")

    def test_rejects_counting_the_providers_cut_as_revenue(self):
        self._mutate(lambda d: _category(d, "provider_cost").__setitem__("is_revenue", True),
                     "FEE_COST_AS_REVENUE")

    def test_rejects_charging_internal_cost_to_the_merchant(self):
        self._mutate(lambda d: _category(d, "internal_cost").__setitem__(
            "charged_to_merchant", True), "FEE_INTERNAL_COST_CHARGED")

    def test_rejects_an_unexplained_category(self):
        self._mutate(lambda d: _category(d, "tax").__setitem__("notes", ""),
                     "FEE_CATEGORY_NOTES")

    # -- rounding ---------------------------------------------------------
    def test_rejects_a_missing_rounding_rule(self):
        self._mutate(lambda d: d.__setitem__("rounding", []), "FEE_ROUNDING_UNDECLARED")

    def test_rejects_an_unknown_rounding_mode(self):
        self._mutate(lambda d: d["rounding"].__setitem__("mode", "whatever"),
                     "FEE_ROUNDING_UNDECLARED")

    def test_rejects_rounding_outside_minor_units(self):
        self._mutate(lambda d: d["rounding"].__setitem__("unit", "major"),
                     "FEE_ROUNDING_UNIT")

    def test_rejects_an_undeclared_rounding_rule(self):
        self._mutate(lambda d: d["rounding"].__setitem__("declared", False),
                     "FEE_ROUNDING_UNDECLARED")

    def test_rejects_parts_that_need_not_add_up(self):
        self._mutate(lambda d: d["rounding"].__setitem__("sum_must_equal_total", False),
                     "FEE_SPLIT_UNBALANCED")

    def test_rejects_a_remainder_with_no_owner(self):
        self._mutate(lambda d: d["rounding"].__setitem__("remainder_owner", "whoever"),
                     "FEE_NO_REMAINDER_OWNER")

    def test_rejects_an_unexplained_rounding_rule(self):
        self._mutate(lambda d: d["rounding"].__setitem__("notes", ""), "FEE_ROUNDING_NOTES")

    # -- schedules --------------------------------------------------------
    def test_rejects_a_model_with_no_schedules(self):
        self._mutate(lambda d: d.__setitem__("schedules", []), "FEE_NO_SCHEDULES")

    def test_rejects_a_non_snake_case_schedule_id(self):
        self._mutate(lambda d: _schedule(d, "stripe_eu_cost").__setitem__("id", "Stripe EU"),
                     "FEE_SCHEDULE_ID")

    def test_rejects_a_duplicate_schedule(self):
        self._mutate(lambda d: d["schedules"].append(dict(_schedule(d, "stripe_eu_cost"))),
                     "FEE_SCHEDULE_DUPLICATE")

    def test_rejects_a_schedule_in_an_undeclared_category(self):
        self._mutate(lambda d: _schedule(d, "stripe_eu_cost").__setitem__("category",
                                                                          "surcharge"),
                     "FEE_CATEGORY_UNKNOWN")

    def test_rejects_a_schedule_with_no_declared_basis(self):
        self._mutate(lambda d: _schedule(d, "stripe_eu_cost").__setitem__("basis", ""),
                     "FEE_BASIS_UNKNOWN")

    def test_rejects_tax_levied_on_the_payment_amount(self):
        self._mutate(lambda d: _schedule(d, "tax_eu_vat").__setitem__("basis", "payment"),
                     "FEE_TAX_ON_PAYMENT")

    def test_rejects_pricing_a_provider_with_no_binding(self):
        self._mutate(lambda d: _schedule(d, "stripe_eu_cost").__setitem__("provider", "klarna"),
                     "FEE_PROVIDER_UNKNOWN")

    def test_rejects_a_currency_the_money_model_does_not_know(self):
        self._mutate(lambda d: _schedule(d, "stripe_eu_cost").__setitem__("currency", "XYZ"),
                     "FEE_CURRENCY_UNKNOWN")

    def test_rejects_pricing_a_payment_that_cannot_happen(self):
        self._mutate(lambda d: _schedule(d, "stripe_eu_cost").__setitem__("region", "CN"),
                     "FEE_SCHEDULE_UNREACHABLE")

    def test_rejects_a_provider_with_no_cost_schedule(self):
        self._mutate(lambda d: d.__setitem__(
            "schedules", [s for s in d["schedules"] if s["provider"] != "paypal"]),
            "FEE_PROVIDER_NO_COST")

    def test_rejects_a_percentage_outside_its_range(self):
        self._mutate(lambda d: _schedule(d, "stripe_eu_cost").__setitem__("percentage_bp",
                                                                          20000),
                     "FEE_PERCENTAGE_RANGE")

    def test_rejects_a_non_integer_percentage(self):
        self._mutate(lambda d: _schedule(d, "stripe_eu_cost").__setitem__("percentage_bp",
                                                                          "1.4%"),
                     "FEE_PERCENTAGE_RANGE")

    def test_rejects_a_non_integer_fixed_amount(self):
        self._mutate(lambda d: _schedule(d, "stripe_eu_cost").__setitem__("fixed_minor", 0.25),
                     "FEE_FIXED_NOT_INTEGER")

    def test_rejects_a_schedule_that_charges_nothing(self):
        self._mutate(lambda d: (_schedule(d, "stripe_eu_cost").__setitem__("percentage_bp", 0),
                                _schedule(d, "stripe_eu_cost").__setitem__("fixed_minor", 0)),
                     "FEE_SCHEDULE_FREE")

    def test_rejects_a_non_integer_bound(self):
        self._mutate(lambda d: _schedule(d, "platform_eu").__setitem__("min_minor", 1.5),
                     "FEE_BOUND_NOT_INTEGER")

    def test_rejects_a_cap_below_its_floor(self):
        self._mutate(lambda d: _schedule(d, "platform_eu").__setitem__("min_minor", 10 ** 9),
                     "FEE_BOUNDS_INVERTED")

    def test_rejects_an_uncapped_percentage_service_fee(self):
        self._mutate(lambda d: _schedule(d, "platform_eu").__setitem__("max_minor", 0),
                     "FEE_UNCAPPED_PERCENT")

    def test_rejects_an_unexplained_schedule(self):
        self._mutate(lambda d: _schedule(d, "stripe_eu_cost").__setitem__("notes", ""),
                     "FEE_SCHEDULE_NOTES")

    # -- settlement -------------------------------------------------------
    def test_rejects_a_missing_settlement_policy(self):
        self._mutate(lambda d: d.__setitem__("settlement", []), "FEE_BOOK_IS_TRUTH")

    def test_rejects_treating_the_book_value_as_truth(self):
        self._mutate(lambda d: d["settlement"].__setitem__("book_value_is_estimate", False),
                     "FEE_BOOK_IS_TRUTH")

    def test_rejects_an_authoritative_source_that_is_not_the_report(self):
        self._mutate(lambda d: d["settlement"].__setitem__("authoritative_source",
                                                           "our_ledger"),
                     "FEE_NO_AUTHORITATIVE_SOURCE")

    def test_rejects_ignoring_a_mismatch(self):
        self._mutate(lambda d: d["settlement"].__setitem__("mismatch_opens_reconciliation",
                                                           False), "FEE_MISMATCH_IGNORED")

    def test_rejects_silently_overwriting_the_estimate(self):
        self._mutate(lambda d: d["settlement"].__setitem__("silent_overwrite_allowed", True),
                     "FEE_SILENT_OVERWRITE")

    def test_rejects_a_tolerance_for_integer_amounts(self):
        self._mutate(lambda d: d["settlement"].__setitem__("tolerance_minor", 5),
                     "FEE_TOLERANCE_NONZERO")

    def test_rejects_an_estimate_that_is_never_escalated(self):
        self._mutate(lambda d: d["settlement"].__setitem__("max_settle_lag_days", 0),
                     "FEE_SETTLE_LAG_UNBOUNDED")

    def test_rejects_an_unexplained_settlement_policy(self):
        self._mutate(lambda d: d["settlement"].__setitem__("notes", ""),
                     "FEE_SETTLEMENT_NOTES")

    # -- split, currency, metering ----------------------------------------
    def test_rejects_a_split_missing_a_party(self):
        self._mutate(lambda d: d["split"].__setitem__("parties",
                                                      ["merchant", "platform", "provider"]),
                     "FEE_SPLIT_PARTY_MISSING")

    def test_rejects_a_split_that_need_not_balance(self):
        self._mutate(lambda d: d["split"].__setitem__("must_sum_to_total", False),
                     "FEE_SPLIT_UNBALANCED")

    def test_rejects_a_residue_with_no_owner(self):
        self._mutate(lambda d: d["split"].__setitem__("residue_to", "nobody"),
                     "FEE_NO_REMAINDER_OWNER")

    def test_rejects_an_unexplained_split(self):
        self._mutate(lambda d: d["split"].__setitem__("notes", ""), "FEE_SPLIT_NOTES")

    def test_rejects_a_missing_currency_policy(self):
        self._mutate(lambda d: d.__setitem__("currency", []), "FEE_IMPLICIT_CONVERSION")

    def test_rejects_a_fee_in_another_currency(self):
        self._mutate(lambda d: d["currency"].__setitem__(
            "fee_currency_equals_payment_currency", False), "FEE_CURRENCY_MISMATCH")

    def test_rejects_implicit_conversion(self):
        self._mutate(lambda d: d["currency"].__setitem__("implicit_conversion_allowed", True),
                     "FEE_IMPLICIT_CONVERSION")

    def test_rejects_conversion_without_a_rate_record(self):
        self._mutate(lambda d: d["currency"].__setitem__("conversion_requires_rate_record",
                                                         False), "FEE_NO_RATE_RECORD")

    def test_rejects_an_incomplete_rate_record(self):
        self._mutate(lambda d: d["currency"].__setitem__("rate_record_fields", ["rate"]),
                     "FEE_NO_RATE_RECORD")

    def test_rejects_an_unexplained_currency_policy(self):
        self._mutate(lambda d: d["currency"].__setitem__("notes", ""), "FEE_CURRENCY_NOTES")

    def test_rejects_metering_keyed_by_anything_else(self):
        self._mutate(lambda d: d["metering"].__setitem__("event_key", "session_id"),
                     "FEE_METERING_KEY")

    def test_rejects_a_non_idempotent_meter(self):
        self._mutate(lambda d: d["metering"].__setitem__("idempotent", False),
                     "FEE_METERING_NOT_IDEMPOTENT")

    def test_rejects_a_meter_that_cannot_be_recomputed(self):
        self._mutate(lambda d: d["metering"].__setitem__("recomputable", False),
                     "FEE_METERING_UNRECOMPUTABLE")

    def test_rejects_metering_thrown_away_before_a_dispute_ends(self):
        self._mutate(lambda d: d["metering"].__setitem__("retention_days", 30),
                     "FEE_METERING_RETENTION_SHORT")

    def test_rejects_an_unexplained_metering_policy(self):
        self._mutate(lambda d: d["metering"].__setitem__("notes", ""), "FEE_METERING_NOTES")

    def test_rejects_an_unknown_audit_class(self):
        self._mutate(lambda d: d.__setitem__("audit_event_class", "fee.vanished"),
                     "FEE_AUDIT_CLASS_UNKNOWN")

    def test_rejects_recording_fees_as_a_configuration_change(self):
        self._mutate(lambda d: d.__setitem__("audit_event_class", "config.change"),
                     "FEE_AUDIT_CLASS_TOO_WEAK")


class PricerReferenceModel(FixtureTestCase):
    MODEL = json.loads((REAL_ROOT / REL).read_text(encoding="utf-8"))

    def pricer(self) -> F.Pricer:
        return F.Pricer(self.MODEL)

    def payment(self, pid="pay_0001", provider="stripe", method="card", region="EU",
                currency="EUR", amount=10000, day=DAY) -> F.Payment:
        return F.Payment(id=pid, provider=provider, method=method, region=region,
                         currency=currency, amount_minor=amount, day=day)

    def refused(self, fn, code):
        with self.assertRaises(F.PricingRefused) as ctx:
            fn()
        self.assertEqual(ctx.exception.code, code)

    # -- arithmetic -------------------------------------------------------
    def test_percentages_are_integer_arithmetic_with_declared_rounding(self):
        pricer = self.pricer()
        self.assertEqual(pricer.apply_percentage(10000, 140), 140)
        self.assertEqual(pricer.apply_percentage(999, 60), 6)
        self.assertEqual(pricer.apply_percentage(0, 140), 0)

    def test_a_float_amount_is_refused_not_rounded(self):
        pricer = self.pricer()
        self.refused(lambda: pricer.apply_percentage(100.5, 60), F.AMOUNT_NOT_INTEGER)
        self.refused(lambda: pricer.apply_percentage(True, 60), F.AMOUNT_NOT_INTEGER)

    def test_a_negative_amount_is_refused(self):
        self.refused(lambda: self.pricer().apply_percentage(-1, 60), F.AMOUNT_NEGATIVE)

    def test_an_unknown_rounding_mode_is_refused(self):
        model = json.loads(json.dumps(self.MODEL))
        model["rounding"]["mode"] = "toward_the_house"
        self.refused(lambda: F.Pricer(model).apply_percentage(100, 60), F.UNKNOWN_ROUNDING)

    def test_half_even_rounding_is_available_and_differs(self):
        model = json.loads(json.dumps(self.MODEL))
        model["rounding"]["mode"] = "half_even"
        even = F.Pricer(model)
        model2 = json.loads(json.dumps(self.MODEL))
        model2["rounding"]["mode"] = "down"
        down = F.Pricer(model2)
        self.assertEqual(down.apply_percentage(999, 60), 5)
        self.assertEqual(even.apply_percentage(999, 60), 6)

    # -- quoting ----------------------------------------------------------
    def test_a_quote_is_a_breakdown_not_a_number(self):
        quote = self.pricer().quote(self.payment())
        self.assertEqual(quote.total_minor,
                         sum(c.amount_minor for c in quote.components))
        self.assertIn("provider_cost", {c.category for c in quote.components})
        self.assertEqual(quote.status, F.ESTIMATED)

    def test_an_unpriced_combination_is_refused_not_defaulted(self):
        pricer = self.pricer()
        self.refused(lambda: pricer.quote(self.payment(provider="paypal", method="card")),
                     F.NO_SCHEDULE)

    def test_tax_is_levied_on_the_service_fee_not_the_payment(self):
        pricer = self.pricer()
        quote = pricer.quote(self.payment(amount=10000))
        fee = quote.by_category("platform_service_fee")
        tax = quote.by_category("tax")
        rate = _schedule(self.MODEL, "tax_eu_vat")["percentage_bp"]
        self.assertEqual(tax, pricer.apply_percentage(fee, rate))
        # The wrong basis would have produced two orders of magnitude more.
        self.assertLess(tax, pricer.apply_percentage(10000, rate))

    def test_a_floor_and_a_cap_are_applied(self):
        pricer = self.pricer()
        tiny = pricer.quote(self.payment(amount=1))
        self.assertGreaterEqual(tiny.by_category("platform_service_fee"),
                                _schedule(self.MODEL, "platform_eu")["min_minor"])
        huge = pricer.quote(self.payment(amount=10 ** 9))
        self.assertLessEqual(huge.by_category("platform_service_fee"),
                             _schedule(self.MODEL, "platform_eu")["max_minor"])

    # -- who owns what ----------------------------------------------------
    def test_revenue_is_only_the_service_fee(self):
        pricer = self.pricer()
        quote = pricer.quote(self.payment())
        self.assertEqual(pricer.revenue(quote), quote.by_category("platform_service_fee"))
        self.assertEqual(pricer.remitted(quote), quote.by_category("tax"))

    def test_revenue_refuses_a_category_that_is_both_revenue_and_remitted(self):
        model = json.loads(json.dumps(self.MODEL))
        _category(model, "tax")["is_revenue"] = True
        pricer = F.Pricer(model)
        quote = pricer.quote(self.payment())
        self.refused(lambda: pricer.revenue(quote), F.TAX_IN_REVENUE)

    def test_internal_cost_is_not_charged_to_the_merchant(self):
        pricer = self.pricer()
        quote = pricer.quote(self.payment(provider="wechat", method="wechat_pay",
                                          region="CN", currency="CNY"))
        self.assertGreater(quote.by_category("internal_cost"), 0)
        self.assertEqual(pricer.charged_to_merchant(quote),
                         quote.total_minor - quote.by_category("internal_cost"))

    def test_the_split_adds_back_to_the_total_exactly(self):
        pricer = self.pricer()
        for amount in (1, 999, 10000, 123457):
            quote = pricer.quote(self.payment(amount=amount))
            parts = pricer.split(quote)
            self.assertEqual(sum(parts.values()), amount, amount)
            self.assertEqual(set(parts), fees.PARTIES)

    # -- currency ---------------------------------------------------------
    def test_the_same_currency_needs_no_rate(self):
        self.assertEqual(self.pricer().convert(1000, from_currency="EUR", to_currency="EUR",
                                               rate=None), 1000)

    def test_conversion_without_a_rate_record_is_refused(self):
        pricer = self.pricer()
        self.refused(lambda: pricer.convert(1000, from_currency="EUR", to_currency="USD",
                                            rate=None), F.IMPLICIT_CONVERSION)

    def test_an_incomplete_rate_record_is_refused(self):
        pricer = self.pricer()
        self.refused(lambda: pricer.convert(1000, from_currency="EUR", to_currency="USD",
                                            rate=F.Rate(11000, 0, "ecb")),
                     F.INCOMPLETE_RATE_RECORD)
        self.refused(lambda: pricer.convert(1000, from_currency="EUR", to_currency="USD",
                                            rate=F.Rate(11000, DAY, "")),
                     F.INCOMPLETE_RATE_RECORD)

    def test_a_complete_rate_record_converts(self):
        self.assertEqual(self.pricer().convert(1000, from_currency="EUR", to_currency="USD",
                                               rate=F.Rate(11000, DAY, "ecb")), 1100)

    def test_a_fee_in_another_currency_is_refused(self):
        pricer = self.pricer()
        quote = pricer.quote(self.payment())
        self.refused(lambda: pricer.require_same_currency(quote, self.payment(currency="USD")),
                     F.CURRENCY_MISMATCH)

    # -- settlement -------------------------------------------------------
    def test_a_settlement_that_disagrees_does_not_overwrite_the_estimate(self):
        pricer = self.pricer()
        quote = pricer.quote(self.payment())
        book = quote.total_minor
        item = pricer.settle(quote, book + 7, day=DAY + 2, payment_day=DAY)
        self.assertIsNotNone(item)
        self.assertEqual(item.difference_minor, 7)
        # The estimate survives. That is the entire point of this method.
        self.assertEqual(pricer.book_value(quote), book)
        self.assertEqual(quote.settled_total_minor, book + 7)
        self.assertEqual(quote.status, F.DISPUTED)
        self.assertEqual(len(pricer.breaks), 1)

    def test_a_settlement_that_agrees_closes_the_quote(self):
        pricer = self.pricer()
        quote = pricer.quote(self.payment())
        self.assertIsNone(pricer.settle(quote, quote.total_minor, day=DAY + 1,
                                        payment_day=DAY))
        self.assertEqual(quote.status, F.SETTLED)
        self.assertEqual(pricer.breaks, [])

    def test_a_quote_cannot_be_settled_twice(self):
        pricer = self.pricer()
        quote = pricer.quote(self.payment())
        pricer.settle(quote, quote.total_minor, day=DAY + 1, payment_day=DAY)
        self.refused(lambda: pricer.settle(quote, 1, day=DAY + 2, payment_day=DAY),
                     F.ALREADY_SETTLED)

    def test_a_disputed_quote_cannot_be_settled_again_either(self):
        pricer = self.pricer()
        quote = pricer.quote(self.payment())
        pricer.settle(quote, quote.total_minor + 1, day=DAY + 1, payment_day=DAY)
        self.refused(lambda: pricer.settle(quote, quote.total_minor, day=DAY + 2,
                                           payment_day=DAY), F.ALREADY_SETTLED)

    def test_a_settlement_that_never_arrives_is_escalated(self):
        pricer = self.pricer()
        quote = pricer.quote(self.payment())
        self.refused(lambda: pricer.settle(quote, 1, day=DAY + 999, payment_day=DAY),
                     F.SETTLEMENT_OVERDUE)

    def test_a_negative_settlement_is_refused(self):
        pricer = self.pricer()
        quote = pricer.quote(self.payment())
        self.refused(lambda: pricer.settle(quote, -1, day=DAY + 1, payment_day=DAY),
                     F.AMOUNT_NEGATIVE)

    # -- metering ---------------------------------------------------------
    def test_the_meter_is_idempotent(self):
        pricer = self.pricer()
        quote = pricer.quote(self.payment())
        self.assertEqual(pricer.record(quote), "RECORDED")
        self.assertEqual(pricer.record(quote), "DUPLICATE")
        self.assertEqual(pricer.meter.duplicates, 1)
        self.assertEqual(len(pricer.meter.events), 1)

    def test_a_period_can_be_recomputed_from_the_raw_payments(self):
        pricer = self.pricer()
        payments = [self.payment(pid="a"), self.payment(pid="b", amount=25000)]
        for entry in payments:
            pricer.record(pricer.quote(entry))
        self.assertEqual(pricer.recompute(payments), pricer.metered_total())
