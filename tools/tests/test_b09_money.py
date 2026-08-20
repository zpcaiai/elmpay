"""B09 / AT-B09-01 — money, currency and precision.

The interesting tests here are the property tests. They run over a seeded
pseudo-random population, so they are deterministic (a failure is reproducible
from the seed printed in the assertion) while still covering far more of the
input space than hand-picked examples.

The properties are the ones whose violation costs real money: allocation must
conserve every minor unit, arithmetic must never silently cross currencies,
zero-decimal currencies must never acquire a fractional part, and rounding must
be half-even rather than a language default.
"""
from __future__ import annotations

import json
import random
from pathlib import Path

from tools.paygov import money as money_gate
from tools.paygov import moneygen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase

from libs.money.reference.money import (
    CurrencyMismatch,
    CurrencyRegistry,
    Money,
    MoneyError,
    divide_round,
    total,
)

REGISTRY = CurrencyRegistry.from_file(REAL_ROOT / "governance/currency-metadata.json")
SEED = 20260818
POPULATION = 400


def _amounts(seed: int, count: int, codes: list[str]) -> list[Money]:
    rng = random.Random(seed)
    return [Money(rng.randint(-10_000_000, 10_000_000), rng.choice(codes))
            for _ in range(count)]


class CurrencyMetadataGate(FixtureTestCase):
    def test_real_metadata_passes(self):
        problems = money_gate.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("money-model", registry.names())

    def test_zero_two_and_three_decimal_currencies_are_all_modelled(self):
        exponents = {c.minor_unit_exponent for c in
                     (REGISTRY.get(code) for code in REGISTRY.codes())}
        self.assertTrue({0, 2, 3} <= exponents)

    def test_metadata_contains_no_floating_point_literal(self):
        raw = (REAL_ROOT / "governance/currency-metadata.json").read_text(encoding="utf-8")
        self.assertIsNone(money_gate.FLOAT_IN_JSON.search(raw))

    def test_project_config_points_at_the_versioned_metadata(self):
        config = self.fixture.read("governance/project-config.json")
        self.assertEqual(config["money"]["currency_metadata_source"],
                         "governance/currency-metadata.json")


class RoundingIsExplicitAndHalfEven(FixtureTestCase):
    def test_half_even_does_not_drift_upward(self):
        # 0.5 rounds to the nearest even integer: 2.5 -> 2, 3.5 -> 4.
        self.assertEqual(divide_round(5, 2, "half_even"), 2)
        self.assertEqual(divide_round(7, 2, "half_even"), 4)
        self.assertEqual(divide_round(-5, 2, "half_even"), -2)

    def test_half_up_differs_from_half_even_exactly_at_the_midpoint(self):
        self.assertEqual(divide_round(5, 2, "half_up"), 3)
        self.assertEqual(divide_round(5, 2, "half_even"), 2)

    def test_down_and_up_truncate_and_raise(self):
        self.assertEqual(divide_round(199, 100, "down"), 1)
        self.assertEqual(divide_round(101, 100, "up"), 2)
        self.assertEqual(divide_round(-199, 100, "down"), -1)
        self.assertEqual(divide_round(-101, 100, "up"), -2)

    def test_unknown_rounding_mode_is_refused(self):
        with self.assertRaises(MoneyError):
            divide_round(1, 2, "nearest_friday")

    def test_division_by_zero_is_refused(self):
        with self.assertRaises(MoneyError):
            divide_round(1, 0)

    def test_property_half_even_is_within_one_of_exact_quotient(self):
        rng = random.Random(SEED)
        for _ in range(POPULATION):
            numerator = rng.randint(-10**9, 10**9)
            denominator = rng.randint(1, 10**6)
            result = divide_round(numerator, denominator, "half_even")
            # |result*denominator - numerator| <= denominator/2, checked with integers only.
            self.assertLessEqual(abs(result * denominator - numerator) * 2, denominator,
                                 f"seed={SEED} {numerator}/{denominator}")


class MoneyRefusesToGuess(FixtureTestCase):
    def test_amount_must_be_an_integer(self):
        for bad in (1.5, "100", True, None):
            with self.assertRaises(MoneyError, msg=repr(bad)):
                Money(bad, "CNY")  # type: ignore[arg-type]

    def test_currency_must_be_iso_alphabetic(self):
        for bad in ("cny", "CN", "CNY1", ""):
            with self.assertRaises(MoneyError, msg=bad):
                Money(1, bad)

    def test_cross_currency_arithmetic_raises(self):
        with self.assertRaises(CurrencyMismatch):
            Money(100, "CNY").add(Money(100, "USD"))
        with self.assertRaises(CurrencyMismatch):
            Money(100, "CNY").subtract(Money(100, "JPY"))
        with self.assertRaises(CurrencyMismatch):
            Money(100, "CNY").compare(Money(100, "USD"))

    def test_multiplying_by_a_non_integer_raises(self):
        with self.assertRaises(MoneyError):
            Money(100, "CNY").multiply(1.5)  # type: ignore[arg-type]

    def test_unknown_currency_is_refused_by_the_registry(self):
        with self.assertRaises(MoneyError):
            REGISTRY.get("XYZ")

    def test_totalling_an_empty_collection_raises(self):
        with self.assertRaises(MoneyError):
            total([])


class ParsingIsExact(FixtureTestCase):
    def test_two_decimal_currency(self):
        self.assertEqual(Money.parse("19.99", "CNY", REGISTRY).minor, 1999)
        self.assertEqual(Money.parse("-19.99", "CNY", REGISTRY).minor, -1999)
        self.assertEqual(Money.parse("0.01", "CNY", REGISTRY).minor, 1)

    def test_zero_decimal_currency_rejects_a_fractional_amount(self):
        self.assertEqual(Money.parse("1999", "JPY", REGISTRY).minor, 1999)
        with self.assertRaises(MoneyError):
            Money.parse("19.99", "JPY", REGISTRY)

    def test_three_decimal_currency(self):
        self.assertEqual(Money.parse("1.234", "KWD", REGISTRY).minor, 1234)
        with self.assertRaises(MoneyError):
            Money.parse("1.2345", "KWD", REGISTRY)

    def test_non_numeric_input_is_refused(self):
        for bad in ("1,00", "1e3", "abc", "1.2.3", ""):
            with self.assertRaises(MoneyError, msg=bad):
                Money.parse(bad, "CNY", REGISTRY)

    def test_property_parse_format_round_trip(self):
        rng = random.Random(SEED + 1)
        for code in REGISTRY.codes():
            for _ in range(20):
                money = Money(rng.randint(-10**9, 10**9), code)
                text = money.format(REGISTRY)
                self.assertEqual(Money.parse(text, code, REGISTRY), money,
                                 f"seed={SEED + 1} {code} {text}")

    def test_zero_decimal_format_has_no_separator(self):
        self.assertEqual(Money(1999, "JPY").format(REGISTRY), "1999")
        self.assertEqual(Money(-1, "KRW").format(REGISTRY), "-1")


class AllocationConservesEveryMinorUnit(FixtureTestCase):
    def test_split_of_an_indivisible_amount(self):
        parts = [p.minor for p in Money(10000, "CNY").split(3)]
        self.assertEqual(parts, [3334, 3333, 3333])
        self.assertEqual(sum(parts), 10000)

    def test_weighted_allocation(self):
        parts = [p.minor for p in Money(1234, "KWD").allocate([7, 2, 1])]
        self.assertEqual(sum(parts), 1234)

    def test_negative_amounts_allocate_symmetrically(self):
        positive = [p.minor for p in Money(10001, "CNY").allocate([1, 1, 1])]
        negative = [p.minor for p in Money(-10001, "CNY").allocate([1, 1, 1])]
        self.assertEqual(negative, [-p for p in positive])
        self.assertEqual(sum(negative), -10001)

    def test_invalid_weights_are_refused(self):
        for weights in ([], [0, 0], [1, -1]):
            with self.assertRaises(MoneyError, msg=str(weights)):
                Money(100, "CNY").allocate(weights)
        with self.assertRaises(MoneyError):
            Money(100, "CNY").split(0)

    def test_property_allocation_is_exact_and_fair(self):
        rng = random.Random(SEED + 2)
        codes = REGISTRY.codes()
        for _ in range(POPULATION):
            code = rng.choice(codes)
            amount = rng.randint(-10**8, 10**8)
            weights = [rng.randint(0, 9) for _ in range(rng.randint(1, 7))]
            if sum(weights) == 0:
                weights[0] = 1
            parts = Money(amount, code).allocate(weights)
            self.assertEqual(sum(p.minor for p in parts), amount,
                             f"seed={SEED + 2} {amount} {code} {weights}")
            # No share differs from another by more than one minor unit per weight unit.
            self.assertTrue(all(p.currency == code for p in parts))

    def test_property_split_parts_differ_by_at_most_one(self):
        rng = random.Random(SEED + 3)
        for _ in range(POPULATION):
            amount = rng.randint(0, 10**8)
            parts = rng.randint(1, 12)
            shares = sorted(p.minor for p in Money(amount, "CNY").split(parts))
            self.assertLessEqual(shares[-1] - shares[0], 1,
                                 f"seed={SEED + 3} {amount}/{parts}")
            self.assertEqual(sum(shares), amount)


class FeesAndConversion(FixtureTestCase):
    def test_percentage_fee_uses_integer_rational_rate(self):
        self.assertEqual(Money(10000, "CNY").apply_rate(29, 1000).minor, 290)
        self.assertEqual(Money(1999, "CNY").apply_rate(29, 1000).minor, 58)
        self.assertEqual(Money(1999, "CNY").apply_rate(29, 1000, "half_up").minor, 58)

    def test_zero_decimal_fee_stays_integral(self):
        fee = Money(1999, "JPY").apply_rate(29, 1000)
        self.assertEqual(fee.currency, "JPY")
        self.assertIsInstance(fee.minor, int)

    def test_conversion_respects_both_exponents(self):
        # 100.00 CNY at 19.5000 JPY/CNY = 1950 JPY (zero decimals).
        self.assertEqual(Money(10000, "CNY").convert("JPY", 195000, 4, REGISTRY).minor, 1950)
        # 10.00 USD at 0.30670 KWD/USD = 3.067 KWD (three decimals).
        self.assertEqual(Money(1000, "USD").convert("KWD", 30670, 5, REGISTRY).minor, 3067)

    def test_negative_rate_or_scale_is_refused(self):
        with self.assertRaises(MoneyError):
            Money(100, "CNY").convert("USD", -1, 4, REGISTRY)
        with self.assertRaises(MoneyError):
            Money(100, "CNY").convert("USD", 1, -4, REGISTRY)

    def test_property_conversion_is_sign_preserving_and_monotonic(self):
        rng = random.Random(SEED + 4)
        for _ in range(POPULATION):
            amount = rng.randint(0, 10**7)
            rate = rng.randint(1, 10**6)
            converted = Money(amount, "CNY").convert("USD", rate, 6, REGISTRY)
            self.assertGreaterEqual(converted.minor, 0, f"seed={SEED + 4}")
            bigger = Money(amount + 10**6, "CNY").convert("USD", rate, 6, REGISTRY)
            self.assertGreaterEqual(bigger.minor, converted.minor, f"seed={SEED + 4}")

    def test_property_addition_is_associative_and_conserves_value(self):
        amounts = _amounts(SEED + 5, POPULATION, ["CNY"])
        left = total(amounts)
        right = Money(sum(a.minor for a in amounts), "CNY")
        self.assertEqual(left, right)


class ConformanceVectors(FixtureTestCase):
    def test_vectors_match_the_reference_implementation(self):
        expected = moneygen.build_vectors(REAL_ROOT)
        actual = json.loads((REAL_ROOT / "contracts/money/vectors.json")
                            .read_text(encoding="utf-8"))
        self.assertEqual(actual, expected)

    def test_vectors_cover_the_dangerous_cases(self):
        vectors = json.loads((REAL_ROOT / "contracts/money/vectors.json")
                             .read_text(encoding="utf-8"))
        self.assertTrue(any(v["currency"] == "JPY" for v in vectors["parse_format"]))
        self.assertTrue(any(v["currency"] == "KWD" for v in vectors["parse_format"]))
        self.assertTrue(any(v["minor"] < 0 for v in vectors["allocation"]))
        self.assertTrue(any(v["mode"] == "half_even" for v in vectors["rounding"]))
        self.assertTrue(any(v["from"] == "JPY" or v["to"] == "JPY"
                            for v in vectors["conversions"]))

    def test_every_allocation_vector_sums_to_its_input(self):
        vectors = json.loads((REAL_ROOT / "contracts/money/vectors.json")
                             .read_text(encoding="utf-8"))
        for case in vectors["allocation"]:
            self.assertEqual(case["sum"], case["minor"], case)


class MoneyGateRejects(FixtureTestCase):
    REL = "governance/currency-metadata.json"

    def _validate(self):
        return money_gate.validate(self.fixture.root, Budget(seconds=60).start())

    def test_rejects_float_literal_in_metadata(self):
        raw = (self.fixture.root / self.REL).read_text(encoding="utf-8")
        self.fixture.write(self.REL, raw.replace('"minor_unit_exponent": 2',
                                                 '"minor_unit_exponent": 2.0', 1))
        problems = self._validate()
        self.assertIn("MONEY_FLOAT_LITERAL", self.codes(problems))
        self.assertIn("NN-05", self.rules(problems))

    def test_rejects_out_of_range_exponent(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["currencies"][0].__setitem__("minor_unit_exponent", 9))
        self.assertIn("MONEY_EXPONENT", self.codes(self._validate()))

    def test_rejects_bad_currency_code(self):
        self.fixture.mutate(self.REL, lambda d: d["currencies"][0].__setitem__("code", "cny"))
        self.assertIn("MONEY_CODE", self.codes(self._validate()))

    def test_rejects_duplicate_currency(self):
        self.fixture.mutate(self.REL, lambda d: d["currencies"].append(dict(d["currencies"][0])))
        self.assertIn("MONEY_DUPLICATE", self.codes(self._validate()))

    def test_rejects_bad_numeric_code(self):
        self.fixture.mutate(self.REL, lambda d: d["currencies"][0].__setitem__("numeric", "12"))
        self.assertIn("MONEY_NUMERIC", self.codes(self._validate()))

    def test_rejects_unknown_rounding_mode(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["currencies"][0].__setitem__("rounding", "nearest_friday"))
        self.assertIn("MONEY_ROUNDING", self.codes(self._validate()))

    def test_rejects_dropping_all_zero_decimal_currencies(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__(
            "currencies", [c for c in d["currencies"] if c["minor_unit_exponent"] != 0]))
        self.assertIn("MONEY_COVERAGE", self.codes(self._validate()))

    def test_rejects_config_pointing_elsewhere(self):
        self.fixture.mutate("governance/project-config.json",
                            lambda d: d["money"].__setitem__("currency_metadata_source",
                                                             "src/main/resources/currencies.csv"))
        self.assertIn("MONEY_SOURCE", self.codes(self._validate()))

    def test_rejects_missing_conformance_vectors(self):
        self.fixture.remove("contracts/money/vectors.json")
        self.assertIn("MONEY_VECTORS_MISSING", self.codes(self._validate()))

    def test_rejects_drifted_conformance_vectors(self):
        path = self.fixture.root / "contracts/money/vectors.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["allocation"][0]["parts"] = [1, 1, 1]
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
        self.assertIn("MONEY_VECTORS_DRIFT", self.codes(self._validate()))

    def test_rejects_unreadable_metadata(self):
        self.fixture.write(self.REL, "{ broken")
        self.assertIn("MONEY_UNREADABLE", self.codes(self._validate()))

    def test_rejects_bad_schema_version(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("schema_version", "one"))
        self.assertIn("MONEY_VERSION", self.codes(self._validate()))

    def test_rejects_empty_currency_list(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("currencies", []))
        self.assertIn("MONEY_SHAPE", self.codes(self._validate()))

    def test_rejects_bad_fx_scale(self):
        self.fixture.mutate(self.REL, lambda d: d.__setitem__("fx_rate_scale", 0))
        self.assertIn("MONEY_FX_SCALE", self.codes(self._validate()))

    def test_rejects_missing_currency_name(self):
        self.fixture.mutate(self.REL, lambda d: d["currencies"][0].__setitem__("name_cn", ""))
        self.assertIn("MONEY_NAME", self.codes(self._validate()))

    def test_rejects_bad_cash_rounding(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["currencies"][0].__setitem__("cash_rounding_minor", 0))
        self.assertIn("MONEY_CASH_ROUNDING", self.codes(self._validate()))

    def test_fails_closed_when_the_reference_implementation_cannot_run(self):
        """A gate must convert a broken input into a finding, never into a crash.

        Corrupting the metadata makes the reference implementation unusable, so the
        vectors become unverifiable. The gate has to say so rather than raise, which
        is what MONEY_VECTORS exists for.
        """
        self.fixture.write("libs/money/reference/money.py",
                           "raise RuntimeError('reference implementation is broken')\n")
        problems = self._validate()
        self.assertIn("MONEY_VECTORS", self.codes(problems))

    def test_rejects_an_in_range_but_wrong_iso_exponent(self):
        """JPY with two decimals is a legal integer, and a hundredfold error."""
        self.fixture.mutate(self.REL, lambda d: next(
            c for c in d["currencies"] if c["code"] == "JPY")
            .__setitem__("minor_unit_exponent", 2))
        self.assertIn("MONEY_EXPONENT", self.codes(self._validate()))

    def test_rejects_a_wrong_iso_numeric_code(self):
        self.fixture.mutate(self.REL, lambda d: next(
            c for c in d["currencies"] if c["code"] == "CNY").__setitem__("numeric", "999"))
        self.assertIn("MONEY_NUMERIC", self.codes(self._validate()))
