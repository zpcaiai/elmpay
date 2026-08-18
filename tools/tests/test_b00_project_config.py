"""B00 / AT-B00-01 — project configuration gate.

Covers the happy path plus the rejection paths for every non-negotiable the
configuration is responsible for: NN-02 card data, NN-05 money model,
NN-07 credential references, NN-11 four-eyes, NN-13 licence boundary.
"""
from __future__ import annotations

from tools.paygov import config
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class ProjectConfigHappyPath(FixtureTestCase):
    def test_real_repository_configuration_passes(self):
        self.assertEqual(config.validate(REAL_ROOT, Budget().start()), [])

    def test_fixture_copy_passes(self):
        self.assertEqual(config.validate(self.fixture.root, Budget().start()), [])

    def test_validation_is_idempotent(self):
        first = config.validate(self.fixture.root, Budget().start())
        second = config.validate(self.fixture.root, Budget().start())
        self.assertEqual(first, second)


class ProjectConfigRejects(FixtureTestCase):
    REL = "governance/project-config.json"

    def _validate(self):
        return config.validate(self.fixture.root, Budget().start())

    def test_rejects_enabled_stored_value(self):
        self.fixture.mutate(self.REL, lambda d: d["regulated_features"].__setitem__("stored_value", True))
        problems = self._validate()
        self.assertIn("CONFIG_REGULATED", self.codes(problems))
        self.assertIn("NN-13", self.rules(problems))

    def test_rejects_fund_pool_and_clearing_together(self):
        def enable(d):
            d["regulated_features"]["fund_pool"] = True
            d["regulated_features"]["cross_merchant_clearing"] = True
        self.fixture.mutate(self.REL, enable)
        problems = [p for p in self._validate() if p.code == "CONFIG_REGULATED"]
        self.assertEqual(len(problems), 2)

    def test_rejects_raw_card_data_allowed(self):
        self.fixture.mutate(self.REL, lambda d: d["security"].__setitem__("raw_card_data", "allowed"))
        self.assertIn("CONFIG_CARD_DATA", self.codes(self._validate()))

    def test_rejects_stripe_raw_card_mode(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["providers"]["stripe"].__setitem__("card_data_mode", "raw_pan"))
        problems = [p for p in self._validate() if p.rule == "NN-02"]
        self.assertTrue(problems)

    def test_rejects_apple_pay_direct_decryption(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["providers"]["apple_pay"].__setitem__("direct_token_decryption", True))
        self.assertIn("CONFIG_CARD_DATA", self.codes(self._validate()))

    def test_rejects_literal_provider_secret(self):
        # paygov:allow-secret-pattern - synthetic value, never a real key
        literal = "sk_" + "live_" + "ABCDEF0123456789"
        self.fixture.mutate(self.REL,
                            lambda d: d["providers"]["stripe"].__setitem__("credentials", literal))
        problems = self._validate()
        self.assertIn("CONFIG_CREDENTIAL_REF", self.codes(problems))
        self.assertIn("NN-07", self.rules(problems))

    def test_rejects_non_webauthn_admin_mfa(self):
        self.fixture.mutate(self.REL, lambda d: d["security"].__setitem__("admin_mfa", "sms_otp"))
        self.assertIn("CONFIG_MFA", self.codes(self._validate()))

    def test_rejects_disabled_four_eyes(self):
        self.fixture.mutate(self.REL, lambda d: d["security"].__setitem__("high_risk_four_eyes", False))
        self.assertIn("CONFIG_FOUR_EYES", self.codes(self._validate()))

    def test_rejects_float_money_representation(self):
        self.fixture.mutate(self.REL, lambda d: d["money"].__setitem__("representation", "decimal_float"))
        problems = self._validate()
        self.assertIn("CONFIG_MONEY", self.codes(problems))
        self.assertIn("NN-05", self.rules(problems))

    def test_rejects_same_executor_and_reviewer(self):
        self.fixture.mutate(self.REL, lambda d: d["evidence"].__setitem__("reviewer", d["evidence"]["executor"]))
        self.assertIn("CONFIG_EVIDENCE", self.codes(self._validate()))

    def test_rejects_production_evidence_environment(self):
        self.fixture.mutate(self.REL, lambda d: d["evidence"].__setitem__("environment", "production"))
        self.assertIn("CONFIG_EVIDENCE", self.codes(self._validate()))

    def test_rejects_invalid_residency_code(self):
        self.fixture.mutate(self.REL, lambda d: d["project"].__setitem__("data_residency", ["china"]))
        self.assertIn("CONFIG_RESIDENCY", self.codes(self._validate()))

    def test_rejects_missing_section(self):
        def drop(d):
            del d["money"]
        self.fixture.mutate(self.REL, drop)
        self.assertIn("CONFIG_SHAPE", self.codes(self._validate()))

    def test_rejects_malformed_json(self):
        self.fixture.write(self.REL, "{ not json")
        problems = self._validate()
        self.assertIn("CONFIG_UNREADABLE", self.codes(problems))

    def test_rejects_all_providers_disabled(self):
        def disable(d):
            for provider in d["providers"].values():
                provider["enabled"] = False
        self.fixture.mutate(self.REL, disable)
        self.assertIn("CONFIG_PROVIDER", self.codes(self._validate()))
