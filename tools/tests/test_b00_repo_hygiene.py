"""B00 / AT-B00-01 — repository hygiene.

Proves that credential material (NN-07) and floating-point money (NN-05) are
detected in first-party source, and that the governance toolchain itself stays
dependency free so it can run on an offline evidence agent.
"""
from __future__ import annotations

from tools.paygov import hygiene
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class HygieneHappyPath(FixtureTestCase):
    def test_real_repository_is_clean(self):
        problems = hygiene.validate(REAL_ROOT, Budget(seconds=120).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_kms_and_vault_references_are_not_flagged(self):
        self.fixture.write("services/payment-core/app.conf",
                           "wechat.credentials = kms://elmpay/wechat/merchant/main\n")
        self.assertEqual(hygiene.validate(self.fixture.root, Budget().start()), [])


class HygieneDetects(FixtureTestCase):
    def _validate(self):
        return hygiene.validate(self.fixture.root, Budget().start())

    def test_detects_private_key_block(self):
        self.fixture.write("connectors/alipay/app_private_key.pem",
                           "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----\n")
        self.assertIn("SECRET_PRIVATE_KEY", self.codes(self._validate()))

    def test_detects_live_psp_key(self):
        self.fixture.write("services/payment-core/settings.properties",
                           "stripe.token=sk_live_51QQQQQQQQQQQQQQQQQQQ\n")
        self.assertIn("SECRET_STRIPE_LIVE", self.codes(self._validate()))

    def test_detects_aws_access_key(self):
        self.fixture.write("platform/terraform/main.tf", 'access_key = "AKIA1234567890ABCDEF"\n')
        codes = self.codes(self._validate())
        self.assertIn("SECRET_AWS_KEY", codes)

    def test_detects_generic_secret_assignment(self):
        self.fixture.write("services/webhook-ingress/config.yaml",
                           "app_secret: 8f2c19aa41bd4e7d9c0aa17b3e5f6d21\n")
        self.assertIn("SECRET_GENERIC_ASSIGN", self.codes(self._validate()))

    def test_detects_float_money_field(self):
        self.fixture.write("services/ledger-service/Entry.java",
                           "public class Entry { private double amountMinor; }\n")
        problems = self._validate()
        self.assertIn("MONEY_FLOAT_TYPE", self.codes(problems))
        self.assertIn("NN-05", self.rules(problems))

    def test_detects_float_money_literal(self):
        self.fixture.write("services/payment-core/fixture.json", '{ "refund_amount": 12.34 }\n')
        self.assertIn("MONEY_FLOAT_LITERAL", self.codes(self._validate()))

    def test_float_outside_money_paths_is_not_flagged(self):
        self.fixture.write("docs/notes.md", "latency total = 12.34 ms\n")
        self.assertEqual(self._validate(), [])

    def test_detects_third_party_import_in_toolchain(self):
        self.fixture.write("tools/paygov/bad.py", "import requests\n")
        problems = self._validate()
        self.assertIn("TOOLCHAIN_THIRD_PARTY", self.codes(problems))


class HygieneScanIsBounded(FixtureTestCase):
    def test_budget_is_enforced(self):
        from tools.paygov.errors import BudgetExceeded
        budget = Budget(seconds=0.0).start()
        with self.assertRaises(BudgetExceeded):
            hygiene.validate(REAL_ROOT, budget)
