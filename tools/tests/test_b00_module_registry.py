"""B00 / AT-B00-01 — module boundary rules.

These are the checks that keep the "monolith first, splittable later" promise
in the charter honest, and that keep business-order data out of the platform
(NN-01) and tenants apart (NN-09).
"""
from __future__ import annotations

from tools.paygov import modules
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class ModuleRegistryHappyPath(FixtureTestCase):
    def test_real_registry_passes(self):
        self.assertEqual(modules.validate(REAL_ROOT, Budget().start()), [])

    def test_every_declared_module_directory_has_portable_content(self):
        registry = self.fixture.read("governance/module-registry.json")
        for module in registry["modules"]:
            path = REAL_ROOT / module["path"]
            self.assertTrue(path.is_dir(), module["path"])
            self.assertTrue(any(item.is_file() and item.stat().st_size > 0
                                for item in path.rglob("*")), module["path"])

    def test_table_ownership_is_exclusive(self):
        registry = self.fixture.read("governance/module-registry.json")
        seen: dict[str, str] = {}
        for module in registry["modules"]:
            for table in module["owned_tables"]:
                self.assertNotIn(table, seen, f"{table} owned twice")
                seen[table] = module["name"]
        self.assertIn("ledger_entry", seen)
        self.assertEqual(seen["ledger_entry"], "ledger-service")

    def test_connectors_own_no_tables(self):
        registry = self.fixture.read("governance/module-registry.json")
        for module in registry["modules"]:
            if module["layer"] == "connector":
                self.assertEqual(module["owned_tables"], [], module["name"])


class ModuleRegistryRejects(FixtureTestCase):
    REL = "governance/module-registry.json"

    def _validate(self):
        return modules.validate(self.fixture.root, Budget().start())

    def _module(self, data, name):
        return next(m for m in data["modules"] if m["name"] == name)

    def test_rejects_connector_depending_on_a_service(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._module(d, "stripe")["depends_on"].append("payment-core"))
        problems = self._validate()
        self.assertIn("MODULE_DEP_LAYER", self.codes(problems))
        self.assertIn("NN-01", self.rules(problems))

    def test_rejects_service_depending_on_an_app(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._module(d, "payment-core")["depends_on"].append("admin-web"))
        self.assertIn("MODULE_DEP_LAYER", self.codes(self._validate()))

    def test_rejects_library_depending_on_a_service(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._module(d, "money")["depends_on"].append("ledger-service"))
        self.assertIn("MODULE_DEP_LAYER", self.codes(self._validate()))

    def test_rejects_dependency_cycle(self):
        def cycle(d):
            self._module(d, "merchant-config")["depends_on"].append("payment-core")
        self.fixture.mutate(self.REL, cycle)
        problems = self._validate()
        self.assertIn("MODULE_DEP_CYCLE", self.codes(problems))

    def test_rejects_self_dependency(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._module(d, "risk-engine")["depends_on"].append("risk-engine"))
        self.assertIn("MODULE_DEP_SELF", self.codes(self._validate()))

    def test_rejects_unknown_dependency(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._module(d, "payment-core")["depends_on"].append("ghost-service"))
        self.assertIn("MODULE_DEP_UNKNOWN", self.codes(self._validate()))

    def test_rejects_business_order_table_ownership(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._module(d, "payment-core")["owned_tables"].append("business_order"))
        problems = self._validate()
        self.assertIn("MODULE_BUSINESS_TABLE", self.codes(problems))
        self.assertIn("NN-01", self.rules(problems))

    def test_rejects_shared_table_ownership(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._module(d, "risk-engine")["owned_tables"].append("payment_intent"))
        self.assertIn("MODULE_TABLE_CONFLICT", self.codes(self._validate()))

    def test_rejects_connector_owning_tables(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._module(d, "alipay")["owned_tables"].append("alipay_cache"))
        self.assertIn("MODULE_CONNECTOR_DB", self.codes(self._validate()))

    def test_rejects_module_without_owner(self):
        self.fixture.mutate(self.REL, lambda d: self._module(d, "money").__setitem__("owner", "  "))
        self.assertIn("MODULE_OWNER", self.codes(self._validate()))

    def test_rejects_module_without_threats(self):
        self.fixture.mutate(self.REL, lambda d: self._module(d, "money").__setitem__("threats", []))
        self.assertIn("MODULE_THREATS", self.codes(self._validate()))

    def test_rejects_module_with_missing_directory(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._module(d, "money").__setitem__("path", "libs/does-not-exist"))
        self.assertIn("MODULE_PATH", self.codes(self._validate()))

    def test_rejects_module_directory_that_would_disappear_from_a_git_checkout(self):
        empty = self.fixture.root / "libs/empty-boundary"
        empty.mkdir(parents=True)
        self.fixture.mutate(
            self.REL,
            lambda d: self._module(d, "money").__setitem__("path", "libs/empty-boundary"),
        )
        self.assertIn("MODULE_PATH", self.codes(self._validate()))

    def test_rejects_duplicate_module_name(self):
        def duplicate(d):
            clone = dict(self._module(d, "money"))
            d["modules"].append(clone)
        self.fixture.mutate(self.REL, duplicate)
        self.assertIn("MODULE_DUPLICATE", self.codes(self._validate()))
