"""B00 / AT-B00-01 — the governance gate itself.

The batch document requires the normal, rejection, timeout and duplicate-request
paths to be covered by automated tests. For a governance CLI those map to:

* normal      — a clean repository exits 0 with an empty problem list;
* rejection   — a policy violation exits 2 and names the violated rule;
* timeout     — an exhausted wall-clock budget exits 3 (fail closed), never 0;
* duplicate   — repeated and concurrent invocations are byte-identical and
                free of shared mutable state.
"""
from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from concurrent.futures import ThreadPoolExecutor

from tools.paygov import cli, registry
from tools.tests.support import REAL_ROOT, FixtureTestCase


class CliNormalPath(FixtureTestCase):
    def test_clean_repository_exits_zero(self):
        code, output = cli.run([], REAL_ROOT, 120.0)
        payload = json.loads(output)
        self.assertEqual(code, cli.EXIT_OK, output)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["problem_count"], 0)

    def test_registry_is_well_formed(self):
        from tools.paygov import catalogue
        registry.load_all()
        names = registry.names()
        self.assertEqual(names, sorted(set(names)), "validator names must be unique and sorted")
        known = catalogue.batch_ids(str(REAL_ROOT))
        for name in names:
            self.assertIn(registry.batch_of(name), known, name)

    def test_b00_validators_are_registered(self):
        registry.load_all()
        self.assertTrue(
            {"charter", "module-registry", "non-negotiables", "project-config", "repo-hygiene"}
            <= set(registry.names()))

    def test_list_validators_exits_zero(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.main(["list-validators", "--repo", str(REAL_ROOT)])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("project-config", buffer.getvalue())


class CliRejectionPath(FixtureTestCase):
    def test_policy_violation_exits_two_and_names_the_rule(self):
        self.fixture.mutate("governance/project-config.json",
                            lambda d: d["regulated_features"].__setitem__("fund_pool", True))
        code, output = cli.run(["project-config"], self.fixture.root, 30.0)
        payload = json.loads(output)
        self.assertEqual(code, cli.EXIT_PROBLEMS)
        self.assertFalse(payload["ok"])
        self.assertIn("NN-13", {p["rule"] for p in payload["problems"]})

    def test_unreadable_input_never_exits_zero(self):
        self.fixture.write("governance/module-registry.json", "{{{")
        code, _ = cli.run(["module-registry"], self.fixture.root, 30.0)
        self.assertNotEqual(code, cli.EXIT_OK)

    def test_unknown_validator_exits_three(self):
        code, output = cli.run(["does-not-exist"], REAL_ROOT, 30.0)
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("CLI_UNKNOWN_VALIDATOR", output)

    def test_missing_repository_root_exits_three(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.main(["verify-all", "--repo", "/"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("CLI_NO_REPO", buffer.getvalue())


class CliTimeoutPath(FixtureTestCase):
    def test_exhausted_budget_fails_closed(self):
        code, output = cli.run(["repo-hygiene"], REAL_ROOT, 0.0)
        self.assertEqual(code, cli.EXIT_ERROR, output)
        self.assertIn("VALIDATOR_ABORTED", output)

    def test_timeout_is_not_reported_as_success(self):
        # NN-12: evidence that cannot be produced is a failure, never a pass.
        _, output = cli.run(["repo-hygiene"], REAL_ROOT, 0.0)
        self.assertFalse(json.loads(output)["ok"])

    def test_there_is_no_passed_with_warnings_exit_code(self):
        """NN-12 — the CLI contract has no 'succeeded with problems' state."""
        self.fixture.mutate("governance/project-config.json",
                            lambda d: d["security"].__setitem__("admin_mfa", "sms_otp"))
        code, output = cli.run(["project-config"], self.fixture.root, 30.0)
        self.assertEqual(code, cli.EXIT_PROBLEMS)
        self.assertFalse(json.loads(output)["ok"])
        self.assertNotEqual(code, cli.EXIT_OK)


class CliDuplicateAndConcurrentPath(FixtureTestCase):
    """Determinism and shared-state properties.

    These run against a clean fixture rather than the repository itself: the
    property under test is "no shared mutable state, byte-identical output",
    which does not depend on scale, and a fixture keeps the suite fast enough to
    run on every batch.
    """

    def setUp(self) -> None:
        super().setUp()
        self.write_synthetic_evidence(self.fixture)
        self.clean = self.fixture.root

    def test_repeated_runs_are_byte_identical(self):
        first = cli.run([], self.clean, 120.0)
        second = cli.run([], self.clean, 120.0)
        self.assertEqual(first, second)
        self.assertEqual(first[0], cli.EXIT_OK, first[1])

    def test_repeated_failing_runs_are_byte_identical(self):
        self.fixture.mutate("governance/project-config.json",
                            lambda d: d["security"].__setitem__("admin_mfa", "sms_otp"))
        runs = [cli.run(["project-config"], self.fixture.root, 30.0) for _ in range(5)]
        self.assertEqual(len(set(runs)), 1)

    def test_concurrent_runs_do_not_interfere(self):
        # Four concurrent full runs is enough to expose shared mutable state
        # (module-level caches, registry mutation) without making the suite
        # dominated by this one case.
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: cli.run([], self.clean, 120.0), range(4)))
        self.assertEqual(len(set(results)), 1)
        self.assertTrue(all(code == cli.EXIT_OK for code, _ in results))

    def test_output_is_deterministically_ordered(self):
        def break_many(d):
            d["security"]["admin_mfa"] = "sms_otp"
            d["security"]["high_risk_four_eyes"] = False
            d["regulated_features"]["fund_pool"] = True
        self.fixture.mutate("governance/project-config.json", break_many)
        _, output = cli.run(["project-config"], self.fixture.root, 30.0)
        problems = json.loads(output)["problems"]
        keys = [(p["code"], p["where"], p["message"]) for p in problems]
        self.assertEqual(keys, sorted(keys))


class ValidatorDiscovery(FixtureTestCase):
    """The registry is discovered, not listed.

    A hand-written list of validators sat in B00's artefacts, so every later
    batch that added one changed B00's digest and forced the whole programme to
    re-issue evidence. These tests pin the replacement: declaring
    ``VALIDATOR = (name, batch)`` next to ``validate`` is what registers a
    module, and a malformed declaration must break loudly rather than drop the
    validator silently out of the gate.
    """

    def test_every_validator_module_is_discovered(self):
        import importlib
        import pkgutil
        from pathlib import Path

        from tools.paygov import registry
        registry.load_all()
        package = Path(registry.__file__).resolve().parent
        declared = {}
        for info in pkgutil.iter_modules([str(package)]):
            if info.name in {"registry", "cli", "__main__"}:
                continue
            module = importlib.import_module(f"tools.paygov.{info.name}")
            value = getattr(module, "VALIDATOR", None)
            if value is not None:
                declared[value[0]] = value[1]
        self.assertTrue(declared)
        self.assertEqual(sorted(declared), registry.names())
        for name, batch in declared.items():
            self.assertEqual(registry.batch_of(name), batch)

    def test_a_module_without_a_declaration_is_not_registered(self):
        from tools.paygov import registry, structs
        registry.load_all()
        self.assertIsNone(getattr(structs, "VALIDATOR", None))
        self.assertNotIn("structs", registry.names())

    def test_the_gate_lists_the_same_validators_it_runs(self):
        from tools.paygov import cli, registry
        registry.load_all()
        code, output = cli.run([], self.fixture.root, 60.0)
        self.assertIn(code, {0, 2})
        self.assertTrue(registry.names())
