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

    def test_every_registered_validator_runs(self):
        registry.load_all()
        self.assertEqual(
            registry.names(),
            ["charter", "module-registry", "non-negotiables", "project-config", "repo-hygiene"],
        )

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
        _, output = cli.run(["repo-hygiene"], REAL_ROOT, 0.0)
        self.assertFalse(json.loads(output)["ok"])


class CliDuplicateAndConcurrentPath(FixtureTestCase):
    def test_repeated_runs_are_byte_identical(self):
        first = cli.run([], REAL_ROOT, 120.0)
        second = cli.run([], REAL_ROOT, 120.0)
        self.assertEqual(first, second)

    def test_repeated_failing_runs_are_byte_identical(self):
        self.fixture.mutate("governance/project-config.json",
                            lambda d: d["security"].__setitem__("admin_mfa", "sms_otp"))
        runs = [cli.run(["project-config"], self.fixture.root, 30.0) for _ in range(5)]
        self.assertEqual(len(set(runs)), 1)

    def test_concurrent_runs_do_not_interfere(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: cli.run([], REAL_ROOT, 120.0), range(8)))
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
