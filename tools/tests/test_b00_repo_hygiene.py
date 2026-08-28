"""B00 / AT-B00-01 — repository hygiene.

Proves that credential material (NN-07) and floating-point money (NN-05) are
detected in first-party source, and that the governance toolchain itself stays
dependency free so it can run on an offline evidence agent.
"""
from __future__ import annotations

from pathlib import Path

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

    def test_no_card_number_shaped_value_is_committed(self):
        """NN-02 — the repository must never contain raw card data."""
        import re
        from tools.paygov.repo import iter_repo_files
        pan = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")

        def luhn(digits: str) -> bool:
            total, parity = 0, len(digits) % 2
            for index, char in enumerate(digits):
                value = int(char)
                if index % 2 == parity:
                    value = value * 2 - 9 if value * 2 > 9 else value * 2
                total += value
            return total % 10 == 0

        offenders = []
        budget = Budget(seconds=120).start()
        for path in iter_repo_files(REAL_ROOT, budget, suffixes=(".json", ".md", ".yaml", ".yml",
                                                                 ".txt", ".properties", ".conf")):
            rel = path.relative_to(REAL_ROOT).as_posix()
            if rel.startswith("evidence/") or "test_" in rel:
                continue
            for candidate in pan.findall(path.read_text(encoding="utf-8", errors="replace")):
                digits = re.sub(r"\D", "", candidate)
                if 13 <= len(digits) <= 19 and luhn(digits):
                    offenders.append(f"{rel}: {candidate}")
        self.assertEqual(offenders, [])

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

    def test_accepts_zipfile_from_the_standard_library(self):
        self.fixture.write("tools/paygov/archive_check.py", "import zipfile\n")
        self.assertNotIn("TOOLCHAIN_THIRD_PARTY", self.codes(self._validate()))

    def test_accepts_sqlite3_for_durable_offline_controls(self):
        self.fixture.write("tools/runtime/durable_control.py", "import calendar\nimport sqlite3\n")
        self.assertNotIn("TOOLCHAIN_THIRD_PARTY", self.codes(self._validate()))


class HygieneScanIsBounded(FixtureTestCase):
    def test_budget_is_enforced(self):
        from tools.paygov.errors import BudgetExceeded
        budget = Budget(seconds=0.0).start()
        with self.assertRaises(BudgetExceeded):
            hygiene.validate(REAL_ROOT, budget)


class ScanMemoIsContentKeyed(FixtureTestCase):
    """The gate memoises per-file scans; the memo must never mask a change.

    Running the whole gate 180+ times (the negative-control harness) spent most
    of its time re-scanning files that were byte-identical between scenarios.
    The memo is keyed on the SHA-256 of the file's text rather than its
    timestamp, so the only way to get a cached answer is to present the same
    bytes. These tests exist because a caching bug in a fail-closed gate does
    not look like a bug — it looks like a pass.
    """

    def test_the_same_path_with_new_content_is_rescanned(self):
        rel = "docs/charter/PROGRAM_CHARTER.md"
        first = self.codes(hygiene.validate(self.fixture.root, Budget(seconds=60).start()))
        path = self.fixture.root / rel
        path.write_text(path.read_text(encoding="utf-8")
                        + '\nAWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
        second = self.codes(hygiene.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertNotEqual(first, second)
        self.assertTrue(second - first)

    def test_a_new_forbidden_import_is_not_masked_by_the_memo(self):
        target = self.fixture.root / "libs/kms/reference/envelope.py"
        hygiene.validate(self.fixture.root, Budget(seconds=60).start())
        target.write_text("import requests\n" + target.read_text(encoding="utf-8"),
                          encoding="utf-8")
        codes = self.codes(hygiene.validate(self.fixture.root, Budget(seconds=60).start()))
        self.assertIn("TOOLCHAIN_THIRD_PARTY", codes)

    def test_identical_content_at_a_different_path_is_judged_separately(self):
        source = self.fixture.root / "libs/kms/reference/envelope.py"
        text = "import requests\n" + source.read_text(encoding="utf-8")
        source.write_text(text, encoding="utf-8")
        twin = self.fixture.root / "libs/kms/reference/envelope_twin.py"
        twin.write_text(text, encoding="utf-8")
        problems = hygiene.validate(self.fixture.root, Budget(seconds=60).start())
        wheres = {p.where.split(":")[0] for p in problems if p.code == "TOOLCHAIN_THIRD_PARTY"}
        self.assertEqual(wheres, {"libs/kms/reference/envelope.py",
                                  "libs/kms/reference/envelope_twin.py"})


class SharedFixtureIsolation(FixtureTestCase):
    """The shared fixture must be indistinguishable from a private one.

    From B33 one fixture serves a whole process and is restored between tests,
    because rebuilding it per test was 78% of the suite's wall clock and the
    suite had reached the ceiling on a single execution step. That trade is only
    safe if restoration is total: a leak here would not fail loudly, it would
    quietly make some other test pass for the wrong reason — the exact failure
    mode this programme exists to prevent. These tests are the guard.
    """

    REL = "governance/project-config.json"

    def test_restore_undoes_a_tracked_write(self):
        original = (self.fixture.root / self.REL).read_text(encoding="utf-8")
        self.fixture.write(self.REL, "{ broken")
        self.fixture.restore()
        self.assertEqual((self.fixture.root / self.REL).read_text(encoding="utf-8"),
                         original)

    def test_restore_undoes_a_deletion(self):
        original = (self.fixture.root / self.REL).read_bytes()
        self.fixture.remove(self.REL)
        self.assertFalse((self.fixture.root / self.REL).exists())
        self.fixture.restore()
        self.assertEqual((self.fixture.root / self.REL).read_bytes(), original)

    def test_restore_undoes_an_untracked_write_through_the_path(self):
        # The dangerous case: a test that never touches the fixture API.
        path = self.fixture.root / self.REL
        original = path.read_bytes()
        path.write_text("{ broken", encoding="utf-8")
        self.fixture.restore()
        self.assertEqual(path.read_bytes(), original)

    def test_restore_removes_a_file_the_test_invented(self):
        path = self.fixture.root / "governance" / "invented.json"
        path.write_text("{}", encoding="utf-8")
        self.fixture.restore()
        self.assertFalse(path.exists())

    def test_restore_undoes_a_rename(self):
        path = self.fixture.root / self.REL
        moved = self.fixture.root / "governance" / "renamed.json"
        original = path.read_bytes()
        path.rename(moved)
        self.fixture.restore()
        self.assertFalse(moved.exists())
        self.assertEqual(path.read_bytes(), original)

    def test_a_fresh_fixture_can_still_be_demanded(self):
        other = self.new_fixture()
        self.assertNotEqual(other.root, self.fixture.root)

    def test_the_runner_covers_every_discovered_module(self):
        """A faster runner that skipped a module would shrink the evidence."""
        import importlib.util
        import unittest as _unittest

        spec = importlib.util.spec_from_file_location(
            "test_summary_runner", REAL_ROOT / "scripts" / "test-summary.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        discovered = set()

        def walk(item):
            if isinstance(item, _unittest.TestSuite):
                for child in item:
                    walk(child)
            else:
                discovered.add(type(item).__module__)

        walk(_unittest.TestLoader().discover(start_dir=str(REAL_ROOT / "tools" / "tests"),
                                             top_level_dir=str(REAL_ROOT)))
        self.assertEqual(set(module.discovered_modules()), discovered)


def _negative_controls():
    """Import scripts/negative-controls.py once.

    It is a script, not a package module, and importing it materialises a
    ~1700-file snapshot; the cache keeps that cost at one per test process.
    """
    global _NC
    try:
        return _NC
    except NameError:
        pass
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "negative_controls", REAL_ROOT / "scripts" / "negative-controls.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _NC = module
    return _NC


class NegativeControlSharding(FixtureTestCase):
    """``--shard I/N`` must partition the scenario set, not sample it.

    The proof is only allowed to be split across invocations because the
    slices are disjoint and exhaustive. If a scenario could fall into no shard
    — or into two — the recorded evidence would claim coverage the run never
    had, and B06's EVIDENCE_SHARD_INCOMPLETE check would be guarding an
    already-broken partition.
    """

    def test_slices_are_disjoint_and_exhaustive(self):
        nc = _negative_controls()
        for total in (0, 1, 7, 480):
            for count in (1, 2, 3, 5):
                seen = []
                for index in range(1, count + 1):
                    seen += nc._slice(total, 0, index, count)
                self.assertEqual(sorted(seen), list(range(total)),
                                 f"total={total} count={count}")
                self.assertEqual(len(seen), len(set(seen)),
                                 f"total={total} count={count}: a scenario ran twice")

    def test_negative_fixture_carries_real_module_boundary_content(self):
        nc = _negative_controls()
        for module_path in nc._MODULE_PATHS:
            prefix = f"{module_path.rstrip('/')}/"
            self.assertTrue(any(rel.startswith(prefix) and blob
                                for rel, blob in nc._SNAPSHOT.items()), module_path)

    def test_negative_fixture_carries_every_generated_ci_target(self):
        from tools.paygov import cigen

        nc = _negative_controls()
        for relative in cigen.TARGETS:
            self.assertIn(relative, nc._SNAPSHOT)
            self.assertTrue(nc._SNAPSHOT[relative], relative)

    def test_offset_keeps_the_second_list_from_piling_onto_one_shard(self):
        nc = _negative_controls()
        # Both scenario lists are sliced with the same partition; the offset is
        # what stops shard 1 from taking the first element of each list. It is
        # a rotation by offset % count, so it only does nothing when the first
        # list happens to be a whole number of partitions long.
        self.assertEqual(nc._slice(9, 0, 1, 3), [0, 3, 6])
        self.assertEqual(nc._slice(9, 1, 1, 3), [2, 5, 8])
        self.assertEqual(nc._slice(9, 9, 1, 3), [0, 3, 6])
        # Whatever the offset, the partition stays exhaustive.
        for offset in (0, 1, 2, 452):
            seen = sum((nc._slice(9, offset, i, 3) for i in (1, 2, 3)), [])
            self.assertEqual(sorted(seen), list(range(9)), offset)

    def test_real_scenario_set_splits_evenly_enough_to_fit_the_window(self):
        nc = _negative_controls()
        total = len(nc.SCENARIOS) + len(nc.TEXT_SCENARIOS)
        sizes = [len(nc._slice(len(nc.SCENARIOS), 0, i, 3))
                 + len(nc._slice(len(nc.TEXT_SCENARIOS), len(nc.SCENARIOS), i, 3))
                 for i in (1, 2, 3)]
        self.assertEqual(sum(sizes), total)
        self.assertLessEqual(max(sizes) - min(sizes), 1, sizes)

    def test_absent_shard_argument_runs_everything(self):
        nc = _negative_controls()
        self.assertEqual(nc._parse_shard([]), (1, 1))
        self.assertEqual(nc._parse_shard(["--shard", "2/3"]), (2, 3))

    def test_help_prints_usage_and_exits_successfully(self):
        import contextlib
        import io

        nc = _negative_controls()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as stopped:
            nc._parse_shard(["--help"])
        self.assertEqual(stopped.exception.code, 0)
        self.assertIn("usage:", stdout.getvalue())
        self.assertIn("--shard", stdout.getvalue())

    def test_unknown_arguments_are_refused_by_the_cli_parser(self):
        import contextlib
        import io

        nc = _negative_controls()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as stopped:
            nc._parse_shard(["--unknown"])
        self.assertEqual(stopped.exception.code, 2)
        self.assertIn("unrecognized arguments: --unknown", stderr.getvalue())

    def test_shard_option_requires_a_value(self):
        import contextlib
        import io

        nc = _negative_controls()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as stopped:
            nc._parse_shard(["--shard"])
        self.assertEqual(stopped.exception.code, 2)
        self.assertIn("expected one argument", stderr.getvalue())

    def test_nonsensical_shard_arguments_are_refused(self):
        import contextlib
        import io

        nc = _negative_controls()
        for raw in ("0/3", "4/3", "1/0", "-1/2", "garbage", "1", "1/2/3", "/2", "1/"):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit, msg=raw) as stopped:
                    nc._parse_shard(["--shard", raw])
            self.assertEqual(stopped.exception.code, 2, raw)

    def test_programmatic_main_still_accepts_an_explicit_argv(self):
        from unittest import mock

        nc = _negative_controls()
        stopped = RuntimeError("stop after parsing")
        with mock.patch.object(nc, "_parse_shard", side_effect=stopped) as parse:
            with self.assertRaisesRegex(RuntimeError, "stop after parsing"):
                nc.main(("--shard", "2/3"))
        parse.assert_called_once_with(["--shard", "2/3"])


def _test_summary():
    """Import scripts/test-summary.py once per process."""
    global _TS
    try:
        return _TS
    except NameError:
        pass
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "test_summary_runner", REAL_ROOT / "scripts" / "test-summary.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _TS = module
    return _TS


class TestSummarySharding(FixtureTestCase):
    """The suite may be split across invocations only if nothing falls out.

    Sharding the regression run is what keeps a batch's own evidence inside the
    environment's per-step ceiling. It is also the easiest place to lose tests
    without noticing, so the merge — not the shards — is the control: it
    recomputes the expected unit list and refuses anything that is not an exact
    partition.
    """

    def test_units_cover_every_test_unittest_discovery_finds(self):
        import unittest as _unittest
        ts = _test_summary()
        loader = _unittest.TestLoader()

        def ids(suite, out):
            for item in suite:
                if isinstance(item, _unittest.TestSuite):
                    ids(item, out)
                else:
                    out.add(item.id())
            return out

        discovered = ids(loader.discover(start_dir=str(REAL_ROOT / "tools" / "tests"),
                                         top_level_dir=str(REAL_ROOT)), set())
        from_units = set()
        for unit in ts.discovered_units():
            ids(loader.loadTestsFromName(unit), from_units)

        # A module that fails to import is represented on both sides by
        # unittest's placeholder case, but the two entry points label it
        # differently — discovery names it after the dotted module path,
        # loadTestsFromName after the bare module. Compare real test ids
        # exactly, and placeholders by the module they stand for. This is not a
        # weakening: a module that vanished from one side would still leave the
        # broken-module sets unequal.
        def split(names):
            placeholder = "unittest.loader._FailedTest."
            real = {n for n in names if not n.startswith(placeholder)}
            broken = {n[len(placeholder):].rsplit(".", 1)[-1] for n in names - real}
            return real, broken

        real_units, broken_units = split(from_units)
        real_discovered, broken_discovered = split(discovered)
        self.assertEqual(real_units, real_discovered)
        self.assertEqual(broken_units, broken_discovered)

    def test_shards_partition_the_unit_list(self):
        ts = _test_summary()
        units = ts.discovered_units()
        for count in (1, 2, 3, 5):
            seen = []
            for index in range(1, count + 1):
                seen += ts._slice(units, index, count)
            self.assertEqual(sorted(seen), sorted(units), count)
            self.assertEqual(len(seen), len(set(seen)), count)

    def test_nonsensical_shard_arguments_are_refused(self):
        ts = _test_summary()
        self.assertEqual(ts._parse_shard(None), (1, 1))
        self.assertEqual(ts._parse_shard("2/5"), (2, 5))
        for raw in ("0/3", "4/3", "1/0"):
            with self.assertRaises(SystemExit, msg=raw):
                ts._parse_shard(raw)

    def _partial(self, units: list[str], run: int, shard: str) -> str:
        import json as _json
        name = f"summary-{shard.replace('/', 'of')}-{len(units)}-{run}.json"
        total = int(shard.split("/")[1])
        self.fixture.write(name, _json.dumps({
            "units": units, "shard": shard, "shards": total,
            "run": run, "passed": run, "failed": 0, "skipped": 0,
            "skipped_critical": 0, "failures": [], "errors": []}))
        return str(self.fixture.root / name)

    def _mutate_partial(self, path: str, fn) -> str:
        import json as _json
        target = Path(path)
        data = _json.loads(target.read_text(encoding="utf-8"))
        fn(data)
        target.write_text(_json.dumps(data), encoding="utf-8")
        return path

    def _merge(self, paths: list[str]) -> int:
        ts = _test_summary()
        return ts._merge(paths, self.fixture.root / "merged.json", None)

    def test_merge_accepts_a_complete_partition(self):
        ts = _test_summary()
        units = ts.discovered_units()
        half = len(units) // 2
        self.assertEqual(self._merge([self._partial(ts._slice(units, 1, 2), 3, "1/2"),
                                      self._partial(ts._slice(units, 2, 2), 4, "2/2")]), 0)
        merged = __import__("json").loads(
            (self.fixture.root / "merged.json").read_text(encoding="utf-8"))
        self.assertEqual(merged["shards"], 2)

    def test_merge_refuses_a_missing_shard(self):
        ts = _test_summary()
        units = ts.discovered_units()
        self.assertEqual(self._merge([
            self._partial(ts._slice(units, 1, 2), 3, "1/2")]), 1)

    def test_merge_refuses_a_shard_counted_twice(self):
        ts = _test_summary()
        units = ts.discovered_units()
        first = self._partial(ts._slice(units, 1, 2), 3, "1/2")
        duplicate = self._partial(ts._slice(units, 2, 2), 4, "2/2")
        self._mutate_partial(duplicate, lambda data: data.__setitem__("shard", "1/2"))
        self.assertEqual(self._merge([first, duplicate]), 1)

    def test_merge_refuses_mixed_denominators(self):
        ts = _test_summary()
        units = ts.discovered_units()
        self.assertEqual(self._merge([
            self._partial(ts._slice(units, 1, 2), 3, "1/2"),
            self._partial(ts._slice(units, 2, 3), 4, "2/3")]), 1)

    def test_merge_refuses_units_that_do_not_match_the_shard_metadata(self):
        ts = _test_summary()
        units = ts.discovered_units()
        first = self._partial(ts._slice(units, 2, 2), 3, "1/2")
        second = self._partial(ts._slice(units, 1, 2), 4, "2/2")
        self.assertEqual(self._merge([first, second]), 1)

    def test_merge_refuses_an_unknown_extra_unit(self):
        ts = _test_summary()
        units = ts.discovered_units()
        first = self._partial(ts._slice(units, 1, 2) + ["tools.tests.unknown.Forged"],
                              3, "1/2")
        second = self._partial(ts._slice(units, 2, 2), 4, "2/2")
        self.assertEqual(self._merge([first, second]), 1)

    def test_merge_requires_each_part_to_declare_shards_n(self):
        ts = _test_summary()
        units = ts.discovered_units()
        first = self._partial(ts._slice(units, 1, 2), 3, "1/2")
        second = self._partial(ts._slice(units, 2, 2), 4, "2/2")
        self._mutate_partial(first, lambda data: data.pop("shards"))
        self.assertEqual(self._merge([first, second]), 1)
