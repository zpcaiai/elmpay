"""Negative controls for the additive RR-02 scan gate, not scanner substitutes."""
import copy
import importlib.util
from pathlib import Path
import unittest
import json
import tempfile
from tools.paygov import cigen


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("rr02_security", ROOT / "scripts/rr02-security.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SarifControls(unittest.TestCase):
    def test_real_pipeline_requires_every_source_security_language_and_findings_gate(self):
        doc = json.loads((ROOT / 'governance/ci-pipeline.json').read_text())
        self.assertEqual(doc['source_security'], {
            'languages': ['java-kotlin', 'javascript-typescript', 'python'],
            'queries': 'security-extended', 'fail_on_any_result': True})
        static = next(s for s in doc['stages'] if s['id'] == 'static-analysis')
        self.assertTrue(static['required'])
        self.assertTrue(static['fail_closed'])
        self.assertIn('static-analysis', doc['required_stages'])

    def setUp(self):
        self.document = {"version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "CodeQL", "version": "2.27.3",
                                "rules": [{"id": "java/command-line-injection"}]}},
            "invocations": [{"executionSuccessful": True}], "results": [],
        }]}

    def test_actual_complete_zero_findings_report_is_accepted(self):
        self.assertEqual(MODULE.check_sarif(self.document)["findings"], 0)

    def test_codeql_query_pack_extensions_have_real_rules(self):
        tool = self.document["runs"][0]["tool"]
        rules = tool["driver"].pop("rules")
        tool["extensions"] = [{"name": "codeql/java-queries", "rules": rules}]
        self.assertEqual(MODULE.check_sarif(self.document)["rules"], 1)
        tool["extensions"][0]["rules"] = []
        with self.assertRaises(ValueError):
            MODULE.check_sarif(self.document)

    def test_empty_missing_or_failed_execution_is_rejected(self):
        mutations = [
            lambda d: d.update(runs=[]),
            lambda d: d["runs"][0].pop("results"),
            lambda d: d["runs"][0]["tool"]["driver"].update(rules=[]),
            lambda d: d["runs"][0].update(invocations=[{"executionSuccessful": False}]),
            lambda d: d["runs"][0].update(invocations=[]),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                doc = copy.deepcopy(self.document)
                mutate(doc)
                with self.assertRaises(ValueError):
                    MODULE.check_sarif(doc)

    def test_findings_cannot_be_suppressed_or_downgraded_to_pass(self):
        for level in ("error", "warning", "note", "none"):
            doc = copy.deepcopy(self.document)
            doc["runs"][0]["results"] = [{"ruleId": "java/command-line-injection",
                "level": level, "suppressions": [{"status": "accepted"}]}]
            with self.subTest(level=level), self.assertRaises(ValueError):
                MODULE.check_sarif(doc)

    def test_invocation_error_even_with_success_flag_is_rejected(self):
        self.document["runs"][0]["invocations"][0]["toolExecutionNotifications"] = [
            {"level": "error", "message": {"text": "extractor failed"}}]
        with self.assertRaises(ValueError):
            MODULE.check_sarif(self.document)

    def test_dynamic_scan_refuses_external_target(self):
        for origin in ("https://elmpay.vercel.app", "http://localhost:10000",
                       "http://127.0.0.1:10000/path", "http://user@127.0.0.1:10000"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                MODULE.local_origin(origin)
        self.assertEqual(MODULE.local_origin("http://127.0.0.1:10000"),
                         "http://127.0.0.1:10000")

    def test_native_junit_denominator_rejects_missing_zero_and_skipped_tests(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'governance').mkdir()
            (root / 'governance/version-catalog.json').write_text(json.dumps({
                'modules_by_build_system': {'gradle': ['money']}}))
            (root / 'governance/module-registry.json').write_text(json.dumps({
                'modules': [{'name': 'money', 'path': 'libs/money'}]}))
            with self.assertRaises(ValueError):
                MODULE.check_junit(root)
            directory = root / 'libs/money/build/test-results/test'
            directory.mkdir(parents=True)
            for tests, failed, skipped in [(0, 0, 0), (1, 1, 0), (1, 0, 1)]:
                (directory / 'TEST-Money.xml').write_text(
                    f'<testsuite tests="{tests}" errors="0" failures="{failed}" skipped="{skipped}"/>')
                with self.assertRaises(ValueError):
                    MODULE.check_junit(root)
            (directory / 'TEST-Money.xml').write_text(
                '<testsuite tests="2" errors="0" failures="0" skipped="0"/>')
            self.assertEqual(MODULE.check_junit(root)['money']['tests'], 2)

    def test_generated_static_stage_retains_original_checks_and_adds_real_scanners(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'governance').mkdir()
            for name in ('ci-pipeline.json', 'version-catalog.json', 'module-registry.json'):
                (root / 'governance' / name).write_bytes((ROOT / 'governance' / name).read_bytes())
            pipeline = json.loads((root / 'governance/ci-pipeline.json').read_text())
            pipeline['source_security'] = {
                'languages': ['java-kotlin', 'javascript-typescript', 'python'],
                'queries': 'security-extended', 'fail_on_any_result': True,
            }
            for name in ('init', 'analyze'):
                pipeline['actions'].append({'name': 'github/codeql-action/' + name,
                    'ref': '9b3254085494b55a0f7c4c2b3d2d52cc712ce370',
                    'version_comment': 'v4.39.1'})
            (root / 'governance/ci-pipeline.json').write_text(json.dumps(pipeline))
            text = cigen.workflow(root)
            static = text.split('\n  static-analysis:\n', 1)[1].split('\n  secret-scan:\n', 1)[0]
            for expected in ('github/codeql-action/init@', 'github/codeql-action/analyze@',
                    'queries: security-extended', 'scripts/rr02-security.py sarif',
                    'scripts/rr02-security.py dast', 'apps/free-demo/src/start.mjs',
                    './gradlew --no-daemon check -x test', 'verify module-registry'):
                self.assertIn(expected, static)
            self.assertIn('upload: never', static)
            self.assertIn('name: source-security-artifacts', static)
            self.assertIn('name: static-analysis-artifacts', static)
            self.assertNotIn('continue-on-error', static)
            pipeline['source_security']['fail_on_any_result'] = False
            (root / 'governance/ci-pipeline.json').write_text(json.dumps(pipeline))
            with self.assertRaises(ValueError):
                cigen.workflow(root)
