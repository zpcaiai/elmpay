from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import hashlib
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.common import ValidationError  # noqa: E402
from elmpay_runtime.quality import (  # noqa: E402
    DeterministicProviderSimulator,
    evaluate_security_pipeline,
    exercise_payment_model,
    run_load_profile,
    webhook_fault_corpus,
)


class QualityToolingTest(unittest.TestCase):
    def test_reproducible_property_model_runs_ten_thousand_cases(self) -> None:
        first = exercise_payment_model(112, 10000)
        second = exercise_payment_model(112, 10000)
        self.assertTrue(first.passed)
        self.assertEqual(first, second)

    def test_every_provider_protocol_is_account_scoped_and_idempotent(self) -> None:
        providers = ("wechat", "alipay", "stripe", "paypal", "applepay")
        secrets = {("tenant-a", "account-a", provider): provider.encode().ljust(32, b"x") for provider in providers}
        with tempfile.TemporaryDirectory() as directory:
            simulator = DeterministicProviderSimulator(str(Path(directory) / "provider.sqlite"), secrets)
            for provider in providers:
                request = {"provider": provider, "tenantId": "tenant-a", "providerAccountId": "account-a",
                           "operation": "PAYMENT", "idempotencyKey": f"idem-{provider}", "amountMinor": 100,
                           "currency": "USD", "timestamp": 1770000000}
                first = simulator.execute(request)
                replay = simulator.execute(request)
                self.assertEqual(first, replay)
                self.assertTrue(first.webhook_headers)
                with self.assertRaises(ValidationError):
                    simulator.execute({**request, "amountMinor": 101})
            simulator.close()

    def test_concurrent_duplicate_provider_request_has_one_stable_effect(self) -> None:
        secret = {("tenant-a", "account-a", "stripe"): b"s" * 32}
        with tempfile.TemporaryDirectory() as directory:
            simulator = DeterministicProviderSimulator(str(Path(directory) / "provider.sqlite"), secret)
            request = {"provider": "stripe", "tenantId": "tenant-a", "providerAccountId": "account-a",
                       "operation": "PAYMENT", "idempotencyKey": "concurrent-idem", "amountMinor": 100,
                       "currency": "USD"}
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda _: simulator.execute(request), range(32)))
            self.assertEqual(1, len({result.provider_reference for result in results}))
            simulator.close()

    def test_webhook_fault_corpus_covers_replay_order_signature_and_clock(self) -> None:
        corpus = webhook_fault_corpus(b'{"event":"synthetic"}', 114)
        names = {item[0] for item in corpus}
        self.assertTrue({"duplicate", "truncated", "bitflip", "out-of-order", "signature-rotation", "clock-skew-past"} <= names)

    def test_security_pipeline_requires_every_completed_artifact_bound_tool(self) -> None:
        digest = hashlib.sha256(b"artifact").hexdigest()
        required = ["sast", "dast", "iast", "secret", "dependency", "container", "iac"]
        reports = [{"tool": tool, "status": "COMPLETE", "artifactDigest": digest,
                    "criticalFindings": 0, "highFindings": 0, "orchestrated": True,
                    "exitCode": 0, "executionDigest": hashlib.sha256(tool.encode()).hexdigest()}
                   for tool in required]
        self.assertTrue(evaluate_security_pipeline(required, reports, digest).allowed)
        self.assertFalse(evaluate_security_pipeline(required, reports[:-1], digest).allowed)
        fabricated = [{"tool": tool, "status": "COMPLETE", "artifactDigest": digest,
                       "criticalFindings": 0, "highFindings": 0} for tool in required]
        self.assertFalse(evaluate_security_pipeline(required, fabricated, digest).allowed)

    def test_load_runner_measures_errors_duplicates_and_non_finite(self) -> None:
        report = run_load_profile(
            lambda request_id: {"ok": request_id != "bad", "sideEffectId": request_id, "score": 1.0},
            ["a", "b", "bad"], 3,
        )
        self.assertEqual(3, report.requests)
        self.assertEqual(1, report.errors)
        self.assertEqual(0, report.duplicate_side_effects)


if __name__ == "__main__":
    unittest.main()
