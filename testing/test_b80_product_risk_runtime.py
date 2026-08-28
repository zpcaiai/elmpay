from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.common import ValidationError  # noqa: E402
from elmpay_runtime.risk_control import ModelResult, SQLiteRiskControl  # noqa: E402
from elmpay_runtime.risk_runtime import (  # noqa: E402
    HmacRequestAuthenticator,
    LocalSandboxRiskSignalProvider,
    RiskRuntimeService,
    encode_evaluation,
)


NOW = datetime(2026, 8, 28, tzinfo=timezone.utc)


class FixedModel:
    def score(self, request, timeout_milliseconds):
        del request, timeout_milliseconds
        return ModelResult(True, "model-1", "a" * 64, Decimal("0.10"), "MODEL_LOW_RISK")


class ProductRiskRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        policy = json.loads((ROOT / "platform/risk/runtime-policy.json").read_text())
        self.control = SQLiteRiskControl(str(Path(self.directory.name) / "risk.sqlite"), policy)
        rules = [{"id": "velocity", "priority": 100, "signal": "velocity5m",
                  "operator": "GT", "threshold": "5", "action": "BLOCK",
                  "reasonCode": "VELOCITY_LIMIT"}]
        self.control.propose_rule_set("tenant-a", "rules-1", rules, "analyst-a", NOW, NOW)
        self.control.approve_rule_set("tenant-a", "rules-1", "reviewer-b", NOW)

    def tearDown(self) -> None:
        self.control.close()
        self.directory.cleanup()

    def test_product_service_persists_decision_and_outbox(self) -> None:
        service = RiskRuntimeService(self.control, LocalSandboxRiskSignalProvider(),
                                     FixedModel(), lambda: NOW)
        request = {"tenantId": "tenant-a", "requestId": "PAYMENT_CREATE:key-1",
                   "operation": "PAYMENT_CREATE", "subjectId": "merchant-1",
                   "amountMinor": 100, "currency": "USD", "occurredAt": NOW.isoformat(),
                   "attributes": {"channel": "api"}}

        decision = service.evaluate(request)

        self.assertEqual("APPROVE", decision.action)
        self.assertEqual("PAYMENT_CREATE", encode_evaluation(decision)["operation"])
        self.assertEqual(decision.decision_id,
                         self.control.pending_decision_events()[0]["eventId"])

    def test_hmac_authentication_rejects_tamper_expiry_and_nonce_replay(self) -> None:
        secret = b"risk-runtime-test-secret-at-least-32-bytes"
        authenticator = HmacRequestAuthenticator(secret, lambda: NOW)
        body = b'{"tenantId":"tenant-a"}'
        timestamp = str(int(NOW.timestamp()))
        nonce = "nonce-1"
        signed = f"{timestamp}\n{nonce}\n{hashlib.sha256(body).hexdigest()}".encode()
        signature = hmac.new(secret, signed, hashlib.sha256).hexdigest()
        authenticator.verify(body, timestamp, nonce, signature)
        with self.assertRaises(ValidationError):
            authenticator.verify(body, timestamp, nonce, signature)
        with self.assertRaises(ValidationError):
            authenticator.verify(body + b"x", timestamp, "nonce-2", signature)
        with self.assertRaises(ValidationError):
            authenticator.verify(body, str(int(NOW.timestamp()) - 61), "nonce-3", signature)

    def test_executable_requires_explicit_local_policy_and_never_claims_certification(self) -> None:
        environment = os.environ.copy()
        environment.update({
            "ELMPAY_RISK_SIGNAL_MODE": "local-sandbox",
            "ELMPAY_ENABLE_LOCAL_SANDBOX": "true",
            "ELMPAY_RISK_HMAC_SECRET": "s" * 40,
        })
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/risk_runtime.py"), "--db",
             str(Path(self.directory.name) / "server.sqlite"), "--check-config"],
            cwd=ROOT, env=environment, capture_output=True, text=True, check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("NOT_CERTIFIED", json.loads(result.stdout)["certificationStatus"])


if __name__ == "__main__":
    unittest.main()
