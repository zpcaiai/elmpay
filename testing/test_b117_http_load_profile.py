from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.common import ValidationError  # noqa: E402
from elmpay_runtime.quality import run_http_load_profile, run_http_resilience_plan  # noqa: E402


TEST_TOKEN = "test-" + "l" * 40


class _TestOnlyLoadHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    environment = "TEST"
    fault = "NONE"

    def do_GET(self) -> None:  # noqa: N802
        if not self._authenticated():
            self._send(403, {"ok": False})
            return
        if self.path == "/test/recovery":
            self._send(200, {
                "environment": "TEST",
                "recovered": self.fault == "NONE",
                "queueDepth": 0 if self.fault == "NONE" else 10,
                "databaseAvailable": self.fault != "DATABASE_UNAVAILABLE",
                "providerAvailable": self.fault != "PROVIDER_DEGRADED",
            })
            return
        if self.path != "/healthz":
            self._send(404, {"ok": False})
            return
        self._send(200, {
            "environment": self.environment,
            "loadTest": True,
            "production": self.environment == "PRODUCTION",
            "tokenRequired": True,
        })

    def do_POST(self) -> None:  # noqa: N802
        if not self._authenticated():
            self._send(403, {"ok": False})
            return
        if self.path == "/test/fault":
            try:
                size = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(size))
                if body.get("synthetic") is not True:
                    raise ValueError("fault must be synthetic")
                fault = str(body["fault"])
                type(self).fault = fault if body.get("enabled") is True else "NONE"
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                self._send(400, {"ok": False})
                return
            self._send(200, {
                "ok": True,
                "environment": "TEST",
                "fault": fault,
                "enabled": body.get("enabled") is True,
            })
            return
        if self.path != "/test/load":
            self._send(404, {"ok": False})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(size))
            request_id = self.headers["X-Elmpay-Test-Request-Id"]
            if (body.get("synthetic") is not True
                    or body.get("requestId") != request_id
                    or body.get("idempotencyKey") != request_id
                    or self.headers.get("Idempotency-Key") != request_id):
                raise ValueError("request binding mismatch")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self._send(400, {"ok": False})
            return
        if self.fault in {"DATABASE_UNAVAILABLE", "PROVIDER_DEGRADED"}:
            self._send(503, {"ok": False, "fault": self.fault})
            return
        self._send(200, {
            "ok": True,
            "requestId": request_id,
            "sideEffectId": f"effect-{request_id}",
            "resultId": f"result-{request_id}",
            "score": 1.0,
        })

    def _authenticated(self) -> bool:
        return (self.headers.get("Authorization") == f"Bearer {TEST_TOKEN}"
                and self.headers.get("X-Elmpay-Load-Test") == "true")

    def _send(self, status: int, document: object) -> None:
        body = json.dumps(document, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class B117LoopbackHttpLoadTest(unittest.TestCase):
    def setUp(self) -> None:
        _TestOnlyLoadHandler.environment = "TEST"
        _TestOnlyLoadHandler.fault = "NONE"
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _TestOnlyLoadHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def profile(self) -> dict[str, object]:
        return {
            "target": "loopback-http-test-v1",
            "baseUrl": f"http://127.0.0.1:{self.server.server_port}/",
            "healthPath": "/healthz",
            "requestPath": "/test/load",
            "method": "POST",
            "testTokenEnv": "ELMPAY_TEST_LOAD_TOKEN",
            "workers": 4,
            "durationSeconds": 0.25,
            "maximumRequests": 10_000,
            "timeoutMilliseconds": 1_000,
            "expectedStatus": 200,
            "idempotencyPrefix": "test-b117-load",
            "body": {"synthetic": True, "scenario": "bounded-load"},
            "thresholds": {
                "minimumThroughputRps": 1,
                "maximumErrorRate": 0,
                "maximumP99Milliseconds": 1_000,
                "minimumRequests": 8,
            },
        }

    def test_cli_measures_real_loopback_requests_and_marks_complete_proof(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"
            path.write_text(json.dumps(self.profile()), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/quality_gate.py"),
                 "load-profile", "--profile", str(path)],
                cwd=ROOT, text=True, capture_output=True, check=False,
                env={**os.environ, "ELMPAY_TEST_LOAD_TOKEN": TEST_TOKEN},
            )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["allowed"])
        self.assertTrue(report["complete_b117_proof"])
        self.assertEqual("LOOPBACK_TEST_HTTP", report["evidence_class"])
        self.assertGreaterEqual(report["requests"], 8)
        self.assertEqual(0, report["errors"])
        self.assertGreater(report["throughput_rps"], 0)

    def test_non_loopback_and_production_health_are_rejected(self) -> None:
        external = self.profile()
        external["baseUrl"] = "http://192.0.2.1:9999/"
        with self.assertRaisesRegex(ValidationError, "not loopback"):
            run_http_load_profile(external, TEST_TOKEN)

        _TestOnlyLoadHandler.environment = "PRODUCTION"
        with self.assertRaisesRegex(ValidationError, "TEST-only"):
            run_http_load_profile(self.profile(), TEST_TOKEN)

    def test_peak_burst_soak_and_fault_recovery_are_measured(self) -> None:
        profile = self.profile()
        profile.update({
            "faultControlPath": "/test/fault",
            "recoveryPath": "/test/recovery",
            "recoveryTimeoutMilliseconds": 1_000,
            "phases": [
                self._phase("peak", "PEAK", "QUEUE_BACKLOG", 4, 0),
                self._phase("burst", "BURST", "DATABASE_UNAVAILABLE", 4, 1),
                self._phase("soak", "SOAK", "PROVIDER_DEGRADED", 2, 1),
            ],
        })
        report = run_http_resilience_plan(profile, TEST_TOKEN)
        self.assertTrue(report.complete_b117_proof)
        self.assertEqual({"PEAK", "BURST", "SOAK"},
                         {phase.shape for phase in report.phases})
        self.assertTrue(all(phase.recovered for phase in report.phases))
        self.assertEqual({"QUEUE_BACKLOG", "DATABASE_UNAVAILABLE", "PROVIDER_DEGRADED"},
                         {phase.fault for phase in report.phases})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "resilience-profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            command = subprocess.run(
                [sys.executable, str(ROOT / "tools/quality_gate.py"),
                 "load-profile", "--profile", str(path)],
                cwd=ROOT, text=True, capture_output=True, check=False,
                env={**os.environ, "ELMPAY_TEST_LOAD_TOKEN": TEST_TOKEN}, timeout=10,
            )
        self.assertEqual(0, command.returncode, command.stdout + command.stderr)
        self.assertTrue(json.loads(command.stdout)["allowed"])

    @staticmethod
    def _phase(name: str, shape: str, fault: str, workers: int,
               maximum_error_rate: int) -> dict[str, object]:
        return {
            "name": name,
            "shape": shape,
            "fault": fault,
            "workers": workers,
            "durationSeconds": 0.1,
            "maximumRequests": 10_000,
            "idempotencyPrefix": f"test-b117-{name}",
            "thresholds": {
                "minimumThroughputRps": 1,
                "maximumErrorRate": maximum_error_rate,
                "maximumP99Milliseconds": 1_000,
                "minimumRequests": 2,
            },
        }


if __name__ == "__main__":
    unittest.main()
