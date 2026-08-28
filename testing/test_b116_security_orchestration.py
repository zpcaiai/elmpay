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

from elmpay_runtime.security_testing import (  # noqa: E402
    artifact_digest,
    orchestrate_security_pipeline,
)


TEST_TOKEN = "test-b116-security-token-0000000000000000"


class _SecurityTarget(BaseHTTPRequestHandler):
    bound_artifact_digest = ""
    observed_dast_requests = 0

    def log_message(self, *_args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        if (self.headers.get("Authorization") != f"Bearer {TEST_TOKEN}"
                or self.headers.get("X-Elmpay-Security-Test") != "true"):
            self._json(403, {"environment": "TEST"})
            return
        if self.path == "/healthz":
            self._json(200, {
                "environment": "TEST",
                "securityTest": True,
                "production": False,
                "tokenRequired": True,
            })
            return
        if self.path == "/dast":
            type(self).observed_dast_requests += 1
            self._json(200, {
                "environment": "TEST",
                "securityFinding": False,
            })
            return
        if self.path == "/iast":
            self._json(200, {
                "environment": "TEST",
                "hookActive": True,
                "artifactDigest": type(self).bound_artifact_digest,
                "observedRequests": type(self).observed_dast_requests,
                "criticalFindings": 0,
                "highFindings": 0,
                "processExitCode": 0,
            })
            return
        self._json(404, {"environment": "TEST"})

    def _json(self, status: int, value: dict[str, object]) -> None:
        body = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class SecurityOrchestrationTest(unittest.TestCase):
    def setUp(self) -> None:
        _SecurityTarget.observed_dast_requests = 0
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _SecurityTarget)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_discovers_scanners_and_binds_real_dast_and_iast_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = self._artifact(root)
            scanners = root / "bin"
            scanners.mkdir()
            for name in ("semgrep", "gitleaks", "trivy"):
                executable = scanners / name
                executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                executable.chmod(0o700)
            sast_config = root / "semgrep.yml"
            sast_config.write_text("rules: []\n", encoding="utf-8")
            plan = self._plan(artifact, sast_config)
            plan_path = root / "security-plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")

            result = orchestrate_security_pipeline(plan, environment={
                "PATH": str(scanners),
                "ELMPAY_TEST_SECURITY_TOKEN": TEST_TOKEN,
            })
            command = subprocess.run(
                [sys.executable, str(ROOT / "tools/quality_gate.py"),
                 "security", "--plan", str(plan_path)],
                cwd=ROOT, check=False, capture_output=True, text=True, timeout=10,
                env={**os.environ, "PATH": str(scanners),
                     "ELMPAY_TEST_SECURITY_TOKEN": TEST_TOKEN},
            )

        self.assertTrue(result.allowed, result.reasons)
        self.assertEqual(0, command.returncode, command.stdout + command.stderr)
        self.assertTrue(json.loads(command.stdout)["allowed"])
        self.assertEqual({"sast", "secret", "dependency", "dast", "iast"},
                         {report["tool"] for report in result.reports})
        for report in result.reports:
            self.assertEqual("COMPLETE", report["status"])
            self.assertEqual(0, report["exitCode"])
            self.assertEqual(result.artifact_digest, report["artifactDigest"])
            self.assertTrue(report["orchestrated"])

    def test_missing_scanners_are_blocked_and_cannot_be_reported_complete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = self._artifact(root)
            sast_config = root / "semgrep.yml"
            sast_config.write_text("rules: []\n", encoding="utf-8")
            result = orchestrate_security_pipeline(
                self._plan(artifact, sast_config),
                environment={"PATH": "", "ELMPAY_TEST_SECURITY_TOKEN": TEST_TOKEN},
            )

        self.assertFalse(result.allowed)
        blocked = {report["tool"]: report for report in result.reports
                   if report["status"] == "BLOCKED"}
        self.assertEqual({"sast", "secret", "dependency"}, set(blocked))
        self.assertTrue(all(report["exitCode"] == 127 for report in blocked.values()))

    def _artifact(self, root: Path) -> Path:
        artifact = root / "artifact"
        artifact.mkdir()
        (artifact / "application.py").write_text("print('test artifact')\n", encoding="utf-8")
        _SecurityTarget.bound_artifact_digest = artifact_digest(artifact)
        return artifact

    def _plan(self, artifact: Path, sast_config: Path) -> dict[str, object]:
        base_url = f"http://127.0.0.1:{self.server.server_port}"
        endpoint = {
            "baseUrl": base_url,
            "healthPath": "/healthz",
            "testTokenEnv": "ELMPAY_TEST_SECURITY_TOKEN",
            "timeoutMilliseconds": 2_000,
        }
        return {
            "schemaVersion": 1,
            "environment": "TEST",
            "artifactPath": str(artifact),
            "artifactDigest": artifact_digest(artifact),
            "scannerTimeoutSeconds": 5,
            "sastConfigPath": str(sast_config),
            "dast": {**endpoint, "probes": [{"path": "/dast", "expectedStatus": 200}]},
            "iast": {**endpoint, "resultPath": "/iast"},
        }


if __name__ == "__main__":
    unittest.main()
