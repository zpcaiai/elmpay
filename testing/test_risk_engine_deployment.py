from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RiskEngineDeploymentTest(unittest.TestCase):
    def setUp(self) -> None:
        workload = json.loads((ROOT / "platform/kubernetes/workload-policy.json").read_text())
        self.risk = next(item for item in workload["services"] if item["name"] == "risk-engine")
        self.edge = next(item for item in workload["services"] if item["name"] == "edge-gateway")
        self.egress = json.loads((ROOT / "platform/kubernetes/egress-policy.json").read_text())
        self.callers = json.loads((ROOT / "platform/kubernetes/service-callers.json").read_text())

    def test_three_replica_mtls_runtime_has_isolated_strict_readiness(self) -> None:
        self.assertEqual(3, self.risk["replicas"])
        self.assertEqual("https-mtls", self.risk["transport"])
        self.assertNotEqual(self.risk["port"], self.risk["healthPort"])
        self.assertNotIn("healthOnly", self.risk)
        self.assertEqual(
            {
                "startup": "/health/startup",
                "liveness": "/health/live",
                "readiness": "/health/ready",
            },
            self.risk["healthProbes"],
        )
        source = (ROOT / self.risk["runtime"]["healthSource"]).read_text()
        self.assertIn("decisions.ready()", source)
        self.assertIn("ready ? 200 : 503", source)

    def test_all_sensitive_inputs_are_read_only_mounts_not_secret_env_values(self) -> None:
        fixed = self.risk["fixedEnvironment"]
        mounts = {item["mountPath"] for item in self.risk["configuration"]["secretMounts"]}
        sensitive = {
            key: value
            for key, value in fixed.items()
            if any(marker in key for marker in ("PASSWORD", "PRIVATE_KEY", "CERTIFICATE", "CA_", "POLICY_FILE"))
        }
        self.assertTrue(sensitive)
        for value in sensitive.values():
            self.assertTrue(any(value.startswith(mount + "/") for mount in mounts), value)
        self.assertNotIn("envFrom", self.risk)
        self.assertNotIn("ELMPAY_RISK_HMAC_SECRET", fixed)
        self.assertNotIn("ELMPAY_RISK_HMAC_SECRET_FILE", fixed)

    def test_egress_and_callers_are_exact(self) -> None:
        self.assertEqual(["edge-gateway"], self.callers["risk-engine"])
        self.assertEqual(
            {"postgres-primary", "risk-signal-service", "risk-model-service"},
            set(self.egress["workloads"]["risk-engine"]),
        )
        self.assertIn("risk-engine-internal", self.egress["workloads"]["edge-gateway"])
        destinations = {item["id"]: item for item in self.egress["destinations"]}
        self.assertEqual("risk-engine", destinations["risk-engine-internal"]["targetWorkload"])
        self.assertEqual("RISK_SIGNAL", destinations["risk-signal-service"]["category"])
        self.assertEqual("RISK_MODEL", destinations["risk-model-service"]["category"])
        self.assertEqual("TLS", destinations["risk-signal-service"]["protocol"])
        self.assertEqual("TLS", destinations["risk-model-service"]["protocol"])


if __name__ == "__main__":
    unittest.main()
