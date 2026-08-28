from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.common import ValidationError  # noqa: E402
from elmpay_runtime.egress_policy import render_egress_controls  # noqa: E402


class B89EgressPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workloads = json.loads(
            (ROOT / "platform/kubernetes/workload-policy.json").read_text(encoding="utf-8")
        )
        self.egress = json.loads(
            (ROOT / "platform/kubernetes/egress-policy.json").read_text(encoding="utf-8")
        )

    def test_renders_default_deny_exact_dns_fqdn_and_mesh_boundaries(self) -> None:
        rendered = render_egress_controls(self.workloads, self.egress)
        items = rendered["items"]
        service_count = len(self.workloads["services"])
        self.assertEqual(service_count + 1,
                         sum(item["kind"] == "NetworkPolicy" for item in items))
        self.assertEqual(service_count,
                         sum(item["kind"] == "CiliumNetworkPolicy" for item in items))
        self.assertEqual(service_count, sum(item["kind"] == "Sidecar" for item in items))
        self.assertEqual(4, sum(item["kind"] == "ServiceEntry" for item in items))

        default_deny = next(item for item in items
                            if item["metadata"]["name"] == "egress-default-deny")
        self.assertEqual([], default_deny["spec"]["egress"])
        self.assertEqual(["Egress"], default_deny["spec"]["policyTypes"])

        payment = next(item for item in items
                       if item["metadata"]["name"] == "allow-controlled-egress-payment-core")
        self.assertEqual("DATABASE,KAFKA,KMS,OTEL,PSP,REDIS",
                         payment["metadata"]["annotations"]["elmpay.io/categories"])
        dns_rule = payment["spec"]["egress"][0]
        self.assertEqual("kube-system", dns_rule["to"][0]["namespaceSelector"]
                         ["matchLabels"]["kubernetes.io/metadata.name"])
        self.assertEqual({("UDP", 53), ("TCP", 53)},
                         {(port["protocol"], port["port"]) for port in dns_rule["ports"]})

        cilium = next(item for item in items
                      if item["metadata"]["name"] == "fqdn-egress-payment-core")
        fqdn_rules = [rule for rule in cilium["spec"]["egress"] if "toFQDNs" in rule]
        self.assertEqual({"api.mch.weixin.qq.com", "openapi.alipay.com",
                          "api.stripe.com", "api-m.paypal.com"},
                         {rule["toFQDNs"][0]["matchName"] for rule in fqdn_rules})
        self.assertFalse(any("matchPattern" in rule["toFQDNs"][0] for rule in fqdn_rules))

        for sidecar in (item for item in items if item["kind"] == "Sidecar"):
            self.assertEqual("REGISTRY_ONLY",
                             sidecar["spec"]["outboundTrafficPolicy"]["mode"])
        for service_entry in (item for item in items if item["kind"] == "ServiceEntry"):
            self.assertEqual("MESH_EXTERNAL", service_entry["spec"]["location"])
            self.assertEqual("DNS", service_entry["spec"]["resolution"])
            self.assertEqual("TLS", service_entry["spec"]["ports"][0]["protocol"])
            self.assertNotIn("*", service_entry["spec"]["hosts"][0])

    def test_rejects_wildcard_broad_ip_and_incomplete_workload_maps(self) -> None:
        wildcard = deepcopy(self.egress)
        next(item for item in wildcard["destinations"]
             if item["id"] == "wechat-api")["host"] = "*.weixin.qq.com"
        with self.assertRaises(ValidationError):
            render_egress_controls(self.workloads, wildcard)

        broad_ip = deepcopy(self.egress)
        redis = next(item for item in broad_ip["destinations"]
                     if item["id"] == "redis-cache")
        redis.clear()
        redis.update({
            "id": "redis-cache", "category": "REDIS", "type": "cidr",
            "cidr": "0.0.0.0/0", "except": [], "port": 6379, "protocol": "TCP",
        })
        with self.assertRaises(ValidationError):
            render_egress_controls(self.workloads, broad_ip)

        incomplete = deepcopy(self.egress)
        del incomplete["workloads"]["payment-core"]
        with self.assertRaises(ValidationError):
            render_egress_controls(self.workloads, incomplete)

    def test_command_renders_the_checked_in_production_policy(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "tools/render_egress_policy.py"),
             "--workload-policy", str(ROOT / "platform/kubernetes/workload-policy.json"),
             "--egress-policy", str(ROOT / "platform/kubernetes/egress-policy.json")],
            check=False, capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        rendered = json.loads(completed.stdout)
        self.assertEqual("List", rendered["kind"])
        self.assertTrue(any(item["kind"] == "CiliumNetworkPolicy"
                            for item in rendered["items"]))


if __name__ == "__main__":
    unittest.main()
