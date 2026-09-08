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
from elmpay_runtime.egress_policy import (  # noqa: E402
    render_egress_controls,
    validate_data_plane_destinations,
    validate_internal_service_egress,
    validate_job_database_egress,
    validate_risk_service_egress,
)


class B89EgressPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workloads = json.loads(
            (ROOT / "platform/kubernetes/workload-policy.json").read_text(encoding="utf-8")
        )
        self.egress = json.loads(
            (ROOT / "platform/kubernetes/egress-policy.json").read_text(encoding="utf-8")
        )
        self.data_plane = json.loads(
            (ROOT / "platform/kubernetes/data-plane-policy.json").read_text(encoding="utf-8")
        )
        self.callers = json.loads(
            (ROOT / "platform/kubernetes/service-callers.json").read_text(encoding="utf-8")
        )

    def test_database_jobs_are_bound_to_the_canonical_primary_service(self) -> None:
        validate_job_database_egress(self.workloads, self.egress)

        wrong_namespace = deepcopy(self.workloads)
        wrong_namespace["jobs"][0]["databaseEgress"]["namespace"] = "elmpay"
        with self.assertRaises(ValidationError):
            validate_job_database_egress(wrong_namespace, self.egress)

        poisoned_url = deepcopy(self.workloads)
        poisoned_url["jobs"][0]["configuration"]["configMapData"][
            "ELMPAY_MIGRATION_DATABASE_URL"
        ] = "jdbc:postgresql://attacker.invalid:5432/elmpay"
        with self.assertRaises(ValidationError):
            validate_job_database_egress(poisoned_url, self.egress)

    def test_renders_default_deny_exact_dns_fqdn_and_mesh_boundaries(self) -> None:
        rendered = render_egress_controls(self.workloads, self.egress)
        items = rendered["items"]
        service_count = len(self.workloads["services"])
        self.assertEqual(service_count + 1,
                         sum(item["kind"] == "NetworkPolicy" for item in items))
        self.assertEqual(service_count,
                         sum(item["kind"] == "CiliumNetworkPolicy" for item in items))
        self.assertEqual(service_count, sum(item["kind"] == "Sidecar" for item in items))
        self.assertEqual(2, sum(item["kind"] == "ServiceEntry" for item in items))

        default_deny = next(item for item in items
                            if item["metadata"]["name"] == "egress-default-deny")
        self.assertEqual([], default_deny["spec"]["egress"])
        self.assertEqual(["Egress"], default_deny["spec"]["policyTypes"])

        payment = next(item for item in items
                       if item["metadata"]["name"] == "allow-controlled-egress-edge-gateway")
        self.assertEqual("DATABASE,INTERNAL_API,KAFKA,KMS,OTEL,PSP,REDIS",
                         payment["metadata"]["annotations"]["elmpay.io/categories"])
        dns_rule = payment["spec"]["egress"][0]
        self.assertEqual("kube-system", dns_rule["to"][0]["namespaceSelector"]
                         ["matchLabels"]["kubernetes.io/metadata.name"])
        self.assertEqual({("UDP", 53), ("TCP", 53)},
                         {(port["protocol"], port["port"]) for port in dns_rule["ports"]})

        cilium = next(item for item in items
                      if item["metadata"]["name"] == "fqdn-egress-edge-gateway")
        fqdn_rules = [rule for rule in cilium["spec"]["egress"] if "toFQDNs" in rule]
        self.assertEqual({"api.mch.weixin.qq.com", "openapi.alipay.com"},
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

        checkout = next(item for item in items
                        if item["metadata"]["name"] ==
                        "allow-controlled-egress-checkout-web")
        self.assertEqual("INTERNAL_API,OTEL",
                         checkout["metadata"]["annotations"]["elmpay.io/categories"])
        self.assertEqual("edge-gateway-internal,otel-collector",
                         checkout["metadata"]["annotations"]["elmpay.io/destination-ids"])

        admin = next(item for item in items
                     if item["metadata"]["name"] ==
                     "allow-controlled-egress-admin-web")
        self.assertEqual("DATABASE,INTERNAL_API",
                         admin["metadata"]["annotations"]["elmpay.io/categories"])
        self.assertEqual("edge-gateway-internal,postgres-primary",
                         admin["metadata"]["annotations"]["elmpay.io/destination-ids"])

        risk = next(item for item in items
                    if item["metadata"]["name"] ==
                    "allow-controlled-egress-risk-engine")
        self.assertEqual("DATABASE,RISK_MODEL,RISK_SIGNAL",
                         risk["metadata"]["annotations"]["elmpay.io/categories"])
        self.assertEqual(
            "postgres-primary,risk-model-service,risk-signal-service",
            risk["metadata"]["annotations"]["elmpay.io/destination-ids"],
        )

        worker = next(item for item in items
                      if item["metadata"]["name"] ==
                      "allow-controlled-egress-worker-scheduler")
        self.assertEqual("DATABASE,KAFKA",
                         worker["metadata"]["annotations"]["elmpay.io/categories"])
        self.assertEqual("kafka-events,postgres-primary",
                         worker["metadata"]["annotations"]["elmpay.io/destination-ids"])
        worker_rules = worker["spec"]["egress"][1:]
        self.assertFalse(any("ipBlock" in target
                             for rule in worker_rules for target in rule.get("to", [])))
        self.assertEqual(
            {("elmpay-cn-east-1", 5432), ("elmpay-cn-east-1", 9093)},
            {
                (rule["to"][0]["namespaceSelector"]["matchLabels"]
                     ["kubernetes.io/metadata.name"], rule["ports"][0]["port"])
                for rule in worker_rules
            },
        )
        worker_cilium = next(item for item in items
                             if item["metadata"]["name"] ==
                             "fqdn-egress-worker-scheduler")
        worker_dns = worker_cilium["spec"]["egress"][0]["toPorts"][0]["rules"]["dns"]
        names = {rule["matchName"] for rule in worker_dns}
        self.assertIn(
            "payments-events-kafka-0.payments-events-kafka-brokers."
            "elmpay-cn-east-1.svc.cluster.local", names,
        )
        self.assertFalse(any("matchPattern" in rule for rule in worker_dns))

        worker_sidecar = next(item for item in items
                              if item["metadata"]["name"] ==
                              "registry-only-worker-scheduler")
        self.assertEqual(
            [
                "elmpay-cn-east-1/payments-events-kafka-bootstrap."
                "elmpay-cn-east-1.svc.cluster.local",
                "elmpay-cn-east-1/payments-events-kafka-brokers."
                "elmpay-cn-east-1.svc.cluster.local",
                "elmpay-cn-east-1/payments-postgres-rw."
                "elmpay-cn-east-1.svc.cluster.local",
            ],
            worker_sidecar["spec"]["egress"][0]["hosts"],
        )

        webhook = next(item for item in items
                       if item["metadata"]["name"] ==
                       "allow-controlled-egress-webhook-processor")
        self.assertEqual("DATABASE",
                         webhook["metadata"]["annotations"]["elmpay.io/categories"])
        self.assertEqual("postgres-primary",
                         webhook["metadata"]["annotations"]["elmpay.io/destination-ids"])
        webhook_rules = webhook["spec"]["egress"][1:]
        self.assertEqual(1, len(webhook_rules))
        self.assertEqual(5432, webhook_rules[0]["ports"][0]["port"])
        self.assertFalse(any("ipBlock" in target
                             for rule in webhook_rules for target in rule.get("to", [])))
        webhook_sidecar = next(item for item in items
                               if item["metadata"]["name"] ==
                               "registry-only-webhook-processor")
        self.assertEqual(
            ["elmpay-cn-east-1/payments-postgres-rw."
             "elmpay-cn-east-1.svc.cluster.local"],
            webhook_sidecar["spec"]["egress"][0]["hosts"],
        )
        validate_data_plane_destinations(self.egress, self.data_plane)
        validate_internal_service_egress(
            self.workloads, self.egress, self.callers
        )
        validate_risk_service_egress(self.workloads, self.egress)

    def test_internal_service_ingress_and_egress_graph_must_match(self) -> None:
        missing_admin_route = deepcopy(self.egress)
        missing_admin_route["workloads"]["admin-web"].remove(
            "edge-gateway-internal"
        )
        with self.assertRaises(ValidationError):
            validate_internal_service_egress(
                self.workloads, missing_admin_route, self.callers
            )

        undeclared_checkout_route = deepcopy(self.callers)
        undeclared_checkout_route["edge-gateway"].remove("checkout-web")
        with self.assertRaises(ValidationError):
            validate_internal_service_egress(
                self.workloads, self.egress, undeclared_checkout_route
            )

        wrong_target = deepcopy(self.egress)
        edge = next(item for item in wrong_target["destinations"]
                    if item["id"] == "edge-gateway-internal")
        edge["targetWorkload"] = "admin-web"
        with self.assertRaises(ValidationError):
            validate_internal_service_egress(
                self.workloads, wrong_target, self.callers
            )

        orphaned_health_route = deepcopy(self.egress)
        orphaned_health_route["destinations"].append({
            "id": "worker-scheduler-internal",
            "category": "INTERNAL_API",
            "type": "service",
            "namespace": "elmpay",
            "serviceName": "worker-scheduler",
            "targetWorkload": "worker-scheduler",
            "podLabels": {"app.kubernetes.io/name": "worker-scheduler"},
            "port": 8081,
            "protocol": "TLS",
        })
        with self.assertRaises(ValidationError):
            validate_internal_service_egress(
                self.workloads, orphaned_health_route, self.callers
            )

    def test_risk_endpoints_and_routes_are_one_exact_graph(self) -> None:
        poisoned_endpoint = deepcopy(self.workloads)
        risk = next(item for item in poisoned_endpoint["services"]
                    if item["name"] == "risk-engine")
        risk["configuration"]["configMapData"]["ELMPAY_RISK_SIGNAL_ENDPOINT"] = (
            "https://kms-broker.security.svc.cluster.local:8443/v1/risk/signals"
        )
        with self.assertRaises(ValidationError):
            validate_risk_service_egress(poisoned_endpoint, self.egress)

        dynamic_edge_endpoint = deepcopy(self.workloads)
        edge = next(item for item in dynamic_edge_endpoint["services"]
                    if item["name"] == "edge-gateway")
        del edge["fixedEnvironment"]["ELMPAY_RISK_ENDPOINT"]
        edge["configuration"]["configMapKeys"].append("ELMPAY_RISK_ENDPOINT")
        with self.assertRaises(ValidationError):
            validate_risk_service_egress(dynamic_edge_endpoint, self.egress)

        slow_edge = deepcopy(self.workloads)
        edge = next(item for item in slow_edge["services"]
                    if item["name"] == "edge-gateway")
        edge["fixedEnvironment"]["ELMPAY_RISK_TIMEOUT_MILLISECONDS"] = "5000"
        with self.assertRaises(ValidationError):
            validate_risk_service_egress(slow_edge, self.egress)

        restarted_dependency_budget = deepcopy(self.workloads)
        risk = next(item for item in restarted_dependency_budget["services"]
                    if item["name"] == "risk-engine")
        risk["configuration"]["configMapData"][
            "ELMPAY_RISK_DEPENDENCY_TIMEOUT_MILLISECONDS"
        ] = "300"
        with self.assertRaises(ValidationError):
            validate_risk_service_egress(restarted_dependency_budget, self.egress)

        broadened = deepcopy(self.egress)
        broadened["workloads"]["edge-gateway"].append("risk-signal-service")
        with self.assertRaises(ValidationError):
            validate_risk_service_egress(self.workloads, broadened)

        wrong_selector = deepcopy(self.egress)
        signal = next(item for item in wrong_selector["destinations"]
                      if item["id"] == "risk-signal-service")
        signal["podLabels"] = {"app.kubernetes.io/name": "unreviewed-signal"}
        with self.assertRaises(ValidationError):
            validate_risk_service_egress(self.workloads, wrong_selector)

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
        del incomplete["workloads"]["edge-gateway"]
        with self.assertRaises(ValidationError):
            render_egress_controls(self.workloads, incomplete)

        escaped_service_dns = deepcopy(self.egress)
        kafka = next(item for item in escaped_service_dns["destinations"]
                     if item["id"] == "kafka-events")
        kafka["dnsNames"][0] = "broker.attacker.example"
        with self.assertRaises(ValidationError):
            render_egress_controls(self.workloads, escaped_service_dns)

        mismatched_brokers = deepcopy(self.data_plane)
        mismatched_brokers["kafka"]["brokers"] = 4
        with self.assertRaises(ValidationError):
            validate_data_plane_destinations(self.egress, mismatched_brokers)

        broadened_worker = deepcopy(self.egress)
        broadened_worker["workloads"]["worker-scheduler"].append("otel-collector")
        with self.assertRaises(ValidationError):
            render_egress_controls(self.workloads, broadened_worker)

        broadened_webhook = deepcopy(self.egress)
        broadened_webhook["workloads"]["webhook-processor"].append("kafka-events")
        with self.assertRaises(ValidationError):
            render_egress_controls(self.workloads, broadened_webhook)

        mismatched_dns = deepcopy(self.workloads)
        mismatched_dns["dnsEgress"]["podLabels"] = {"k8s-app": "unreviewed-dns"}
        with self.assertRaises(ValidationError):
            render_egress_controls(mismatched_dns, self.egress)

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
