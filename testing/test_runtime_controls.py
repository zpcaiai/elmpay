from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.billing import calculate_invoice  # noqa: E402
from elmpay_runtime.attestation import attach_dsse, generate_ed25519_keypair  # noqa: E402
from elmpay_runtime.capacity import evaluate_capacity  # noqa: E402
from elmpay_runtime.common import GateReport, ValidationError, read_json  # noqa: E402
from elmpay_runtime.compliance import (  # noqa: E402
    evaluate_vendor,
    evaluate_vulnerability_report,
)
from elmpay_runtime.kubernetes import (  # noqa: E402
    _cronjob_annotations,
    render_workloads,
    validate_workload_sources,
)
from elmpay_runtime.release import (  # noqa: E402
    release_binding,
    verify_release,
)
from elmpay_runtime.rollout import (  # noqa: E402
    ShadowDiff,
    compare_shadow,
    evaluate_canary,
    evaluate_go_no_go,
)
from elmpay_runtime.validate import validate_repository  # noqa: E402


NOW = datetime(2026, 8, 26, 0, 0, tzinfo=timezone.utc)


class PlatformValidationTest(unittest.TestCase):
    def test_repository_platform_policy_is_machine_valid(self) -> None:
        report = validate_repository(ROOT)
        self.assertTrue(report.allowed, report.reasons)
        self.assertGreater(len(report.checks), 20)

    def test_control_cli_is_fail_closed_for_missing_release_input(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/runtime/control.py"),
                "release-gate",
                "--manifest",
                str(ROOT / "testing/does-not-exist.json"),
                "--trust",
                str(ROOT / "testing/does-not-exist-trust.json"),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(2, result.returncode)
        output = json.loads(result.stdout)
        self.assertFalse(output["allowed"])


class KubernetesControlTest(unittest.TestCase):
    def test_cronjob_annotations_require_exact_namespace_and_named_key(self) -> None:
        annotations = {
            "elmpay.io/owner": "platform",
            "elmpay.io.evil/owner": "foreign",
            "foreign/elmpay.io/owner": "foreign",
            "elmpay.io": "unnamed",
            "elmpay.io/": "unnamed",
            "elmpay.io/requires-drained-database-roles": "edge",
            "argocd.argoproj.io/hook": "PreSync",
        }
        self.assertEqual({"elmpay.io/owner": "platform"},
                         _cronjob_annotations(annotations))

    def setUp(self) -> None:
        self.policy = read_json(ROOT / "platform/kubernetes/workload-policy.json")

    def test_renderer_requires_exact_digest_pinned_images(self) -> None:
        images = {
            item["name"]: f"registry.example/{item['name']}@sha256:" + "a" * 64
            for item in self.policy["services"]
        }
        images["edge-gateway"] = "registry.example/edge-gateway:latest"
        with self.assertRaises(ValidationError):
            render_workloads(self.policy, images)

    def test_inventory_contains_only_real_entrypoints_with_declared_probe_handlers(self) -> None:
        self.assertEqual(
            {"edge-gateway", "checkout-web", "admin-web", "worker-scheduler",
             "webhook-processor", "risk-engine"},
            {item["name"] for item in self.policy["services"]},
        )
        validate_workload_sources(ROOT, self.policy)

        missing_main = deepcopy(self.policy)
        missing_main["services"][0]["runtime"]["entrypoint"] = (
            "apps/edge-gateway/src/main/java/com/elmpay/gateway/PaymentHttpHandler.java"
        )
        with self.assertRaises(ValidationError):
            validate_workload_sources(ROOT, missing_main)

        missing_probe = deepcopy(self.policy)
        missing_probe["services"][1]["healthProbes"]["readiness"] = "/health/configured"
        with self.assertRaises(ValidationError):
            validate_workload_sources(ROOT, missing_probe)

        no_production_mode = deepcopy(self.policy)
        no_production_mode["services"][0]["fixedEnvironment"] = {}
        images = {
            item["name"]: f"registry.example/{item['name']}@sha256:" + "a" * 64
            for item in no_production_mode["services"]
        }
        with self.assertRaises(ValidationError):
            render_workloads(no_production_mode, images)

        unsupported_mode = deepcopy(self.policy)
        checkout = next(item for item in unsupported_mode["services"]
                        if item["name"] == "checkout-web")
        checkout["runtime"]["modeEnvironment"] = "LD_PRELOAD"
        checkout["runtime"]["modeValue"] = "/tmp/attacker.so"
        checkout["fixedEnvironment"]["LD_PRELOAD"] = "/tmp/attacker.so"
        with self.assertRaises(ValidationError):
            render_workloads(unsupported_mode, images)

        incomplete_mode = deepcopy(self.policy)
        checkout = next(item for item in incomplete_mode["services"]
                        if item["name"] == "checkout-web")
        checkout["runtime"]["modeEnvironment"] = "ADMIN_RUNTIME_MODE"
        with self.assertRaises(ValidationError):
            render_workloads(incomplete_mode, images)

    def test_renderer_applies_hardened_ha_workloads(self) -> None:
        rendered = render_workloads(self.policy, {
            item["name"]: f"registry.example/{item['name']}@sha256:" + "a" * 64
            for item in self.policy["services"]
        })
        deployments = [item for item in rendered["items"] if item["kind"] == "Deployment"]
        config_maps = [item for item in rendered["items"] if item["kind"] == "ConfigMap"]
        self.assertEqual(len(self.policy["services"]), len(deployments))
        self.assertEqual(
            {
                service["configuration"]["configMap"]
                for service in [*self.policy["services"], *self.policy.get("jobs", []),
                                *self.policy.get("cronJobs", [])]
                if service["configuration"].get("configMapData")
            },
            {item["metadata"]["name"] for item in config_maps},
        )
        self.assertTrue(all(item["immutable"] for item in config_maps))
        self.assertTrue(all("ELMPAY_DATABASE_PASSWORD_FILE" not in item["data"]
                            for item in config_maps))
        for deployment in deployments:
            self.assertGreaterEqual(deployment["spec"]["replicas"], 3)
            pod = deployment["spec"]["template"]["spec"]
            container = pod["containers"][0]
            self.assertFalse(pod["automountServiceAccountToken"])
            self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
            self.assertEqual(["ALL"], container["securityContext"]["capabilities"]["drop"])
            self.assertEqual(2, len(pod["topologySpreadConstraints"]))
            self.assertEqual(
                {"/health/startup", "/health/live", "/health/ready"},
                {
                    container["startupProbe"]["httpGet"]["path"],
                    container["livenessProbe"]["httpGet"]["path"],
                    container["readinessProbe"]["httpGet"]["path"],
                },
            )
            self.assertNotIn("envFrom", container)
            fixed = {item["name"]: item.get("value") for item in container["env"]}
            service_policy = next(
                item for item in self.policy["services"]
                if item["name"] == deployment["metadata"]["name"]
            )
            configuration = service_policy["configuration"]
            expected_config_keys = set(
                configuration.get("configMapData", {})
                or configuration.get("configMapKeys", [])
            )
            actual_config_refs = {
                item["name"]: item.get("valueFrom", {}).get("configMapKeyRef")
                for item in container["env"]
                if "configMapKeyRef" in item.get("valueFrom", {})
            }
            self.assertEqual(expected_config_keys, set(actual_config_refs))
            for key in expected_config_keys:
                self.assertEqual(
                    {
                        "name": configuration["configMap"],
                        "key": key,
                        "optional": False,
                    },
                    actual_config_refs[key],
                )
            if deployment["metadata"]["name"] == "edge-gateway":
                self.assertEqual("postgres", fixed["ELMPAY_RUNTIME_MODE"])
                self.assertEqual(
                    "https://risk-engine.elmpay.svc.cluster.local:8443/v1/risk/decisions",
                    fixed["ELMPAY_RISK_ENDPOINT"],
                )
                self.assertEqual("300", fixed["ELMPAY_RISK_TIMEOUT_MILLISECONDS"])
                self.assertEqual(
                    [{"name": "https", "containerPort": 8443},
                     {"name": "health", "containerPort": 8081}],
                    container["ports"],
                )
                self.assertEqual(
                    {
                        "sidecar.istio.io/rewriteAppHTTPProbers": "false",
                        "traffic.sidecar.istio.io/excludeInboundPorts": "8081",
                    },
                    deployment["spec"]["template"]["metadata"]["annotations"],
                )
                self.assertEqual(
                    {"health"},
                    {container[name]["httpGet"]["port"] for name in
                     ("startupProbe", "livenessProbe", "readinessProbe")},
                )
                self.assertTrue(any(
                    mount.get("mountPath") == "/var/run/secrets/elmpay/provider-tls"
                    and mount.get("readOnly") is True
                    for mount in container["volumeMounts"]
                ))
                self.assertTrue(any(
                    mount.get("mountPath") == "/var/run/secrets/elmpay/gateway-mtls"
                    and mount.get("readOnly") is True
                    for mount in container["volumeMounts"]
                ))
            elif deployment["metadata"]["name"] == "checkout-web":
                self.assertEqual("production", fixed["ELMPAY_CHECKOUT_WEB_MODE"])
                self.assertEqual([{"name": "http", "containerPort": 8080}],
                                 container["ports"])
                self.assertEqual({}, actual_config_refs)
                self.assertTrue(any(
                    mount.get("mountPath") == "/var/run/secrets/elmpay/edge-client-mtls"
                    and mount.get("readOnly") is True
                    for mount in container["volumeMounts"]
                ))
            elif deployment["metadata"]["name"] == "admin-web":
                self.assertEqual("production", fixed["ADMIN_RUNTIME_MODE"])
                self.assertEqual([{"name": "https", "containerPort": 8443}],
                                 container["ports"])
                self.assertEqual(
                    {"HTTPS"},
                    {container[name]["httpGet"].get("scheme") for name in
                     ("startupProbe", "livenessProbe", "readinessProbe")},
                )
                self.assertEqual(
                    {
                        "/var/run/secrets/elmpay/admin-idp",
                        "/var/run/secrets/elmpay/admin-governance",
                        "/var/run/secrets/elmpay/admin-server-tls",
                        "/var/run/secrets/elmpay/admin-postgres",
                        "/var/run/secrets/elmpay/admin-upstream-mtls",
                    },
                    {
                        mount["mountPath"] for mount in container["volumeMounts"]
                        if mount["name"] != "tmp"
                    },
                )
            elif deployment["metadata"]["name"] == "risk-engine":
                self.assertEqual("production", fixed["ELMPAY_RISK_MODE"])
                self.assertEqual(
                    [{"name": "https", "containerPort": 8443},
                     {"name": "health", "containerPort": 9081}],
                    container["ports"],
                )
                self.assertEqual(
                    {"health"},
                    {container[name]["httpGet"]["port"] for name in
                     ("startupProbe", "livenessProbe", "readinessProbe")},
                )
                self.assertEqual(
                    {
                        "sidecar.istio.io/rewriteAppHTTPProbers": "false",
                        "traffic.sidecar.istio.io/excludeInboundPorts": "9081",
                    },
                    deployment["spec"]["template"]["metadata"]["annotations"],
                )
                self.assertEqual(
                    {
                        "/var/run/secrets/elmpay/risk-server-mtls",
                        "/var/run/secrets/elmpay/risk-database-credentials",
                        "/var/run/secrets/elmpay/risk-database-mtls",
                        "/var/run/secrets/elmpay/risk-signal-mtls",
                        "/var/run/secrets/elmpay/risk-model-mtls",
                        "/var/run/secrets/elmpay/risk-governance",
                    },
                    {
                        mount["mountPath"] for mount in container["volumeMounts"]
                        if mount["name"] != "tmp"
                    },
                )
            elif deployment["metadata"]["name"] == "worker-scheduler":
                self.assertEqual([{"name": "health", "containerPort": 8081}],
                                 container["ports"])
                self.assertEqual(
                    {
                        "sidecar.istio.io/rewriteAppHTTPProbers": "false",
                        "traffic.sidecar.istio.io/excludeInboundPorts": "8081",
                    },
                    deployment["spec"]["template"]["metadata"]["annotations"],
                )
                fields = {
                    item["name"]: item.get("valueFrom", {}).get("fieldRef", {}).get("fieldPath")
                    for item in container["env"]
                    if "fieldRef" in item.get("valueFrom", {})
                }
                self.assertEqual("metadata.name", fields["ELMPAY_WORKER_ID"])
                self.assertEqual("metadata.name", fields["ELMPAY_KAFKA_CLIENT_ID"])
                self.assertEqual(
                    {
                        "/var/run/secrets/elmpay/worker-database-credentials",
                        "/var/run/secrets/elmpay/worker-database-mtls",
                        "/var/run/secrets/elmpay/worker-kafka-trust",
                        "/var/run/secrets/elmpay/worker-kafka-identity",
                        "/var/run/secrets/elmpay/worker-admin-governance",
                    },
                    {
                        mount["mountPath"] for mount in container["volumeMounts"]
                        if mount["name"] != "tmp"
                    },
                )
            elif deployment["metadata"]["name"] == "webhook-processor":
                self.assertEqual([{"name": "health", "containerPort": 8081}],
                                 container["ports"])
                fields = {
                    item["name"]: item.get("valueFrom", {}).get("fieldRef", {}).get("fieldPath")
                    for item in container["env"]
                    if "fieldRef" in item.get("valueFrom", {})
                }
                self.assertEqual("metadata.name", fields["ELMPAY_WEBHOOK_PROCESSOR_ID"])
                self.assertEqual(
                    {
                        "/var/run/secrets/elmpay/webhook-processor-database-credentials",
                        "/var/run/secrets/elmpay/webhook-processor-database-mtls",
                    },
                    {
                        mount["mountPath"] for mount in container["volumeMounts"]
                        if mount["name"] != "tmp"
                    },
                )
            else:
                self.fail(f"untested production workload: {deployment['metadata']['name']}")
            for volume in pod["volumes"]:
                if "secret" in volume:
                    self.assertEqual(0o440, volume["secret"]["defaultMode"])

    def test_migration_job_dependencies_are_earlier_persistent_presync_hooks(self) -> None:
        rendered = render_workloads(self.policy, {
            item["name"]: f"registry.example/{item['name']}@sha256:" + "a" * 64
            for item in self.policy["services"]
        })
        items = rendered["items"]
        job = next(item for item in items
                   if item["kind"] == "Job" and item["metadata"]["name"] ==
                   "database-migrator")
        job_annotations = job["metadata"]["annotations"]
        self.assertEqual("PreSync", job_annotations["argocd.argoproj.io/hook"])
        self.assertEqual("-10", job_annotations["argocd.argoproj.io/sync-wave"])
        self.assertEqual(
            "BeforeHookCreation,HookSucceeded",
            job_annotations["argocd.argoproj.io/hook-delete-policy"],
        )
        self.assertEqual(
            "elmpay_edge_gateway,elmpay_risk_engine,elmpay_worker",
            job_annotations["elmpay.io/requires-drained-database-roles"],
        )
        dependencies = [item for item in items
                        if item["metadata"].get("labels", {}).get(
                            "app.kubernetes.io/name") == "database-migrator"
                        and item["kind"] in {"ConfigMap", "ServiceAccount", "NetworkPolicy"}]
        self.assertEqual(3, len(dependencies))
        for dependency in dependencies:
            annotations = dependency["metadata"]["annotations"]
            self.assertEqual("PreSync", annotations["argocd.argoproj.io/hook"])
            self.assertEqual("-20", annotations["argocd.argoproj.io/sync-wave"])
            self.assertEqual(
                "BeforeHookCreation",
                annotations["argocd.argoproj.io/hook-delete-policy"],
            )

        early_delete = deepcopy(self.policy)
        early_delete["jobs"][0]["gitOps"]["dependencyWave"] = -5
        with self.assertRaises(ValidationError):
            render_workloads(early_delete, {
                item["name"]: f"registry.example/{item['name']}@sha256:" + "a" * 64
                for item in early_delete["services"]
            })

        initializer = next(item for item in items if item["kind"] == "Job"
                           and item["metadata"]["name"] ==
                           "tenant-partition-initializer")
        self.assertEqual("-5", initializer["metadata"]["annotations"]
                         ["argocd.argoproj.io/sync-wave"])

        cron = next(item for item in items if item["kind"] == "CronJob"
                    and item["metadata"]["name"] == "tenant-partition-maintenance")
        self.assertEqual("17 2 * * *", cron["spec"]["schedule"])
        self.assertEqual("Etc/UTC", cron["spec"]["timeZone"])
        self.assertEqual("Forbid", cron["spec"]["concurrencyPolicy"])
        self.assertFalse(cron["spec"]["suspend"])
        self.assertNotIn("argocd.argoproj.io/hook", cron["metadata"]["annotations"])

    def test_health_only_replica_identity_and_config_map_secrets_fail_closed(self) -> None:
        images = {
            item["name"]: f"registry.example/{item['name']}@sha256:" + "a" * 64
            for item in self.policy["services"]
        }
        shared_identity = deepcopy(self.policy)
        worker = next(item for item in shared_identity["services"]
                      if item["name"] == "worker-scheduler")
        worker["fieldEnvironment"].pop("ELMPAY_WORKER_ID")
        worker["fixedEnvironment"]["ELMPAY_WORKER_ID"] = "shared-worker"
        with self.assertRaises(ValidationError):
            render_workloads(shared_identity, images)

        exposed = deepcopy(self.policy)
        worker = next(item for item in exposed["services"]
                      if item["name"] == "worker-scheduler")
        worker["exposeService"] = True
        with self.assertRaises(ValidationError):
            render_workloads(exposed, images)

        leaked = deepcopy(self.policy)
        worker = next(item for item in leaked["services"]
                      if item["name"] == "worker-scheduler")
        worker["configuration"]["configMapData"]["ELMPAY_DATABASE_PASSWORD"] = "unsafe"
        with self.assertRaises(ValidationError):
            render_workloads(leaked, images)

        webhook_shared_identity = deepcopy(self.policy)
        webhook = next(item for item in webhook_shared_identity["services"]
                       if item["name"] == "webhook-processor")
        webhook["fieldEnvironment"].pop("ELMPAY_WEBHOOK_PROCESSOR_ID")
        webhook["fixedEnvironment"]["ELMPAY_WEBHOOK_PROCESSOR_ID"] = "shared-processor"
        with self.assertRaises(ValidationError):
            render_workloads(webhook_shared_identity, images)

        webhook_leaked = deepcopy(self.policy)
        webhook = next(item for item in webhook_leaked["services"]
                       if item["name"] == "webhook-processor")
        webhook["configuration"]["configMapData"]["ELMPAY_DATABASE_PASSWORD"] = "unsafe"
        with self.assertRaises(ValidationError):
            render_workloads(webhook_leaked, images)

        arbitrary_runtime_injection = deepcopy(self.policy)
        edge = next(item for item in arbitrary_runtime_injection["services"]
                    if item["name"] == "edge-gateway")
        edge["configuration"]["configMapKeys"].append("JAVA_TOOL_OPTIONS")
        with self.assertRaises(ValidationError):
            render_workloads(arbitrary_runtime_injection, images)

        fixed_secret_injection = deepcopy(self.policy)
        risk = next(item for item in fixed_secret_injection["services"]
                    if item["name"] == "risk-engine")
        risk["fixedEnvironment"]["ELMPAY_RISK_HMAC_SECRET"] = "unsafe"
        with self.assertRaises(ValidationError):
            render_workloads(fixed_secret_injection, images)

        restarted_edge_budget = deepcopy(self.policy)
        edge = next(item for item in restarted_edge_budget["services"]
                    if item["name"] == "edge-gateway")
        edge["fixedEnvironment"]["ELMPAY_RISK_TIMEOUT_MILLISECONDS"] = "100"
        with self.assertRaises(ValidationError):
            render_workloads(restarted_edge_budget, images)

        restarted_dependency_budget = deepcopy(self.policy)
        risk = next(item for item in restarted_dependency_budget["services"]
                    if item["name"] == "risk-engine")
        risk["configuration"]["configMapData"][
            "ELMPAY_RISK_DEPENDENCY_TIMEOUT_MILLISECONDS"
        ] = "300"
        with self.assertRaises(ValidationError):
            render_workloads(restarted_dependency_budget, images)


class RolloutControlTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = read_json(ROOT / "platform/rollout/policy.json")

    def test_shadow_rejects_mismatch_and_candidate_side_effect(self) -> None:
        baseline = [{
            "requestId": "r1",
            "action": "APPROVE",
            "amountMinor": 100,
            "currency": "USD",
            "reasonCodes": ["OK"],
        }]
        candidate = [{
            "requestId": "r1",
            "action": "BLOCK",
            "amountMinor": 100,
            "currency": "USD",
            "reasonCodes": ["RULE"],
            "sideEffects": ["provider_call"],
        }]
        result = compare_shadow(baseline, candidate)
        self.assertFalse(result.passed)
        self.assertIn("r1", result.candidate_side_effects)
        self.assertIn("r1:action", result.mismatches)

    def test_canary_auto_stops_on_first_ledger_mismatch(self) -> None:
        baseline = self._metrics()
        candidate = self._metrics(ledgerMismatchCount=1)
        report = evaluate_canary(baseline, candidate, self.policy)
        self.assertFalse(report.allowed)
        self.assertIn("ledgerMismatchCount_exceeded", report.reasons)

    def test_canary_rejects_non_finite_string_metrics(self) -> None:
        with self.assertRaises(ValidationError):
            evaluate_canary(
                self._metrics(), self._metrics(errorRate="NaN"), self.policy
            )

    @staticmethod
    def _metrics(**overrides: object) -> dict[str, object]:
        metrics: dict[str, object] = {
            "requestCount": 10000,
            "errorRate": 0.001,
            "latencyP99Ms": 400,
            "authorizationRate": 0.90,
            "ledgerMismatchCount": 0,
            "duplicateSideEffectCount": 0,
            "securityCriticalCount": 0,
        }
        metrics.update(overrides)
        return metrics


class BillingControlTest(unittest.TestCase):
    def test_usage_is_tenant_scoped_and_deduplicated(self) -> None:
        policy = read_json(ROOT / "platform/rollout/billing-policy.json")
        event = {
            "tenantId": "tenant-a",
            "meter": "payment_attempt",
            "attempt_id": "attempt-1",
            "occurredAt": "2026-08-26T00:10:00Z",
        }
        invoice = calculate_invoice(
            policy,
            "tenant-a",
            NOW,
            datetime(2026, 8, 27, tzinfo=timezone.utc),
            [event, dict(event)],
        )
        self.assertEqual(1, invoice.duplicate_events)
        self.assertEqual(3, invoice.total_minor)

        with self.assertRaises(ValidationError):
            calculate_invoice(
                policy,
                "tenant-b",
                NOW,
                datetime(2026, 8, 27, tzinfo=timezone.utc),
                [event],
            )


class CapacityControlTest(unittest.TestCase):
    def test_forecast_below_headroom_blocks_go_no_go(self) -> None:
        policy = read_json(ROOT / "platform/observability/capacity.json")
        samples = {
            resource: [
                {"used": 50, "capacity": 100, "observedAt": "2026-08-01T00:00:00Z"},
                {"used": 55, "capacity": 100, "observedAt": "2026-08-10T00:00:00Z"},
                {"used": 60, "capacity": 100, "observedAt": "2026-08-20T00:00:00Z"},
            ]
            for resource in policy["resources"]
        }
        assessment = evaluate_capacity(policy, samples)
        self.assertFalse(assessment.report.allowed)
        self.assertTrue(any(reason.startswith("forecast_headroom_low") for reason in assessment.report.reasons))

    def test_go_no_go_aggregates_every_gate(self) -> None:
        rollout_policy = read_json(ROOT / "platform/rollout/policy.json")
        allowed = GateReport(True, (), ("verified",))
        shadow = ShadowDiff(10, (), (), (), ())
        blocked_capacity = GateReport(False, ("forecast_headroom_low:database",), ())
        report = evaluate_go_no_go(
            allowed,
            shadow,
            allowed,
            blocked_capacity,
            {"rollbackTestPassed": True, "gitopsDriftCount": 0, "openCriticalIncidents": 0},
            rollout_policy,
        )
        self.assertFalse(report.allowed)
        self.assertIn("capacity:forecast_headroom_low:database", report.reasons)


class ComplianceGateTest(unittest.TestCase):
    def test_missing_scan_type_and_findings_block(self) -> None:
        policy = read_json(ROOT / "platform/compliance/vulnerability-policy.json")
        report = {
            "scans": [{
                "type": "dependency",
                "status": "COMPLETE",
                "artifactDigest": "a" * 64,
                "completedAt": "2026-08-25T23:00:00Z",
                "findings": {"critical": 1, "high": 0, "medium": 0},
            }]
        }
        result = evaluate_vulnerability_report(policy, report, "a" * 64, now=NOW)
        self.assertFalse(result.allowed)
        self.assertIn("finding_threshold_exceeded:dependency:critical", result.reasons)
        self.assertIn("missing_scan:container", result.reasons)

    def test_vendor_requires_independent_current_review(self) -> None:
        policy = read_json(ROOT / "platform/compliance/vendor-policy.json")
        assessment = {
            "vendorId": "vendor-1",
            "critical": True,
            "completedControls": policy["required"],
            "assessor": "reviewer-a",
            "approver": "reviewer-a",
            "reviewedAt": "2026-08-25T00:00:00Z",
        }
        result = evaluate_vendor(policy, assessment, now=NOW)
        self.assertFalse(result.allowed)
        self.assertIn("vendor_approver_not_independent", result.reasons)


class FinalReleaseGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = read_json(ROOT / "platform/compliance/required-release-gates.json")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.private = {}
        public = {}
        for key_id in ("rm", "sec", "external"):
            self.private[key_id], public[key_id] = generate_ed25519_keypair()
        self.trust = {
            "replayDatabase": str(Path(self.temporary.name) / "nonces.db"),
            "keys": {
                "rm": {
                    "identity": "release-a",
                    "role": "release_manager",
                    "algorithm": "Ed25519",
                    "publicKeyPem": public["rm"],
                    "independent": False,
                    "revoked": False,
                    "notBefore": "2026-08-01T00:00:00Z",
                    "notAfter": "2026-09-01T00:00:00Z",
                },
                "sec": {
                    "identity": "security-b",
                    "role": "security",
                    "algorithm": "Ed25519",
                    "publicKeyPem": public["sec"],
                    "independent": False,
                    "revoked": False,
                    "notBefore": "2026-08-01T00:00:00Z",
                    "notAfter": "2026-09-01T00:00:00Z",
                },
                "external": {
                    "identity": "independent-verifier",
                    "role": "external_verifier",
                    "algorithm": "Ed25519",
                    "publicKeyPem": public["external"],
                    "independent": True,
                    "revoked": False,
                    "notBefore": "2026-08-01T00:00:00Z",
                    "notAfter": "2026-09-01T00:00:00Z",
                },
            }
        }

    def test_missing_human_and_external_evidence_blocks(self) -> None:
        manifest = self._base_manifest()
        report = verify_release(
            manifest, self.policy, self.trust, now=NOW
        )
        self.assertFalse(report.allowed)
        self.assertIn("missing_approval_role:security", report.reasons)
        self.assertIn("missing_evidence:uat_acceptance", report.reasons)

    def test_complete_signed_binding_passes_and_tamper_fails(self) -> None:
        manifest = self._base_manifest()
        binding = release_binding(manifest)
        approvals = [
            self._signed(
                {
                    "actor": "release-a",
                    "role": "release_manager",
                    "decision": "APPROVE",
                    "signedAt": "2026-08-25T23:30:00Z",
                    "issuedAt": "2026-08-25T23:30:00Z",
                    "expiresAt": "2026-08-26T12:00:00Z",
                    "nonce": "approval-release-a-0001",
                    "bindingDigest": binding,
                },
                "rm",
            ),
            self._signed(
                {
                    "actor": "security-b",
                    "role": "security",
                    "decision": "APPROVE",
                    "signedAt": "2026-08-25T23:31:00Z",
                    "issuedAt": "2026-08-25T23:31:00Z",
                    "expiresAt": "2026-08-26T12:00:00Z",
                    "nonce": "approval-security-b-0001",
                    "bindingDigest": binding,
                },
                "sec",
            ),
        ]
        evidence = [
            self._signed(
                {
                    "category": category,
                    "verifier": "independent-verifier",
                    "role": "external_verifier",
                    "status": "VERIFIED",
                    "evidenceDigest": f"{index + 1:064x}",
                    "observedAt": "2026-08-25T22:00:00Z",
                    "expiresAt": "2026-08-27T00:00:00Z",
                    "issuedAt": "2026-08-25T22:00:00Z",
                    "nonce": f"evidence-external-{index:04d}",
                    "bindingDigest": binding,
                },
                "external",
            )
            for index, category in enumerate(self.policy["requiredEvidence"])
        ]
        manifest = {**manifest, "approvals": approvals, "evidence": evidence}

        report = verify_release(
            manifest, self.policy, self.trust, now=NOW
        )
        self.assertTrue(report.allowed, report.reasons)

        manifest["images"]["risk-engine"] = "registry.example/risk@sha256:" + "d" * 64
        tampered = verify_release(
            manifest, self.policy, self.trust, now=NOW
        )
        self.assertFalse(tampered.allowed)
        self.assertTrue(any("release_binding_mismatch" in reason for reason in tampered.reasons))

    def _signed(self, record: dict[str, object], key_id: str) -> dict[str, object]:
        return attach_dsse(record, key_id, self.private[key_id])

    @staticmethod
    def _base_manifest() -> dict[str, object]:
        policy = read_json(ROOT / "platform/compliance/required-release-gates.json")
        return {
            "releaseId": "release-2026-08-26-1",
            "commitSha": "c" * 40,
            "artifactDigest": "a" * 64,
            "productImageManifestDigest": policy["productImageManifestDigest"],
            "imageAdmissionPolicyDigest": policy["imageAdmissionPolicyDigest"],
            "productImageIndexDigest": "f" * 64,
            "images": {
                name: f"registry.example/{name}@sha256:" + f"{index + 1:064x}"
                for index, name in enumerate(policy["requiredProductImages"])
            },
            "generatedAt": "2026-08-25T23:00:00Z",
            "expiresAt": "2026-08-26T12:00:00Z",
            "approvals": [],
            "evidence": [],
        }


if __name__ == "__main__":
    unittest.main()
