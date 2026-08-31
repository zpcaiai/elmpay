from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from .common import GateReport, ValidationError, read_json, require_list, require_mapping
from .egress_policy import (
    render_egress_controls,
    validate_data_plane_destinations,
    validate_internal_service_egress,
    validate_job_database_egress,
    validate_risk_service_egress,
)
from .infrastructure import render_regional_data_plane, render_service_controls
from .kubernetes import render_workloads, validate_workload_sources
from .oci import (
    admission_policy_digest,
    product_image_manifest_digest,
    validate_admission_policy,
    validate_product_image_manifest,
)


JSON_DIRECTORIES = (
    "platform/kubernetes",
    "platform/policies",
    "platform/observability",
    "platform/alerts",
    "platform/dr",
    "platform/rollout",
    "platform/compliance",
    "platform/risk",
    "platform/oci",
)


def validate_repository(root: Path) -> GateReport:
    reasons: list[str] = []
    checks: list[str] = []
    documents: dict[str, Any] = {}
    for relative_directory in JSON_DIRECTORIES:
        directory = root / relative_directory
        if not directory.is_dir():
            reasons.append(f"missing_directory:{relative_directory}")
            continue
        for path in sorted(directory.rglob("*.json")):
            relative = str(path.relative_to(root))
            try:
                documents[relative] = read_json(path)
                checks.append(f"json:{relative}")
            except ValidationError as exc:
                reasons.append(f"json_invalid:{relative}:{exc}")

    required_files = {
        "platform/kubernetes/static-bundle.json",
        "platform/kubernetes/workload-policy.json",
        "platform/kubernetes/service-callers.json",
        "platform/kubernetes/data-plane-policy.json",
        "platform/kubernetes/egress-policy.json",
        "platform/kubernetes/image-admission-policy.json",
        "platform/oci/product-images.json",
        "platform/policies/workload-security.json",
        "platform/policies/gitops.json",
        "platform/policies/service-mesh.json",
        "platform/policies/data-residency.json",
        "platform/observability/collector.json",
        "platform/observability/slos.json",
        "platform/observability/capacity.json",
        "platform/alerts/prometheus-rules.json",
        "platform/alerts/siem-rules.json",
        "platform/dr/plan.json",
        "platform/rollout/policy.json",
        "platform/rollout/billing-policy.json",
        "platform/compliance/data-lifecycle.json",
        "platform/compliance/vulnerability-policy.json",
        "platform/compliance/vendor-policy.json",
        "platform/compliance/supply-chain-policy.json",
        "platform/compliance/control-matrix.json",
        "platform/compliance/required-release-gates.json",
        "platform/compliance/external-evidence-policy.json",
        "platform/compliance/regional-boundaries.json",
        "platform/compliance/aml-boundary.json",
        "platform/policies/event-resilience.json",
        "platform/policies/cache-resilience.json",
        "platform/policies/provider-resilience.json",
        "platform/policies/edge-security.json",
        "platform/risk/runtime-policy.json",
    }
    for relative in sorted(required_files - set(documents)):
        reasons.append(f"required_config_missing:{relative}")
    if reasons:
        return GateReport.from_reasons(reasons, checks)

    semantic_checks = (
        _validate_static_kubernetes,
        _validate_workload_policy,
        _validate_product_images,
        _validate_security_policies,
        _validate_observability,
        _validate_alerts,
        _validate_dr,
        _validate_rollout,
        _validate_compliance,
    )
    for check in semantic_checks:
        try:
            check(root, documents)
            checks.append(f"semantic:{check.__name__}")
        except (ValidationError, KeyError, TypeError, ValueError) as exc:
            reasons.append(f"semantic:{check.__name__}:{exc}")

    for relative in (
        "runbooks/incident-response.md",
        "runbooks/disaster-recovery.md",
        "runbooks/rollout.md",
        "runbooks/capacity.md",
        "runbooks/data-deletion.md",
    ):
        path = root / relative
        if not path.is_file() or path.stat().st_size < 200:
            reasons.append(f"runbook_missing_or_empty:{relative}")
        else:
            checks.append(f"runbook:{relative}")
    return GateReport.from_reasons(reasons, checks)


def _validate_static_kubernetes(root: Path, documents: Mapping[str, Any]) -> None:
    del root
    bundle = require_mapping(
        documents["platform/kubernetes/static-bundle.json"], "static bundle"
    )
    if bundle.get("apiVersion") != "v1" or bundle.get("kind") != "List":
        raise ValidationError("static Kubernetes bundle must be a v1 List")
    items = require_list(bundle.get("items"), "static bundle items")
    by_kind: dict[str, list[Mapping[str, Any]]] = {}
    for raw in items:
        item = require_mapping(raw, "Kubernetes item")
        by_kind.setdefault(str(item.get("kind")), []).append(item)
    required_kinds = {
        "Namespace",
        "ServiceAccount",
        "Service",
        "PodDisruptionBudget",
        "HorizontalPodAutoscaler",
        "NetworkPolicy",
        "PeerAuthentication",
        "AuthorizationPolicy",
        "DestinationRule",
    }
    missing = required_kinds - set(by_kind)
    if missing:
        raise ValidationError(f"static Kubernetes controls missing: {sorted(missing)}")
    policy = require_mapping(
        documents["platform/kubernetes/workload-policy.json"], "workload policy"
    )
    services = [require_mapping(item, "workload service") for item in require_list(
        policy.get("services"), "workload services"
    )]
    expected = {str(item["name"]): item for item in services}
    if len(expected) != len(services):
        raise ValidationError("workload names must be unique")
    rendered_controls = render_service_controls(
        policy,
        require_mapping(
            documents["platform/kubernetes/service-callers.json"], "service callers"
        ),
    )
    controlled_kinds = {
        "ServiceAccount", "Service", "PodDisruptionBudget", "HorizontalPodAutoscaler",
        "NetworkPolicy", "PeerAuthentication", "AuthorizationPolicy",
    }
    expected_controls = {
        (str(item["kind"]), str(item["metadata"]["name"])): item
        for item in rendered_controls["items"] if item["kind"] in controlled_kinds
    }
    actual_controls = {
        (str(item["kind"]), str(item["metadata"]["name"])): item
        for item in items if item.get("kind") in controlled_kinds
    }
    actual_control_count = sum(item.get("kind") in controlled_kinds for item in items)
    if len(actual_controls) != actual_control_count or actual_controls != expected_controls:
        raise ValidationError("static Kubernetes controls differ from the service renderer")
    for kind in (
        "ServiceAccount", "PodDisruptionBudget",
        "HorizontalPodAutoscaler", "AuthorizationPolicy",
    ):
        actual = {str(item["metadata"]["name"]) for item in by_kind.get(kind, [])}
        if actual != set(expected) or len(actual) != len(by_kind.get(kind, [])):
            raise ValidationError(f"static {kind} inventory must exactly match workloads")
    exposed = {
        name for name, service in expected.items()
        if service.get("exposeService", True) is True
    }
    actual_services = {
        str(item["metadata"]["name"]) for item in by_kind.get("Service", [])
    }
    if actual_services != exposed or len(actual_services) != len(by_kind.get("Service", [])):
        raise ValidationError("static Service inventory must exactly match exposed workloads")
    namespace = by_kind["Namespace"][0]
    if len(by_kind["Namespace"]) != 1 or len(by_kind["PeerAuthentication"]) != 1 \
            or len(by_kind["DestinationRule"]) != 1:
        raise ValidationError("static singleton Kubernetes controls must not be duplicated")
    labels = namespace["metadata"]["labels"]
    if labels.get("pod-security.kubernetes.io/enforce") != "restricted":
        raise ValidationError("namespace must enforce restricted pod security")
    if any(item.get("automountServiceAccountToken") is not False for item in by_kind["ServiceAccount"]):
        raise ValidationError("all service accounts must disable token mounting")
    if not any(
        item["spec"].get("podSelector") == {}
        and set(item["spec"].get("policyTypes", [])) == {"Ingress", "Egress"}
        and not item["spec"].get("ingress")
        and not item["spec"].get("egress")
        for item in by_kind["NetworkPolicy"]
    ):
        raise ValidationError("default-deny ingress and egress policy is required")
    if by_kind["PeerAuthentication"][0]["spec"]["mtls"].get("mode") != "STRICT":
        raise ValidationError("service mesh mTLS must be STRICT")
    if any(item["spec"].get("minAvailable", 0) < 2 for item in by_kind["PodDisruptionBudget"]):
        raise ValidationError("PDB minAvailable must be at least two")
    for item in by_kind["Service"]:
        name = str(item["metadata"]["name"])
        if item["spec"].get("selector") != {"app.kubernetes.io/name": name}:
            raise ValidationError(f"{name} Service selector does not match its workload")
        ports = item["spec"].get("ports", [])
        target_port = (
            "https" if expected[name].get("transport") in {"https", "https-mtls"}
            else "http"
        )
        if len(ports) != 1 or ports[0].get("port") != expected[name].get("port") \
                or ports[0].get("targetPort") != target_port:
            raise ValidationError(f"{name} Service port does not match its workload")
    for kind in ("PodDisruptionBudget", "AuthorizationPolicy"):
        for item in by_kind[kind]:
            name = str(item["metadata"]["name"])
            selector = item["spec"].get("selector", {}).get("matchLabels", {})
            if selector.get("app.kubernetes.io/name") != name:
                raise ValidationError(f"{name} {kind} selector does not match its workload")
    for item in by_kind["HorizontalPodAutoscaler"]:
        name = str(item["metadata"]["name"])
        target = item["spec"].get("scaleTargetRef", {})
        if target != {"apiVersion": "apps/v1", "kind": "Deployment", "name": name}:
            raise ValidationError(f"{name} HPA target does not match its workload")
    allow_policies = {
        str(item["metadata"]["name"]): item for item in by_kind["NetworkPolicy"]
        if str(item["metadata"]["name"]).startswith("allow-")
    }
    if set(allow_policies) != {f"allow-{name}" for name in expected}:
        raise ValidationError("static workload NetworkPolicy inventory must match workloads")
    for policy_name, item in allow_policies.items():
        name = policy_name.removeprefix("allow-")
        selector = item["spec"].get("podSelector", {}).get("matchLabels", {})
        if selector.get("app.kubernetes.io/name") != name:
            raise ValidationError(f"{policy_name} selector does not match its workload")


def _validate_workload_policy(root: Path, documents: Mapping[str, Any]) -> None:
    policy = require_mapping(
        documents["platform/kubernetes/workload-policy.json"], "workload policy"
    )
    validate_workload_sources(root, policy)
    images = {
        service["name"]: (
            f"registry.invalid/elmpay/{service['name']}@sha256:"
            + hashlib.sha256(service["name"].encode("utf-8")).hexdigest()
        )
        for service in policy["services"]
    }
    render_workloads(policy, images)
    render_service_controls(
        policy,
        require_mapping(
            documents["platform/kubernetes/service-callers.json"], "service callers"
        ),
    )
    render_regional_data_plane(
        require_mapping(
            documents["platform/kubernetes/data-plane-policy.json"], "data plane policy"
        )
    )
    egress = require_mapping(
        documents["platform/kubernetes/egress-policy.json"], "egress policy"
    )
    render_egress_controls(policy, egress)
    validate_internal_service_egress(
        policy,
        egress,
        require_mapping(
            documents["platform/kubernetes/service-callers.json"], "service callers"
        ),
    )
    validate_risk_service_egress(policy, egress)
    validate_data_plane_destinations(
        egress,
        require_mapping(
            documents["platform/kubernetes/data-plane-policy.json"], "data plane policy"
        ),
    )
    validate_job_database_egress(policy, egress)


def _validate_product_images(root: Path, documents: Mapping[str, Any]) -> None:
    manifest = require_mapping(
        documents["platform/oci/product-images.json"], "product image manifest"
    )
    admission = require_mapping(
        documents["platform/kubernetes/image-admission-policy.json"],
        "image admission policy",
    )
    validate_admission_policy(admission)
    validate_product_image_manifest(
        root,
        manifest,
        require_mapping(
            documents["platform/kubernetes/workload-policy.json"], "workload policy"
        ),
    )


def _validate_security_policies(root: Path, documents: Mapping[str, Any]) -> None:
    del root
    workload = documents["platform/policies/workload-security.json"]
    required = workload["required"]
    for key in (
        "imageDigest",
        "runAsNonRoot",
        "readOnlyRootFilesystem",
        "capabilitiesDropAll",
        "seccompRuntimeDefault",
        "resourceRequestsAndLimits",
        "livenessAndReadinessProbes",
    ):
        if required.get(key) is not True:
            raise ValidationError(f"workload policy must require {key}")
    if required.get("allowPrivilegeEscalation") is not False:
        raise ValidationError("privilege escalation must be denied")
    gitops = documents["platform/policies/gitops.json"]
    if gitops["source"].get("requireSignedCommit") is not True:
        raise ValidationError("GitOps requires signed commits")
    if gitops["drift"].get("blockReleaseWhenPresent") is not True:
        raise ValidationError("GitOps drift must block release")
    mesh = documents["platform/policies/service-mesh.json"]
    if mesh.get("mtlsMode") != "STRICT" or mesh.get("plaintextFallbackAllowed") is not False:
        raise ValidationError("mesh policy must deny plaintext fallback")
    residency = documents["platform/policies/data-residency.json"]
    if residency.get("defaultAction") != "DENY":
        raise ValidationError("data residency must default deny")
    events = documents["platform/policies/event-resilience.json"]
    if events.get("consumerIdempotencyRequired") is not True or events["deadLetter"].get("replayRequiresDistinctApprover") is not True:
        raise ValidationError("event replay requires idempotency and independent approval")
    cache = documents["platform/policies/cache-resilience.json"]
    if cache.get("cacheIsSourceOfTruth") is not False or cache.get("failOpenAllowed") is not False:
        raise ValidationError("cache must not be authoritative or fail open")
    provider = documents["platform/policies/provider-resilience.json"]
    if provider.get("unknownStateAction") != "BLOCK_NEW_ROUTING":
        raise ValidationError("unknown provider health must block new routing")
    edge = documents["platform/policies/edge-security.json"]
    if (
        edge.get("unknownTenantAction") != "DENY"
        or edge.get("stateUnavailableAction") != "DENY"
        or edge.get("replayStateRequired") is not True
        or not edge.get("trustedProxyCidrs")
    ):
        raise ValidationError("edge security must fail closed with durable replay state")
    risk = documents["platform/risk/runtime-policy.json"]
    if (
        risk.get("modelUnavailableAction") != "REVIEW"
        or risk.get("missingSignalAction") != "REVIEW"
        or risk.get("crossTenantAction") != "DENY"
        or risk.get("ruleActivationRequiresDistinctApprover") is not True
        or risk.get("operationsRequireDistinctApprover") is not True
        or risk.get("auditChainRequired") is not True
    ):
        raise ValidationError("risk runtime must fail closed and require four-eyes audit")


def _validate_observability(root: Path, documents: Mapping[str, Any]) -> None:
    del root
    collector = documents["platform/observability/collector.json"]
    actions = collector["processors"]["attributes/redact"]["actions"]
    deleted = {action["key"] for action in actions if action.get("action") == "delete"}
    required_deleted = {
        "payment.card.number",
        "payment.card.cvv",
        "http.request.header.authorization",
        "enduser.email",
        "db.statement",
    }
    if not required_deleted <= deleted:
        raise ValidationError("collector redaction set is incomplete")
    for exporter in collector["exporters"].values():
        if exporter.get("tls", {}).get("insecure") is not False:
            raise ValidationError("telemetry exporters must use verified TLS")
    for pipeline in collector["service"]["pipelines"].values():
        processors = pipeline.get("processors", [])
        if "attributes/redact" not in processors or "memory_limiter" not in processors:
            raise ValidationError("every telemetry pipeline must redact and bound memory")
    slos = documents["platform/observability/slos.json"]
    for slo in require_list(slos.get("services"), "SLO services"):
        objective = slo.get("objective")
        if not isinstance(objective, (int, float)) or not 0 < objective < 1:
            raise ValidationError("SLO objective must be between zero and one")
        if not slo.get("burnRates"):
            raise ValidationError("every SLO needs burn-rate windows")
    capacity = documents["platform/observability/capacity.json"]
    if capacity.get("minimumHeadroomRatio", 0) < 0.30 or not capacity.get("resources"):
        raise ValidationError("capacity policy must require measured headroom")


def _validate_alerts(root: Path, documents: Mapping[str, Any]) -> None:
    prometheus = documents["platform/alerts/prometheus-rules.json"]
    rules = [rule for group in prometheus["groups"] for rule in group["rules"]]
    if not rules:
        raise ValidationError("at least one alert rule is required")
    records = [rule.get("record") for rule in rules if "record" in rule]
    if len(records) != len(set(records)):
        raise ValidationError("Prometheus recording rule names must be unique")
    for rule in (item for item in rules if "alert" in item):
        runbook = rule.get("annotations", {}).get("runbook")
        if not isinstance(runbook, str):
            raise ValidationError(f"alert {rule.get('alert')} lacks a runbook")
        target = runbook.split("#", maxsplit=1)[0]
        if not (root / target).is_file():
            raise ValidationError(f"alert runbook does not exist: {target}")
    siem = documents["platform/alerts/siem-rules.json"]
    identifiers = [rule["id"] for rule in siem["rules"]]
    if len(identifiers) != len(set(identifiers)):
        raise ValidationError("SIEM rule identifiers must be unique")


def _validate_dr(root: Path, documents: Mapping[str, Any]) -> None:
    del root
    plan = documents["platform/dr/plan.json"]
    if plan.get("rpoSeconds", 0) <= 0 or plan.get("rtoSeconds", 0) <= 0:
        raise ValidationError("DR RPO and RTO must be positive")
    if plan.get("minimumRegions", 0) < 2:
        raise ValidationError("DR requires at least two regions")
    promotion = plan["promotion"]
    if promotion.get("automatic") is not False or promotion.get("requiresDistinctApprovers", 0) < 2:
        raise ValidationError("DR promotion must be manual and four-eyes")
    if plan["exercises"].get("externalEvidenceRequired") is not True:
        raise ValidationError("DR exercise must require external evidence")


def _validate_rollout(root: Path, documents: Mapping[str, Any]) -> None:
    del root
    policy = documents["platform/rollout/policy.json"]
    traffic = [stage["trafficPercent"] for stage in policy["stages"]]
    if traffic != sorted(traffic) or traffic[0] != 0 or traffic[-1] != 100:
        raise ValidationError("rollout traffic stages must progress from shadow to 100 percent")
    stops = policy["autoStop"]
    for key in ("ledgerMismatchCount", "duplicateSideEffectCount", "securityCriticalCount"):
        if stops.get(key) != 0:
            raise ValidationError(f"{key} must auto-stop on the first event")
    if policy["goNoGo"].get("requireExternalEvidence") is not True:
        raise ValidationError("Go/No-Go must require external evidence")
    billing = documents["platform/rollout/billing-policy.json"]
    names = [meter["name"] for meter in billing["meters"]]
    if len(names) != len(set(names)):
        raise ValidationError("billing meter names must be unique")


def _validate_compliance(root: Path, documents: Mapping[str, Any]) -> None:
    del root
    lifecycle = documents["platform/compliance/data-lifecycle.json"]
    if lifecycle.get("defaultAction") != "DENY_DELETE":
        raise ValidationError("data lifecycle must default deny deletion")
    for item in lifecycle["classes"]:
        if item["minimumDays"] > item["maximumDays"]:
            raise ValidationError(f"retention range invalid for {item['name']}")
    if not all(lifecycle["deletion"].values()):
        raise ValidationError("all destructive deletion controls are mandatory")
    vulnerability = documents["platform/compliance/vulnerability-policy.json"]
    if vulnerability.get("blockUnknownScanState") is not True:
        raise ValidationError("unknown vulnerability scan state must block")
    vendor = documents["platform/compliance/vendor-policy.json"]
    if vendor.get("defaultAction") != "BLOCK_ONBOARDING":
        raise ValidationError("vendor onboarding must default block")
    supply_chain = documents["platform/compliance/supply-chain-policy.json"]
    if (
        supply_chain.get("signatureAlgorithm") != "Ed25519"
        or supply_chain.get("signatureEnvelope") != "DSSE"
        or supply_chain.get("unknownOrMissingAction") != "BLOCK_RELEASE"
        or supply_chain.get("allowedBuilders") != [
            "https://github.com/zpcaiai/elmpay/.github/workflows/ci.yml"
        ]
        or not supply_chain.get("requiredMaterials")
    ):
        raise ValidationError("supply-chain provenance must be Ed25519 DSSE and fail closed")
    matrix = documents["platform/compliance/control-matrix.json"]
    if matrix["certification"].get("localValidationMayCertify") is not False:
        raise ValidationError("local validation cannot certify compliance")
    gates = documents["platform/compliance/required-release-gates.json"]
    if gates.get("minimumDistinctApprovers", 0) < 2:
        raise ValidationError("release gate must require distinct approvers")
    if not gates.get("requiredEvidence"):
        raise ValidationError("release gate requires external evidence categories")
    if gates.get("externalEvidenceRequired") is not True:
        raise ValidationError("release gate must require the external evidence bundle")
    if gates.get("productImageIndexRequired") is not True:
        raise ValidationError("release gate must require the exact product image index")
    if gates.get("productImageManifestDigest") != product_image_manifest_digest(
        require_mapping(documents["platform/oci/product-images.json"], "product image manifest")
    ):
        raise ValidationError("release gate product image manifest digest is stale")
    if gates.get("imageAdmissionPolicyDigest") != admission_policy_digest(
        require_mapping(
            documents["platform/kubernetes/image-admission-policy.json"],
            "image admission policy",
        )
    ):
        raise ValidationError("release gate image admission policy digest is stale")
    external = documents["platform/compliance/external-evidence-policy.json"]
    if external.get("schemaVersion") != 1 or external.get("status") != "NOT_CERTIFIED":
        raise ValidationError("external evidence policy must remain schema v1 and NOT_CERTIFIED")
    if external.get("localValidationMayCertify") is not False or external.get("independentEvidenceRequired") is not True:
        raise ValidationError("external evidence policy must be independent and fail closed")
    if external.get("minimumDistinctVerifiers", 0) < 2:
        raise ValidationError("external evidence must require two distinct verifiers")
    categories = external.get("requiredCategories")
    if not isinstance(categories, dict) or len(categories) < 10:
        raise ValidationError("external evidence category policy is incomplete")
    for name, category in categories.items():
        if not isinstance(category, dict) or category.get("category") != name:
            raise ValidationError(f"external evidence category metadata invalid: {name}")
        if category.get("requiredRole") != "external_verifier" or category.get("externalVerifierRequired") is not True:
            raise ValidationError(f"external evidence category must require external verifier: {name}")
        if not isinstance(category.get("requiredFields"), list) or not category["requiredFields"]:
            raise ValidationError(f"external evidence fields missing: {name}")
    regional = documents["platform/compliance/regional-boundaries.json"]
    if regional.get("unknownMarketAction") != "BLOCK_ONBOARDING" or regional.get("localConfigurationMayApproveMarket") is not False:
        raise ValidationError("regional onboarding must fail closed pending external legal review")
    aml = documents["platform/compliance/aml-boundary.json"]
    if aml["suspiciousActivityReporting"].get("automatedFilingAllowed") is not False:
        raise ValidationError("regulatory filing cannot be automatically approved")
