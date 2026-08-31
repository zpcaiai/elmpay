"""Fail-closed B89 Kubernetes and service-mesh egress policy renderer."""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Mapping

from .common import ValidationError, require_exact_keys, require_list, require_mapping, require_text


DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
LABEL_KEY = re.compile(r"^(?:[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?/)?"
                       r"[A-Za-z0-9](?:[-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$")
LABEL_VALUE = re.compile(r"^$|^[A-Za-z0-9](?:[-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$")
CATEGORIES = frozenset({
    "PSP", "DATABASE", "KAFKA", "REDIS", "KMS", "OTEL", "INTERNAL_API",
    "RISK_SIGNAL", "RISK_MODEL",
})
EXTERNAL_SUFFIX_DENYLIST = (
    ".cluster.local", ".internal", ".invalid", ".local", ".localhost",
    ".onion", ".svc", ".test", ".example",
)


def render_egress_controls(workload_policy: Mapping[str, Any],
                           egress_policy: Mapping[str, Any]) -> dict[str, Any]:
    """Render exact workload egress without admitting a caller-provided wildcard.

    Standard NetworkPolicy enforces pod/CIDR reachability. Cilium FQDN policy
    constrains DNS queries and the IPs learned from those answers. Istio
    ``REGISTRY_ONLY`` and exact ServiceEntries provide a second, identity-aware
    boundary for external TLS destinations.
    """
    require_exact_keys(
        egress_policy,
        required={"schemaVersion", "namespace", "dns", "destinations", "workloads"},
        optional=set(),
        field="egress policy",
    )
    if egress_policy.get("schemaVersion") != 1:
        raise ValidationError("egress policy schemaVersion must be 1")
    namespace = _dns_label(egress_policy.get("namespace"), "namespace")
    if namespace != require_text(workload_policy.get("namespace"), "workload namespace"):
        raise ValidationError("egress policy namespace must match the workload policy")
    workload_names = _workload_names(workload_policy)
    dns = _dns_configuration(egress_policy.get("dns"))
    workload_dns = _dns_configuration(workload_policy.get("dnsEgress"))
    if workload_dns != dns:
        raise ValidationError("workload and egress DNS selectors must match exactly")
    destinations = _destinations(egress_policy.get("destinations"))
    if {item["category"] for item in destinations.values()} != CATEGORIES:
        raise ValidationError(
            "egress destinations must cover PSP, DB, Kafka, Redis, KMS, OTel, "
            "internal API, risk signal and risk model"
        )
    assignments = _assignments(egress_policy.get("workloads"), workload_names, destinations)
    _validate_internal_destination_targets(
        workload_names, namespace, destinations
    )
    validate_risk_service_egress(workload_policy, egress_policy)
    _validate_health_only_assignments(workload_policy, assignments, destinations)

    items: list[dict[str, Any]] = [_default_deny(namespace)]
    for workload in sorted(workload_names):
        selected = [destinations[item] for item in assignments[workload]]
        items.append(_network_policy(namespace, workload, dns, selected))
        items.append(_cilium_policy(namespace, workload, dns, selected))
        items.append(_sidecar(namespace, workload, selected))
    for destination in sorted(destinations.values(), key=lambda item: str(item["id"])):
        if destination["type"] == "fqdn":
            items.extend(_external_tls_resources(namespace, destination))
    return {"apiVersion": "v1", "kind": "List", "items": items}


def validate_internal_service_egress(
    workload_policy: Mapping[str, Any],
    egress_policy: Mapping[str, Any],
    allowed_callers: Mapping[str, Any],
) -> None:
    """Bind mesh caller authorization to exact INTERNAL_API egress routes.

    NetworkPolicy/Sidecar egress and Istio AuthorizationPolicy ingress are two
    halves of one service call.  Validating them independently can leave a
    declared caller authorized at the destination but unable to reach it (or a
    workload with an undeclared route to an internal service).  This check
    requires the two policy documents to describe precisely the same graph.
    """

    workload_names = _workload_names(workload_policy)
    namespace = _dns_label(workload_policy.get("namespace"), "workload namespace")
    if namespace != _dns_label(egress_policy.get("namespace"), "egress namespace"):
        raise ValidationError("egress namespace must match the workload namespace")
    if set(allowed_callers) != workload_names:
        raise ValidationError("mesh caller map must exactly cover every workload")

    callers_by_target: dict[str, set[str]] = {}
    exposed_business_services = {
        require_text(service.get("name"), "service.name")
        for service in (
            require_mapping(item, "workload service")
            for item in require_list(workload_policy.get("services"), "workload services")
        )
        if service.get("exposeService", True) is True
        and service.get("healthOnly", False) is False
    }
    for target in sorted(workload_names):
        raw_callers = require_list(allowed_callers[target], f"{target} callers")
        if any(not isinstance(caller, str) or caller not in workload_names
               for caller in raw_callers) \
                or len(raw_callers) != len(set(raw_callers)):
            raise ValidationError(f"{target} caller list is invalid")
        if target in raw_callers:
            raise ValidationError(f"{target} cannot authorize itself as a mesh caller")
        callers_by_target[target] = set(raw_callers)

    destinations = _destinations(egress_policy.get("destinations"))
    _validate_internal_destination_targets(
        workload_names, namespace, destinations
    )
    assignments = _assignments(
        egress_policy.get("workloads"), workload_names, destinations
    )
    internal_by_target = {
        str(destination["targetWorkload"]): identifier
        for identifier, destination in destinations.items()
        if destination["category"] == "INTERNAL_API"
    }
    for target in sorted(workload_names):
        destination_id = internal_by_target.get(target)
        if destination_id is not None and (
                target not in exposed_business_services or not callers_by_target[target]):
            raise ValidationError(
                f"{target} has an orphaned or non-business INTERNAL_API destination"
            )
        actual_callers = (
            {
                workload
                for workload, assigned in assignments.items()
                if destination_id in assigned
            }
            if destination_id is not None
            else set()
        )
        if actual_callers != callers_by_target[target]:
            raise ValidationError(
                f"{target} mesh callers and INTERNAL_API egress routes differ"
            )


def validate_risk_service_egress(
    workload_policy: Mapping[str, Any],
    egress_policy: Mapping[str, Any],
) -> None:
    """Bind the risk runtime endpoints to its exact least-privilege routes.

    Merely assigning a ``RISK_SIGNAL`` category is insufficient: a poisoned
    ConfigMap could otherwise redirect the client to a different service that
    happens to be reachable.  The runtime endpoints, Kubernetes service
    selectors and edge-to-risk endpoint are therefore one fail-closed graph.
    """

    workload_names = _workload_names(workload_policy)
    if "risk-engine" not in workload_names or "edge-gateway" not in workload_names:
        raise ValidationError("risk egress requires risk-engine and edge-gateway workloads")
    services = {
        require_text(service.get("name"), "service.name"): service
        for service in (
            require_mapping(item, "workload service")
            for item in require_list(workload_policy.get("services"), "workload services")
        )
    }
    risk_configuration = require_mapping(
        services["risk-engine"].get("configuration"), "risk-engine.configuration"
    )
    risk_config = require_mapping(
        risk_configuration.get("configMapData"), "risk-engine.configuration.configMapData"
    )
    if risk_config.get("ELMPAY_RISK_DEPENDENCY_TIMEOUT_MILLISECONDS") != "100":
        raise ValidationError(
            "risk signal and model transports must each use the fixed 100ms dependency budget"
        )
    edge_fixed = require_mapping(
        services["edge-gateway"].get("fixedEnvironment"),
        "edge-gateway.fixedEnvironment",
    )

    destinations = _destinations(egress_policy.get("destinations"))
    assignments = _assignments(
        egress_policy.get("workloads"), workload_names, destinations
    )
    requirements = {
        "RISK_SIGNAL": (
            "risk-signal-service", "risk-platform", "risk-signal",
            "ELMPAY_RISK_SIGNAL_ENDPOINT", "/v1/risk/signals",
            "ELMPAY_RISK_SIGNAL_READINESS_ENDPOINT",
        ),
        "RISK_MODEL": (
            "risk-model-service", "risk-platform", "risk-model",
            "ELMPAY_RISK_MODEL_ENDPOINT", "/v1/risk/model-score",
            "ELMPAY_RISK_MODEL_READINESS_ENDPOINT",
        ),
    }
    for category, requirement in requirements.items():
        (identifier, namespace, service_name, endpoint_key, endpoint_path,
         readiness_key) = requirement
        matching = [
            destination for destination in destinations.values()
            if destination["category"] == category
        ]
        if len(matching) != 1:
            raise ValidationError(f"{category} must have exactly one destination")
        destination = matching[0]
        if destination != {
            "id": identifier,
            "category": category,
            "type": "service",
            "port": 8443,
            "protocol": "TLS",
            "namespace": namespace,
            "serviceName": service_name,
            "serviceNames": [service_name],
            "dnsNames": [f"{service_name}.{namespace}.svc.cluster.local"],
            "podLabels": {"app.kubernetes.io/name": service_name},
        }:
            raise ValidationError(f"{category} does not select its exact mTLS service")
        expected_origin = f"https://{service_name}.{namespace}.svc.cluster.local:8443"
        if risk_config.get(endpoint_key) != expected_origin + endpoint_path \
                or risk_config.get(readiness_key) != expected_origin + "/health/ready":
            raise ValidationError(f"{category} runtime endpoints differ from egress policy")
        assigned = {
            workload for workload, identifiers in assignments.items()
            if identifier in identifiers
        }
        if assigned != {"risk-engine"}:
            raise ValidationError(f"{category} may only be assigned to risk-engine")

    internal = [
        destination for destination in destinations.values()
        if destination.get("category") == "INTERNAL_API"
        and destination.get("targetWorkload") == "risk-engine"
    ]
    if len(internal) != 1:
        raise ValidationError("risk-engine must have exactly one INTERNAL_API destination")
    risk_origin = "https://risk-engine.{}.svc.cluster.local:8443".format(
        require_text(workload_policy.get("namespace"), "workload namespace")
    )
    if edge_fixed.get("ELMPAY_RISK_ENDPOINT") != risk_origin + "/v1/risk/decisions":
        raise ValidationError("edge risk endpoint must be fixed to the risk-engine Service")
    if edge_fixed.get("ELMPAY_RISK_TIMEOUT_MILLISECONDS") != "300":
        raise ValidationError("edge risk timeout must preserve the 300ms request budget")


def validate_data_plane_destinations(egress_policy: Mapping[str, Any],
                                     data_plane_policy: Mapping[str, Any]) -> None:
    """Bind database/Kafka egress names and broker DNS to rendered primary-region CRDs."""

    destinations = _destinations(egress_policy.get("destinations"))
    regions = [require_mapping(item, "data plane region") for item in require_list(
        data_plane_policy.get("regions"), "data plane regions"
    )]
    primary_regions = [item for item in regions if item.get("primary") is True]
    if len(primary_regions) != 1:
        raise ValidationError("data plane must declare exactly one primary region")
    primary = _dns_label(primary_regions[0].get("name"), "primary region name")
    namespace = f"elmpay-{primary}"
    postgres = destinations.get("postgres-primary")
    if postgres is None or postgres != {
        "id": "postgres-primary",
        "category": "DATABASE",
        "type": "service",
        "port": 5432,
        "protocol": "TLS",
        "namespace": namespace,
        "serviceName": "payments-postgres-rw",
        "serviceNames": ["payments-postgres-rw"],
        "dnsNames": [f"payments-postgres-rw.{namespace}.svc.cluster.local"],
        "podLabels": {"cnpg.io/cluster": "payments-postgres"},
    }:
        raise ValidationError("postgres-primary egress does not match the rendered primary CRD")

    kafka_policy = require_mapping(data_plane_policy.get("kafka"), "data plane kafka")
    brokers = _integer(kafka_policy.get("brokers"), "kafka.brokers", 3, 16)
    broker_service = "payments-events-kafka-brokers"
    kafka = destinations.get("kafka-events")
    expected_dns = [
        f"payments-events-kafka-bootstrap.{namespace}.svc.cluster.local",
        f"{broker_service}.{namespace}.svc.cluster.local",
        *[
            f"payments-events-kafka-{index}.{broker_service}.{namespace}.svc.cluster.local"
            for index in range(brokers)
        ],
    ]
    if kafka is None or kafka != {
        "id": "kafka-events",
        "category": "KAFKA",
        "type": "service",
        "port": 9093,
        "protocol": "TLS",
        "namespace": namespace,
        "serviceName": "payments-events-kafka-bootstrap",
        "serviceNames": ["payments-events-kafka-bootstrap", broker_service],
        "dnsNames": expected_dns,
        "podLabels": {"strimzi.io/cluster": "payments-events"},
    }:
        raise ValidationError("kafka-events egress does not match the rendered primary CRD")


def validate_job_database_egress(workload_policy: Mapping[str, Any],
                                 egress_policy: Mapping[str, Any]) -> None:
    """Bind one-shot database jobs to the canonical primary service and selector.

    Job NetworkPolicies are rendered outside the long-running workload egress graph.  Without
    this cross-document check a migration job can name a different namespace, selector or JDBC
    host while both policy files remain individually valid.
    """

    postgres = _destinations(egress_policy.get("destinations")).get("postgres-primary")
    if postgres is None:
        raise ValidationError("database jobs require the canonical postgres-primary destination")
    expected_egress = {
        "namespace": postgres["namespace"],
        "podLabels": postgres["podLabels"],
        "port": postgres["port"],
    }
    expected_url = (
        f"jdbc:postgresql://{postgres['serviceName']}.{postgres['namespace']}"
        f".svc.cluster.local:{postgres['port']}/elmpay"
    )
    jobs = [
        *require_list(workload_policy.get("jobs", []), "workload jobs"),
        *require_list(workload_policy.get("cronJobs", []), "workload cronJobs"),
    ]
    if not jobs:
        raise ValidationError("database schema changes require a declared migration job")
    for raw_job in jobs:
        job = require_mapping(raw_job, "workload job")
        name = _dns_label(job.get("name"), "job.name")
        if require_mapping(job.get("databaseEgress"), f"{name}.databaseEgress") \
                != expected_egress:
            raise ValidationError(f"{name} database egress differs from postgres-primary")
        configuration = require_mapping(job.get("configuration"), f"{name}.configuration")
        data = require_mapping(
            configuration.get("configMapData"), f"{name}.configuration.configMapData"
        )
        url_keys = [key for key in data if key.endswith("DATABASE_URL")]
        if len(url_keys) != 1 or data[url_keys[0]] != expected_url:
            raise ValidationError(f"{name} JDBC URL differs from postgres-primary")


def _workload_names(policy: Mapping[str, Any]) -> set[str]:
    services = require_list(policy.get("services"), "workload services")
    names = [_dns_label(require_mapping(item, "workload service").get("name"), "service.name")
             for item in services]
    if not names or len(names) != len(set(names)):
        raise ValidationError("workload service names must be unique")
    return set(names)


def _dns_configuration(raw: Any) -> dict[str, Any]:
    value = require_mapping(raw, "dns")
    require_exact_keys(value, required={"namespace", "podLabels"}, optional=set(), field="dns")
    return {
        "namespace": _dns_label(value.get("namespace"), "dns.namespace"),
        "podLabels": _labels(value.get("podLabels"), "dns.podLabels"),
    }


def _destinations(raw: Any) -> dict[str, dict[str, Any]]:
    values = require_list(raw, "destinations")
    if not values or len(values) > 128:
        raise ValidationError("egress destinations must contain 1..128 entries")
    indexed: dict[str, dict[str, Any]] = {}
    for raw_destination in values:
        destination = require_mapping(raw_destination, "destination")
        destination_type = require_text(destination.get("type"), "destination.type")
        common = {"id", "category", "type", "port", "protocol"}
        allowed_optional: set[str]
        if destination_type == "fqdn":
            allowed_optional = {"mtlsCredentialName"}
            required = common | {"host"}
        elif destination_type == "service":
            allowed_optional = {
                "additionalServiceNames", "dnsNames", "targetWorkload",
            }
            required = common | {"namespace", "serviceName", "podLabels"}
        elif destination_type == "cidr":
            allowed_optional = set()
            required = common | {"cidr", "except"}
        else:
            raise ValidationError("destination.type must be fqdn, service or cidr")
        require_exact_keys(
            destination, required=required, optional=allowed_optional, field="destination"
        )
        identifier = _dns_label(destination.get("id"), "destination.id")
        category = require_text(destination.get("category"), "destination.category")
        if category not in CATEGORIES:
            raise ValidationError("destination category is unsupported")
        port = _integer(destination.get("port"), "destination.port", 1, 65_535)
        protocol = require_text(destination.get("protocol"), "destination.protocol")
        if protocol not in {"TCP", "TLS"}:
            raise ValidationError("destination protocol must be TCP or TLS")
        if category in {
            "PSP", "KMS", "INTERNAL_API", "RISK_SIGNAL", "RISK_MODEL",
        } and protocol != "TLS":
            raise ValidationError(
                "PSP, KMS, internal API and risk-service destinations require TLS"
            )
        normalized: dict[str, Any] = {
            "id": identifier, "category": category, "type": destination_type,
            "port": port, "protocol": protocol,
        }
        if destination_type == "fqdn":
            if port != 443 or protocol != "TLS":
                raise ValidationError("external FQDN egress is restricted to TLS port 443")
            normalized["host"] = _external_fqdn(destination.get("host"))
            credential = destination.get("mtlsCredentialName")
            if credential is not None:
                normalized["mtlsCredentialName"] = _dns_label(
                    credential, "destination.mtlsCredentialName"
                )
        elif destination_type == "service":
            service_namespace = _dns_label(
                destination.get("namespace"), "destination.namespace"
            )
            primary_service = _dns_label(
                destination.get("serviceName"), "destination.serviceName"
            )
            additional_services = [
                _dns_label(item, "destination.additionalServiceNames")
                for item in require_list(
                    destination.get("additionalServiceNames", []),
                    "destination.additionalServiceNames",
                )
            ]
            service_names = [primary_service, *additional_services]
            if len(service_names) > 8 or len(service_names) != len(set(service_names)):
                raise ValidationError("service destination names must be unique and bounded")
            declared_dns_names = [
                _internal_service_fqdn(item, service_namespace, service_names)
                for item in require_list(
                    destination.get("dnsNames", []), "destination.dnsNames"
                )
            ]
            service_dns_names = [
                f"{service}.{service_namespace}.svc.cluster.local"
                for service in service_names
            ]
            dns_names = [*service_dns_names, *declared_dns_names]
            if len(dns_names) > 40 or len(dns_names) != len(set(dns_names)):
                raise ValidationError("service destination DNS names must be unique and bounded")
            normalized.update({
                "namespace": service_namespace,
                "serviceName": primary_service,
                "serviceNames": service_names,
                "dnsNames": dns_names,
                "podLabels": _labels(destination.get("podLabels"), "destination.podLabels"),
            })
            target_workload = destination.get("targetWorkload")
            if category == "INTERNAL_API":
                normalized["targetWorkload"] = _dns_label(
                    target_workload, "destination.targetWorkload"
                )
            elif target_workload is not None:
                raise ValidationError(
                    "targetWorkload is reserved for INTERNAL_API destinations"
                )
        else:
            network = _network(destination.get("cidr"))
            exceptions = [_network(item) for item in require_list(
                destination.get("except"), "destination.except"
            )]
            if any(item.version != network.version or not item.subnet_of(network)
                   or item.prefixlen <= network.prefixlen for item in exceptions):
                raise ValidationError("CIDR exceptions must be proper subnets of their destination")
            normalized["cidr"] = str(network)
            normalized["except"] = [str(item) for item in exceptions]
        if identifier in indexed:
            raise ValidationError("egress destination IDs must be unique")
        indexed[identifier] = normalized
    return indexed


def _validate_internal_destination_targets(
    workload_names: set[str], namespace: str,
    destinations: Mapping[str, Mapping[str, Any]],
) -> None:
    targets: set[str] = set()
    for destination in destinations.values():
        if destination["category"] != "INTERNAL_API":
            continue
        if destination["type"] != "service":
            raise ValidationError("INTERNAL_API destinations must use the service type")
        target = str(destination["targetWorkload"])
        if target not in workload_names:
            raise ValidationError("INTERNAL_API targetWorkload is not a workload")
        if target in targets:
            raise ValidationError("each workload may have only one INTERNAL_API destination")
        if destination["namespace"] != namespace \
                or destination["serviceName"] != target \
                or destination["serviceNames"] != [target] \
                or destination["podLabels"] != {"app.kubernetes.io/name": target}:
            raise ValidationError(
                "INTERNAL_API destination must exactly select its target workload Service"
            )
        targets.add(target)


def _assignments(raw: Any, workloads: set[str],
                 destinations: Mapping[str, Mapping[str, Any]]) -> dict[str, list[str]]:
    values = require_mapping(raw, "workloads")
    if set(values) != workloads:
        raise ValidationError("egress workload map must exactly cover every workload")
    result: dict[str, list[str]] = {}
    referenced: set[str] = set()
    for workload in sorted(workloads):
        assigned = require_list(values[workload], f"workloads.{workload}")
        if not assigned or len(assigned) != len(set(assigned)):
            raise ValidationError(f"{workload} egress destinations must be non-empty and unique")
        if any(not isinstance(item, str) or item not in destinations for item in assigned):
            raise ValidationError(f"{workload} references an unknown egress destination")
        result[workload] = list(assigned)
        referenced.update(assigned)
    if referenced != set(destinations):
        raise ValidationError("every declared egress destination must be assigned")
    return result


def _validate_health_only_assignments(
    workload_policy: Mapping[str, Any], assignments: Mapping[str, list[str]],
    destinations: Mapping[str, Mapping[str, Any]],
) -> None:
    for raw_service in require_list(workload_policy.get("services"), "workload services"):
        service = require_mapping(raw_service, "workload service")
        name = _dns_label(service.get("name"), "service.name")
        health_only = service.get("healthOnly", False)
        categories_value = service.get("allowedEgressCategories")
        if not isinstance(health_only, bool):
            raise ValidationError(f"{name}.healthOnly must be a boolean")
        if not health_only:
            if categories_value is not None:
                raise ValidationError(
                    f"{name}.allowedEgressCategories is reserved for health-only workloads"
                )
            continue
        if service.get("exposeService") is not False:
            raise ValidationError(f"{name} health-only workload must not expose a Service")
        categories = require_list(
            categories_value, f"{name}.allowedEgressCategories"
        )
        if not categories or any(not isinstance(category, str) for category in categories) \
                or len(categories) != len(set(categories)) \
                or any(category not in CATEGORIES for category in categories):
            raise ValidationError(f"{name} allowed egress categories are invalid")
        selected = {str(destinations[item]["category"]) for item in assignments[name]}
        if selected != set(categories) or any(
                destinations[item]["type"] != "service" for item in assignments[name]
        ):
            raise ValidationError(
                f"{name} health-only egress must exactly match declared service categories"
            )


def _default_deny(namespace: str) -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "egress-default-deny", "namespace": namespace},
        "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": []},
    }


def _network_policy(namespace: str, workload: str, dns: Mapping[str, Any],
                    destinations: list[Mapping[str, Any]]) -> dict[str, Any]:
    categories = sorted({str(item["category"]) for item in destinations})
    rules: list[dict[str, Any]] = [{
        "to": [{
            "namespaceSelector": {"matchLabels": {
                "kubernetes.io/metadata.name": dns["namespace"],
            }},
            "podSelector": {"matchLabels": dns["podLabels"]},
        }],
        "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}],
    }]
    for item in destinations:
        port = {"protocol": "TCP", "port": item["port"]}
        if item["type"] == "service":
            rules.append({
                "to": [{
                    "namespaceSelector": {"matchLabels": {
                        "kubernetes.io/metadata.name": item["namespace"],
                    }},
                    "podSelector": {"matchLabels": item["podLabels"]},
                }],
                "ports": [port],
            })
        elif item["type"] == "cidr":
            rules.append({"to": [{"ipBlock": {
                "cidr": item["cidr"], "except": item["except"],
            }}], "ports": [port]})
    return {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {
            "name": f"allow-controlled-egress-{workload}", "namespace": namespace,
            "annotations": {
                "elmpay.io/categories": ",".join(categories),
                "elmpay.io/destination-ids": ",".join(
                    sorted(str(item["id"]) for item in destinations)
                ),
            },
        },
        "spec": {
            "podSelector": {"matchLabels": {"app.kubernetes.io/name": workload}},
            "policyTypes": ["Egress"], "egress": rules,
        },
    }


def _cilium_policy(namespace: str, workload: str, dns: Mapping[str, Any],
                   destinations: list[Mapping[str, Any]]) -> dict[str, Any]:
    fqdn_destinations = [item for item in destinations if item["type"] == "fqdn"]
    dns_names = sorted(
        {str(item["host"]) for item in fqdn_destinations}
        | {
            str(name)
            for item in destinations if item["type"] == "service"
            for name in item["dnsNames"]
        }
    )
    dns_rule: dict[str, Any] = {
        "toEndpoints": [{"matchLabels": {
            "k8s:io.kubernetes.pod.namespace": dns["namespace"],
            **{f"k8s:{key}": value for key, value in dns["podLabels"].items()},
        }}],
        "toPorts": [{
            "ports": [{"port": "53", "protocol": "UDP"},
                      {"port": "53", "protocol": "TCP"}],
            "rules": {"dns": [{"matchName": name} for name in dns_names]},
        }],
    }
    egress = [dns_rule]
    egress.extend({
        "toFQDNs": [{"matchName": item["host"]}],
        "toPorts": [{"ports": [{"port": str(item["port"]), "protocol": "TCP"}]}],
    } for item in fqdn_destinations)
    return {
        "apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
        "metadata": {"name": f"fqdn-egress-{workload}", "namespace": namespace},
        "spec": {
            "endpointSelector": {"matchLabels": {"app.kubernetes.io/name": workload}},
            "egress": egress,
        },
    }


def _sidecar(namespace: str, workload: str,
             destinations: list[Mapping[str, Any]]) -> dict[str, Any]:
    hosts = []
    for item in destinations:
        if item["type"] == "service":
            hosts.extend(
                f'{item["namespace"]}/{service}.{item["namespace"]}.svc.cluster.local'
                for service in item["serviceNames"]
            )
        elif item["type"] == "fqdn":
            hosts.append(f'./{item["host"]}')
    return {
        "apiVersion": "networking.istio.io/v1", "kind": "Sidecar",
        "metadata": {"name": f"registry-only-{workload}", "namespace": namespace},
        "spec": {
            "workloadSelector": {"labels": {"app.kubernetes.io/name": workload}},
            "outboundTrafficPolicy": {"mode": "REGISTRY_ONLY"},
            "egress": [{"hosts": sorted(hosts)}],
        },
    }


def _external_tls_resources(namespace: str, destination: Mapping[str, Any]
                            ) -> list[dict[str, Any]]:
    identifier = str(destination["id"])
    host = str(destination["host"])
    tls: dict[str, Any] = {"mode": "SIMPLE", "sni": host}
    if "mtlsCredentialName" in destination:
        tls = {
            "mode": "MUTUAL", "sni": host,
            "credentialName": destination["mtlsCredentialName"],
        }
    return [
        {
            "apiVersion": "networking.istio.io/v1", "kind": "ServiceEntry",
            "metadata": {"name": identifier, "namespace": namespace},
            "spec": {
                "hosts": [host], "location": "MESH_EXTERNAL", "resolution": "DNS",
                "exportTo": ["."],
                "ports": [{"number": destination["port"], "name": "tls-443", "protocol": "TLS"}],
            },
        },
        {
            "apiVersion": "networking.istio.io/v1", "kind": "DestinationRule",
            "metadata": {"name": identifier, "namespace": namespace},
            "spec": {
                "host": host,
                "trafficPolicy": {
                    "tls": tls,
                    "connectionPool": {"tcp": {"connectTimeout": "2s", "maxConnections": 128}},
                    "outlierDetection": {
                        "consecutive5xxErrors": 5, "interval": "5s", "baseEjectionTime": "30s",
                        "maxEjectionPercent": 100,
                    },
                },
            },
        },
    ]


def _labels(raw: Any, field: str) -> dict[str, str]:
    values = require_mapping(raw, field)
    if not values or len(values) > 16:
        raise ValidationError(f"{field} must contain 1..16 labels")
    result: dict[str, str] = {}
    for key, value in values.items():
        if not isinstance(key, str) or not LABEL_KEY.fullmatch(key):
            raise ValidationError(f"{field} contains an invalid label key")
        if not isinstance(value, str) or not LABEL_VALUE.fullmatch(value):
            raise ValidationError(f"{field} contains an invalid label value")
        result[key] = value
    return result


def _network(raw: Any) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    value = require_text(raw, "destination.cidr")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exception:
        raise ValidationError("destination CIDR must be canonical") from exception
    minimum_prefix = 24 if network.version == 4 else 64
    if (network.prefixlen < minimum_prefix or network.is_loopback or network.is_link_local
            or network.is_multicast or network.is_unspecified):
        raise ValidationError("destination CIDR is too broad or unsafe")
    return network


def _external_fqdn(raw: Any) -> str:
    value = require_text(raw, "destination.host").lower()
    if value.endswith(".") or "*" in value or len(value) > 253:
        raise ValidationError("external destination must be an exact FQDN")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValidationError("IP destinations must use the CIDR destination type")
    labels = value.split(".")
    if len(labels) < 2 or any(not DNS_LABEL.fullmatch(label) for label in labels):
        raise ValidationError("external destination FQDN is invalid")
    if any(value == suffix.removeprefix(".") or value.endswith(suffix)
           for suffix in EXTERNAL_SUFFIX_DENYLIST):
        raise ValidationError("external destination uses a non-routable DNS suffix")
    return value


def _internal_service_fqdn(raw: Any, namespace: str,
                           service_names: list[str]) -> str:
    value = require_text(raw, "destination.dnsNames").lower()
    suffix = f".{namespace}.svc.cluster.local"
    if value.endswith(".") or "*" in value or len(value) > 253 \
            or not value.endswith(suffix):
        raise ValidationError("service destination DNS name must be exact and namespace-scoped")
    service_host = value[:-len(suffix)]
    labels = service_host.split(".")
    if not labels or any(not DNS_LABEL.fullmatch(label) for label in labels) \
            or labels[-1] not in service_names:
        raise ValidationError("service destination DNS name is outside its declared Services")
    return value


def _dns_label(raw: Any, field: str) -> str:
    value = require_text(raw, field)
    if not DNS_LABEL.fullmatch(value):
        raise ValidationError(f"{field} must be a DNS label")
    return value


def _integer(raw: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or not minimum <= raw <= maximum:
        raise ValidationError(f"{field} is outside the safe bound")
    return raw
