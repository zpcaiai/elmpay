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
CATEGORIES = frozenset({"PSP", "DATABASE", "KAFKA", "REDIS", "KMS", "OTEL"})
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
    destinations = _destinations(egress_policy.get("destinations"))
    if {item["category"] for item in destinations.values()} != CATEGORIES:
        raise ValidationError("egress destinations must cover PSP, DB, Kafka, Redis, KMS and OTel")
    assignments = _assignments(egress_policy.get("workloads"), workload_names, destinations)

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
            allowed_optional = set()
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
        if category in {"PSP", "KMS"} and protocol != "TLS":
            raise ValidationError("PSP and KMS destinations require TLS")
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
            normalized.update({
                "namespace": _dns_label(destination.get("namespace"), "destination.namespace"),
                "serviceName": _dns_label(
                    destination.get("serviceName"), "destination.serviceName"
                ),
                "podLabels": _labels(destination.get("podLabels"), "destination.podLabels"),
            })
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
    dns_names = sorted({str(item["host"]) for item in fqdn_destinations}
                       | {f'{item["serviceName"]}.{item["namespace"]}.svc.cluster.local'
                          for item in destinations if item["type"] == "service"})
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
            hosts.append(f'{item["namespace"]}/{item["serviceName"]}.{item["namespace"]}.svc.cluster.local')
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


def _dns_label(raw: Any, field: str) -> str:
    value = require_text(raw, field)
    if not DNS_LABEL.fullmatch(value):
        raise ValidationError(f"{field} must be a DNS label")
    return value


def _integer(raw: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or not minimum <= raw <= maximum:
        raise ValidationError(f"{field} is outside the safe bound")
    return raw
