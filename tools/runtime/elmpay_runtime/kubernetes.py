from __future__ import annotations

import re
from typing import Any, Mapping

from .common import ValidationError, require_list, require_mapping, require_text


IMAGE_PATTERN = re.compile(r"^.+@sha256:[0-9a-f]{64}$")


def render_workloads(policy: Mapping[str, Any], images: Mapping[str, Any]) -> dict[str, Any]:
    services = require_list(policy.get("services"), "workload policy services")
    expected = {require_text(item.get("name"), "service name") for item in services}
    supplied = set(images)
    if supplied != expected:
        raise ValidationError(
            f"image set must exactly match services; missing={sorted(expected - supplied)}, "
            f"unknown={sorted(supplied - expected)}"
        )
    namespace = require_text(policy.get("namespace"), "namespace")
    security = require_mapping(policy.get("security"), "security")
    availability = require_mapping(policy.get("availability"), "availability")
    items = [
        _deployment(namespace, require_mapping(service, "service"), security, availability,
                    _validated_image(images[require_text(service.get("name"), "service name")]))
        for service in services
    ]
    rendered = {"apiVersion": "v1", "kind": "List", "items": items}
    validate_rendered_workloads(rendered, policy)
    return rendered


def _validated_image(value: object) -> str:
    image = require_text(value, "image")
    if not IMAGE_PATTERN.fullmatch(image):
        raise ValidationError("every workload image must use an immutable sha256 digest")
    return image


def _deployment(
    namespace: str,
    service: Mapping[str, Any],
    security: Mapping[str, Any],
    availability: Mapping[str, Any],
    image: str,
) -> dict[str, Any]:
    name = require_text(service.get("name"), "service.name")
    port = service.get("port")
    replicas = service.get("replicas")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValidationError(f"{name} port must be an integer from 1 to 65535")
    minimum = availability.get("minimumReplicas")
    if not isinstance(replicas, int) or not isinstance(minimum, int) or replicas < minimum:
        raise ValidationError(f"{name} must meet the minimum replica policy")
    run_as_user = security.get("runAsUser")
    if isinstance(run_as_user, bool) or not isinstance(run_as_user, int) or run_as_user <= 0:
        raise ValidationError("runAsUser must be a positive numeric uid")
    if security.get("seccompProfile") != "RuntimeDefault":
        raise ValidationError("seccompProfile must be RuntimeDefault")
    if security.get("dropCapabilities") != ["ALL"]:
        raise ValidationError("all Linux capabilities must be dropped")
    for field in ("cpuRequest", "cpuLimit", "memoryRequest", "memoryLimit"):
        require_text(service.get(field), f"{name}.{field}")
    labels = {
        "app.kubernetes.io/name": name,
        "app.kubernetes.io/part-of": "elmpay",
    }
    topology = require_list(availability.get("topologyKeys"), "topologyKeys")
    if not topology:
        raise ValidationError("at least one topology key is required")
    container_security = {
        "allowPrivilegeEscalation": security.get("allowPrivilegeEscalation"),
        "readOnlyRootFilesystem": security.get("readOnlyRootFilesystem"),
        "runAsNonRoot": security.get("runAsNonRoot"),
        "runAsUser": run_as_user,
        "capabilities": {"drop": security.get("dropCapabilities")},
    }
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "spec": {
            "replicas": replicas,
            "strategy": {
                "type": "RollingUpdate",
                "rollingUpdate": {"maxUnavailable": 0, "maxSurge": 1},
            },
            "selector": {"matchLabels": {"app.kubernetes.io/name": name}},
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "serviceAccountName": require_text(
                        service.get("serviceAccount"), "serviceAccount"
                    ),
                    "automountServiceAccountToken": False,
                    "securityContext": {
                        "runAsNonRoot": security.get("runAsNonRoot"),
                        "runAsUser": run_as_user,
                        "runAsGroup": run_as_user,
                        "fsGroup": run_as_user,
                        "seccompProfile": {"type": security.get("seccompProfile")},
                    },
                    "topologySpreadConstraints": [
                        {
                            "maxSkew": 1,
                            "topologyKey": key,
                            "whenUnsatisfiable": "DoNotSchedule",
                            "labelSelector": {
                                "matchLabels": {"app.kubernetes.io/name": name}
                            },
                        }
                        for key in (require_text(item, "topology key") for item in topology)
                    ],
                    "containers": [
                        {
                            "name": name,
                            "image": image,
                            "imagePullPolicy": "IfNotPresent",
                            "securityContext": container_security,
                            "ports": [{"name": "http", "containerPort": port}],
                            "env": [
                                {"name": "ELMPAY_ENVIRONMENT", "value": "production"},
                                {
                                    "name": "ELMPAY_POD_NAME",
                                    "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}},
                                },
                            ],
                            "resources": {
                                "requests": {
                                    "cpu": service.get("cpuRequest"),
                                    "memory": service.get("memoryRequest"),
                                },
                                "limits": {
                                    "cpu": service.get("cpuLimit"),
                                    "memory": service.get("memoryLimit"),
                                },
                            },
                            "startupProbe": {
                                "httpGet": {"path": "/health/startup", "port": "http"},
                                "failureThreshold": 30,
                                "periodSeconds": 5,
                            },
                            "livenessProbe": {
                                "httpGet": {"path": "/health/live", "port": "http"},
                                "periodSeconds": 10,
                                "failureThreshold": 3,
                            },
                            "readinessProbe": {
                                "httpGet": {"path": "/health/ready", "port": "http"},
                                "periodSeconds": 5,
                                "failureThreshold": 2,
                            },
                            "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
                        }
                    ],
                    "volumes": [{"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}}],
                },
            },
        },
    }


def validate_rendered_workloads(bundle: Mapping[str, Any], policy: Mapping[str, Any]) -> None:
    if bundle.get("apiVersion") != "v1" or bundle.get("kind") != "List":
        raise ValidationError("Kubernetes workload bundle must be a v1 List")
    items = require_list(bundle.get("items"), "bundle.items")
    expected = {item["name"] for item in policy["services"]}
    seen: set[str] = set()
    for item in items:
        document = require_mapping(item, "deployment")
        if document.get("apiVersion") != "apps/v1" or document.get("kind") != "Deployment":
            raise ValidationError("workload bundle may only contain apps/v1 Deployments")
        name = document["metadata"]["name"]
        seen.add(name)
        pod = document["spec"]["template"]["spec"]
        container = pod["containers"][0]
        security = container["securityContext"]
        required_true = [
            pod["securityContext"].get("runAsNonRoot"),
            security.get("runAsNonRoot"),
            security.get("readOnlyRootFilesystem"),
        ]
        if required_true != [True, True, True]:
            raise ValidationError(f"{name} violates required non-root/read-only controls")
        if security.get("allowPrivilegeEscalation") is not False:
            raise ValidationError(f"{name} permits privilege escalation")
        if security.get("capabilities", {}).get("drop") != ["ALL"]:
            raise ValidationError(f"{name} must drop all Linux capabilities")
        if pod.get("automountServiceAccountToken") is not False:
            raise ValidationError(f"{name} must disable service-account token mounting")
        _validated_image(container.get("image"))
        if not container.get("resources", {}).get("limits"):
            raise ValidationError(f"{name} is missing resource limits")
        for probe in ("startupProbe", "livenessProbe", "readinessProbe"):
            if probe not in container:
                raise ValidationError(f"{name} is missing {probe}")
    if seen != expected:
        raise ValidationError("rendered workload names do not match policy")
