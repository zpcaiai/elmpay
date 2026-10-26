from __future__ import annotations

import json
from pathlib import Path
import re
import shlex
from typing import Any, Mapping

from .common import ValidationError, require_list, require_mapping, require_text


IMAGE_PATTERN = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
DNS_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
ENVIRONMENT_NAME_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
CONTROL_CHARACTER_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
CONFIG_MAP_SECRET_NAME_PATTERN = re.compile(
    r"(?:^|_)(?:PASSWORD|PRIVATE_KEY|SECRET|TOKEN|API_KEY|ACCESS_KEY|CREDENTIAL|KEYSTORE|"
    r"SIGNING_KEY|TICKET_KEY|HMAC_KEY)"
    r"(?:_B64|_BASE64|_VALUE)?$"
)
FORBIDDEN_RUNTIME_ENVIRONMENT = frozenset({
    "BASH_ENV", "ENV", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "LD_LIBRARY_PATH",
    "LD_PRELOAD", "NODE_OPTIONS", "NODE_PATH", "PYTHONHOME", "PYTHONPATH",
    "SSLKEYLOGFILE", "_JAVA_OPTIONS",
    "ADMIN_DATABASE_URL", "PGPASSWORD",
    "ELMPAY_API_PRINCIPALS", "ELMPAY_ENABLE_LOCAL_SANDBOX",
    "ELMPAY_LOCAL_RISK_POLICY", "ELMPAY_RISK_HMAC_SECRET",
    "ELMPAY_RISK_HMAC_SECRET_FILE",
})
ALLOWED_FIELD_PATHS = frozenset({"metadata.name"})
ALLOWED_RUNTIME_MODES = frozenset({
    ("ELMPAY_RUNTIME_MODE", "postgres"),
    ("ELMPAY_CHECKOUT_WEB_MODE", "production"),
    ("ADMIN_RUNTIME_MODE", "production"),
    ("ELMPAY_RISK_MODE", "production"),
    ("ELMPAY_MIGRATION_MODE", "apply"),
    ("ELMPAY_PARTITION_MODE", "precreate"),
    ("ELMPAY_ARCHIVE_RECEIPT_MODE", "verify-and-ingest"),
    ("ELMPAY_ARCHIVE_DETACH_VERIFIER_MODE", "verify-detach-authorization"),
    ("ELMPAY_ARCHIVE_DETACH_MODE", "detach-authorized"),
})


def render_workloads(policy: Mapping[str, Any], images: Mapping[str, Any]) -> dict[str, Any]:
    if policy.get("schemaVersion") != 2:
        raise ValidationError("workload policy schemaVersion must be 2")
    services = [require_mapping(item, "service") for item in require_list(
        policy.get("services"), "workload policy services"
    )]
    names = [require_text(item.get("name"), "service name") for item in services]
    jobs = [require_mapping(item, "job") for item in require_list(
        policy.get("jobs", []), "workload policy jobs"
    )]
    job_names = [require_text(item.get("name"), "job name") for item in jobs]
    cron_jobs = [require_mapping(item, "cron job") for item in require_list(
        policy.get("cronJobs", []), "workload policy cronJobs"
    )]
    cron_job_names = [require_text(item.get("name"), "cron job name")
                      for item in cron_jobs]
    expected = set(names)
    if not services or len(expected) != len(names) or len(set(job_names)) != len(job_names) \
            or expected.intersection(job_names) or expected.intersection(cron_job_names) \
            or set(job_names).intersection(cron_job_names) \
            or len(set(cron_job_names)) != len(cron_job_names):
        raise ValidationError("workload services, jobs and cronJobs must have unique names")
    if any(require_text(job.get("imageFrom"), "job.imageFrom") not in expected
           for job in [*jobs, *cron_jobs]):
        raise ValidationError(
            "every job and cronJob imageFrom must name a declared immutable service image"
        )
    _validate_job_order(jobs)
    supplied = set(images)
    if supplied != expected:
        raise ValidationError(
            f"image set must exactly match services; missing={sorted(expected - supplied)}, "
            f"unknown={sorted(supplied - expected)}"
        )
    namespace = require_text(policy.get("namespace"), "namespace")
    security = require_mapping(policy.get("security"), "security")
    availability = require_mapping(policy.get("availability"), "availability")
    config_maps = [
        _config_map(namespace, workload, "gitOps" in workload)
        for workload in [*services, *jobs, *cron_jobs]
        if require_mapping(
            workload.get("configuration"), "workload.configuration",
        ).get("configMapData")
    ]
    items = [*config_maps, *[
        _deployment(namespace, require_mapping(service, "service"), security, availability,
                    _validated_image(images[require_text(service.get("name"), "service name")]))
        for service in services
    ], *[
        resource
        for job in jobs
        for resource in _job_resources(
            namespace, job, security,
            _validated_image(images[require_text(job.get("imageFrom"), "job.imageFrom")]),
            require_mapping(policy.get("dnsEgress"), "dnsEgress"),
        )
    ], *[
        resource
        for cron_job in cron_jobs
        for resource in _cronjob_resources(
            namespace, cron_job, security,
            _validated_image(images[require_text(cron_job.get("imageFrom"),
                                                 "cronJob.imageFrom")]),
            require_mapping(policy.get("dnsEgress"), "dnsEgress"),
        )
    ]]
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
    health_port = service.get("healthPort", port)
    transport = require_text(service.get("transport"), f"{name}.transport")
    health_only, expose_service = _workload_exposure(service, name)
    replicas = service.get("replicas")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValidationError(f"{name} port must be an integer from 1 to 65535")
    if not isinstance(health_port, int) or not 1 <= health_port <= 65535:
        raise ValidationError(f"{name} healthPort must be an integer from 1 to 65535")
    if transport not in {"http", "https", "https-mtls"}:
        raise ValidationError(f"{name}.transport is unsupported")
    if health_only and (port != health_port or transport != "http"):
        raise ValidationError(f"{name} health-only workload must use one HTTP health port")
    if health_only and expose_service:
        raise ValidationError(f"{name} health-only workload must not expose a Service")
    if transport == "https-mtls" and health_port == port:
        raise ValidationError(f"{name} mTLS business and health ports must be isolated")
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
    runtime = require_mapping(service.get("runtime"), f"{name}.runtime")
    runtime_kind = require_text(runtime.get("kind"), f"{name}.runtime.kind")
    if runtime_kind not in {"java-main", "node-start"}:
        raise ValidationError(f"{name}.runtime.kind is unsupported")
    entrypoint = require_text(runtime.get("entrypoint"), f"{name}.runtime.entrypoint")
    service_account = require_text(service.get("serviceAccount"), f"{name}.serviceAccount")
    if service_account != name:
        raise ValidationError(f"{name}.serviceAccount must match the workload identity")
    probes = _health_probes(service, name)
    configuration = _runtime_configuration(service, name, runtime_kind)
    field_environment = _field_environment(service, name)
    replica_identity_value = service.get("replicaIdentityEnvironment")
    if health_only:
        replica_identity = require_text(
            replica_identity_value, f"{name}.replicaIdentityEnvironment"
        )
        if ENVIRONMENT_NAME_PATTERN.fullmatch(replica_identity) is None \
                or field_environment.get(replica_identity) != "metadata.name":
            raise ValidationError(
                f"{name} replica identity must come from downward API metadata.name"
            )
    elif replica_identity_value is not None:
        replica_identity = require_text(
            replica_identity_value, f"{name}.replicaIdentityEnvironment"
        )
        if ENVIRONMENT_NAME_PATTERN.fullmatch(replica_identity) is None \
                or field_environment.get(replica_identity) != "metadata.name":
            raise ValidationError(
                f"{name} replica identity must come from downward API metadata.name"
            )
    reserved_environment = {
        "ELMPAY_ENVIRONMENT", "ELMPAY_POD_NAME",
        *configuration["fixedEnvironment"], *configuration["configMapKeys"],
    }
    if reserved_environment.intersection(field_environment):
        raise ValidationError(f"{name} field environment collides with another source")
    if ({"ELMPAY_ENVIRONMENT", "ELMPAY_POD_NAME"}
            & (set(configuration["fixedEnvironment"]) | set(configuration["configMapKeys"]))):
        raise ValidationError(f"{name} runtime configuration overrides a reserved environment")
    if set(configuration["fixedEnvironment"]).intersection(configuration["configMapKeys"]):
        raise ValidationError(f"{name} fixed environment collides with its ConfigMap")
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
    business_port_name = "https" if transport in {"https", "https-mtls"} else "http"
    ports = ([{"name": "health", "containerPort": health_port}]
             if health_only else [{"name": business_port_name, "containerPort": port}])
    probe_port_name = "health" if health_only else business_port_name
    if not health_only and health_port != port:
        ports.append({"name": "health", "containerPort": health_port})
        probe_port_name = "health"
    isolated_health_listener = health_only or health_port != port
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": labels,
            "annotations": {
                "elmpay.io/runtime-kind": runtime_kind,
                "elmpay.io/source-entrypoint": entrypoint,
            },
        },
        "spec": {
            "replicas": replicas,
            "strategy": {
                "type": "RollingUpdate",
                "rollingUpdate": {"maxUnavailable": 0, "maxSurge": 1},
            },
            "selector": {"matchLabels": {"app.kubernetes.io/name": name}},
            "template": {
                "metadata": {
                    "labels": labels,
                    **({"annotations": {
                        "sidecar.istio.io/rewriteAppHTTPProbers": "false",
                        "traffic.sidecar.istio.io/excludeInboundPorts": str(health_port),
                    }} if isolated_health_listener else {}),
                },
                "spec": {
                    "serviceAccountName": service_account,
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
                            "ports": ports,
                            "env": [
                                {"name": "ELMPAY_ENVIRONMENT", "value": "production"},
                                {
                                    "name": "ELMPAY_POD_NAME",
                                    "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}},
                                },
                                *[
                                    {"name": key, "value": value}
                                    for key, value in configuration["fixedEnvironment"].items()
                                ],
                                *[
                                    {
                                        "name": key,
                                        "valueFrom": {"fieldRef": {"fieldPath": field_path}},
                                    }
                                    for key, field_path in field_environment.items()
                                ],
                                *[
                                    {
                                        "name": key,
                                        "valueFrom": {"configMapKeyRef": {
                                            "name": configuration["configMap"],
                                            "key": key,
                                            "optional": False,
                                        }},
                                    }
                                    for key in configuration["configMapKeys"]
                                ],
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
                                "httpGet": {"path": probes["startup"], "port": probe_port_name,
                                            **({"scheme": "HTTPS"}
                                               if transport == "https" and health_port == port
                                               else {})},
                                "failureThreshold": 30,
                                "periodSeconds": 5,
                            },
                            "livenessProbe": {
                                "httpGet": {"path": probes["liveness"], "port": probe_port_name,
                                            **({"scheme": "HTTPS"}
                                               if transport == "https" and health_port == port
                                               else {})},
                                "periodSeconds": 10,
                                "failureThreshold": 3,
                            },
                            "readinessProbe": {
                                "httpGet": {"path": probes["readiness"], "port": probe_port_name,
                                            **({"scheme": "HTTPS"}
                                               if transport == "https" and health_port == port
                                               else {})},
                                "periodSeconds": 5,
                                "failureThreshold": 2,
                            },
                            "volumeMounts": [
                                {"name": "tmp", "mountPath": "/tmp"},
                                *[
                                    {
                                        "name": mount["name"],
                                        "mountPath": mount["mountPath"],
                                        "readOnly": True,
                                    }
                                    for mount in configuration["secretMounts"]
                                ],
                            ],
                        }
                    ],
                    "volumes": [
                        {"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}},
                        *[
                            {"name": mount["name"], "secret": {
                                "secretName": mount["secretName"], "optional": False,
                                "defaultMode": 0o440,
                            }}
                            for mount in configuration["secretMounts"]
                        ],
                    ],
                },
            },
        },
    }


def _job_gitops(job: Mapping[str, Any], name: str) -> dict[str, Any]:
    raw = require_mapping(job.get("gitOps"), f"{name}.gitOps")
    if set(raw) != {"phase", "dependencyWave", "executionWave",
                    "requiresDrainedDatabaseRoles"} or raw.get("phase") != "PreSync":
        raise ValidationError(f"{name}.gitOps must declare the governed PreSync contract")
    dependency_wave = raw.get("dependencyWave")
    execution_wave = raw.get("executionWave")
    if any(isinstance(value, bool) or not isinstance(value, int)
           for value in (dependency_wave, execution_wave)) \
            or not -100 <= dependency_wave < execution_wave < 0:
        raise ValidationError(
            f"{name}.gitOps dependencies must precede execution in negative waves"
        )
    drained = require_list(
        raw.get("requiresDrainedDatabaseRoles"),
        f"{name}.gitOps.requiresDrainedDatabaseRoles",
    )
    expected_roles = ["elmpay_edge_gateway", "elmpay_risk_engine", "elmpay_worker"]
    if drained != expected_roles:
        raise ValidationError(
            f"{name}.gitOps must fail closed until legacy runtime roles are drained"
        )
    return {
        "phase": "PreSync",
        "dependencyWave": dependency_wave,
        "executionWave": execution_wave,
        "requiresDrainedDatabaseRoles": expected_roles,
    }


def _manual_job_execution(job: Mapping[str, Any], name: str) -> dict[str, Any]:
    raw = require_mapping(job.get("manualExecution"), f"{name}.manualExecution")
    if set(raw) != {"suspend", "evidenceState"} \
            or raw.get("suspend") is not True \
            or raw.get("evidenceState") != "EVIDENCE_PENDING":
        raise ValidationError(
            f"{name}.manualExecution must remain suspended with EVIDENCE_PENDING"
        )
    return {"suspend": True, "evidenceState": "EVIDENCE_PENDING"}


def _validate_job_order(jobs: list[Mapping[str, Any]]) -> None:
    by_name = {require_text(job.get("name"), "job.name"): job for job in jobs}
    if "database-migrator" not in by_name:
        raise ValidationError("the schema migration job is required")
    migration = _job_gitops(by_name["database-migrator"], "database-migrator")
    initializer = by_name.get("tenant-partition-initializer")
    if initializer is None:
        raise ValidationError("an initial partition horizon job is required")
    partition = _job_gitops(initializer, "tenant-partition-initializer")
    if partition["executionWave"] <= migration["executionWave"]:
        raise ValidationError(
            "initial partitions must run after successful schema migration"
        )


def _dependency_hook_annotations(job: Mapping[str, Any], name: str) -> dict[str, str]:
    is_manual = "manualExecution" in job
    if is_manual == ("gitOps" in job):
        raise ValidationError(
            f"{name} must declare exactly one of gitOps or manualExecution"
        )
    manual = _manual_job_execution(job, name) if is_manual else None
    gitops = None if is_manual else _job_gitops(job, name)
    return {
        "argocd.argoproj.io/hook": gitops["phase"],
        "argocd.argoproj.io/sync-wave": str(gitops["dependencyWave"]),
        # Dependency objects must remain available for the Job.  HookSucceeded would
        # delete them before the later execution wave on a first installation.
        "argocd.argoproj.io/hook-delete-policy": "BeforeHookCreation",
    }


def _config_map(namespace: str, service: Mapping[str, Any],
                presync_dependency: bool = False) -> dict[str, Any]:
    name = require_text(service.get("name"), "service.name")
    runtime = require_mapping(service.get("runtime"), f"{name}.runtime")
    configuration = _runtime_configuration(
        service, name, require_text(runtime.get("kind"), f"{name}.runtime.kind")
    )
    if not configuration["configMapData"]:
        raise ValidationError(f"{name} has no inline ConfigMap data")
    metadata: dict[str, Any] = {
        "name": configuration["configMap"],
        "namespace": namespace,
        "labels": {
            "app.kubernetes.io/name": name,
            "app.kubernetes.io/part-of": "elmpay",
        },
    }
    if presync_dependency:
        metadata["annotations"] = _dependency_hook_annotations(service, name)
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": metadata,
        "immutable": True,
        "data": configuration["configMapData"],
    }


def _job_resources(
    namespace: str,
    job: Mapping[str, Any],
    security: Mapping[str, Any],
    image: str,
    dns_egress: Mapping[str, Any],
) -> list[dict[str, Any]]:
    name = _dns_label(job.get("name"), "job.name")
    service_account = _dns_label(job.get("serviceAccount"), f"{name}.serviceAccount")
    if service_account != name:
        raise ValidationError(f"{name}.serviceAccount must match the job identity")
    image_from = _dns_label(job.get("imageFrom"), f"{name}.imageFrom")
    runtime = require_mapping(job.get("runtime"), f"{name}.runtime")
    if set(runtime) != {"kind", "entrypoint", "launcher", "mainClass", "modeEnvironment", "modeValue"} \
            or runtime.get("kind") != "java-job":
        raise ValidationError(f"{name}.runtime must be an explicit java-job entrypoint")
    entrypoint = require_text(runtime.get("entrypoint"), f"{name}.runtime.entrypoint")
    launcher = require_text(runtime.get("launcher"), f"{name}.runtime.launcher")
    if launcher != "/opt/elmpay/bin/java-main":
        raise ValidationError(f"{name}.runtime.launcher must use the immutable image launcher")
    main_class = require_text(runtime.get("mainClass"), f"{name}.runtime.mainClass")
    if re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", main_class) is None:
        raise ValidationError(f"{name}.runtime.mainClass is invalid")
    if image_from == name:
        raise ValidationError(f"{name} must reuse a separately declared immutable service image")
    deadline = job.get("activeDeadlineSeconds")
    if not isinstance(deadline, int) or isinstance(deadline, bool) or not 60 <= deadline <= 1800:
        raise ValidationError(f"{name}.activeDeadlineSeconds must be 60..1800")
    for field in ("cpuRequest", "cpuLimit", "memoryRequest", "memoryLimit"):
        require_text(job.get(field), f"{name}.{field}")
    run_as_user = security.get("runAsUser")
    if isinstance(run_as_user, bool) or not isinstance(run_as_user, int) or run_as_user <= 0:
        raise ValidationError("runAsUser must be a positive numeric uid")
    is_manual = "manualExecution" in job
    if is_manual == ("gitOps" in job):
        raise ValidationError(
            f"{name} must declare exactly one of gitOps or manualExecution"
        )
    manual = _manual_job_execution(job, name) if is_manual else None
    gitops = None if is_manual else _job_gitops(job, name)
    configuration = _runtime_configuration(job, name, "java-job")
    database_egress = require_mapping(job.get("databaseEgress"), f"{name}.databaseEgress")
    if set(database_egress) != {"namespace", "podLabels", "port"}:
        raise ValidationError(f"{name}.databaseEgress fields are invalid")
    database_namespace = _dns_label(
        database_egress.get("namespace"), f"{name}.databaseEgress.namespace"
    )
    database_labels = require_mapping(
        database_egress.get("podLabels"), f"{name}.databaseEgress.podLabels"
    )
    if not database_labels or any(
        not isinstance(key, str) or not _valid_label_key(key)
        or not isinstance(value, str) or DNS_LABEL_PATTERN.fullmatch(value) is None
        for key, value in database_labels.items()
    ):
        raise ValidationError(f"{name}.databaseEgress podLabels are invalid")
    database_port = database_egress.get("port")
    if not isinstance(database_port, int) or isinstance(database_port, bool) \
            or not 1 <= database_port <= 65535:
        raise ValidationError(f"{name}.databaseEgress.port is invalid")
    dns_namespace = _dns_label(dns_egress.get("namespace"), "dnsEgress.namespace")
    dns_labels = require_mapping(dns_egress.get("podLabels"), "dnsEgress.podLabels")
    labels = {"app.kubernetes.io/name": name, "app.kubernetes.io/part-of": "elmpay"}
    container_security = {
        "allowPrivilegeEscalation": security.get("allowPrivilegeEscalation"),
        "readOnlyRootFilesystem": security.get("readOnlyRootFilesystem"),
        "runAsNonRoot": security.get("runAsNonRoot"),
        "runAsUser": run_as_user,
        "capabilities": {"drop": security.get("dropCapabilities")},
    }
    mounts = configuration["secretMounts"]
    job_document = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": name, "namespace": namespace, "labels": labels,
            "annotations": {
                "elmpay.io/runtime-kind": "java-job",
                "elmpay.io/source-entrypoint": entrypoint,
                "elmpay.io/image-source": image_from,
                **({
                    "elmpay.io/manual-evidence-state": manual["evidenceState"],
                    "elmpay.io/manual-instantiation-required": "true",
                } if is_manual else {
                    "argocd.argoproj.io/hook": gitops["phase"],
                    "argocd.argoproj.io/sync-wave": str(gitops["executionWave"]),
                    "argocd.argoproj.io/hook-delete-policy":
                        "BeforeHookCreation,HookSucceeded",
                    "elmpay.io/requires-drained-database-roles": ",".join(
                        gitops["requiresDrainedDatabaseRoles"]
                    ),
                }),
            },
        },
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": deadline,
            "ttlSecondsAfterFinished": 300,
            **({"suspend": True} if is_manual else {}),
            "template": {
                "metadata": {"labels": labels, "annotations": {"sidecar.istio.io/inject": "false"}},
                "spec": {
                    "serviceAccountName": service_account,
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Never",
                    "securityContext": {
                        "runAsNonRoot": security.get("runAsNonRoot"),
                        "runAsUser": run_as_user,
                        "runAsGroup": run_as_user,
                        "fsGroup": run_as_user,
                        "seccompProfile": {"type": security.get("seccompProfile")},
                    },
                    "containers": [{
                        "name": name,
                        "image": image,
                        "imagePullPolicy": "IfNotPresent",
                        "command": [launcher],
                        "args": [main_class],
                        "securityContext": container_security,
                        "env": [
                            {"name": "ELMPAY_ENVIRONMENT", "value": "production"},
                            *[{"name": key, "value": value}
                              for key, value in configuration["fixedEnvironment"].items()],
                            *[{"name": key, "valueFrom": {"configMapKeyRef": {
                                "name": configuration["configMap"], "key": key,
                                "optional": False,
                            }}} for key in configuration["configMapKeys"]],
                        ],
                        "resources": {
                            "requests": {"cpu": job.get("cpuRequest"),
                                         "memory": job.get("memoryRequest")},
                            "limits": {"cpu": job.get("cpuLimit"),
                                       "memory": job.get("memoryLimit")},
                        },
                        "volumeMounts": [
                            {"name": "tmp", "mountPath": "/tmp"},
                            *[{"name": mount["name"], "mountPath": mount["mountPath"],
                               "readOnly": True} for mount in mounts],
                        ],
                    }],
                    "volumes": [
                        {"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}},
                        *[{"name": mount["name"], "secret": {
                            "secretName": mount["secretName"], "optional": False,
                            "defaultMode": 0o440,
                        }} for mount in mounts],
                    ],
                },
            },
        },
    }
    dependency_annotations = None if is_manual else _dependency_hook_annotations(job, name)
    service_account_document = {
        "apiVersion": "v1", "kind": "ServiceAccount",
        "metadata": {"name": name, "namespace": namespace, "labels": labels,
                     **({} if dependency_annotations is None else {
                         "annotations": dependency_annotations,
                     })},
        "automountServiceAccountToken": False,
    }
    network_policy = {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": namespace, "labels": labels,
                     **({} if dependency_annotations is None else {
                         "annotations": dependency_annotations,
                     })},
        "spec": {
            "podSelector": {"matchLabels": {"app.kubernetes.io/name": name}},
            "policyTypes": ["Ingress", "Egress"], "ingress": [],
            "egress": [
                {"to": [{"namespaceSelector": {"matchLabels": {
                    "kubernetes.io/metadata.name": dns_namespace,
                }}, "podSelector": {"matchLabels": dict(dns_labels)}}],
                 "ports": [{"protocol": "UDP", "port": 53},
                           {"protocol": "TCP", "port": 53}]},
                {"to": [{"namespaceSelector": {"matchLabels": {
                    "kubernetes.io/metadata.name": database_namespace,
                }}, "podSelector": {"matchLabels": dict(database_labels)}}],
                 "ports": [{"protocol": "TCP", "port": database_port}]},
            ],
        },
    }
    return [service_account_document, network_policy, job_document]


def _cronjob_annotations(annotations: Mapping[str, str]) -> dict[str, str]:
    selected = {}
    for key, value in annotations.items():
        namespace, separator, name = key.partition("/")
        if namespace == "elmpay.io" and separator and name \
                and name != "requires-drained-database-roles":
            selected[key] = value
    return selected


def _cronjob_resources(
    namespace: str,
    cron_job: Mapping[str, Any],
    security: Mapping[str, Any],
    image: str,
    dns_egress: Mapping[str, Any],
) -> list[dict[str, Any]]:
    name = _dns_label(cron_job.get("name"), "cronJob.name")
    schedule = require_text(cron_job.get("schedule"), f"{name}.schedule")
    if re.fullmatch(r"(?:[0-5]?\d|\*) (?:[01]?\d|2[0-3]|\*) \* \* \*", schedule) is None:
        raise ValidationError(f"{name}.schedule must be a bounded daily UTC cron")
    if cron_job.get("concurrencyPolicy") != "Forbid":
        raise ValidationError(f"{name}.concurrencyPolicy must be Forbid")
    starting_deadline = cron_job.get("startingDeadlineSeconds")
    successful_history = cron_job.get("successfulJobsHistoryLimit")
    failed_history = cron_job.get("failedJobsHistoryLimit")
    if not isinstance(starting_deadline, int) or isinstance(starting_deadline, bool) \
            or not 60 <= starting_deadline <= 3600 \
            or not isinstance(successful_history, int) or isinstance(successful_history, bool) \
            or not 1 <= successful_history <= 10 \
            or not isinstance(failed_history, int) or isinstance(failed_history, bool) \
            or not 1 <= failed_history <= 10:
        raise ValidationError(f"{name} CronJob history/deadline controls are invalid")
    internal_policy = dict(cron_job)
    internal_policy["gitOps"] = {
        "phase": "PreSync",
        "dependencyWave": -20,
        "executionWave": -5,
        "requiresDrainedDatabaseRoles": [
            "elmpay_edge_gateway", "elmpay_risk_engine", "elmpay_worker",
        ],
    }
    service_account, network_policy, job = _job_resources(
        namespace, internal_policy, security, image, dns_egress
    )
    for dependency in (service_account, network_policy):
        dependency["metadata"].pop("annotations", None)
    job_annotations = job["metadata"]["annotations"]
    cron_annotations = _cronjob_annotations(job_annotations)
    cron_annotations["elmpay.io/schedule-timezone"] = "UTC"
    job_spec = job["spec"]
    job_spec.pop("ttlSecondsAfterFinished", None)
    cron_document = {
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": job["metadata"]["labels"],
            "annotations": cron_annotations,
        },
        "spec": {
            "schedule": schedule,
            "timeZone": "Etc/UTC",
            "concurrencyPolicy": "Forbid",
            "suspend": False,
            "startingDeadlineSeconds": starting_deadline,
            "successfulJobsHistoryLimit": successful_history,
            "failedJobsHistoryLimit": failed_history,
            "jobTemplate": {"spec": job_spec},
        },
    }
    return [service_account, network_policy, cron_document]


def _valid_label_key(value: str) -> bool:
    if len(value) > 317 or value.count("/") > 1:
        return False
    prefix, separator, name = value.rpartition("/")
    if not separator:
        name = prefix
        prefix = ""
    if re.fullmatch(r"[a-z0-9](?:[-_.a-z0-9]{0,61}[a-z0-9])?", name) is None:
        return False
    return not prefix or (len(prefix) <= 253 and all(
        DNS_LABEL_PATTERN.fullmatch(label) is not None for label in prefix.split(".")
    ))


def validate_rendered_workloads(bundle: Mapping[str, Any], policy: Mapping[str, Any]) -> None:
    if bundle.get("apiVersion") != "v1" or bundle.get("kind") != "List":
        raise ValidationError("Kubernetes workload bundle must be a v1 List")
    items = require_list(bundle.get("items"), "bundle.items")
    policy_services: dict[str, Mapping[str, Any]] = {}
    for raw_service in require_list(policy.get("services"), "workload policy services"):
        service = require_mapping(raw_service, "service")
        service_name = require_text(service.get("name"), "service.name")
        if service_name in policy_services:
            raise ValidationError("workload service names must be unique")
        policy_services[service_name] = service
    policy_jobs: dict[str, Mapping[str, Any]] = {}
    for raw_job in require_list(policy.get("jobs", []), "workload policy jobs"):
        job = require_mapping(raw_job, "job")
        job_name = require_text(job.get("name"), "job.name")
        if job_name in policy_jobs or job_name in policy_services:
            raise ValidationError("workload service and job names must be unique")
        policy_jobs[job_name] = job
    policy_cron_jobs: dict[str, Mapping[str, Any]] = {}
    for raw_cron_job in require_list(policy.get("cronJobs", []),
                                     "workload policy cronJobs"):
        cron_job = require_mapping(raw_cron_job, "cron job")
        name = require_text(cron_job.get("name"), "cronJob.name")
        if name in policy_cron_jobs or name in policy_jobs or name in policy_services:
            raise ValidationError("workload names must be unique across all runtime kinds")
        policy_cron_jobs[name] = cron_job
    expected = set(policy_services)
    expected_config_maps: dict[str, dict[str, Any]] = {}
    for name, service in {**policy_services, **policy_jobs, **policy_cron_jobs}.items():
        runtime = require_mapping(service.get("runtime"), f"{name}.runtime")
        configuration = _runtime_configuration(
            service, name, require_text(runtime.get("kind"), f"{name}.runtime.kind")
        )
        if configuration["configMapData"]:
            config_map_name = configuration["configMap"]
            if config_map_name in expected_config_maps:
                raise ValidationError("inline workload ConfigMap names must be unique")
            expected_config_maps[config_map_name] = _config_map(
                require_text(policy.get("namespace"), "namespace"), service,
                "gitOps" in service,
            )
    seen_config_maps: set[str] = set()
    seen: set[str] = set()
    expected_job_resources: dict[tuple[str, str], dict[str, Any]] = {}
    for name, job in policy_jobs.items():
        image_from = require_text(job.get("imageFrom"), f"{name}.imageFrom")
        # Validation is about exact structure; the digest value itself is independently pinned.
        placeholder = f"registry.invalid/{image_from}@sha256:" + "0" * 64
        for resource in _job_resources(
                require_text(policy.get("namespace"), "namespace"), job,
                require_mapping(policy.get("security"), "security"), placeholder,
                require_mapping(policy.get("dnsEgress"), "dnsEgress")):
            expected_job_resources[(resource["kind"], resource["metadata"]["name"])] = resource
    for name, cron_job in policy_cron_jobs.items():
        image_from = require_text(cron_job.get("imageFrom"), f"{name}.imageFrom")
        placeholder = f"registry.invalid/{image_from}@sha256:" + "0" * 64
        for resource in _cronjob_resources(
                require_text(policy.get("namespace"), "namespace"), cron_job,
                require_mapping(policy.get("security"), "security"), placeholder,
                require_mapping(policy.get("dnsEgress"), "dnsEgress")):
            expected_job_resources[(resource["kind"], resource["metadata"]["name"])] = resource
    seen_job_resources: set[tuple[str, str]] = set()
    for item in items:
        document = require_mapping(item, "workload document")
        if document.get("apiVersion") == "v1" and document.get("kind") == "ConfigMap":
            metadata = require_mapping(document.get("metadata"), "ConfigMap metadata")
            config_map_name = require_text(metadata.get("name"), "ConfigMap name")
            if config_map_name not in expected_config_maps or config_map_name in seen_config_maps:
                raise ValidationError(f"rendered ConfigMap {config_map_name} is not declared")
            if document != expected_config_maps[config_map_name]:
                raise ValidationError(f"rendered ConfigMap {config_map_name} does not match policy")
            seen_config_maps.add(config_map_name)
            continue
        key = (str(document.get("kind")), str(document.get("metadata", {}).get("name")))
        if key in expected_job_resources:
            expected_job = expected_job_resources[key]
            candidate = dict(document)
            expected_candidate = dict(expected_job)
            if key[0] in {"Job", "CronJob"}:
                candidate = json.loads(json.dumps(candidate))
                expected_candidate = json.loads(json.dumps(expected_candidate))
                actual_pod = (candidate["spec"]["template"]["spec"]
                              if key[0] == "Job"
                              else candidate["spec"]["jobTemplate"]["spec"]["template"]["spec"])
                expected_pod = (expected_candidate["spec"]["template"]["spec"]
                                if key[0] == "Job"
                                else expected_candidate["spec"]["jobTemplate"]["spec"]
                                ["template"]["spec"])
                actual_pod["containers"][0]["image"] = \
                    expected_pod["containers"][0]["image"]
                _validated_image(
                    (document["spec"]["template"]["spec"]
                     if key[0] == "Job"
                     else document["spec"]["jobTemplate"]["spec"]["template"]["spec"])
                    ["containers"][0].get("image")
                )
            if candidate != expected_candidate or key in seen_job_resources:
                raise ValidationError(f"rendered job resource {key[1]} does not match policy")
            seen_job_resources.add(key)
            continue
        if document.get("apiVersion") != "apps/v1" or document.get("kind") != "Deployment":
            raise ValidationError(
                "workload bundle contains an undeclared resource"
            )
        name = document["metadata"]["name"]
        if name not in policy_services:
            raise ValidationError(f"rendered workload {name} is not declared")
        seen.add(name)
        service = policy_services[name]
        runtime = require_mapping(service.get("runtime"), f"{name}.runtime")
        annotations = document["metadata"].get("annotations", {})
        if annotations.get("elmpay.io/runtime-kind") != runtime.get("kind") \
                or annotations.get("elmpay.io/source-entrypoint") != runtime.get("entrypoint"):
            raise ValidationError(f"{name} runtime annotations do not match policy")
        pod = document["spec"]["template"]["spec"]
        template_metadata = document["spec"]["template"].get("metadata", {})
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
        expected_probes = _health_probes(service, name)
        transport = require_text(service.get("transport"), f"{name}.transport")
        health_only, _ = _workload_exposure(service, name)
        health_port = service.get("healthPort", service.get("port"))
        expected_probe_annotations = ({
            "sidecar.istio.io/rewriteAppHTTPProbers": "false",
            "traffic.sidecar.istio.io/excludeInboundPorts": str(
                service.get("healthPort", service.get("port"))
            ),
        } if health_only or health_port != service.get("port") else {})
        if template_metadata.get("annotations", {}) != expected_probe_annotations:
            raise ValidationError(f"{name} health listener mesh isolation does not match policy")
        business_port_name = "https" if transport in {"https", "https-mtls"} else "http"
        probe_port_name = (
            "health" if health_only or health_port != service.get("port") else business_port_name
        )
        expected_ports = (
            [{"name": "health", "containerPort": health_port}]
            if health_only else [{"name": business_port_name, "containerPort": service.get("port")}]
        )
        if not health_only and health_port != service.get("port"):
            expected_ports.append({"name": "health", "containerPort": health_port})
        if container.get("ports") != expected_ports:
            raise ValidationError(f"{name} business/health ports do not match policy")
        for probe, policy_name in (
            ("startupProbe", "startup"),
            ("livenessProbe", "liveness"),
            ("readinessProbe", "readiness"),
        ):
            if probe not in container:
                raise ValidationError(f"{name} is missing {probe}")
            if container[probe].get("httpGet", {}).get("path") != expected_probes[policy_name]:
                raise ValidationError(f"{name} {probe} path does not match policy")
            if container[probe].get("httpGet", {}).get("port") != probe_port_name:
                raise ValidationError(f"{name} {probe} is not bound to the isolated health port")
            expected_scheme = "HTTPS" if transport == "https" \
                and health_port == service.get("port") else None
            if container[probe].get("httpGet", {}).get("scheme") != expected_scheme:
                raise ValidationError(f"{name} {probe} scheme does not match its listener")
        configuration = _runtime_configuration(
            service, name, require_text(runtime.get("kind"), f"{name}.runtime.kind")
        )
        environment = {
            item.get("name"): item.get("value") for item in container.get("env", [])
            if "value" in item
        }
        if environment.get("ELMPAY_ENVIRONMENT") != "production" or any(
                environment.get(key) != value
                for key, value in configuration["fixedEnvironment"].items()):
            raise ValidationError(f"{name} fixed runtime environment does not match policy")
        expected_fields = {
            "ELMPAY_POD_NAME": "metadata.name", **_field_environment(service, name),
        }
        actual_fields = {
            item.get("name"): item.get("valueFrom", {}).get("fieldRef", {}).get("fieldPath")
            for item in container.get("env", [])
            if "fieldRef" in item.get("valueFrom", {})
        }
        if actual_fields != expected_fields:
            raise ValidationError(f"{name} field environment does not match policy")
        expected_config_map_environment = {
            key: {
                "name": configuration["configMap"],
                "key": key,
                "optional": False,
            }
            for key in configuration["configMapKeys"]
        }
        actual_config_map_environment = {
            item.get("name"): item.get("valueFrom", {}).get("configMapKeyRef")
            for item in container.get("env", [])
            if "configMapKeyRef" in item.get("valueFrom", {})
        }
        if actual_config_map_environment != expected_config_map_environment:
            raise ValidationError(
                f"{name} explicit ConfigMap environment does not match policy"
            )
        if container.get("envFrom") not in (None, []):
            raise ValidationError(
                f"{name} may not bulk-inject ConfigMap or Secret environment values"
            )
        expected_mounts = {
            (mount["name"], mount["mountPath"], True)
            for mount in configuration["secretMounts"]
        }
        actual_mounts = {
            (mount.get("name"), mount.get("mountPath"), mount.get("readOnly"))
            for mount in container.get("volumeMounts", []) if mount.get("name") != "tmp"
        }
        if actual_mounts != expected_mounts:
            raise ValidationError(f"{name} secret mounts do not match policy")
        expected_volumes = {
            (mount["name"], mount["secretName"], False, 0o440)
            for mount in configuration["secretMounts"]
        }
        actual_volumes = {
            (volume.get("name"), volume.get("secret", {}).get("secretName"),
             volume.get("secret", {}).get("optional"),
             volume.get("secret", {}).get("defaultMode"))
            for volume in pod.get("volumes", []) if volume.get("name") != "tmp"
        }
        if actual_volumes != expected_volumes:
            raise ValidationError(f"{name} secret volumes do not match policy")
    if seen != expected:
        raise ValidationError("rendered workload names do not match policy")
    if seen_config_maps != set(expected_config_maps):
        raise ValidationError("rendered inline ConfigMaps do not match policy")
    if seen_job_resources != set(expected_job_resources):
        raise ValidationError("rendered job/CronJob resources do not match policy")


def validate_workload_sources(root: Path, policy: Mapping[str, Any]) -> None:
    """Reject inventory entries that lack a real process entrypoint and probe handlers."""

    if policy.get("schemaVersion") != 2:
        raise ValidationError("workload policy schemaVersion must be 2")
    repository = root.resolve(strict=True)
    services = require_list(policy.get("services"), "workload policy services")
    if not services:
        raise ValidationError("workload policy must declare at least one runnable service")
    seen: set[str] = set()
    for raw_service in services:
        service = require_mapping(raw_service, "service")
        name = require_text(service.get("name"), "service.name")
        if name in seen:
            raise ValidationError("workload service names must be unique")
        seen.add(name)
        runtime = require_mapping(service.get("runtime"), f"{name}.runtime")
        kind = require_text(runtime.get("kind"), f"{name}.runtime.kind")
        entrypoint = _repository_file(repository, runtime.get("entrypoint"),
                                      f"{name}.runtime.entrypoint")
        health_source = _repository_file(repository, runtime.get("healthSource"),
                                         f"{name}.runtime.healthSource")
        entrypoint_text = entrypoint.read_text(encoding="utf-8")
        health_text = health_source.read_text(encoding="utf-8")
        for probe in _health_probes(service, name).values():
            if probe not in health_text:
                raise ValidationError(f"{name} does not implement declared probe {probe}")

        if kind == "java-main":
            if set(runtime) not in (
                {"kind", "entrypoint", "healthSource"},
                {"kind", "entrypoint", "healthSource", "modeEnvironment", "modeValue"},
            ):
                raise ValidationError(f"{name} java-main runtime fields are invalid")
            if re.search(r"\bpublic\s+static\s+void\s+main\s*\(", entrypoint_text) is None:
                raise ValidationError(f"{name} Java entrypoint has no public static main")
        elif kind == "node-start":
            if set(runtime) not in (
                {"kind", "entrypoint", "manifest", "healthSource"},
                {"kind", "entrypoint", "manifest", "healthSource",
                 "modeEnvironment", "modeValue"},
            ):
                raise ValidationError(f"{name} node-start runtime fields are invalid")
            manifest = _repository_file(repository, runtime.get("manifest"),
                                        f"{name}.runtime.manifest")
            try:
                package = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise ValidationError(f"{name} package manifest is invalid") from exc
            scripts = require_mapping(require_mapping(package, f"{name} package").get("scripts"),
                                      f"{name}.scripts")
            command = require_text(scripts.get("start"), f"{name}.scripts.start")
            try:
                arguments = shlex.split(command)
            except ValueError as exc:
                raise ValidationError(f"{name} start command is malformed") from exc
            if len(arguments) != 2 or arguments[0] != "node":
                raise ValidationError(f"{name} start command must directly execute one Node entrypoint")
            if Path(arguments[1]).is_absolute():
                raise ValidationError(f"{name} start command entrypoint must be relative")
            try:
                command_entrypoint = (manifest.parent / arguments[1]).resolve(strict=True)
            except OSError as exc:
                raise ValidationError(f"{name} start command entrypoint does not exist") from exc
            if command_entrypoint != entrypoint:
                raise ValidationError(f"{name} start command does not execute its declared entrypoint")
            if "createServer" not in entrypoint_text or re.search(
                    r"\.listen\s*\(", entrypoint_text) is None:
                raise ValidationError(f"{name} Node entrypoint does not start an HTTP server")
        else:
            raise ValidationError(f"{name}.runtime.kind is unsupported")
    scheduled_jobs = [
        *require_list(policy.get("jobs", []), "workload policy jobs"),
        *require_list(policy.get("cronJobs", []), "workload policy cronJobs"),
    ]
    for raw_job in scheduled_jobs:
        job = require_mapping(raw_job, "job")
        name = require_text(job.get("name"), "job.name")
        if name in seen:
            raise ValidationError("workload service and job names must be unique")
        seen.add(name)
        runtime = require_mapping(job.get("runtime"), f"{name}.runtime")
        if runtime.get("kind") != "java-job" or set(runtime) != {
                "kind", "entrypoint", "launcher", "mainClass", "modeEnvironment", "modeValue"}:
            raise ValidationError(f"{name}.runtime fields are invalid")
        if runtime.get("launcher") != "/opt/elmpay/bin/java-main":
            raise ValidationError(f"{name} Java job launcher is not the governed image launcher")
        entrypoint = _repository_file(repository, runtime.get("entrypoint"),
                                      f"{name}.runtime.entrypoint")
        source = entrypoint.read_text(encoding="utf-8")
        if re.search(r"\bpublic\s+static\s+void\s+main\s*\(", source) is None:
            raise ValidationError(f"{name} Java job entrypoint has no public static main")
        main_class = require_text(runtime.get("mainClass"), f"{name}.runtime.mainClass")
        if main_class.rsplit(".", 1)[-1] not in source:
            raise ValidationError(f"{name} Java job mainClass does not match its entrypoint")


def _health_probes(service: Mapping[str, Any], name: str) -> dict[str, str]:
    raw = require_mapping(service.get("healthProbes"), f"{name}.healthProbes")
    if set(raw) != {"startup", "liveness", "readiness"}:
        raise ValidationError(f"{name}.healthProbes must declare startup, liveness and readiness")
    result = {key: require_text(raw.get(key), f"{name}.healthProbes.{key}")
              for key in ("startup", "liveness", "readiness")}
    if len(set(result.values())) != 3 or any(
            re.fullmatch(r"/health/[a-z0-9-]+", value) is None for value in result.values()
    ):
        raise ValidationError(f"{name}.healthProbes paths must be unique /health endpoints")
    return result


def _workload_exposure(service: Mapping[str, Any], name: str) -> tuple[bool, bool]:
    health_only = service.get("healthOnly", False)
    expose_service = service.get("exposeService", True)
    if not isinstance(health_only, bool) or not isinstance(expose_service, bool):
        raise ValidationError(f"{name} healthOnly and exposeService must be booleans")
    if health_only and expose_service:
        raise ValidationError(f"{name} health-only workload must not expose a Service")
    return health_only, expose_service


def _field_environment(service: Mapping[str, Any], name: str) -> dict[str, str]:
    raw = service.get("fieldEnvironment", {})
    values = require_mapping(raw, f"{name}.fieldEnvironment")
    normalized: dict[str, str] = {}
    for key in sorted(values):
        if not isinstance(key, str) or ENVIRONMENT_NAME_PATTERN.fullmatch(key) is None:
            raise ValidationError(f"{name}.fieldEnvironment contains an invalid name")
        if key in FORBIDDEN_RUNTIME_ENVIRONMENT:
            raise ValidationError(f"{name}.fieldEnvironment contains a forbidden name")
        field_path = require_text(values.get(key), f"{name}.fieldEnvironment.{key}")
        if field_path not in ALLOWED_FIELD_PATHS:
            raise ValidationError(f"{name}.fieldEnvironment uses an unsupported field path")
        normalized[key] = field_path
    return normalized


def _runtime_configuration(service: Mapping[str, Any], name: str,
                           runtime_kind: str) -> dict[str, Any]:
    fixed = require_mapping(service.get("fixedEnvironment"), f"{name}.fixedEnvironment")
    runtime = require_mapping(service.get("runtime"), f"{name}.runtime")
    explicit_mode_name = runtime.get("modeEnvironment")
    explicit_mode_value = runtime.get("modeValue")
    if (explicit_mode_name is None) != (explicit_mode_value is None):
        raise ValidationError(f"{name}.runtime mode selector must declare name and value")
    if explicit_mode_name is None:
        expected_mode = (
            ("ELMPAY_RUNTIME_MODE", "postgres") if runtime_kind == "java-main"
            else ("ELMPAY_CHECKOUT_WEB_MODE", "production")
        )
    else:
        expected_mode = (
            require_text(explicit_mode_name, f"{name}.runtime.modeEnvironment"),
            require_text(explicit_mode_value, f"{name}.runtime.modeValue"),
        )
    if expected_mode not in ALLOWED_RUNTIME_MODES:
        raise ValidationError(f"{name}.runtime production mode selector is not allowed")
    if fixed.get(expected_mode[0]) != expected_mode[1]:
        raise ValidationError(f"{name}.fixedEnvironment must select its production runtime")
    normalized_fixed: dict[str, str] = {}
    for key in sorted(fixed):
        value = require_text(fixed.get(key), f"{name}.fixedEnvironment.{key}")
        if ENVIRONMENT_NAME_PATTERN.fullmatch(key) is None:
            raise ValidationError(f"{name}.fixedEnvironment contains an invalid name")
        if key in FORBIDDEN_RUNTIME_ENVIRONMENT or CONFIG_MAP_SECRET_NAME_PATTERN.search(key):
            raise ValidationError(f"{name}.fixedEnvironment contains a forbidden name")
        normalized_fixed[key] = value

    configuration = require_mapping(service.get("configuration"), f"{name}.configuration")
    configuration_fields = set(configuration)
    if not {"configMap", "secretMounts"}.issubset(configuration_fields) \
            or configuration_fields - {
                "configMap", "configMapData", "configMapKeys", "secret", "secretMounts",
            }:
        raise ValidationError(f"{name}.configuration fields are invalid")
    config_map = _dns_label(configuration.get("configMap"), f"{name}.configuration.configMap")
    raw_config_map_data = require_mapping(
        configuration.get("configMapData", {}), f"{name}.configuration.configMapData"
    )
    if len(raw_config_map_data) > 128:
        raise ValidationError(f"{name}.configuration.configMapData is too large")
    config_map_data: dict[str, str] = {}
    for key in sorted(raw_config_map_data):
        if not isinstance(key, str) or ENVIRONMENT_NAME_PATTERN.fullmatch(key) is None:
            raise ValidationError(f"{name}.configuration.configMapData has an invalid key")
        if key in FORBIDDEN_RUNTIME_ENVIRONMENT or CONFIG_MAP_SECRET_NAME_PATTERN.search(key):
            raise ValidationError(f"{name}.configuration.configMapData may not contain secrets")
        value = require_text(
            raw_config_map_data.get(key), f"{name}.configuration.configMapData.{key}"
        )
        if len(value.encode("utf-8")) > 2_048 or CONTROL_CHARACTER_PATTERN.search(value):
            raise ValidationError(f"{name}.configuration.configMapData has an unsafe value")
        config_map_data[key] = value
    raw_config_map_keys = require_list(
        configuration.get("configMapKeys", []),
        f"{name}.configuration.configMapKeys",
    )
    if len(raw_config_map_keys) > 128 or any(
        not isinstance(key, str) or ENVIRONMENT_NAME_PATTERN.fullmatch(key) is None
        or key in FORBIDDEN_RUNTIME_ENVIRONMENT
        for key in raw_config_map_keys
    ) or len(raw_config_map_keys) != len(set(raw_config_map_keys)):
        raise ValidationError(f"{name}.configuration.configMapKeys are invalid")
    if any(CONFIG_MAP_SECRET_NAME_PATTERN.search(key) for key in raw_config_map_keys):
        raise ValidationError(
            f"{name}.configuration.configMapKeys may not reference secrets"
        )
    if config_map_data and raw_config_map_keys:
        raise ValidationError(
            f"{name}.configuration may not mix inline and external ConfigMap keys"
        )
    config_map_keys = (
        sorted(config_map_data) if config_map_data else sorted(raw_config_map_keys)
    )
    if name == "edge-gateway" \
            and normalized_fixed.get("ELMPAY_RISK_TIMEOUT_MILLISECONDS") != "300":
        raise ValidationError(
            "edge-gateway must preserve the fixed 300ms shared risk deadline"
        )
    if name == "risk-engine" \
            and config_map_data.get("ELMPAY_RISK_DEPENDENCY_TIMEOUT_MILLISECONDS") != "100":
        raise ValidationError(
            "risk-engine signal and model transports must each use a fixed 100ms timeout"
        )
    secret_value = configuration.get("secret")
    if secret_value is not None:
        raise ValidationError(
            f"{name}.configuration may not inject Secret values through environment variables"
        )
    secret = None
    mounts: list[dict[str, str]] = []
    names: set[str] = set()
    paths: set[str] = set()
    for raw_mount in require_list(configuration.get("secretMounts"),
                                  f"{name}.configuration.secretMounts"):
        mount = require_mapping(raw_mount, f"{name} secret mount")
        if set(mount) != {"name", "secretName", "mountPath"}:
            raise ValidationError(f"{name} secret mount fields are invalid")
        mount_name = _dns_label(mount.get("name"), f"{name} secret mount name")
        secret_name = _dns_label(mount.get("secretName"), f"{name} secret name")
        mount_path = require_text(mount.get("mountPath"), f"{name} secret mount path")
        path = Path(mount_path)
        if not path.is_absolute() or ".." in path.parts \
                or not mount_path.startswith("/var/run/secrets/elmpay/"):
            raise ValidationError(f"{name} secret mount path is outside the reserved directory")
        if mount_name == "tmp" or mount_name in names or mount_path in paths:
            raise ValidationError(f"{name} secret mounts must have unique names and paths")
        names.add(mount_name)
        paths.add(mount_path)
        mounts.append({"name": mount_name, "secretName": secret_name,
                       "mountPath": mount_path})
    return {
        "fixedEnvironment": normalized_fixed,
        "configMap": config_map,
        "configMapData": config_map_data,
        "configMapKeys": config_map_keys,
        "secret": secret,
        "secretMounts": mounts,
    }


def _dns_label(value: object, field: str) -> str:
    text = require_text(value, field)
    if DNS_LABEL_PATTERN.fullmatch(text) is None:
        raise ValidationError(f"{field} must be a DNS label")
    return text


def _repository_file(repository: Path, value: object, field: str) -> Path:
    relative = Path(require_text(value, field))
    if relative.is_absolute():
        raise ValidationError(f"{field} must be repository-relative")
    try:
        candidate = (repository / relative).resolve(strict=True)
        candidate.relative_to(repository)
    except (OSError, ValueError) as exc:
        raise ValidationError(f"{field} must resolve to a repository file") from exc
    if not candidate.is_file():
        raise ValidationError(f"{field} must resolve to a repository file")
    return candidate
