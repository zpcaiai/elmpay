"""B89-B95 deployable infrastructure decisions and durable fencing controls."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import sqlite3
from typing import Any, Mapping

from .common import (
    GateReport,
    ValidationError,
    parse_instant,
    require_list,
    require_mapping,
    require_text,
    sha256_json,
)
from .downstream_receipt import verify_downstream_receipt


DNS_LABEL = __import__("re").compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")


def render_regional_data_plane(policy: Mapping[str, Any]) -> dict[str, Any]:
    """Render operator-backed PostgreSQL, Kafka and Redis HA resources per region."""
    regions = [require_mapping(item, "region") for item in require_list(policy.get("regions"), "regions")]
    if len(regions) < 2 or sum(item.get("primary") is True for item in regions) != 1:
        raise ValidationError("data plane requires exactly one primary and at least two regions")
    postgres = require_mapping(policy.get("postgres"), "postgres")
    kafka = require_mapping(policy.get("kafka"), "kafka")
    redis = require_mapping(policy.get("redis"), "redis")
    items: list[dict[str, Any]] = []
    for region in regions:
        name = require_text(region.get("name"), "region.name")
        if not DNS_LABEL.fullmatch(name):
            raise ValidationError("region name must be a DNS label")
        namespace = f"elmpay-{name}"
        primary = region.get("primary") is True
        items.extend([
            {
                "apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace, "labels": {
                    "pod-security.kubernetes.io/enforce": "restricted", "elmpay.io/region": name,
                }},
            },
            {
                "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                "metadata": {"name": "default-deny", "namespace": namespace},
                "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
            },
            {
                "apiVersion": "postgresql.cnpg.io/v1", "kind": "Cluster",
                "metadata": {"name": "payments-postgres", "namespace": namespace},
                "spec": {
                    "instances": int(postgres["instances"]),
                    "primaryUpdateStrategy": "unsupervised",
                    "storage": {"size": postgres["storageSize"], "storageClass": postgres["encryptedStorageClass"]},
                    "walStorage": {"size": postgres["walStorageSize"], "storageClass": postgres["encryptedStorageClass"]},
                    "postgresql": {"parameters": {
                        "synchronous_commit": "on", "ssl_min_protocol_version": "TLSv1.3",
                        "log_connections": "on", "log_disconnections": "on",
                    }},
                    "bootstrap": {"initdb": {"database": "elmpay", "owner": "elmpay"}} if primary else {
                        "recovery": {"source": "primary-region-backup"}
                    },
                    "externalClusters": [] if primary else [{
                        "name": "primary-region-backup",
                        "barmanObjectStore": {
                            "destinationPath": postgres["backupDestination"],
                            "serverName": postgres["primaryBackupServerName"],
                            "s3Credentials": {"inheritFromIAMRole": True},
                            "wal": {"maxParallel": 8},
                        },
                    }],
                    "backup": {
                        "retentionPolicy": postgres["retentionPolicy"],
                        "barmanObjectStore": {
                            "destinationPath": postgres["backupDestination"],
                            "serverName": f"payments-{name}",
                            "s3Credentials": {"inheritFromIAMRole": True},
                            "data": {"compression": "bzip2", "encryption": "AES256"},
                            "wal": {"compression": "bzip2", "encryption": "AES256", "maxParallel": 8},
                        },
                    },
                    "monitoring": {"enablePodMonitor": True},
                },
            },
            {
                "apiVersion": "kafka.strimzi.io/v1beta2", "kind": "Kafka",
                "metadata": {"name": "payments-events", "namespace": namespace},
                "spec": {
                    "kafka": {
                        "version": kafka["version"], "replicas": int(kafka["brokers"]),
                        "listeners": [{"name": "tls", "port": 9093, "type": "internal", "tls": True,
                                       "authentication": {"type": "tls"}}],
                        "authorization": {"type": "simple"},
                        "config": {
                            "default.replication.factor": int(kafka["replicationFactor"]),
                            "min.insync.replicas": int(kafka["minimumInSyncReplicas"]),
                            "unclean.leader.election.enable": False,
                            "auto.create.topics.enable": False,
                            "transaction.state.log.replication.factor": int(kafka["replicationFactor"]),
                            "transaction.state.log.min.isr": int(kafka["minimumInSyncReplicas"]),
                        },
                        "storage": {"type": "persistent-claim", "size": kafka["storageSize"],
                                    "class": kafka["encryptedStorageClass"], "deleteClaim": False},
                        "rack": {"topologyKey": "topology.kubernetes.io/zone"},
                    },
                    "zookeeper": {"replicas": 3, "storage": {"type": "persistent-claim", "size": "20Gi",
                                                              "class": kafka["encryptedStorageClass"], "deleteClaim": False}},
                    "entityOperator": {"topicOperator": {}, "userOperator": {}},
                },
            },
            {
                "apiVersion": "databases.spotahome.com/v1", "kind": "RedisFailover",
                "metadata": {"name": "payments-cache", "namespace": namespace},
                "spec": {
                    "sentinel": {"replicas": int(redis["sentinels"])},
                    "redis": {
                        "replicas": int(redis["replicas"]),
                        "customConfig": ["appendonly yes", "appendfsync everysec", "min-replicas-to-write 1", "min-replicas-max-lag 5"],
                        "storage": {"persistentVolumeClaim": {"metadata": {"name": "data"}, "spec": {
                            "accessModes": ["ReadWriteOnce"], "storageClassName": redis["encryptedStorageClass"],
                            "resources": {"requests": {"storage": redis["storageSize"]}},
                        }}},
                    },
                    "authSecretName": redis["authSecretName"],
                },
            },
        ])
    return {"apiVersion": "v1", "kind": "List", "items": items}


def render_service_controls(
    workload_policy: Mapping[str, Any], allowed_callers: Mapping[str, list[str]]
) -> dict[str, Any]:
    """Render service accounts, Services, PDBs, HPAs, network and mesh policy.

    Callers are explicitly enumerated per destination.  Missing destinations or
    unknown identities are rejected instead of creating a permissive policy.
    """

    namespace = require_text(workload_policy.get("namespace"), "namespace")
    services = [require_mapping(item, "service") for item in require_list(
        workload_policy.get("services"), "services"
    )]
    names = {require_text(item.get("name"), "service.name") for item in services}
    if set(allowed_callers) != names:
        raise ValidationError("mesh caller map must exactly cover every service")
    items: list[dict[str, Any]] = [
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "default-deny", "namespace": namespace},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
        },
        {
            "apiVersion": "security.istio.io/v1",
            "kind": "PeerAuthentication",
            "metadata": {"name": "strict-mtls", "namespace": namespace},
            "spec": {"mtls": {"mode": "STRICT"}},
        },
    ]
    for service in services:
        name = str(service["name"])
        callers = allowed_callers[name]
        if len(callers) != len(set(callers)) or any(caller not in names for caller in callers):
            raise ValidationError(f"{name} caller list is invalid")
        labels = {"app.kubernetes.io/name": name, "app.kubernetes.io/part-of": "elmpay"}
        principal = lambda caller: f"cluster.local/ns/{namespace}/sa/{caller}"  # noqa: E731
        destinations = [
            destination for destination in services
            if name in allowed_callers[str(destination["name"])]
        ]
        items.extend(
            [
                {
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": {"name": name, "namespace": namespace},
                    "automountServiceAccountToken": False,
                },
                {
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": {"name": name, "namespace": namespace},
                    "spec": {
                        "selector": {"app.kubernetes.io/name": name},
                        "ports": [{"name": "http", "port": int(service["port"]), "targetPort": "http"}],
                    },
                },
                {
                    "apiVersion": "policy/v1",
                    "kind": "PodDisruptionBudget",
                    "metadata": {"name": name, "namespace": namespace},
                    "spec": {"minAvailable": 2, "selector": {"matchLabels": labels}},
                },
                {
                    "apiVersion": "autoscaling/v2",
                    "kind": "HorizontalPodAutoscaler",
                    "metadata": {"name": name, "namespace": namespace},
                    "spec": {
                        "scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment", "name": name},
                        "minReplicas": int(service["replicas"]),
                        "maxReplicas": max(6, int(service["replicas"]) * 4),
                        "behavior": {
                            "scaleDown": {"stabilizationWindowSeconds": 300},
                            "scaleUp": {"stabilizationWindowSeconds": 30},
                        },
                        "metrics": [{
                            "type": "Resource",
                            "resource": {"name": "cpu", "target": {"type": "Utilization", "averageUtilization": 65}},
                        }],
                    },
                },
                {
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "NetworkPolicy",
                    "metadata": {"name": f"allow-{name}", "namespace": namespace},
                    "spec": {
                        "podSelector": {"matchLabels": {"app.kubernetes.io/name": name}},
                        "policyTypes": ["Ingress", "Egress"],
                        "ingress": [{
                            "from": [{"podSelector": {"matchLabels": {"app.kubernetes.io/name": caller}}}
                                     for caller in callers],
                            "ports": [{"protocol": "TCP", "port": int(service["port"])}],
                        }] if callers else [],
                        "egress": [
                            {
                                "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}],
                                "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}],
                            },
                            *[
                                {
                                    "to": [{"podSelector": {"matchLabels": {"app.kubernetes.io/name": destination["name"]}}}],
                                    "ports": [{"protocol": "TCP", "port": int(destination["port"])}],
                                }
                                for destination in destinations
                            ],
                        ],
                    },
                },
                {
                    "apiVersion": "security.istio.io/v1",
                    "kind": "AuthorizationPolicy",
                    "metadata": {"name": name, "namespace": namespace},
                    "spec": {
                        "selector": {"matchLabels": {"app.kubernetes.io/name": name}},
                        "action": "ALLOW",
                        "rules": [{"from": [{"source": {"principals": [principal(caller) for caller in callers]}}]}]
                        if callers else [],
                    },
                },
            ]
        )
    return {"apiVersion": "v1", "kind": "List", "items": items}


@dataclass(frozen=True)
class Lease:
    resource: str
    holder: str
    fencing_token: int
    expires_at: datetime


class SQLiteFencingStore:
    """Redis-compatible lease semantics backed by a durable SQL CAS."""

    def __init__(self, path: str) -> None:
        self._db = sqlite3.connect(path, timeout=5, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS resource_fence (
              resource TEXT PRIMARY KEY,
              holder TEXT NOT NULL,
              fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
              expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS region_epoch (
              singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
              active_region TEXT NOT NULL,
              fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
              changed_at TEXT NOT NULL,
              request_digest TEXT NOT NULL
            );
            """
        )

    def close(self) -> None:
        self._db.close()

    def acquire(self, resource: str, holder: str, now: datetime, ttl: timedelta) -> Lease | None:
        require_text(resource, "resource")
        require_text(holder, "holder")
        if now.tzinfo is None or ttl <= timedelta(0):
            raise ValidationError("lease time and ttl must be valid")
        current = now.astimezone(timezone.utc)
        expires = current + ttl
        self._db.execute("BEGIN IMMEDIATE")
        try:
            row = self._db.execute(
                "SELECT holder, fencing_token, expires_at FROM resource_fence WHERE resource=?",
                (resource,),
            ).fetchone()
            if row is not None and parse_instant(row[2], "expires_at") > current and row[0] != holder:
                self._db.execute("ROLLBACK")
                return None
            token = (int(row[1]) if row else 0) + 1
            self._db.execute(
                "INSERT INTO resource_fence(resource, holder, fencing_token, expires_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(resource) DO UPDATE SET holder=excluded.holder, "
                "fencing_token=excluded.fencing_token, expires_at=excluded.expires_at",
                (resource, holder, token, expires.isoformat()),
            )
            self._db.execute("COMMIT")
            return Lease(resource, holder, token, expires)
        except Exception:
            self._db.execute("ROLLBACK")
            raise

    def renew(self, lease: Lease, now: datetime, ttl: timedelta) -> Lease | None:
        current = now.astimezone(timezone.utc)
        expires = current + ttl
        changed = self._db.execute(
            "UPDATE resource_fence SET expires_at=? WHERE resource=? AND holder=? "
            "AND fencing_token=? AND expires_at>?",
            (expires.isoformat(), lease.resource, lease.holder, lease.fencing_token, current.isoformat()),
        ).rowcount
        return Lease(lease.resource, lease.holder, lease.fencing_token, expires) if changed == 1 else None

    def is_current(self, lease: Lease, now: datetime) -> bool:
        row = self._db.execute(
            "SELECT holder, fencing_token, expires_at FROM resource_fence WHERE resource=?",
            (lease.resource,),
        ).fetchone()
        return bool(
            row
            and row[0] == lease.holder
            and int(row[1]) == lease.fencing_token
            and parse_instant(row[2], "expires_at") > now.astimezone(timezone.utc)
        )

    def promote_region(
        self, *, target: str, token: int, changed_at: datetime, request_digest: str
    ) -> None:
        require_text(target, "target")
        if isinstance(token, bool) or not isinstance(token, int) or token <= 0:
            raise ValidationError("region fencing token must be a positive integer")
        if changed_at.tzinfo is None:
            raise ValidationError("region change time must be timezone-aware")
        if not __import__("re").fullmatch(r"[0-9a-f]{64}", request_digest):
            raise ValidationError("region request digest is invalid")
        existing = self._db.execute(
            "SELECT active_region, fencing_token, request_digest FROM region_epoch WHERE singleton=1"
        ).fetchone()
        if existing and int(existing[1]) >= token:
            if int(existing[1]) == token and existing[0] == target and existing[2] == request_digest:
                return
            raise ValidationError("stale_or_conflicting_region_fence")
        self._db.execute(
            "INSERT INTO region_epoch(singleton, active_region, fencing_token, changed_at, request_digest) "
            "VALUES (1, ?, ?, ?, ?) ON CONFLICT(singleton) DO UPDATE SET "
            "active_region=excluded.active_region, fencing_token=excluded.fencing_token, "
            "changed_at=excluded.changed_at, request_digest=excluded.request_digest",
            (target, token, changed_at.astimezone(timezone.utc).isoformat(), request_digest),
        )

    def current_region(self) -> dict[str, Any] | None:
        row = self._db.execute(
            "SELECT active_region, fencing_token, changed_at, request_digest "
            "FROM region_epoch WHERE singleton=1"
        ).fetchone()
        if row is None:
            return None
        return {
            "activeRegion": row[0],
            "fencingToken": int(row[1]),
            "changedAt": row[2],
            "requestDigest": row[3],
        }


def evaluate_restore_exercise(
    plan: Mapping[str, Any],
    report: Mapping[str, Any],
    expected_backup_digest: str,
    trust: Mapping[str, Any],
    *,
    now: datetime,
) -> GateReport:
    """Verify an independently signed restore observation against the DR plan.

    The booleans and measurements remain useful facts, but none are trusted
    until an independent ``dr_restore_verifier`` signs the exact backup-bound
    fact set.  This prevents a local caller from certifying its own restore.
    """

    reasons: list[str] = []
    checks: list[str] = []
    fact_names = (
        "backupDigest",
        "backupImmutable",
        "restoreChecksumVerified",
        "ledgerBalanced",
        "failbackVerified",
        "measuredRpoSeconds",
        "measuredRtoSeconds",
        "completedAt",
    )
    facts = {name: report.get(name) for name in fact_names}
    try:
        receipt_digest, signer = verify_downstream_receipt(
            require_mapping(report.get("receipt"), "restore receipt"),
            trust,
            receipt_type="DR_RESTORE_EXERCISE",
            outcome="VERIFIED",
            fields=facts,
            required_role="dr_restore_verifier",
            require_independent=True,
            now=now,
        )
        checks.extend((f"restore_receipt:{receipt_digest}", f"restore_verifier:{signer.identity}"))
    except (ValidationError, TypeError, ValueError) as exc:
        reasons.append(f"restore_receipt_unverified:{exc}")
    if not __import__("re").fullmatch(r"[0-9a-f]{64}", expected_backup_digest):
        reasons.append("backup_digest_invalid")
    if report.get("backupDigest") != expected_backup_digest:
        reasons.append("backup_digest_mismatch")
    if report.get("backupImmutable") is not True:
        reasons.append("backup_not_immutable")
    if report.get("restoreChecksumVerified") is not True:
        reasons.append("restore_checksum_not_verified")
    if report.get("ledgerBalanced") is not True:
        reasons.append("restored_ledger_not_balanced")
    if report.get("failbackVerified") is not True:
        reasons.append("failback_not_verified")
    measured_rpo = report.get("measuredRpoSeconds")
    measured_rto = report.get("measuredRtoSeconds")
    if isinstance(measured_rpo, bool) or not isinstance(measured_rpo, int) or measured_rpo > int(plan["rpoSeconds"]):
        reasons.append("rpo_exceeded")
    if isinstance(measured_rto, bool) or not isinstance(measured_rto, int) or measured_rto > int(plan["rtoSeconds"]):
        reasons.append("rto_exceeded")
    try:
        completed = parse_instant(report.get("completedAt"), "completedAt")
        max_age = int(plan["exercises"]["maximumAgeDays"])
        if completed > now.astimezone(timezone.utc) + timedelta(minutes=5):
            reasons.append("restore_exercise_in_future")
        elif now.astimezone(timezone.utc) - completed > timedelta(days=max_age):
            reasons.append("restore_exercise_stale")
    except (ValidationError, ValueError, TypeError):
        reasons.append("restore_exercise_time_invalid")
    if not reasons:
        checks.extend(("backup_immutable", "restore_checksum", "rpo", "rto", "failback", "ledger_balance"))
    return GateReport.from_reasons(reasons, checks)


def evaluate_region_promotion(
    plan: Mapping[str, Any],
    request: Mapping[str, Any],
    trust: Mapping[str, Any],
    store: SQLiteFencingStore,
    *,
    now: datetime,
) -> GateReport:
    """Authorize and atomically persist a signed multi-region promotion.

    Two independent approvers sign the immutable request digest.  A separately
    trusted DR controller signs the measured operational facts.  Only after all
    checks pass is the monotonically increasing region epoch persisted.
    """

    promotion = require_mapping(plan.get("promotion"), "promotion")
    reasons: list[str] = []
    checks: list[str] = []
    if promotion.get("automatic") is not False:
        reasons.append("automatic_region_promotion_forbidden")
    target = require_text(request.get("targetRegion"), "targetRegion")
    token = request.get("fencingToken")
    if isinstance(token, bool) or not isinstance(token, int) or token <= 0:
        reasons.append("region_fencing_token_invalid")
    changed_at: datetime | None = None
    try:
        changed_at = parse_instant(request.get("changedAt"), "changedAt")
        if changed_at > now.astimezone(timezone.utc) + timedelta(minutes=5):
            reasons.append("region_promotion_time_in_future")
    except ValidationError:
        reasons.append("region_promotion_time_invalid")
    lag = request.get("replicationLagSeconds")
    if isinstance(lag, bool) or not isinstance(lag, int) or lag < 0 or lag > int(promotion["requiresReplicationLagAtMostSeconds"]):
        reasons.append("replication_lag_unsafe")
    for field, reason in (
        ("writeFenceAcquired", "write_fence_missing"),
        ("providerRoutingChecked", "provider_routing_unchecked"),
        ("rollbackPlanVerified", "rollback_plan_unverified"),
        ("targetRegionHealthy", "target_region_unhealthy"),
        ("sourceRegionWritesStopped", "source_writes_not_stopped"),
    ):
        if request.get(field) is not True:
            reasons.append(reason)

    fact_names = (
        "targetRegion",
        "fencingToken",
        "replicationLagSeconds",
        "writeFenceAcquired",
        "providerRoutingChecked",
        "rollbackPlanVerified",
        "targetRegionHealthy",
        "sourceRegionWritesStopped",
        "changedAt",
    )
    facts = {name: request.get(name) for name in fact_names}
    request_digest = sha256_json({"promotion": facts})
    if request.get("requestDigest") != request_digest:
        reasons.append("region_promotion_request_digest_mismatch")

    controller_identity: str | None = None
    try:
        observation_fields = {**facts, "requestDigest": request_digest}
        observation_digest, controller = verify_downstream_receipt(
            require_mapping(request.get("observation"), "promotion observation"),
            trust,
            receipt_type="REGION_PROMOTION_OBSERVATION",
            outcome="VERIFIED",
            fields=observation_fields,
            required_role="dr_controller",
            now=now,
        )
        controller_identity = controller.identity
        checks.extend((f"promotion_observation:{observation_digest}",
                       f"promotion_controller:{controller.identity}"))
    except (ValidationError, TypeError, ValueError) as exc:
        reasons.append(f"region_promotion_observation_unverified:{exc}")

    approver_identities: set[str] = set()
    approvals = require_list(request.get("approvals"), "approvals")
    approval_fields = {
        "requestDigest": request_digest,
        "targetRegion": target,
        "fencingToken": token,
    }
    for index, raw in enumerate(approvals):
        try:
            receipt_digest, signer = verify_downstream_receipt(
                require_mapping(raw, f"approvals[{index}]"),
                trust,
                receipt_type="REGION_PROMOTION_APPROVAL",
                outcome="APPROVED",
                fields=approval_fields,
                required_role="dr_promotion_approver",
                require_independent=True,
                now=now,
            )
            approver_identities.add(signer.identity)
            checks.append(f"promotion_approval:{receipt_digest}:{signer.identity}")
        except (ValidationError, TypeError, ValueError) as exc:
            reasons.append(f"region_promotion_approval_unverified:{index}:{exc}")
    if len(approver_identities) < int(promotion["requiresDistinctApprovers"]):
        reasons.append("insufficient_distinct_approvers")
    if controller_identity in approver_identities:
        reasons.append("promotion_controller_cannot_approve")

    if not reasons and changed_at is not None and isinstance(token, int):
        try:
            store.promote_region(
                target=target,
                token=token,
                changed_at=changed_at,
                request_digest=request_digest,
            )
            checks.append(f"region_epoch_persisted:{token}")
        except ValidationError as exc:
            reasons.append(f"region_fence_commit_failed:{exc}")
    return GateReport.from_reasons(
        reasons,
        (*checks, "four_eyes", "replication", "fencing", "routing", "rollback"),
    )
