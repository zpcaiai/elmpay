#!/usr/bin/env python3
"""Operational CLI for B88-B111 controls without external mutations."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "runtime"))

from elmpay_runtime.assurance import (  # noqa: E402
    SQLiteDeletionWorkflow,
    evaluate_pci_scope,
    evaluate_regional_onboarding,
    evaluate_regulated_identity_decision,
    evaluate_sca_transaction,
    evaluate_supply_chain,
)
from elmpay_runtime.attestation import verify_dsse_record  # noqa: E402
from elmpay_runtime.common import (  # noqa: E402
    GateReport,
    ValidationError,
    parse_instant,
    read_json,
    require_mapping,
    require_text,
)
from elmpay_runtime.downstream_receipt import verify_downstream_receipt  # noqa: E402
from elmpay_runtime.edge_security import (  # noqa: E402
    EdgeGuard,
    EdgeRequest,
    MappingSecretResolver,
    SQLiteEdgeStateStore,
)
from elmpay_runtime.infrastructure import (  # noqa: E402
    SQLiteFencingStore,
    evaluate_region_promotion,
    evaluate_restore_exercise,
    render_regional_data_plane,
    render_service_controls,
)
from elmpay_runtime.monitoring_runtime import (  # noqa: E402
    AuthenticatedOtlpHttpExporter,
    AuthenticatedSiemHttpExporter,
    DurableSiemService,
    MonitoringStore,
    ServiceOperationContext,
    ServiceTelemetryAdapter,
)
from elmpay_runtime.operations import (  # noqa: E402
    SQLiteOperationsStore,
    aggregate_funnel,
    evaluate_security_events,
    evaluate_slo_samples,
    telemetry_record,
)


ROOT = Path(__file__).resolve().parents[1]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="ELMPay platform and assurance controls")
    commands = result.add_subparsers(dest="command", required=True)
    edge = commands.add_parser("edge-authorize")
    edge.add_argument("--request", type=Path, required=True)
    edge.add_argument("--policy", type=Path, default=ROOT / "platform/policies/edge-security.json")
    edge.add_argument("--state", type=Path, required=True)
    edge.add_argument("--secret-env", required=True)
    mesh = commands.add_parser("render-service-controls")
    mesh.add_argument("--workloads", type=Path, default=ROOT / "platform/kubernetes/workload-policy.json")
    mesh.add_argument("--callers", type=Path, default=ROOT / "platform/kubernetes/service-callers.json")
    data_plane = commands.add_parser("render-data-plane")
    data_plane.add_argument("--policy", type=Path, default=ROOT / "platform/kubernetes/data-plane-policy.json")
    restore = commands.add_parser("restore-gate")
    restore.add_argument("--report", type=Path, required=True)
    restore.add_argument("--backup-digest", required=True)
    restore.add_argument("--plan", type=Path, default=ROOT / "platform/dr/plan.json")
    restore.add_argument("--trust", type=Path, required=True)
    promotion = commands.add_parser("region-promotion-gate")
    promotion.add_argument("--request", type=Path, required=True)
    promotion.add_argument("--plan", type=Path, default=ROOT / "platform/dr/plan.json")
    promotion.add_argument("--trust", type=Path, required=True)
    promotion.add_argument("--state", type=Path, required=True)
    slo = commands.add_parser("slo-gate")
    slo.add_argument("--samples", type=Path, required=True)
    slo.add_argument("--policy", type=Path, default=ROOT / "platform/observability/slos.json")
    siem = commands.add_parser("siem-evaluate")
    siem.add_argument("--events", type=Path, required=True)
    siem.add_argument("--policy", type=Path, default=ROOT / "platform/alerts/siem-rules.json")
    siem_ingest = commands.add_parser("siem-ingest")
    siem_ingest.add_argument("--event", type=Path, required=True)
    siem_ingest.add_argument("--state", type=Path, required=True)
    siem_ingest.add_argument("--source-trust", type=Path, required=True)
    siem_ingest.add_argument(
        "--runtime-policy", type=Path,
        default=ROOT / "platform/alerts/siem-runtime-policy.json",
    )
    siem_ingest.add_argument(
        "--detection-policy", type=Path,
        default=ROOT / "platform/alerts/siem-rules.json",
    )
    siem_export = commands.add_parser("siem-export")
    siem_export.add_argument("--state", type=Path, required=True)
    siem_export.add_argument("--source-trust", type=Path, required=True)
    siem_export.add_argument("--receipt-trust", type=Path, required=True)
    siem_export.add_argument("--worker-id", required=True)
    siem_export.add_argument(
        "--runtime-policy", type=Path,
        default=ROOT / "platform/alerts/siem-runtime-policy.json",
    )
    siem_export.add_argument(
        "--detection-policy", type=Path,
        default=ROOT / "platform/alerts/siem-rules.json",
    )
    pci = commands.add_parser("pci-scope-gate")
    pci.add_argument("--inventory", type=Path, required=True)
    regional = commands.add_parser("regional-onboarding-gate")
    regional.add_argument("--request", type=Path, required=True)
    regional.add_argument("--policy", type=Path, default=ROOT / "platform/compliance/regional-boundaries.json")
    regional.add_argument("--trust", type=Path, required=True)
    regulated = commands.add_parser("regulated-identity-gate")
    regulated.add_argument("--decision", type=Path, required=True)
    regulated.add_argument("--policy", type=Path, default=ROOT / "platform/compliance/aml-boundary.json")
    regulated.add_argument("--trust", type=Path, required=True)
    sca = commands.add_parser("sca-gate")
    sca.add_argument("--transaction", type=Path, required=True)
    sca.add_argument("--policy", type=Path, default=ROOT / "platform/compliance/psd2-sca-policy.json")
    sca.add_argument("--trust", type=Path, required=True)
    funnel = commands.add_parser("funnel-aggregate")
    funnel.add_argument("--events", type=Path, required=True)
    funnel.add_argument("--tenant-id", required=True)
    funnel.add_argument("--policy", type=Path, default=ROOT / "platform/observability/funnel-policy.json")
    provider = commands.add_parser("provider-health")
    provider.add_argument("--state", type=Path, required=True)
    provider.add_argument("--tenant-id", required=True)
    provider.add_argument("--account-id", required=True)
    provider.add_argument("--operation", choices=("before-call", "record"), required=True)
    provider.add_argument("--succeeded", choices=("true", "false"))
    provider.add_argument("--latency-ms", type=int)
    provider.add_argument("--policy", type=Path, default=ROOT / "platform/policies/provider-resilience.json")
    admin = commands.add_parser("admin-action")
    admin.add_argument("--state", type=Path, required=True)
    admin.add_argument("--operation", choices=("propose", "approve", "execute"), required=True)
    admin.add_argument("--request", type=Path, required=True)
    admin.add_argument(
        "--downstream-trust",
        type=Path,
        help="Ed25519 trust document required when executing an approved action",
    )
    incident_open = commands.add_parser("incident-open")
    incident_open.add_argument("--state", type=Path, required=True)
    incident_open.add_argument("--request", type=Path, required=True)
    incident_transition = commands.add_parser("incident-transition")
    incident_transition.add_argument("--state", type=Path, required=True)
    incident_transition.add_argument("--request", type=Path, required=True)
    deletion = commands.add_parser("deletion-workflow")
    deletion.add_argument("--state", type=Path, required=True)
    deletion.add_argument("--operation", choices=("propose", "approve", "execute", "confirm"), required=True)
    deletion.add_argument("--request", type=Path, required=True)
    deletion.add_argument("--policy", type=Path, default=ROOT / "platform/compliance/data-lifecycle.json")
    deletion.add_argument("--downstream-trust", type=Path)
    for name in ("deletion-propose", "deletion-approve", "deletion-execute", "deletion-confirm"):
        operation = commands.add_parser(name)
        operation.add_argument("--state", type=Path, required=True)
        operation.add_argument("--request", type=Path, required=True)
        operation.add_argument("--policy", type=Path,
                               default=ROOT / "platform/compliance/data-lifecycle.json")
        operation.add_argument("--downstream-trust", type=Path)
    supply = commands.add_parser("supply-chain-gate")
    supply.add_argument("--statement", type=Path, required=True)
    supply.add_argument("--trust", type=Path, required=True)
    supply.add_argument("--artifact-digest", required=True)
    supply.add_argument("--policy", type=Path, default=ROOT / "platform/compliance/supply-chain-policy.json")
    telemetry = commands.add_parser("telemetry-redact")
    telemetry.add_argument("--record", type=Path, required=True)
    telemetry_emit = commands.add_parser("telemetry-emit")
    telemetry_emit.add_argument("--record", type=Path, required=True)
    telemetry_emit.add_argument("--state", type=Path, required=True)
    telemetry_emit.add_argument(
        "--config", type=Path,
        default=ROOT / "platform/observability/runtime-export.json",
    )
    telemetry_export = commands.add_parser("telemetry-export")
    telemetry_export.add_argument("--state", type=Path, required=True)
    telemetry_export.add_argument("--worker-id", required=True)
    telemetry_export.add_argument(
        "--config", type=Path,
        default=ROOT / "platform/observability/runtime-export.json",
    )
    return result


def emit(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def report(value: GateReport) -> int:
    emit({"allowed": value.allowed, "reasons": value.reasons, "checks": value.checks})
    return 0 if value.allowed else 2


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "edge-authorize":
            raw = read_json(args.request)
            policy = read_json(args.policy)
            secret = os.environ.get(args.secret_env)
            if secret is None:
                raise ValidationError("merchant secret environment reference is unavailable")
            tenant = str(raw["tenantId"])
            project = str(raw["projectId"])
            state = SQLiteEdgeStateStore(str(args.state))
            try:
                guard = EdgeGuard(
                    secrets=MappingSecretResolver({(tenant, project): secret.encode()}),
                    state=state,
                    allowed_origins={key: tuple(value) for key, value in policy["allowedOrigins"].items()},
                    trusted_proxy_cidrs=tuple(policy["trustedProxyCidrs"]),
                    request_limit_per_minute=int(policy["requestLimitPerProjectPerMinute"]),
                    ip_limit_per_minute=int(policy["requestLimitPerSourcePerMinute"]),
                    maximum_body_bytes=int(policy["maximumBodyBytes"]),
                    maximum_clock_skew_seconds=int(policy["maximumClockSkewSeconds"]),
                )
                request = EdgeRequest(
                    tenant, project, str(raw["method"]), str(raw["path"]),
                    str(raw.get("body", "")).encode(), str(raw.get("contentType", "application/json")),
                    raw.get("origin"), str(raw["sourceIp"]), raw.get("forwardedFor"),
                    parse_instant(raw["timestamp"], "timestamp"), str(raw["nonce"]), str(raw["signature"]),
                )
                decision = guard.authorize(request)
            finally:
                state.close()
            emit(decision.__dict__)
            return 0 if decision.allowed else 2
        if args.command == "render-service-controls":
            emit(render_service_controls(read_json(args.workloads), read_json(args.callers)))
            return 0
        if args.command == "render-data-plane":
            emit(render_regional_data_plane(read_json(args.policy)))
            return 0
        if args.command == "restore-gate":
            return report(evaluate_restore_exercise(
                read_json(args.plan), read_json(args.report), args.backup_digest,
                read_json(args.trust),
                now=datetime.now(timezone.utc),
            ))
        if args.command == "region-promotion-gate":
            store = SQLiteFencingStore(str(args.state))
            try:
                return report(evaluate_region_promotion(
                    read_json(args.plan), read_json(args.request), read_json(args.trust), store,
                    now=datetime.now(timezone.utc),
                ))
            finally:
                store.close()
        if args.command == "slo-gate":
            return report(evaluate_slo_samples(read_json(args.policy), read_json(args.samples)))
        if args.command == "siem-evaluate":
            alerts = evaluate_security_events(read_json(args.policy), read_json(args.events))
            emit([alert.__dict__ for alert in alerts])
            return 0
        if args.command == "siem-ingest":
            runtime_policy = read_json(args.runtime_policy)
            service = DurableSiemService(
                MonitoringStore(args.state),
                runtime_policy=runtime_policy,
                detection_policy=read_json(args.detection_policy),
                source_trust=read_json(args.source_trust),
            )
            result = service.ingest(
                read_json(args.event), now=datetime.now(timezone.utc)
            )
            emit({
                "allowed": True,
                "eventId": result.event_id,
                "duplicate": result.duplicate,
                "alertIds": list(result.alert_ids),
                "signerIdentity": result.signer_identity,
                "externalSiemDeploymentStatus": "BLOCKED",
                "certificationStatus": "NOT_CERTIFIED",
            })
            return 0
        if args.command == "siem-export":
            runtime_policy = read_json(args.runtime_policy)
            exporter_policy = require_mapping(
                runtime_policy.get("exporter"), "SIEM exporter policy"
            )
            endpoint_env = require_text(
                exporter_policy.get("endpointEnv"), "SIEM endpointEnv"
            )
            token_env = require_text(
                exporter_policy.get("bearerTokenEnv"), "SIEM bearerTokenEnv"
            )
            endpoint = os.environ.get(endpoint_env)
            token = os.environ.get(token_env)
            if endpoint is None or token is None:
                raise ValidationError("SIEM exporter endpoint or bearer token is unavailable")
            ca_env = exporter_policy.get("caFileEnv")
            ca_file = os.environ.get(str(ca_env)) if isinstance(ca_env, str) else None
            exporter = AuthenticatedSiemHttpExporter(
                endpoint,
                token,
                timeout_seconds=int(exporter_policy.get("timeoutSeconds", 5)),
                allow_insecure_loopback=exporter_policy.get("allowInsecureLoopback") is True,
                ca_file=ca_file,
            )
            service = DurableSiemService(
                MonitoringStore(args.state),
                runtime_policy=runtime_policy,
                detection_policy=read_json(args.detection_policy),
                source_trust=read_json(args.source_trust),
                receipt_trust=read_json(args.receipt_trust),
            )
            summary = service.export_pending(
                exporter,
                destination=require_text(
                    exporter_policy.get("destination"), "SIEM destination"
                ),
                worker_id=args.worker_id,
                limit=int(exporter_policy.get("maximumBatchRecords", 100)),
                lease_seconds=int(exporter_policy.get("leaseSeconds", 30)),
                now=datetime.now(timezone.utc),
            )
            emit({
                "allowed": summary["unknown"] == 0,
                **summary,
                "certificationStatus": "NOT_CERTIFIED",
            })
            return 0 if summary["unknown"] == 0 else 2
        if args.command == "pci-scope-gate":
            return report(evaluate_pci_scope(read_json(args.inventory)))
        if args.command == "regional-onboarding-gate":
            return report(evaluate_regional_onboarding(
                read_json(args.policy), read_json(args.request), read_json(args.trust),
                now=datetime.now(timezone.utc),
            ))
        if args.command == "regulated-identity-gate":
            return report(evaluate_regulated_identity_decision(
                read_json(args.policy), read_json(args.decision), read_json(args.trust),
                now=datetime.now(timezone.utc),
            ))
        if args.command == "sca-gate":
            return report(evaluate_sca_transaction(
                read_json(args.policy), read_json(args.transaction), read_json(args.trust),
                now=datetime.now(timezone.utc),
            ))
        if args.command == "funnel-aggregate":
            raw_events = read_json(args.events)
            if not isinstance(raw_events, list):
                raise ValidationError("funnel events must be a JSON array")
            cells = aggregate_funnel(raw_events, args.tenant_id, read_json(args.policy))
            emit([{
                "dimensions": dict(cell.dimensions),
                "started": cell.started,
                "authorized": cell.authorized,
                "captured": cell.captured,
                "failed": cell.failed,
                "amountMinor": cell.amount_minor,
            } for cell in cells])
            return 0
        if args.command == "provider-health":
            if (args.operation == "record") != (args.succeeded is not None and args.latency_ms is not None):
                raise ValidationError("record requires succeeded and latency-ms; before-call forbids them")
            store = SQLiteOperationsStore(str(args.state))
            try:
                policy = read_json(args.policy)
                if args.operation == "before-call":
                    allowed = store.provider_before_call(
                        args.tenant_id, args.account_id, policy, datetime.now(timezone.utc)
                    )
                    emit({"allowed": allowed, "tenantId": args.tenant_id,
                          "providerAccountId": args.account_id})
                    return 0 if allowed else 2
                state = store.provider_record(
                    args.tenant_id, args.account_id, args.succeeded == "true", args.latency_ms,
                    policy, datetime.now(timezone.utc),
                )
                emit({"allowed": state != "OPEN", "state": state, "tenantId": args.tenant_id,
                      "providerAccountId": args.account_id})
                return 0 if state != "OPEN" else 2
            finally:
                store.close()
        if args.command == "admin-action":
            raw = read_json(args.request)
            store = SQLiteOperationsStore(str(args.state))
            try:
                if args.operation == "propose":
                    action_id = store.propose_action(
                        tenant_id=raw["tenantId"], action_type=raw["actionType"],
                        target=raw["target"], payload=raw["payload"], proposer=raw["proposer"],
                        now=datetime.now(timezone.utc),
                    )
                    emit({"allowed": True, "actionId": action_id, "state": "PROPOSED"})
                    return 0
                if args.operation == "approve":
                    store.approve_action(raw["actionId"], raw["approver"], datetime.now(timezone.utc))
                    emit({"allowed": True, "actionId": raw["actionId"], "state": "APPROVED"})
                    return 0

                if args.downstream_trust is None:
                    raise ValidationError("admin execution requires downstream trust material")
                downstream_trust = read_json(args.downstream_trust)

                def execute_action(action_id: str, tenant_id: str, target: str, payload: bytes) -> str:
                    if raw.get("actionId") != action_id or raw.get("tenantId") != tenant_id \
                            or raw.get("target") != target:
                        raise ValidationError("admin execution receipt binding mismatch")
                    payload_digest = __import__("hashlib").sha256(payload).hexdigest()
                    if raw.get("payloadDigest") != payload_digest:
                        raise ValidationError("admin execution payload digest mismatch")
                    receipt_digest, _ = verify_downstream_receipt(
                        raw.get("receipt"),
                        downstream_trust,
                        receipt_type="ADMIN_ACTION",
                        outcome="APPLIED",
                        fields={
                            "actionId": action_id,
                            "tenantId": tenant_id,
                            "target": target,
                            "payloadDigest": payload_digest,
                        },
                        required_role="admin_downstream",
                        now=datetime.now(timezone.utc),
                    )
                    return receipt_digest

                receipt = store.execute_action(raw["actionId"], execute_action)
                emit({"allowed": True, "actionId": raw["actionId"], "state": "EXECUTED",
                      "receipt": receipt})
                return 0
            finally:
                store.close()
        if args.command in {"incident-open", "incident-transition"}:
            raw = read_json(args.request)
            store = SQLiteOperationsStore(str(args.state))
            try:
                if args.command == "incident-open":
                    store.open_incident(raw["incidentId"], raw["severity"], raw["service"],
                                        raw["publicSummary"], raw["owner"], datetime.now(timezone.utc))
                else:
                    store.transition_incident(raw["incidentId"], int(raw["expectedVersion"]),
                                              raw["targetState"], datetime.now(timezone.utc))
                # This is the status-page publisher boundary: only the sanitized public
                # projection is emitted, ready for an authenticated downstream publisher.
                emit({"allowed": True, "statusPage": store.incident_status(raw["incidentId"])})
                return 0
            finally:
                store.close()
        if args.command == "deletion-workflow" or args.command.startswith("deletion-"):
            raw = read_json(args.request)
            workflow = SQLiteDeletionWorkflow(str(args.state))
            try:
                now = datetime.now(timezone.utc)
                operation = args.operation if args.command == "deletion-workflow" \
                    else args.command.removeprefix("deletion-")
                if operation == "propose":
                    job_id = workflow.propose(
                        read_json(args.policy), tenant_id=raw["tenantId"],
                        data_class=raw["dataClass"], record_digests=raw["recordDigests"],
                        legal_hold_clear=raw["legalHoldClear"], proposer=raw["proposer"], now=now,
                    )
                    emit({"allowed": True, "jobId": job_id, "state": "PROPOSED"})
                    return 0
                if operation == "approve":
                    workflow.approve(raw["jobId"], raw["approver"], now)
                    emit({"allowed": True, "jobId": raw["jobId"], "state": "APPROVED"})
                    return 0
                if operation == "execute":
                    if args.downstream_trust is None:
                        raise ValidationError("deletion execution requires downstream trust material")
                    downstream_trust = read_json(args.downstream_trust)

                    def deletion_receipt(job_id: str, tenant: str, kind: str,
                                         selection: str, count: int) -> tuple[int, str]:
                        expected = (raw.get("jobId"), raw.get("tenantId"), raw.get("dataClass"),
                                    raw.get("selectionDigest"), raw.get("recordCount"))
                        if expected != (job_id, tenant, kind, selection, count):
                            raise ValidationError("deletion receipt binding mismatch")
                        fields = {
                            "jobId": job_id,
                            "tenantId": tenant,
                            "dataClass": kind,
                            "selectionDigest": selection,
                            "recordCount": count,
                            "deletedCount": count,
                        }
                        receipt_digest, _ = verify_downstream_receipt(
                            raw.get("receipt"),
                            downstream_trust,
                            receipt_type="DATA_DELETION",
                            outcome="DELETED",
                            fields=fields,
                            required_role="data_store_operator",
                            now=now,
                        )
                        return count, receipt_digest

                    receipt = workflow.execute(raw["jobId"], raw["executor"], deletion_receipt, now)
                    emit({"allowed": True, "jobId": raw["jobId"],
                          "state": "BACKUP_EXPIRY_PENDING", "receipt": receipt})
                    return 0
                if args.downstream_trust is None:
                    raise ValidationError("backup expiry confirmation requires downstream trust material")
                downstream_trust = read_json(args.downstream_trust)
                verifier = str(raw["verifier"])

                def backup_receipt(job_id: str, execution_receipt: str) -> str:
                    receipt_digest, signer = verify_downstream_receipt(
                        raw.get("receipt"),
                        downstream_trust,
                        receipt_type="BACKUP_EXPIRY",
                        outcome="EXPIRED",
                        fields={
                            "jobId": job_id,
                            "executionReceiptDigest": execution_receipt,
                        },
                        required_role="backup_verifier",
                        require_independent=True,
                        now=now,
                    )
                    if signer.identity != verifier:
                        raise ValidationError("backup expiry verifier identity mismatch")
                    return receipt_digest

                workflow.confirm_backup_expiry(raw["jobId"], verifier, backup_receipt, now)
                emit({"allowed": True, "jobId": raw["jobId"], "state": "COMPLETED"})
                return 0
            finally:
                workflow.close()
        if args.command == "supply-chain-gate":
            statement = read_json(args.statement)
            trust = read_json(args.trust)

            def verify_signature(value: object) -> bool:
                if not isinstance(value, dict):
                    return False
                try:
                    verify_dsse_record(value, trust, args.artifact_digest,
                                       now=datetime.now(timezone.utc))
                    return True
                except ValidationError:
                    return False

            return report(evaluate_supply_chain(
                read_json(args.policy), statement, args.artifact_digest, verify_signature
            ))
        if args.command == "telemetry-redact":
            raw = read_json(args.record)
            emit(telemetry_record(
                tenant_id=raw["tenantId"], project_id=raw["projectId"], trace_id=raw["traceId"],
                correlation_id=raw["correlationId"], operation=raw["operation"], outcome=raw["outcome"],
                attributes=raw.get("attributes", {}), baggage=raw.get("baggage", {}),
            ))
            return 0
        if args.command == "telemetry-emit":
            raw = read_json(args.record)
            config = read_json(args.config)
            if config.get("schemaVersion") != 1:
                raise ValidationError("telemetry runtime config schemaVersion must be 1")
            adapter = ServiceTelemetryAdapter(
                MonitoringStore(args.state),
                service_name=require_text(config.get("serviceName"), "serviceName"),
                service_version=require_text(config.get("serviceVersion"), "serviceVersion"),
                environment=require_text(config.get("environment"), "environment"),
            )
            context = ServiceOperationContext(
                event_id=raw["eventId"],
                tenant_id=raw["tenantId"],
                project_id=raw["projectId"],
                trace_id=raw["traceId"],
                span_id=raw["spanId"],
                correlation_id=raw["correlationId"],
                operation=raw["operation"],
                baggage=require_mapping(raw.get("baggage", {}), "baggage"),
            )
            observed = (
                parse_instant(raw["observedAt"], "observedAt")
                if "observedAt" in raw
                else datetime.now(timezone.utc)
            )
            envelope_ids = adapter.record_operation(
                context,
                outcome=raw["outcome"],
                duration_ms=raw["durationMilliseconds"],
                attributes=require_mapping(raw.get("attributes", {}), "attributes"),
                observed_at=observed,
            )
            emit({
                "allowed": True,
                "state": "PENDING",
                "envelopeIds": list(envelope_ids),
                "certificationStatus": "NOT_CERTIFIED",
            })
            return 0
        if args.command == "telemetry-export":
            config = read_json(args.config)
            if config.get("schemaVersion") != 1:
                raise ValidationError("telemetry runtime config schemaVersion must be 1")
            export_policy = require_mapping(config.get("export"), "telemetry export policy")
            if export_policy.get("mode") != "OTLP_HTTP":
                raise ValidationError("telemetry export mode must be OTLP_HTTP")
            endpoint_env = require_text(export_policy.get("endpointEnv"), "OTLP endpointEnv")
            token_env = require_text(
                export_policy.get("bearerTokenEnv"), "OTLP bearerTokenEnv"
            )
            endpoint = os.environ.get(endpoint_env)
            token = os.environ.get(token_env)
            if endpoint is None or token is None:
                raise ValidationError("OTLP endpoint or bearer token is unavailable")
            ca_env = export_policy.get("caFileEnv")
            ca_file = os.environ.get(str(ca_env)) if isinstance(ca_env, str) else None
            store = MonitoringStore(args.state)
            adapter = ServiceTelemetryAdapter(
                store,
                service_name=require_text(config.get("serviceName"), "serviceName"),
                service_version=require_text(config.get("serviceVersion"), "serviceVersion"),
                environment=require_text(config.get("environment"), "environment"),
            )
            exporter = AuthenticatedOtlpHttpExporter(
                endpoint,
                token,
                timeout_seconds=int(export_policy.get("timeoutSeconds", 5)),
                allow_insecure_loopback=export_policy.get("allowInsecureLoopback") is True,
                ca_file=ca_file,
            )
            summary = adapter.export_pending(
                exporter,
                worker_id=args.worker_id,
                limit=int(export_policy.get("maximumBatchRecords", 100)),
                lease_seconds=int(export_policy.get("leaseSeconds", 30)),
                maximum_attempts=int(export_policy.get("maximumAttempts", 3)),
                now=datetime.now(timezone.utc),
            )
            emit({
                "allowed": (
                    summary["retryPending"] == 0
                    and summary["failed"] == 0
                    and summary["unknown"] == 0
                ),
                **summary,
                "certificationStatus": "NOT_CERTIFIED",
            })
            return 0 if (
                summary["retryPending"] == 0
                and summary["failed"] == 0
                and summary["unknown"] == 0
            ) else 2
        raise ValidationError("unsupported command")
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        emit({"allowed": False, "reasons": [f"input_invalid:{exc}"], "checks": []})
        return 2


if __name__ == "__main__":
    sys.exit(main())
