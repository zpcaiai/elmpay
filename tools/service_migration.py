#!/usr/bin/env python3
"""Executable B15 durable service-migration control plane."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "runtime"))

from elmpay_runtime.common import ValidationError, read_json  # noqa: E402
from elmpay_runtime.service_migration import DeliveryLease, ServiceMigrationControl  # noqa: E402


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="ELMPay durable B15 service migration")
    result.add_argument("--db", type=Path, required=True)
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    register = commands.add_parser("register")
    _scope(register)
    register.add_argument("--configuration", type=Path, required=True)
    record = commands.add_parser("record-provider-result")
    _scope(record)
    record.add_argument("--operation", required=True)
    record.add_argument("--idempotency-key", required=True)
    record.add_argument("--provider-reference", required=True)
    for name in ("request", "provider-result", "legacy-projection", "platform-projection"):
        record.add_argument("--" + name, type=Path, required=True)
    claim = commands.add_parser("claim-delivery")
    _scope(claim)
    claim.add_argument("--target", choices=("legacy", "platform"), required=True)
    claim.add_argument("--worker", required=True)
    claim.add_argument("--lease-seconds", type=int, default=30)
    acknowledge = commands.add_parser("ack-delivery")
    acknowledge.add_argument("--lease", type=Path, required=True)
    acknowledge.add_argument("--remote-digest", required=True)
    backfill = commands.add_parser("backfill-page")
    _scope(backfill)
    backfill.add_argument("--stream", required=True)
    backfill.add_argument("--records", type=Path, required=True)
    propose = commands.add_parser("propose-cutover")
    _scope(propose)
    propose.add_argument("--target-phase", required=True)
    propose.add_argument("--evidence", type=Path, required=True)
    propose.add_argument("--proposer", required=True)
    approve = commands.add_parser("approve-cutover")
    _scope(approve)
    approve.add_argument("--cutover-id", required=True)
    approve.add_argument("--evidence", type=Path, required=True)
    approve.add_argument("--approver", required=True)
    return result


def _scope(command: argparse.ArgumentParser) -> None:
    command.add_argument("--tenant", required=True)
    command.add_argument("--project", required=True)


def _emit(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str))


def _lease(value: object) -> DeliveryLease:
    if not isinstance(value, dict):
        raise ValidationError("lease document must be an object")
    payload = value.get("payload")
    if not isinstance(payload, dict):
        raise ValidationError("lease payload must be an object")
    return DeliveryLease(
        str(value.get("tenant_id", "")), str(value.get("project_id", "")),
        str(value.get("operation_id", "")), str(value.get("target", "")), payload,
        str(value.get("payload_digest", "")), str(value.get("lease_owner", "")),
        int(value.get("lease_token", -1)), str(value.get("lease_expires_at", "")),
    )


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        control = ServiceMigrationControl(arguments.db)
        now = datetime.now(timezone.utc)
        if arguments.command == "init":
            value: object = {"initialized": True, "certificationStatus": "NOT_CERTIFIED"}
        elif arguments.command == "register":
            value = {"configurationDigest": control.register_project(
                arguments.tenant, arguments.project, read_json(arguments.configuration), now=now)}
        elif arguments.command == "record-provider-result":
            value = control.record_provider_result(
                tenant_id=arguments.tenant, project_id=arguments.project,
                operation_id=arguments.operation, idempotency_key=arguments.idempotency_key,
                request=read_json(arguments.request),
                provider_reference=arguments.provider_reference,
                provider_result=read_json(arguments.provider_result),
                legacy_projection=read_json(arguments.legacy_projection),
                platform_projection=read_json(arguments.platform_projection), now=now,
            )
        elif arguments.command == "claim-delivery":
            lease = control.claim_delivery(arguments.tenant, arguments.project, arguments.target,
                                           arguments.worker, now=now,
                                           lease_seconds=arguments.lease_seconds)
            value = None if lease is None else lease.__dict__
        elif arguments.command == "ack-delivery":
            control.acknowledge_delivery(_lease(read_json(arguments.lease)),
                                         arguments.remote_digest, now=now)
            value = {"acknowledged": True}
        elif arguments.command == "backfill-page":
            records = read_json(arguments.records)
            if not isinstance(records, list):
                raise ValidationError("records must be an array")
            value = control.import_backfill_page(arguments.tenant, arguments.project,
                                                 arguments.stream, records, now=now)
        elif arguments.command == "propose-cutover":
            value = {"cutoverId": control.propose_cutover(
                arguments.tenant, arguments.project, arguments.target_phase,
                read_json(arguments.evidence), arguments.proposer, now=now)}
        elif arguments.command == "approve-cutover":
            value = {"phase": control.approve_cutover(
                arguments.tenant, arguments.project, arguments.cutover_id,
                arguments.approver, read_json(arguments.evidence), now=now)}
        else:
            raise ValidationError("unsupported migration command")
        _emit(value)
        return 0
    except (OSError, TypeError, ValueError, ValidationError) as exception:
        _emit({"allowed": False, "reasons": [f"input_invalid:{exception}"]})
        return 2


if __name__ == "__main__":
    sys.exit(main())
