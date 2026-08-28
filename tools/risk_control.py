#!/usr/bin/env python3
"""Executable B80-B83/B87 risk service administration and decision CLI."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "runtime"))

from elmpay_runtime.common import ValidationError, parse_instant, read_json  # noqa: E402
from elmpay_runtime.risk_control import HttpModelClient, ModelResult, SQLiteRiskControl  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


class UnavailableModel:
    def score(self, request, timeout_milliseconds):
        del request, timeout_milliseconds
        return ModelResult(False, "unavailable", "0" * 64, Decimal(0), "MODEL_NOT_CONFIGURED")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="ELMPay durable risk control")
    result.add_argument("--db", type=Path, required=True)
    result.add_argument("--policy", type=Path, default=ROOT / "platform/risk/runtime-policy.json")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    propose = commands.add_parser("propose-rules")
    propose.add_argument("--tenant", required=True)
    propose.add_argument("--version", required=True)
    propose.add_argument("--rules", type=Path, required=True)
    propose.add_argument("--proposer", required=True)
    propose.add_argument("--activate-at", required=True)
    approve = commands.add_parser("approve-rules")
    approve.add_argument("--tenant", required=True)
    approve.add_argument("--version", required=True)
    approve.add_argument("--approver", required=True)
    decide = commands.add_parser("decide")
    decide.add_argument("--request", type=Path, required=True)
    decide.add_argument("--signals", type=Path, required=True)
    decide.add_argument("--model-endpoint")
    decide.add_argument("--feature-schema-digest")
    operation = commands.add_parser("propose-operation")
    operation.add_argument("--tenant", required=True)
    operation.add_argument("--kind", required=True)
    operation.add_argument("--subject", required=True)
    operation.add_argument("--payload", type=Path, required=True)
    operation.add_argument("--proposer", required=True)
    operation.add_argument("--expires-at", required=True)
    approve_operation = commands.add_parser("approve-operation")
    approve_operation.add_argument("--tenant", required=True)
    approve_operation.add_argument("--operation-id", required=True)
    approve_operation.add_argument("--approver", required=True)
    return result


def emit(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str))


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    control = None
    try:
        args.db.parent.mkdir(parents=True, exist_ok=True)
        control = SQLiteRiskControl(str(args.db), read_json(args.policy))
        now = datetime.now(timezone.utc)
        if args.command == "init":
            emit({"initialized": True, "certificationStatus": "NOT_CERTIFIED"})
        elif args.command == "propose-rules":
            digest = control.propose_rule_set(
                args.tenant, args.version, read_json(args.rules), args.proposer,
                parse_instant(args.activate_at, "activate-at"), now,
            )
            emit({"state": "PROPOSED", "digest": digest})
        elif args.command == "approve-rules":
            control.approve_rule_set(args.tenant, args.version, args.approver, now)
            emit({"state": "APPROVED_OR_ACTIVE"})
        elif args.command == "decide":
            if bool(args.model_endpoint) != bool(args.feature_schema_digest):
                raise ValidationError("model endpoint and schema digest must be supplied together")
            model = HttpModelClient(args.model_endpoint, args.feature_schema_digest) if args.model_endpoint else UnavailableModel()
            decision = control.decide(read_json(args.request), read_json(args.signals), model, now=now)
            emit(decision.__dict__)
        elif args.command == "propose-operation":
            operation_id = control.propose_operation(
                args.tenant, args.kind, args.subject, read_json(args.payload), args.proposer,
                parse_instant(args.expires_at, "expires-at"), now,
            )
            emit({"state": "PROPOSED", "operationId": operation_id})
        elif args.command == "approve-operation":
            control.approve_operation(args.tenant, args.operation_id, args.approver, now)
            emit({"state": "APPROVED"})
        else:
            raise ValidationError("unsupported risk command")
        return 0
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        emit({"allowed": False, "reasons": [f"input_invalid:{exc}"]})
        return 2
    finally:
        if control is not None:
            control.close()


if __name__ == "__main__":
    sys.exit(main())
