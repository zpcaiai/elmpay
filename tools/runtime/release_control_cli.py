#!/usr/bin/env python3
"""Fail-closed operator CLI for reconciling a durable rollout rollback."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Mapping

from elmpay_runtime.common import ValidationError, read_json
from elmpay_runtime.release_control import ReleaseControl


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="ELMPay durable release control")
    value.add_argument("--database", required=True, type=Path)
    value.add_argument("--trust", required=True, type=Path)
    value.add_argument("--rollout-policy", required=True, type=Path)
    value.add_argument("--release-policy", required=True, type=Path)
    value.add_argument("--capacity-policy", required=True, type=Path)
    value.add_argument("--external-evidence-policy", required=True, type=Path)
    value.add_argument("--external-evidence-trust", required=True, type=Path)
    commands = value.add_subparsers(dest="command", required=True)
    reconcile = commands.add_parser(
        "reconcile-rollback",
        help="complete an UNKNOWN/expired rollback from a signed executor receipt",
    )
    reconcile.add_argument("--rollout-id", required=True)
    reconcile.add_argument("--receipt", required=True, type=Path)
    reconcile.add_argument("--now", help="RFC-3339 verification instant; defaults to now")
    return value


def _instant(raw: str | None) -> datetime:
    if raw is None:
        return datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValidationError("--now must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        control = ReleaseControl(
            str(args.database),
            read_json(args.trust),
            read_json(args.rollout_policy),
            read_json(args.release_policy),
            read_json(args.capacity_policy),
            read_json(args.external_evidence_policy),
            read_json(args.external_evidence_trust),
        )
        if args.command != "reconcile-rollback":
            raise ValidationError("unsupported release-control command")
        receipt = read_json(args.receipt)

        def receipt_adapter(_request: Mapping[str, Any]) -> Mapping[str, Any]:
            return {"receipt": receipt}

        result = control.reconcile_rollback(
            args.rollout_id, receipt_adapter, now=_instant(args.now)
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, ValidationError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    sys.exit(main())
