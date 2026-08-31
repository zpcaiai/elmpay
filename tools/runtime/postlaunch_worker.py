#!/usr/bin/env python3
"""One-shot CronJob entrypoint for fenced B125 reconciliation windows.

The deployment scheduler invokes this process once per daily/weekly/monthly
window. Ledger, provider and bank adapters supply independently signed source
receipts; raw caller-authored totals are intentionally not accepted.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from elmpay_runtime.common import ValidationError, read_json
from elmpay_runtime.postlaunch import PostLaunchControl


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="ELMPay fenced post-launch reconciliation")
    value.add_argument("--database", type=Path, required=True)
    value.add_argument("--tenant", required=True)
    value.add_argument("--owner", required=True)
    value.add_argument("--kind", choices=("DAILY", "WEEKLY", "MONTHLY"), required=True)
    value.add_argument("--anchor", required=True, help="RFC-3339 scheduler anchor")
    value.add_argument("--currency", required=True, help="uppercase ISO-4217 currency")
    value.add_argument(
        "--source-receipts", type=Path, required=True,
        help="JSON object containing transaction/provider/bank signed receipts",
    )
    value.add_argument(
        "--source-trust", type=Path, required=True,
        help="Ed25519 public trust and durable nonce database configuration",
    )
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        anchor = datetime.fromisoformat(args.anchor.replace("Z", "+00:00"))
        if anchor.tzinfo is None:
            raise ValidationError("anchor must include a UTC offset")
        anchor = anchor.astimezone(timezone.utc)
        execution_now = datetime.now(timezone.utc)
        control = PostLaunchControl(str(args.database))
        job_key = f"reconcile:{args.tenant}:{args.kind}"
        token = control.acquire(job_key, args.owner, now=execution_now)
        start, end = control.window(args.kind, anchor)
        window_id = f"{args.kind.lower()}:{start.isoformat()}"
        result = control.reconcile(
            tenant_id=args.tenant,
            window_id=window_id,
            window_kind=args.kind,
            period_start=start,
            period_end=end,
            currency=args.currency,
            source_receipts=read_json(args.source_receipts),
            trust=read_json(args.source_trust),
            job_key=job_key,
            owner_id=args.owner,
            fence_token=token,
            now=execution_now,
        )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 0 if result["allowedToClose"] else 2
    except (ValidationError, OSError, ValueError) as exc:
        print(json.dumps({"allowedToClose": False, "reason": str(exc)}, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    sys.exit(main())
