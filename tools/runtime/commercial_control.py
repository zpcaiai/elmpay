#!/usr/bin/env python3
"""Durable B126 commercial operations and signed audit-export entrypoint."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

from elmpay_runtime.commercial import CommercialLedger
from elmpay_runtime.common import ValidationError, canonical_json, parse_instant, read_json


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="ELMPay commercial control plane")
    value.add_argument("--database", type=Path, required=True)
    commands = value.add_subparsers(dest="command", required=True)
    for name in (
        "create-pricing",
        "meter",
        "issue-invoice",
        "set-sla",
        "open-ticket",
        "respond-ticket",
        "request-credit",
        "approve-credit",
        "net-invoice",
    ):
        command = commands.add_parser(name)
        command.add_argument("--request", type=Path, required=True)
    export = commands.add_parser("export-audit")
    export.add_argument("--request", type=Path, required=True)
    export.add_argument("--trust", type=Path, required=True)
    export.add_argument("--output", type=Path, required=True)
    return value


def _now(raw: dict[str, object]) -> datetime:
    value = raw.get("now")
    return parse_instant(value, "now") if value is not None else datetime.now(timezone.utc)


def _write_once(path: Path, value: object) -> None:
    """Atomically create an export; refuse a conflicting overwrite."""

    encoded = canonical_json(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValidationError("audit export output cannot be a symbolic link")
    if path.exists():
        if not path.is_file() or path.read_bytes() != encoded:
            raise ValidationError("audit export output already exists with different content")
        return
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        raw = read_json(args.request)
        if not isinstance(raw, dict):
            raise ValidationError("commercial request must be a JSON object")
        ledger = CommercialLedger(str(args.database))
        now = _now(raw)
        if args.command == "create-pricing":
            result: object = {
                "pricingVersionId": ledger.create_pricing(
                    raw["tenantId"], raw["version"], raw["policy"],
                    parse_instant(raw["effectiveAt"], "effectiveAt"),
                    actor=raw["actor"], now=now,
                )
            }
        elif args.command == "meter":
            result = {
                "accepted": ledger.meter(
                    raw["tenantId"], raw["pricingVersionId"], raw["event"],
                    actor=raw["actor"], now=now,
                )
            }
        elif args.command == "issue-invoice":
            result = ledger.issue_invoice(
                raw["invoiceId"], raw["tenantId"], raw["pricingVersionId"],
                parse_instant(raw["periodStart"], "periodStart"),
                parse_instant(raw["periodEnd"], "periodEnd"),
                actor=raw["actor"], now=now,
            )
        elif args.command == "set-sla":
            result = {
                "policyDigest": ledger.set_sla(
                    raw["tenantId"], raw["version"],
                    parse_instant(raw["effectiveAt"], "effectiveAt"),
                    raw["responseMinutes"], raw["serviceCreditBasisPoints"],
                    actor=raw["actor"], now=now,
                )
            }
        elif args.command == "open-ticket":
            result = ledger.open_ticket(
                raw["ticketId"], raw["tenantId"], raw["severity"],
                actor=raw["actor"],
                opened_at=parse_instant(raw["openedAt"], "openedAt"),
            )
        elif args.command == "respond-ticket":
            result = ledger.respond_ticket(
                raw["ticketId"], raw["tenantId"], raw["responder"],
                responded_at=parse_instant(raw["respondedAt"], "respondedAt"),
            )
        elif args.command == "request-credit":
            ledger.request_credit(
                raw["requestId"], raw["tenantId"], raw["invoiceId"], raw["requester"],
                raw["amountMinor"], raw["reason"], now=now,
            )
            result = {"requestId": raw["requestId"], "status": "PENDING"}
        elif args.command == "approve-credit":
            result = ledger.approve_credit(raw["requestId"], raw["approver"], now=now)
        elif args.command == "net-invoice":
            result = {
                "invoiceId": raw["invoiceId"],
                "netMinor": ledger.net_invoice_minor(raw["tenantId"], raw["invoiceId"]),
            }
        elif args.command == "export-audit":
            result = ledger.finalize_audit_export(
                export_id=raw["exportId"], tenant_id=raw["tenantId"],
                period_start=parse_instant(raw["periodStart"], "periodStart"),
                period_end=parse_instant(raw["periodEnd"], "periodEnd"),
                receipt=raw["receipt"], trust=read_json(args.trust), now=now,
            )
            _write_once(args.output, result)
        else:
            raise ValidationError("unsupported commercial command")
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 0
    except (KeyError, OSError, TypeError, ValueError, ValidationError) as exc:
        print(json.dumps(
            {"allowed": False, "reason": f"input_invalid:{exc}"},
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ))
        return 2


if __name__ == "__main__":
    sys.exit(main())
