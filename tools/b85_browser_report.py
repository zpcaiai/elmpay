#!/usr/bin/env python3
"""Executable durable ingest endpoint for sanitized B85 browser reports."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "runtime"))

from elmpay_runtime.browser_integrity import BrowserSecurityReportService  # noqa: E402
from elmpay_runtime.common import ValidationError, parse_instant, read_json, require_mapping  # noqa: E402
from elmpay_runtime.security_store import SecurityStore  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ELMPay B85 sanitized browser report ingest")
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--policy-version", required=True)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--at")
    arguments = parser.parse_args(argv)
    try:
        now = parse_instant(arguments.at, "at") if arguments.at else datetime.now(timezone.utc)
        service = BrowserSecurityReportService(
            SecurityStore(arguments.database), arguments.policy_version,
        )
        digest = service.record(
            arguments.deployment_id,
            require_mapping(read_json(arguments.input), "input"),
            now=now,
        )
        sys.stdout.write(json.dumps({
            "accepted": True, "reportDigest": digest,
            "certificationStatus": "NOT_CERTIFIED",
        }, sort_keys=True) + "\n")
        return 0
    except (TypeError, ValueError, OSError, ValidationError) as exc:
        sys.stdout.write(json.dumps({"accepted": False, "error": type(exc).__name__}, sort_keys=True) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
