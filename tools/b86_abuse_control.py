#!/usr/bin/env python3
"""Executable B86 layered abuse decision and case workflow surface."""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parent / "runtime"))

from elmpay_runtime.abuse_protection import (  # noqa: E402
    AbuseProtectionService,
    AbuseRequest,
    SubjectDigester,
    load_abuse_policy,
)
from elmpay_runtime.common import ValidationError, parse_instant, read_json, require_mapping, require_text  # noqa: E402
from elmpay_runtime.mounted_secrets import read_mounted_secret, secret_path_from_environment  # noqa: E402
from elmpay_runtime.security_store import SecurityStore  # noqa: E402


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="ELMPay B86 abuse control")
    subcommands = value.add_subparsers(dest="command", required=True)
    for name in ("evaluate", "case-action"):
        command = subcommands.add_parser(name)
        command.add_argument("--database", required=True, type=Path)
        command.add_argument("--policy", required=True, type=Path)
        command.add_argument("--input", required=True, type=Path)
    value.add_argument("--at", help="RFC-3339 evaluation time; defaults to current UTC")
    return value


def _subjects() -> SubjectDigester:
    if "ELMPAY_SUBJECT_HMAC_KEY_HEX" in os.environ:
        raise ValidationError(
            "ELMPAY_SUBJECT_HMAC_KEY_HEX is forbidden; use the read-only key mount"
        )
    encoded = read_mounted_secret(secret_path_from_environment(
        "ELMPAY_SUBJECT_HMAC_KEY_FILE"), "subject HMAC key").decode("ascii")
    try:
        secret = bytes.fromhex(encoded)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValidationError("subject digest key is unavailable") from exc
    return SubjectDigester(secret)


def _request(value: Mapping[str, Any]) -> AbuseRequest:
    required = {"tenantId", "requestId", "layer", "routeId", "occurredAt", "sourceIp"}
    optional = {
        "accountId", "deviceId", "sessionId", "authenticationSucceeded",
        "credentialLeakMatch", "webauthnVerified", "newDevice", "impossibleTravel",
        "botScoreBasisPoints", "sourceReputation",
    }
    if not required.issubset(value) or set(value) - required - optional:
        raise ValidationError("abuse request fields are invalid")
    return AbuseRequest(
        tenant_id=require_text(value["tenantId"], "tenantId"),
        request_id=require_text(value["requestId"], "requestId"),
        layer=require_text(value["layer"], "layer"),
        route_id=require_text(value["routeId"], "routeId"),
        occurred_at=parse_instant(value["occurredAt"], "occurredAt"),
        source_ip=require_text(value["sourceIp"], "sourceIp"),
        account_id=value.get("accountId"), device_id=value.get("deviceId"), session_id=value.get("sessionId"),
        authentication_succeeded=value.get("authenticationSucceeded", False),
        credential_leak_match=value.get("credentialLeakMatch", False),
        webauthn_verified=value.get("webauthnVerified", False),
        new_device=value.get("newDevice", False), impossible_travel=value.get("impossibleTravel", False),
        bot_score_basis_points=value.get("botScoreBasisPoints", 0),
        source_reputation=value.get("sourceReputation", "UNKNOWN"),
    )


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        now = parse_instant(arguments.at, "at") if arguments.at else datetime.now(timezone.utc)
        policy = load_abuse_policy(arguments.policy)
        service = AbuseProtectionService(SecurityStore(arguments.database), policy, _subjects())
        value = require_mapping(read_json(arguments.input), "input")
        if arguments.command == "evaluate":
            decision = service.evaluate_or_block(_request(value), now=now)
            output = {**asdict(decision), "certificationStatus": "NOT_CERTIFIED"}
            status = 0 if decision.action in {"ALLOW", "CHALLENGE", "BLOCK"} else 2
        else:
            expected = {"tenantId", "caseId", "eventId", "action", "actor", "reviewer", "reason"}
            if set(value) != expected:
                raise ValidationError("abuse case action fields are invalid")
            state = service.transition_case(
                require_text(value["tenantId"], "tenantId"), require_text(value["caseId"], "caseId"),
                event_id=require_text(value["eventId"], "eventId"), action=require_text(value["action"], "action"),
                actor=require_text(value["actor"], "actor"), reviewer=value["reviewer"],
                reason=require_text(value["reason"], "reason"), now=now,
            )
            output = {"state": state, "certificationStatus": "NOT_CERTIFIED"}
            status = 0
        sys.stdout.write(json.dumps(output, sort_keys=True) + "\n")
        return status
    except (KeyError, TypeError, ValueError, OSError, ValidationError) as exc:
        sys.stdout.write(json.dumps({"allowed": False, "error": type(exc).__name__}, sort_keys=True) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
