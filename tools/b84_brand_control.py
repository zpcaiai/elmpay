#!/usr/bin/env python3
"""Executable B84 brand monitoring and takedown-case control surface."""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parent / "runtime"))

from elmpay_runtime.brand_protection import (  # noqa: E402
    BrandProtectionService,
    DomainControlPosture,
    DomainObservation,
    assess_domain,
    evaluate_domain_posture,
    load_brand_policy,
)
from elmpay_runtime.common import ValidationError, parse_instant, read_json, require_mapping, require_text  # noqa: E402
from elmpay_runtime.security_store import SecurityStore  # noqa: E402


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="ELMPay B84 brand protection control")
    subcommands = value.add_subparsers(dest="command", required=True)
    for name in ("assess", "observe", "posture", "case-action"):
        command = subcommands.add_parser(name)
        command.add_argument("--policy", required=True, type=Path)
        command.add_argument("--input", required=True, type=Path)
        if name in {"observe", "case-action"}:
            command.add_argument("--database", required=True, type=Path)
    value.add_argument("--at", help="RFC-3339 evaluation time; defaults to current UTC")
    return value


def _now(value: str | None) -> datetime:
    return parse_instant(value, "at") if value is not None else datetime.now(timezone.utc)


def _observation(value: Mapping[str, Any]) -> DomainObservation:
    required = {"tenantId", "source", "observationId", "domain", "observedAt"}
    if set(value) not in (required, required | {"certificateIssuer"}):
        raise ValidationError("brand observation fields are invalid")
    return DomainObservation(
        tenant_id=require_text(value["tenantId"], "tenantId"),
        source=require_text(value["source"], "source"),
        observation_id=require_text(value["observationId"], "observationId"),
        domain=require_text(value["domain"], "domain"),
        observed_at=parse_instant(value["observedAt"], "observedAt"),
        certificate_issuer=(
            require_text(value["certificateIssuer"], "certificateIssuer")
            if "certificateIssuer" in value else None
        ),
    )


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        policy = load_brand_policy(arguments.policy)
        value = require_mapping(read_json(arguments.input), "input")
        now = _now(arguments.at)
        if arguments.command == "assess":
            result = assess_domain(policy, _observation(value), now=now)
            output = asdict(result)
        elif arguments.command == "observe":
            service = BrandProtectionService(SecurityStore(arguments.database), policy)
            service.provision_policy(require_text(value.get("tenantId"), "tenantId"), now=now)
            output = asdict(service.observe(_observation(value), now=now))
        elif arguments.command == "posture":
            expected = {
                "tenantId", "domain", "dnssec", "caaIssuers", "registryLock",
                "transferLock", "registrarHardwareMfa", "dmarcPolicy", "observedAt",
            }
            if set(value) != expected:
                raise ValidationError("domain posture fields are invalid")
            posture = DomainControlPosture(
                tenant_id=require_text(value["tenantId"], "tenantId"),
                domain=require_text(value["domain"], "domain"),
                dnssec=value["dnssec"],
                caa_issuers=tuple(value["caaIssuers"]),
                registry_lock=value["registryLock"],
                transfer_lock=value["transferLock"],
                registrar_hardware_mfa=value["registrarHardwareMfa"],
                dmarc_policy=require_text(value["dmarcPolicy"], "dmarcPolicy"),
                observed_at=parse_instant(value["observedAt"], "observedAt"),
            )
            if any(not isinstance(item, bool) for item in (
                posture.dnssec, posture.registry_lock, posture.transfer_lock,
                posture.registrar_hardware_mfa,
            )):
                raise ValidationError("domain posture flags must be boolean")
            result = evaluate_domain_posture(policy, posture, now=now)
            output = asdict(result)
        else:
            expected = {
                "tenantId", "caseId", "actionId", "action", "actor", "reviewer",
                "reason", "externalReceipt",
            }
            if set(value) != expected:
                raise ValidationError("takedown case action fields are invalid")
            service = BrandProtectionService(SecurityStore(arguments.database), policy)
            state = service.transition_case(
                require_text(value["tenantId"], "tenantId"),
                require_text(value["caseId"], "caseId"),
                action_id=require_text(value["actionId"], "actionId"),
                action=require_text(value["action"], "action"),
                actor=require_text(value["actor"], "actor"),
                reviewer=value["reviewer"],
                reason=require_text(value["reason"], "reason"),
                external_receipt=value["externalReceipt"],
                now=now,
            )
            output = {"state": state, "certificationStatus": "NOT_CERTIFIED"}
        sys.stdout.write(json.dumps(output, ensure_ascii=False, sort_keys=True, default=list) + "\n")
        return 0 if output.get("allowed", True) else 2
    except (KeyError, TypeError, ValueError, OSError, ValidationError) as exc:
        sys.stdout.write(json.dumps({"allowed": False, "error": type(exc).__name__}, sort_keys=True) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
