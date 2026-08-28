#!/usr/bin/env python3
"""Execute B31 database/cache/message/log/export isolation probes over HTTPS+mTLS."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import ssl
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "runtime"))

from elmpay_runtime.common import ValidationError, read_json  # noqa: E402
from elmpay_runtime.tenant_isolation_probe import (  # noqa: E402
    HttpIsolationSurface,
    SURFACES,
    TenantIsolationProbeRunner,
)


ROOT = Path(__file__).resolve().parents[1]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="ELMPay durable live tenant-isolation probe")
    result.add_argument("--db", type=Path, required=True)
    result.add_argument("--input", type=Path, required=True)
    result.add_argument("--policy", type=Path,
                        default=ROOT / "platform/security/tenant-isolation-probes.json")
    result.add_argument("--client-cert", type=Path, required=True)
    result.add_argument("--client-key", type=Path, required=True)
    result.add_argument("--ca-bundle", type=Path, required=True)
    result.add_argument("--token-file", type=Path, required=True)
    return result


def _safe_text(path: Path, field: str, maximum: int) -> str:
    resolved = path.absolute()
    if not resolved.is_file() or resolved.is_symlink() or resolved.stat().st_size > maximum:
        raise ValidationError(f"{field} file is unsafe")
    value = resolved.read_text(encoding="utf-8").strip()
    if not value or "\r" in value or "\n" in value:
        raise ValidationError(f"{field} has an invalid format")
    return value


def _emit(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        policy = read_json(arguments.policy)
        request = read_json(arguments.input)
        if set(policy.get("requiredSurfaces", [])) != set(SURFACES):
            raise ValidationError("probe policy must require all five surfaces")
        endpoint_environment = policy.get("endpointEnvironment")
        if not isinstance(endpoint_environment, dict):
            raise ValidationError("probe endpointEnvironment must be an object")
        context = ssl.create_default_context(cafile=str(arguments.ca_bundle.absolute()))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(str(arguments.client_cert.absolute()),
                                str(arguments.client_key.absolute()))
        token = _safe_text(arguments.token_file, "token", 8_192)
        surfaces = {}
        for surface in SURFACES:
            variable = endpoint_environment.get(surface)
            if not isinstance(variable, str) or not variable.startswith("ELMPAY_ISOLATION_"):
                raise ValidationError("probe endpoint environment mapping is invalid")
            endpoint = os.environ.get(variable)
            if not endpoint:
                raise ValidationError(f"{variable} is required")
            surfaces[surface] = HttpIsolationSurface(
                surface, endpoint, context, token,
                timeout_seconds=int(policy.get("requestTimeoutSeconds", 5)),
                maximum_response_bytes=int(policy.get("maximumResponseBytes", 65_536)),
            )
        runner = TenantIsolationProbeRunner(arguments.db, surfaces)
        result = runner.run(
            owner_tenant_id=str(request.get("ownerTenantId", "")),
            attacker_tenant_id=str(request.get("attackerTenantId", "")),
            canary_id=str(request.get("canaryId", "")),
            expected_digest=str(request.get("expectedDigest", "")),
            run_id=request.get("runId"),
        )
        _emit(result)
        return 0 if result["status"] == "PASSED" else 3
    except (OSError, ssl.SSLError, TypeError, ValueError, ValidationError) as exception:
        _emit({"status": "FAILED", "reasons": [f"input_invalid:{exception}"],
               "certificationStatus": "NOT_CERTIFIED"})
        return 2


if __name__ == "__main__":
    sys.exit(main())
