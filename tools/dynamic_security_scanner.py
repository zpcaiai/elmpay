#!/usr/bin/env python3
"""Bounded loopback DAST/IAST scanner used by the B116 orchestration gate.

The scanner derives findings from HTTP observations and instrumented trace events.  It never
accepts an application supplied ``safe``/``securityFinding``/``hookActive`` boolean as proof.
It is intentionally restricted to an explicit TEST-only loopback origin so it cannot be used
to probe a production system by mistake.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
from typing import Any, Mapping
from urllib import error as urlerror
from urllib import request as urlrequest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.common import (  # noqa: E402
    ValidationError,
    canonical_json,
    require_list,
    require_mapping,
    require_text,
)
from elmpay_runtime.quality import (  # noqa: E402
    _loopback_base,
    _safe_http_path,
    _same_origin,
    _validate_test_token,
)


SCANNER_VERSION = "elmpay-dynamic-security/1"
MAX_RESPONSE_BYTES = 65_536
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_DANGEROUS_SINKS = {
    "command-execution", "dynamic-sql", "path-traversal", "server-side-request",
    "unsafe-deserialization", "template-injection", "unescaped-html",
}


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValidationError(f"{field} is outside the safe bound")
    return value


def _context(configuration: Mapping[str, Any]) -> tuple[str, dict[str, str], int]:
    base_url = _loopback_base(require_text(configuration.get("baseUrl"), "baseUrl"))
    token_env = require_text(configuration.get("testTokenEnv"), "testTokenEnv")
    if not token_env.startswith("ELMPAY_TEST_") or not token_env.replace("_", "").isalnum():
        raise ValidationError("security test token environment name is invalid")
    token = os.environ.get(token_env)
    if token is None:
        raise ValidationError("security test token is unavailable")
    _validate_test_token(token)
    timeout_ms = _bounded_int(
        configuration.get("timeoutMilliseconds", 2_000),
        "timeoutMilliseconds", 50, 10_000,
    )
    return base_url, {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "X-Elmpay-Security-Test": "true",
    }, timeout_ms


def _http(url: str, method: str, headers: Mapping[str, str], body: bytes | None,
          timeout_ms: int) -> tuple[int, Mapping[str, str], bytes]:
    request = urlrequest.Request(url, data=body, headers=dict(headers), method=method)
    try:
        response = urlrequest.urlopen(request, timeout=timeout_ms / 1_000)
    except urlerror.HTTPError as exception:
        response = exception
    with response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValidationError("dynamic scanner response exceeded the safe size")
        response_headers = {key.lower(): value for key, value in response.headers.items()}
        return int(response.status), response_headers, raw


def _json(raw: bytes, field: str) -> Mapping[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise ValidationError(f"{field} is not JSON") from exception
    return require_mapping(value, field)


def _preflight(configuration: Mapping[str, Any], base_url: str, headers: Mapping[str, str],
               timeout_ms: int) -> None:
    health_path = _safe_http_path(configuration.get("healthPath", "/healthz"), "healthPath")
    status, _response_headers, raw = _http(
        _same_origin(base_url, health_path), "GET", headers, None, timeout_ms,
    )
    health = _json(raw, "security health response")
    if (status != 200 or health.get("environment") != "TEST"
            or health.get("securityTest") is not True
            or health.get("production") is not False
            or health.get("tokenRequired") is not True):
        raise ValidationError("security target did not prove TEST-only mode")


def _scan_dast(configuration: Mapping[str, Any], artifact_digest: str) -> Mapping[str, Any]:
    base_url, headers, timeout_ms = _context(configuration)
    _preflight(configuration, base_url, headers, timeout_ms)
    probes = require_list(configuration.get("probes"), "dast.probes")
    if not probes or len(probes) > 50:
        raise ValidationError("DAST probes must contain 1..50 bounded requests")
    observations: list[dict[str, Any]] = []
    findings = 0
    for raw_probe in probes:
        probe = require_mapping(raw_probe, "DAST probe")
        path = _safe_http_path(probe.get("path"), "dast.probe.path")
        method = require_text(probe.get("method", "GET"), "dast.probe.method").upper()
        if method not in {"GET", "POST"}:
            raise ValidationError("DAST probe method must be GET or POST")
        expected_status = _bounded_int(
            probe.get("expectedStatus"), "dast.probe.expectedStatus", 100, 599,
        )
        body_value = probe.get("body")
        if body_value is not None and not isinstance(body_value, str):
            raise ValidationError("DAST probe body must be text")
        body = None if body_value is None else body_value.encode("utf-8")
        if body is not None and len(body) > 16_384:
            raise ValidationError("DAST probe body exceeds the safe size")
        request_headers = dict(headers)
        request_headers["X-Elmpay-DAST-Probe"] = "active-v1"
        if body is not None:
            request_headers["Content-Type"] = require_text(
                probe.get("contentType", "application/json"), "dast.probe.contentType",
            )
        status, response_headers, response_body = _http(
            _same_origin(base_url, path), method, request_headers, body, timeout_ms,
        )
        failures: list[str] = []
        if status != expected_status:
            failures.append("unexpected_status")
        required_headers = require_mapping(
            probe.get("requiredHeaders", {}), "dast.probe.requiredHeaders",
        )
        for name, expected in required_headers.items():
            if not isinstance(name, str) or not isinstance(expected, str):
                raise ValidationError("DAST required headers must map text to text")
            if response_headers.get(name.lower(), "").lower() != expected.lower():
                failures.append(f"header:{name.lower()}")
        forbidden = require_list(
            probe.get("forbiddenResponsePatterns", []),
            "dast.probe.forbiddenResponsePatterns",
        )
        decoded = response_body.decode("utf-8", errors="replace")
        for pattern in forbidden:
            if not isinstance(pattern, str) or not pattern or len(pattern) > 256:
                raise ValidationError("DAST forbidden response pattern is invalid")
            if re.search(pattern, decoded, re.IGNORECASE):
                failures.append("forbidden_response_pattern")
        findings += len(failures)
        observations.append({
            "path": path,
            "method": method,
            "status": status,
            "responseDigest": hashlib.sha256(response_body).hexdigest(),
            "failures": failures,
        })
    execution_digest = hashlib.sha256(canonical_json({
        "artifactDigest": artifact_digest,
        "scannerVersion": SCANNER_VERSION,
        "observations": observations,
    })).hexdigest()
    return {
        "tool": "dast", "status": "COMPLETE" if findings == 0 else "FAIL",
        "artifactDigest": artifact_digest, "exitCode": 0 if findings == 0 else 2,
        "criticalFindings": 0, "highFindings": findings,
        "observedRequests": len(observations), "executionDigest": execution_digest,
        "scannerVersion": SCANNER_VERSION,
    }


def _scan_iast(configuration: Mapping[str, Any], artifact_digest: str) -> Mapping[str, Any]:
    base_url, headers, timeout_ms = _context(configuration)
    _preflight(configuration, base_url, headers, timeout_ms)
    probe_path = _safe_http_path(configuration.get("probePath"), "iast.probePath")
    result_path = _safe_http_path(configuration.get("resultPath"), "iast.resultPath")
    expected_agent = require_text(configuration.get("agentDigest"), "iast.agentDigest")
    if not _DIGEST.fullmatch(expected_agent):
        raise ValidationError("IAST agentDigest must be SHA-256")
    correlation = secrets.token_hex(16)
    probe_headers = {**headers, "X-Elmpay-IAST-Correlation": correlation,
                     "X-Elmpay-IAST-Probe": "active-v1"}
    probe_status, _probe_headers, probe_body = _http(
        _same_origin(base_url, probe_path), "GET", probe_headers, None, timeout_ms,
    )
    if probe_status < 200 or probe_status >= 500:
        raise ValidationError("IAST probe did not execute on the TEST target")
    result_status, _result_headers, raw_result = _http(
        _same_origin(base_url, result_path), "GET", probe_headers, None, timeout_ms,
    )
    result = _json(raw_result, "IAST trace result")
    events = require_list(result.get("events"), "IAST events")
    valid = (
        result_status == 200
        and result.get("environment") == "TEST"
        and result.get("artifactDigest") == artifact_digest
        and result.get("agentDigest") == expected_agent
        and result.get("correlationId") == correlation
        and bool(events)
    )
    findings = 0
    event_digests: list[str] = []
    for raw_event in events:
        event = require_mapping(raw_event, "IAST event")
        if event.get("correlationId") != correlation:
            valid = False
        sink = require_text(event.get("sink"), "IAST event sink")
        tainted = event.get("tainted")
        blocked = event.get("blocked")
        if not isinstance(tainted, bool) or not isinstance(blocked, bool):
            valid = False
        if sink in _DANGEROUS_SINKS and tainted is True and blocked is not True:
            findings += 1
        event_digests.append(hashlib.sha256(canonical_json(event)).hexdigest())
    if not valid:
        findings = max(1, findings)
    execution_digest = hashlib.sha256(canonical_json({
        "artifactDigest": artifact_digest,
        "agentDigest": expected_agent,
        "correlationId": correlation,
        "probeResponseDigest": hashlib.sha256(probe_body).hexdigest(),
        "eventDigests": event_digests,
        "scannerVersion": SCANNER_VERSION,
    })).hexdigest()
    return {
        "tool": "iast", "status": "COMPLETE" if findings == 0 else "FAIL",
        "artifactDigest": artifact_digest, "exitCode": 0 if findings == 0 else 2,
        "criticalFindings": findings, "highFindings": 0,
        "observedRequests": len(events), "executionDigest": execution_digest,
        "scannerVersion": SCANNER_VERSION,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("dast", "iast"), required=True)
    parser.add_argument("--artifact-digest", required=True)
    args = parser.parse_args(argv)
    try:
        if not _DIGEST.fullmatch(args.artifact_digest):
            raise ValidationError("artifact digest must be SHA-256")
        raw = sys.stdin.buffer.read(131_073)
        if len(raw) > 131_072:
            raise ValidationError("dynamic scanner configuration is too large")
        configuration = _json(raw, "dynamic scanner configuration")
        report = (_scan_dast(configuration, args.artifact_digest)
                  if args.mode == "dast"
                  else _scan_iast(configuration, args.artifact_digest))
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return int(report["exitCode"])
    except (OSError, ValidationError, ValueError, TypeError) as exception:
        print(json.dumps({
            "tool": args.mode, "status": "FAIL", "artifactDigest": args.artifact_digest,
            "exitCode": 2, "criticalFindings": 1, "highFindings": 0,
            "observedRequests": 0, "scannerVersion": SCANNER_VERSION,
            "errorDigest": hashlib.sha256(str(exception).encode("utf-8")).hexdigest(),
        }, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
