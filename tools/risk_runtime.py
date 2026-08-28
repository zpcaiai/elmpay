#!/usr/bin/env python3
"""Run the authenticated B80-B83/B87 synchronous risk decision endpoint."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.common import ValidationError, canonical_json, require_mapping  # noqa: E402
from elmpay_runtime.risk_control import HttpModelClient, SQLiteRiskControl  # noqa: E402
from elmpay_runtime.risk_runtime import (  # noqa: E402
    HmacRequestAuthenticator,
    HttpRiskSignalProvider,
    LocalSandboxRiskSignalProvider,
    RiskRuntimeService,
    UnavailableModelClient,
    encode_evaluation,
)


MAX_BODY_BYTES = 65_536


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def handler(service: RiskRuntimeService, authenticator: HmacRequestAuthenticator):
    class RiskHandler(BaseHTTPRequestHandler):
        server_version = "elmpay-risk"
        sys_version = ""

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health/live":
                self._send(200, {"status": "live"})
            else:
                self._send(404, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/v1/risk/decisions":
                self._send(404, {"error": "not_found"})
                return
            try:
                content_type = self.headers.get("Content-Type", "")
                if not content_type.lower().startswith("application/json"):
                    raise ValidationError("application/json is required")
                length = int(self.headers.get("Content-Length", "-1"))
                if not 0 <= length <= MAX_BODY_BYTES:
                    raise ValidationError("risk request body length invalid")
                body = self.rfile.read(length)
                authenticator.verify(
                    body,
                    self.headers.get("X-Elmpay-Risk-Timestamp", ""),
                    self.headers.get("X-Elmpay-Risk-Nonce", ""),
                    self.headers.get("X-Elmpay-Risk-Signature", ""),
                )
                document = json.loads(body, parse_constant=lambda value: (_ for _ in ()).throw(
                    ValidationError(f"risk request contained non-finite {value}")
                ))
                request = require_mapping(document, "risk request")
                if set(request) != {"tenantId", "requestId", "operation", "subjectId",
                                   "amountMinor", "currency", "occurredAt", "attributes"}:
                    raise ValidationError("risk request schema invalid")
                self._send(200, encode_evaluation(service.evaluate(request)))
            except (ValidationError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
                self._send(422, {"error": "risk_request_rejected"})
            except Exception:
                self._send(503, {"error": "risk_service_unavailable"})

        def log_message(self, format: str, *args: Any) -> None:
            del format, args

        def _send(self, status: int, document: dict[str, Any]) -> None:
            encoded = canonical_json(document)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    return RiskHandler


def required(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip():
        raise ValidationError(f"{name} is required")
    return value


def build_runtime(arguments: argparse.Namespace) -> tuple[SQLiteRiskControl, RiskRuntimeService,
                                                           HmacRequestAuthenticator]:
    policy = json.loads(arguments.policy.read_text(encoding="utf-8"))
    control = SQLiteRiskControl(str(arguments.db), policy)
    signal_mode = required("ELMPAY_RISK_SIGNAL_MODE")
    if signal_mode == "local-sandbox":
        if os.environ.get("ELMPAY_ENABLE_LOCAL_SANDBOX") != "true":
            control.close()
            raise ValidationError("local risk signals require ELMPAY_ENABLE_LOCAL_SANDBOX=true")
        signals = LocalSandboxRiskSignalProvider()
        model = UnavailableModelClient()
    elif signal_mode == "http":
        signals = HttpRiskSignalProvider(required("ELMPAY_RISK_SIGNAL_ENDPOINT"),
                                         required("ELMPAY_RISK_SIGNAL_TOKEN"))
        model = HttpModelClient(required("ELMPAY_RISK_MODEL_ENDPOINT"),
                                required("ELMPAY_RISK_MODEL_SCHEMA_DIGEST"))
    else:
        control.close()
        raise ValidationError("ELMPAY_RISK_SIGNAL_MODE must be local-sandbox or http")
    service = RiskRuntimeService(control, signals, model, utc_now)
    authenticator = HmacRequestAuthenticator(
        required("ELMPAY_RISK_HMAC_SECRET").encode("utf-8"), utc_now)
    return control, service, authenticator


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--policy", type=Path,
                        default=ROOT / "platform/risk/runtime-policy.json")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8087)
    parser.add_argument("--check-config", action="store_true")
    arguments = parser.parse_args()
    if not 1 <= arguments.port <= 65_535:
        parser.error("--port must be within 1..65535")
    control: SQLiteRiskControl | None = None
    try:
        control, service, authenticator = build_runtime(arguments)
        if arguments.check_config:
            print(json.dumps({"configured": True, "certificationStatus": "NOT_CERTIFIED"},
                             sort_keys=True))
            return 0
        loopback = arguments.bind in {"127.0.0.1", "::1", "localhost"}
        if not loopback:
            raise ValidationError(
                "risk runtime binds loopback only; expose it through an authenticated TLS sidecar")
        server = ThreadingHTTPServer((arguments.bind, arguments.port),
                                     handler(service, authenticator))
        server.serve_forever()
        return 0
    except (OSError, ValidationError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc), "certificationStatus": "NOT_CERTIFIED"},
                         sort_keys=True), file=sys.stderr)
        return 2
    finally:
        if control is not None:
            control.close()


if __name__ == "__main__":
    raise SystemExit(main())
