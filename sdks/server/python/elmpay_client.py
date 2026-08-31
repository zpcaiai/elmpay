"""Standard-library ElmPay client with bounded, typed response handling."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import BinaryIO, Mapping

MAX_RESPONSE_BYTES = 1_048_576
MAX_TIMEOUT_SECONDS = 300.0
_JSON_MEDIA_TYPES = frozenset(("application/json", "application/problem+json"))
_RFC3339 = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


_DEFAULT_OPENER = urllib.request.build_opener(_NoRedirect)


def _urlopen_no_redirect(request, timeout):
    return _DEFAULT_OPENER.open(request, timeout=timeout)


@dataclass(frozen=True)
class CheckoutRequest:
    business_order_no: str
    amount: int
    currency: str
    return_route_id: str | None = None


@dataclass(frozen=True)
class ConfirmRequest:
    payment_method_type: str
    payment_method_reference: str | None = None
    fingerprint: str | None = None


@dataclass(frozen=True)
class CheckoutSession:
    checkout_session_id: str
    expires_at: str
    checkout_url: str


@dataclass(frozen=True)
class ApiProblem:
    type: str
    title: str
    status: int
    code: str
    trace_id: str
    detail: str | None = None


@dataclass(frozen=True)
class ApiResponse:
    status_code: int
    data: CheckoutSession
    request_id: str


class ElmpayResponseError(Exception):
    """Base class for fail-closed response protocol errors."""

    def __init__(self, message: str, *, request_id: str = ""):
        super().__init__(message)
        self.request_id = request_id


class ResponseTooLargeError(ElmpayResponseError):
    pass


class InvalidResponseError(ElmpayResponseError):
    pass


class ApiError(ElmpayResponseError):
    def __init__(self, problem: ApiProblem, *, request_id: str = ""):
        super().__init__(f"ElmPay API error {problem.status}: {problem.code}", request_id=request_id)
        self.problem = problem
        self.status_code = problem.status


class ElmpayClient:
    def __init__(self, base_url: str, bearer_token: str, project_id: str, timeout: float = 5.0,
                 maximum_attempts: int = 3, *, urlopen=_urlopen_no_redirect):
        parsed = urllib.parse.urlparse(base_url)
        if (parsed.scheme != "https" or not parsed.netloc or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment):
            raise ValueError("base_url must be an origin-form HTTPS URL")
        if not bearer_token:
            raise ValueError("bearer_token required")
        if not project_id or len(project_id) > 64:
            raise ValueError("project_id required")
        if (not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
                or not math.isfinite(timeout) or not 0 < timeout <= MAX_TIMEOUT_SECONDS):
            raise ValueError("timeout must be positive and at most five minutes")
        if not 1 <= maximum_attempts <= 5:
            raise ValueError("maximum_attempts must be 1..5")
        self.base_url, self.token, self.project_id = base_url, bearer_token, project_id
        self.timeout, self.attempts, self.urlopen = timeout, maximum_attempts, urlopen

    def create_checkout_session(self, request: CheckoutRequest,
                                idempotency_key: str | None = None) -> ApiResponse:
        if not isinstance(request.amount, int) or isinstance(request.amount, bool) or request.amount <= 0:
            raise ValueError("amount must be a positive integer")
        payload = {"business_order_no": request.business_order_no, "amount": request.amount,
                   "currency": request.currency}
        if request.return_route_id is not None:
            payload["return_route_id"] = request.return_route_id
        return self._send("POST", "/v1/checkout-sessions", payload,
                          idempotency_key or str(uuid.uuid4()), expected_status=201)

    def get_checkout_session(self, session_id: str) -> ApiResponse:
        return self._send("GET", "/v1/checkout-sessions/" + urllib.parse.quote(session_id, safe=""),
                          None, None, expected_status=200)

    def confirm_checkout_session(self, session_id: str, request: ConfirmRequest,
                                 idempotency_key: str | None = None) -> ApiResponse:
        payload = {"payment_method_type": request.payment_method_type}
        if request.payment_method_reference is not None:
            payload["payment_method_reference"] = request.payment_method_reference
        if request.fingerprint is not None:
            payload["fingerprint"] = request.fingerprint
        path = "/v1/checkout-sessions/" + urllib.parse.quote(session_id, safe="") + "/confirm"
        return self._send("POST", path, payload, idempotency_key or str(uuid.uuid4()),
                          expected_status=200)

    def _send(self, method: str, path: str, payload: dict | None,
              idempotency_key: str | None, *, expected_status: int) -> ApiResponse:
        retry_safe = method == "GET" or idempotency_key is not None
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        headers = {"accept": "application/json", "authorization": "Bearer " + self.token,
                   "x-project-id": self.project_id}
        if body is not None:
            headers["content-type"] = "application/json"
        if idempotency_key:
            headers["idempotency-key"] = idempotency_key
        for attempt in range(self.attempts):
            try:
                request = urllib.request.Request(urllib.parse.urljoin(self.base_url, path), body,
                                                 headers, method=method)
                with self.urlopen(request, timeout=self.timeout) as response:
                    return _decode_response(response.status, expected_status, response.headers, response)
            except urllib.error.HTTPError as error:
                try:
                    decoded = _decode_response(error.code, expected_status, error.headers, error)
                except ApiError as api_error:
                    if not retry_safe or not _retryable(error.code) or attempt + 1 == self.attempts:
                        raise api_error from None
                else:
                    raise InvalidResponseError("HTTP transport returned a success status as HTTPError",
                                               request_id=decoded.request_id)
                finally:
                    error.close()
            except (urllib.error.URLError, TimeoutError):
                if not retry_safe or attempt + 1 == self.attempts:
                    raise
            time.sleep(min(1.0, .1 * 2**attempt))
        raise RuntimeError("unreachable")


def _retryable(status: int) -> bool:
    return status in (408, 429) or status >= 500


def _header(headers: Mapping[str, str], name: str) -> str:
    value = headers.get(name)
    if value is None:
        value = next((candidate for key, candidate in headers.items()
                      if str(key).lower() == name.lower()), None)
    return "" if value is None else str(value)


def _read_bounded(stream: BinaryIO, headers: Mapping[str, str], request_id: str) -> bytes:
    raw_length = _header(headers, "content-length").strip()
    if raw_length:
        try:
            content_length = int(raw_length)
        except ValueError as exc:
            raise InvalidResponseError("invalid Content-Length", request_id=request_id) from exc
        if content_length < 0:
            raise InvalidResponseError("invalid Content-Length", request_id=request_id)
        if content_length > MAX_RESPONSE_BYTES:
            raise ResponseTooLargeError("response exceeds 1 MiB limit", request_id=request_id)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = stream.read(min(65_536, MAX_RESPONSE_BYTES + 1 - total))
        if not chunk:
            break
        if not isinstance(chunk, bytes):
            raise InvalidResponseError("response stream returned non-bytes", request_id=request_id)
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise ResponseTooLargeError("response exceeds 1 MiB limit", request_id=request_id)
        chunks.append(chunk)
    return b"".join(chunks)


def _decode_json(raw: bytes, request_id: str) -> dict:
    def reject_constant(token: str):
        raise ValueError(f"invalid JSON constant {token}")
    def reject_duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key}")
            result[key] = value
        return result
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(text, parse_constant=reject_constant,
                           object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise InvalidResponseError("response is not strict UTF-8 JSON", request_id=request_id) from exc
    if not isinstance(value, dict):
        raise InvalidResponseError("response JSON must be an object", request_id=request_id)
    return value


def _required_string(value: dict, name: str, request_id: str) -> str:
    field = value.get(name)
    if not isinstance(field, str) or not field.strip():
        raise InvalidResponseError(f"response field {name} must be a non-empty string",
                                   request_id=request_id)
    return field


def _checkout_session(value: dict, request_id: str) -> CheckoutSession:
    session_id = _required_string(value, "checkout_session_id", request_id)
    expires_at = _required_string(value, "expires_at", request_id)
    checkout_url = _required_string(value, "checkout_url", request_id)
    try:
        if not _RFC3339.fullmatch(expires_at):
            raise ValueError("not RFC 3339")
        parsed_expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidResponseError("expires_at must be an RFC 3339 date-time",
                                   request_id=request_id) from exc
    if parsed_expiry.tzinfo is None:
        raise InvalidResponseError("expires_at must include a timezone", request_id=request_id)
    parsed_url = urllib.parse.urlparse(checkout_url)
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        raise InvalidResponseError("checkout_url must be an absolute HTTPS URL",
                                   request_id=request_id)
    return CheckoutSession(session_id, expires_at, checkout_url)


def _problem(value: dict, status: int, request_id: str) -> ApiProblem:
    problem_type = _required_string(value, "type", request_id)
    if not urllib.parse.urlparse(problem_type).scheme:
        raise InvalidResponseError("problem type must be an absolute URI", request_id=request_id)
    title = _required_string(value, "title", request_id)
    problem_status = value.get("status")
    if not isinstance(problem_status, int) or isinstance(problem_status, bool) or problem_status != status:
        raise InvalidResponseError("problem status must match HTTP status", request_id=request_id)
    code = _required_string(value, "code", request_id)
    trace_id = _required_string(value, "trace_id", request_id)
    detail = value.get("detail")
    if "detail" in value and not isinstance(detail, str):
        raise InvalidResponseError("problem detail must be a string", request_id=request_id)
    return ApiProblem(problem_type, title, problem_status, code, trace_id, detail)


def _decode_response(status: int, expected_status: int, headers: Mapping[str, str],
                     stream: BinaryIO) -> ApiResponse:
    request_id = _header(headers, "x-request-id")
    media_type = _header(headers, "content-type").split(";", 1)[0].strip().lower()
    if media_type not in _JSON_MEDIA_TYPES:
        raise InvalidResponseError("response Content-Type must be JSON", request_id=request_id)
    raw = _read_bounded(stream, headers, request_id)
    value = _decode_json(raw, request_id)
    if status == expected_status:
        if media_type != "application/json":
            raise InvalidResponseError("success response must use application/json",
                                       request_id=request_id)
        return ApiResponse(status, _checkout_session(value, request_id), request_id)
    if 400 <= status <= 599:
        if media_type != "application/problem+json":
            raise InvalidResponseError("error response must use application/problem+json",
                                       request_id=request_id)
        raise ApiError(_problem(value, status, request_id), request_id=request_id)
    raise InvalidResponseError(f"unexpected HTTP status {status}", request_id=request_id)


def verify_webhook(secret: bytes, raw_body: bytes, signature_header: str,
                   now: int | None = None, tolerance: int = 300) -> bool:
    """Verify the raw webhook bytes against one canonical signature tuple.

    The header is deliberately parsed without a dict-comprehension: duplicate
    fields must fail closed instead of being silently overwritten by the last
    value supplied by an intermediary.
    """
    if (not isinstance(secret, bytes) or len(secret) < 32
            or not isinstance(raw_body, bytes)
            or not isinstance(signature_header, str) or len(signature_header) > 4096
            or not isinstance(tolerance, (int, float)) or isinstance(tolerance, bool)
            or not math.isfinite(tolerance) or tolerance < 0):
        return False
    parts: dict[str, str] = {}
    for item in signature_header.split(","):
        key, separator, value = item.strip().partition("=")
        if (not separator or not re.fullmatch(r"[A-Za-z0-9_]{1,16}", key)
                or not value or key not in {"t", "v1"} or key in parts):
            return False
        if any(character.isspace() for character in value):
            return False
        parts[key] = value
    if set(parts) != {"t", "v1"} or not re.fullmatch(r"[0-9]{1,19}", parts["t"]):
        return False
    if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", parts["v1"]):
        return False
    try:
        timestamp = int(parts["t"])
        if timestamp < 0:
            return False
        encoded = parts["v1"]
        padding = "=" * ((4 - len(encoded) % 4) % 4)
        supplied = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
    except (ValueError, TypeError):
        return False
    if len(supplied) != 32:
        return False
    current = time.time() if now is None else now
    if not isinstance(current, (int, float)) or isinstance(current, bool) \
            or not math.isfinite(current) or abs(current - timestamp) > tolerance:
        return False
    expected = hmac.new(secret, str(timestamp).encode() + b"." + raw_body, hashlib.sha256).digest()
    return hmac.compare_digest(expected, supplied)
