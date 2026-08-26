"""Standard-library ElmPay client with bounded idempotent retries."""
from __future__ import annotations
import base64, hashlib, hmac, json, time, urllib.error, urllib.parse, urllib.request, uuid
from dataclasses import dataclass

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

class ElmpayClient:
    def __init__(self, base_url: str, bearer_token: str, project_id: str, timeout: float = 5.0,
                 maximum_attempts: int = 3, *, urlopen=urllib.request.urlopen):
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme != "https": raise ValueError("base_url must use HTTPS")
        if not bearer_token: raise ValueError("bearer_token required")
        if not project_id or len(project_id) > 64: raise ValueError("project_id required")
        if not 1 <= maximum_attempts <= 5: raise ValueError("maximum_attempts must be 1..5")
        self.base_url, self.token, self.project_id = base_url, bearer_token, project_id
        self.timeout, self.attempts, self.urlopen = timeout, maximum_attempts, urlopen

    def create_checkout_session(self, request: CheckoutRequest,
                                idempotency_key: str | None = None) -> tuple[int, bytes]:
        if not isinstance(request.amount, int) or isinstance(request.amount, bool) or request.amount <= 0:
            raise ValueError("amount must be a positive integer")
        payload = {"business_order_no": request.business_order_no, "amount": request.amount,
                   "currency": request.currency}
        if request.return_route_id is not None: payload["return_route_id"] = request.return_route_id
        return self._send("POST", "/v1/checkout-sessions", payload, idempotency_key or str(uuid.uuid4()))

    def get_checkout_session(self, session_id: str) -> tuple[int, bytes]:
        return self._send("GET", "/v1/checkout-sessions/" + urllib.parse.quote(session_id, safe=""), None, None)

    def confirm_checkout_session(self, session_id: str, request: ConfirmRequest,
                                 idempotency_key: str | None = None) -> tuple[int, bytes]:
        payload = {"payment_method_type": request.payment_method_type}
        if request.payment_method_reference is not None:
            payload["payment_method_reference"] = request.payment_method_reference
        if request.fingerprint is not None: payload["fingerprint"] = request.fingerprint
        path = "/v1/checkout-sessions/" + urllib.parse.quote(session_id, safe="") + "/confirm"
        return self._send("POST", path, payload, idempotency_key or str(uuid.uuid4()))

    def _send(self, method: str, path: str, payload: dict | None, idempotency_key: str | None):
        retry_safe = method == "GET" or idempotency_key is not None
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        headers = {"accept": "application/json", "authorization": "Bearer " + self.token,
                   "x-project-id": self.project_id}
        if body is not None: headers["content-type"] = "application/json"
        if idempotency_key: headers["idempotency-key"] = idempotency_key
        for attempt in range(self.attempts):
            try:
                request = urllib.request.Request(urllib.parse.urljoin(self.base_url, path), body, headers, method=method)
                with self.urlopen(request, timeout=self.timeout) as response:
                    return response.status, response.read()
            except urllib.error.HTTPError as error:
                if not retry_safe or error.code not in (408, 429) and error.code < 500 or attempt + 1 == self.attempts:
                    return error.code, error.read()
            except (urllib.error.URLError, TimeoutError):
                if not retry_safe or attempt + 1 == self.attempts: raise
            time.sleep(min(1.0, .1 * 2**attempt))
        raise RuntimeError("unreachable")

def verify_webhook(secret: bytes, raw_body: bytes, signature_header: str, now: int | None = None, tolerance: int = 300) -> bool:
    if len(secret) < 32: return False
    try:
        parts = dict(item.strip().split("=", 1) for item in signature_header.split(","))
        timestamp = int(parts["t"]); supplied = base64.urlsafe_b64decode(parts["v1"] + "==")
    except (KeyError, ValueError, TypeError): return False
    if abs((now or int(time.time())) - timestamp) > tolerance: return False
    expected = hmac.new(secret, str(timestamp).encode() + b"." + raw_body, hashlib.sha256).digest()
    return hmac.compare_digest(expected, supplied)
