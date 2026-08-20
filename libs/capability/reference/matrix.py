"""B27 — an executable capability matrix.

:meth:`Matrix.resolve` is the whole point. It takes the five dimensions a
payment actually has — provider, method, region, currency, device — and either
returns the one row that permits it or refuses. There is no "not sure, try it
and see what the provider says", because that answer is only available *after*
the payer has entered their details, and it comes back as a third-party error
code that nobody in the building can map to a cause.

Everything after resolution is the arithmetic of time:

* an authorisation expires, and capturing afterwards is refused even though a
  real acquirer might accept it — the cardholder can still take it back;
* a refund window closes, and the product may not offer a button past it;
* a dispute deadline is set by the network, and missing it loses by default.

Time is an integer hour (authorisations) or day (refunds, disputes) supplied by
the caller. Nothing here reads the clock.
"""
from __future__ import annotations

from dataclasses import dataclass, field

UNSUPPORTED = "UNSUPPORTED"
UNKNOWN_PROVIDER = "UNKNOWN_PROVIDER"
UNKNOWN_METHOD = "UNKNOWN_METHOD"
REGION_FORBIDS_METHOD = "REGION_FORBIDS_METHOD"
DEVICE_UNSUPPORTED = "DEVICE_UNSUPPORTED"
CURRENCY_UNSUPPORTED = "CURRENCY_UNSUPPORTED"
NO_AUTHORIZATION_STEP = "NO_AUTHORIZATION_STEP"
AUTH_EXPIRED = "AUTH_EXPIRED"
OVER_CAPTURE = "OVER_CAPTURE"
PARTIAL_CAPTURE_UNSUPPORTED = "PARTIAL_CAPTURE_UNSUPPORTED"
ALREADY_CAPTURED = "ALREADY_CAPTURED"
REFUND_WINDOW_CLOSED = "REFUND_WINDOW_CLOSED"
OVER_REFUND = "OVER_REFUND"
PARTIAL_REFUND_UNSUPPORTED = "PARTIAL_REFUND_UNSUPPORTED"
REFUND_ELSEWHERE = "REFUND_ELSEWHERE"
DISPUTE_WINDOW_CLOSED = "DISPUTE_WINDOW_CLOSED"
DISPUTE_DEADLINE_PASSED = "DISPUTE_DEADLINE_PASSED"
DISPUTE_EVIDENCE_INCOMPLETE = "DISPUTE_EVIDENCE_INCOMPLETE"
DISPUTE_AUTO_ACCEPT = "DISPUTE_AUTO_ACCEPT"
SUBSCRIPTION_UNSUPPORTED = "SUBSCRIPTION_UNSUPPORTED"
PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
SILENT_FALLBACK = "SILENT_FALLBACK"


class CapabilityRefused(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class Request:
    provider: str
    method: str
    region: str
    currency: str
    device: str


@dataclass
class Authorization:
    request: Request
    amount_minor: int
    taken_at_hour: int
    captured_minor: int = 0
    captured: bool = False
    history: list[dict] = field(default_factory=list)


class Matrix:
    """The capability matrix as the platform would enforce it."""

    def __init__(self, model: dict) -> None:
        self.model = model
        self.resolution = model["resolution"]
        self.rows = model["capabilities"]
        self.methods = {m["id"]: m for m in model["payment_methods"]}
        self.regions = {r["region"]: r for r in model["region_policy"]}
        self.availability = {a["provider"]: a for a in model["availability"]}
        self.authorization = model["authorization"]
        self.refund_policy = model["refund"]
        self.dispute_policy = model["dispute"]
        self.providers = {row["provider"] for row in self.rows}

    # -- resolution -------------------------------------------------------
    def resolve(self, request: Request) -> dict:
        """The one row that permits this payment, or a refusal. Never a guess."""
        if request.provider not in self.providers:
            raise CapabilityRefused(UNKNOWN_PROVIDER, request.provider)
        if request.method not in self.methods:
            raise CapabilityRefused(UNKNOWN_METHOD, request.method)
        policy = self.regions.get(request.region)
        if policy is None:
            raise CapabilityRefused(UNSUPPORTED, f"region {request.region}")
        if request.method not in policy["allowed_methods"]:
            raise CapabilityRefused(REGION_FORBIDS_METHOD,
                                    f"{request.method} in {request.region}")
        rows = [r for r in self.rows
                if r["provider"] == request.provider and r["method"] == request.method]
        if not rows:
            raise CapabilityRefused(UNSUPPORTED,
                                    f"{request.provider}/{request.method}")
        rows = [r for r in rows if request.region in r["regions"]]
        if not rows:
            raise CapabilityRefused(UNSUPPORTED,
                                    f"{request.provider}/{request.method} in {request.region}")
        currency_rows = [r for r in rows if request.currency in r["currencies"]]
        if not currency_rows:
            raise CapabilityRefused(CURRENCY_UNSUPPORTED, request.currency)
        device_rows = [r for r in currency_rows if request.device in r["devices"]]
        if not device_rows:
            # The device is a hard limit, not a hint: there is no Apple Pay on
            # Android, and offering it produces a dead button.
            raise CapabilityRefused(DEVICE_UNSUPPORTED, request.device)
        return device_rows[0]

    def supports(self, request: Request) -> bool:
        try:
            self.resolve(request)
            return True
        except CapabilityRefused:
            return False

    def requires_strong_customer_authentication(self, region: str) -> bool:
        policy = self.regions.get(region)
        if policy is None:
            raise CapabilityRefused(UNSUPPORTED, f"region {region}")
        return bool(policy["strong_customer_authentication"])

    def fallback(self, request: Request, alternative: Request) -> dict:
        """Switching provider or method behind the payer's back. Always refused."""
        if alternative.provider != request.provider \
                and not self.resolution["silent_fallback_to_another_provider"]:
            raise CapabilityRefused(SILENT_FALLBACK, alternative.provider)
        if alternative.method != request.method \
                and not self.resolution["silent_fallback_to_another_method"]:
            raise CapabilityRefused(SILENT_FALLBACK, alternative.method)
        return self.resolve(alternative)

    # -- availability -----------------------------------------------------
    def check_available(self, provider: str, *, in_maintenance: bool) -> str:
        entry = self.availability.get(provider)
        if entry is None:
            raise CapabilityRefused(UNKNOWN_PROVIDER, provider)
        if in_maintenance:
            if entry["degraded_behaviour"] == "reject":
                raise CapabilityRefused(PROVIDER_UNAVAILABLE, provider)
            return "QUEUED"
        return "OK"

    # -- authorisation and capture ----------------------------------------
    def authorize(self, request: Request, amount_minor: int, *, hour: int) -> Authorization:
        row = self.resolve(request)
        if not row["supports_authorization_capture"]:
            raise CapabilityRefused(NO_AUTHORIZATION_STEP,
                                    f"{request.provider}/{request.method}")
        return Authorization(request=request, amount_minor=amount_minor, taken_at_hour=hour)

    def authorization_expires_at(self, authorization: Authorization) -> int:
        row = self.resolve(authorization.request)
        return authorization.taken_at_hour + min(int(row["authorization_valid_hours"]),
                                                 int(self.authorization["max_valid_hours"]))

    def capture(self, authorization: Authorization, amount_minor: int, *, hour: int) -> int:
        row = self.resolve(authorization.request)
        if authorization.captured:
            raise CapabilityRefused(ALREADY_CAPTURED, str(authorization.captured_minor))
        if hour >= self.authorization_expires_at(authorization):
            # A real acquirer may still accept this. The cardholder may still
            # take it back, and the burden of proof would be ours.
            raise CapabilityRefused(AUTH_EXPIRED, str(hour))
        if amount_minor > authorization.amount_minor:
            raise CapabilityRefused(OVER_CAPTURE, str(amount_minor))
        if amount_minor < authorization.amount_minor and not row["partial_capture"]:
            raise CapabilityRefused(PARTIAL_CAPTURE_UNSUPPORTED,
                                    f"{amount_minor}/{authorization.amount_minor}")
        authorization.captured_minor = amount_minor
        authorization.captured = True
        authorization.history.append({"event": "captured", "hour": hour,
                                      "amount_minor": amount_minor})
        return amount_minor

    def reauthorize(self, authorization: Authorization, *, hour: int) -> Authorization:
        if hour < self.authorization_expires_at(authorization):
            return authorization
        return self.authorize(authorization.request, authorization.amount_minor, hour=hour)

    # -- refunds ----------------------------------------------------------
    def refund_closes_on(self, request: Request, paid_on_day: int) -> int:
        return paid_on_day + int(self.resolve(request)["refund_window_days"])

    def may_offer_refund(self, request: Request, *, paid_on_day: int, day: int) -> bool:
        return day < self.refund_closes_on(request, paid_on_day)

    def refund(self, authorization: Authorization, amount_minor: int, *, paid_on_day: int,
               day: int, to_original_instrument: bool = True) -> int:
        row = self.resolve(authorization.request)
        if not to_original_instrument and row["refund_to_original_instrument_only"]:
            raise CapabilityRefused(REFUND_ELSEWHERE, "refund must return the way it came")
        if day >= self.refund_closes_on(authorization.request, paid_on_day):
            raise CapabilityRefused(REFUND_WINDOW_CLOSED,
                                    self.refund_policy["beyond_window_action"])
        if amount_minor > authorization.captured_minor:
            raise CapabilityRefused(OVER_REFUND,
                                    f"{amount_minor} > {authorization.captured_minor}")
        if amount_minor < authorization.captured_minor and not row["partial_refund"]:
            raise CapabilityRefused(PARTIAL_REFUND_UNSUPPORTED, str(amount_minor))
        authorization.history.append({"event": "refunded", "day": day,
                                      "amount_minor": amount_minor})
        return amount_minor

    # -- disputes ---------------------------------------------------------
    def dispute_response_due(self, request: Request, opened_on_day: int) -> int:
        return opened_on_day + int(self.resolve(request)["dispute_response_days"])

    def open_dispute(self, request: Request, *, paid_on_day: int, day: int) -> int:
        row = self.resolve(request)
        if day > paid_on_day + int(row["dispute_window_days"]):
            raise CapabilityRefused(DISPUTE_WINDOW_CLOSED, str(day))
        return self.dispute_response_due(request, day)

    def respond_to_dispute(self, request: Request, *, opened_on_day: int, day: int,
                           evidence: set[str], accept: bool = False,
                           automated: bool = False) -> str:
        if accept and automated and not self.dispute_policy["auto_accept_allowed"]:
            raise CapabilityRefused(DISPUTE_AUTO_ACCEPT,
                                    "conceding automatically is a repeatable channel for a "
                                    "fraudster")
        if day > self.dispute_response_due(request, opened_on_day):
            # The clock belongs to the network. There is no appeal for missing it.
            raise CapabilityRefused(DISPUTE_DEADLINE_PASSED, str(day))
        if accept:
            return "ACCEPTED"
        missing = set(self.dispute_policy["evidence_required"]) - evidence
        if missing:
            raise CapabilityRefused(DISPUTE_EVIDENCE_INCOMPLETE, ",".join(sorted(missing)))
        return "CONTESTED"

    # -- subscriptions ----------------------------------------------------
    def start_subscription(self, request: Request) -> str:
        row = self.resolve(request)
        if not row["supports_subscription"]:
            raise CapabilityRefused(SUBSCRIPTION_UNSUPPORTED,
                                    f"{request.provider}/{request.method}")
        return "OK"
