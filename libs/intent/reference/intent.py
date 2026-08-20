"""B32 — an executable payment intent.

The interesting methods are the ones that refuse.

:meth:`Intents.amend` will not change ``amount_minor`` or ``currency``. There is
no flag for it and no privileged caller who can. A payer authorised one number;
if that number is editable then "what they agreed to" and "what was taken" may
differ, and afterwards nothing distinguishes a price correction from a fraud.

:meth:`Intents.confirm` requires an idempotency key, refuses an expired intent,
refuses a method outside the snapshot taken at creation, and returns the *same*
result for a repeated key rather than starting a second payment.

:meth:`Intents.succeed_from_return_page` exists only to raise. The browser's
return page is a request from the payer's own machine; success comes from a
verified provider event or a server-side query, and nothing else.

Time is an integer minute supplied by the caller.
"""
from __future__ import annotations

from dataclasses import dataclass, field

CREATED = "created"
REQUIRES_ACTION = "requires_action"
AUTHORIZED = "authorized"
CAPTURED = "captured"
FAILED = "failed"
CANCELED = "canceled"
EXPIRED = "expired"

AMOUNT_IMMUTABLE = "AMOUNT_IMMUTABLE"
AMOUNT_NOT_INTEGER = "AMOUNT_NOT_INTEGER"
AMOUNT_NOT_POSITIVE = "AMOUNT_NOT_POSITIVE"
CURRENCY_UNKNOWN = "CURRENCY_UNKNOWN"
DUPLICATE_LIVE_INTENT = "DUPLICATE_LIVE_INTENT"
ORDER_CONTENT_FORBIDDEN = "ORDER_CONTENT_FORBIDDEN"
NO_IDEMPOTENCY_KEY = "NO_IDEMPOTENCY_KEY"
IDEMPOTENCY_KEY_REUSED = "IDEMPOTENCY_KEY_REUSED"
INTENT_EXPIRED = "INTENT_EXPIRED"
EXPIRY_NOT_EXTENDABLE = "EXPIRY_NOT_EXTENDABLE"
EXPIRY_TOO_LONG = "EXPIRY_TOO_LONG"
METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
METHOD_WIDENED = "METHOD_WIDENED"
ILLEGAL_TRANSITION = "ILLEGAL_TRANSITION"
ALREADY_TERMINAL = "ALREADY_TERMINAL"
RETURN_PAGE_NOT_EVIDENCE = "RETURN_PAGE_NOT_EVIDENCE"
UNTRUSTED_SOURCE = "UNTRUSTED_SOURCE"
OVER_CAPTURE = "OVER_CAPTURE"
OVER_REFUND = "OVER_REFUND"
NOT_SCHEDULER = "NOT_SCHEDULER"
UNKNOWN_INTENT = "UNKNOWN_INTENT"

# The transitions B10 declares for PaymentIntent, as (from, to).
TRANSITIONS = {
    (CREATED, REQUIRES_ACTION), (CREATED, AUTHORIZED), (CREATED, FAILED),
    (CREATED, CANCELED), (CREATED, EXPIRED),
    (REQUIRES_ACTION, AUTHORIZED), (REQUIRES_ACTION, FAILED), (REQUIRES_ACTION, CANCELED),
    (REQUIRES_ACTION, EXPIRED),
    (AUTHORIZED, CAPTURED), (AUTHORIZED, CANCELED), (AUTHORIZED, EXPIRED),
    (AUTHORIZED, FAILED),
}
TERMINAL = {CAPTURED, FAILED, CANCELED, EXPIRED}


class IntentRefused(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class Snapshot:
    """Frozen at creation. A dataclass with ``frozen=True`` is the point."""

    amount_minor: int
    currency: str
    allowed_methods: tuple[str, ...]
    expires_at_minute: int


@dataclass
class Intent:
    id: str
    tenant_id: str
    project_id: str
    external_reference: str
    snapshot: Snapshot
    state: str = CREATED
    captured_minor: int = 0
    refunded_minor: int = 0
    client_secret_ref: str = ""
    confirmations: dict[str, str] = field(default_factory=dict)   # key -> result
    history: list[dict] = field(default_factory=list)

    @property
    def amount_minor(self) -> int:
        return self.snapshot.amount_minor

    @property
    def currency(self) -> str:
        return self.snapshot.currency

    @property
    def is_live(self) -> bool:
        return self.state not in TERMINAL


class Intents:
    def __init__(self, model: dict, currencies: set[str], methods: set[str]) -> None:
        self.model = model
        self.currencies = currencies
        self.methods = methods
        self.expiry = model["expiry"]
        self.confirmation = model["confirmation"]
        self.method_policy = model["method_constraints"]
        self.order_policy = model["order_link"]
        self.invariants = model["amount_invariants"]
        self.intents: dict[str, Intent] = {}

    # -- creation ----------------------------------------------------------
    def create(self, intent_id: str, *, tenant_id: str, project_id: str,
               external_reference: str, amount_minor: int, currency: str,
               allowed_methods: tuple[str, ...], now_minute: int,
               expires_in_minutes: int | None = None, **extra) -> Intent:
        for name in self.order_policy["forbidden_fields"]:
            if name in extra:
                # The platform is not a second order system.
                raise IntentRefused(ORDER_CONTENT_FORBIDDEN, name)
        if isinstance(amount_minor, bool) or not isinstance(amount_minor, int):
            raise IntentRefused(AMOUNT_NOT_INTEGER, repr(amount_minor))
        if amount_minor <= 0:
            # Zero is refused too: a zero-amount intent is a placeholder
            # pretending to be a payment.
            raise IntentRefused(AMOUNT_NOT_POSITIVE, str(amount_minor))
        if currency not in self.currencies:
            raise IntentRefused(CURRENCY_UNKNOWN, currency)
        unknown = [m for m in allowed_methods if m not in self.methods]
        if unknown:
            raise IntentRefused(METHOD_NOT_ALLOWED, ",".join(unknown))
        if self.order_policy["unique_live_intent_per_order"]:
            for other in self.intents.values():
                if (other.project_id, other.external_reference) == (project_id,
                                                                    external_reference) \
                        and other.is_live:
                    raise IntentRefused(DUPLICATE_LIVE_INTENT, other.id)
        minutes = int(expires_in_minutes if expires_in_minutes is not None
                      else self.expiry["default_minutes"])
        if minutes > int(self.expiry["max_minutes"]):
            raise IntentRefused(EXPIRY_TOO_LONG, str(minutes))
        snapshot = Snapshot(amount_minor=amount_minor, currency=currency,
                            allowed_methods=tuple(allowed_methods),
                            expires_at_minute=now_minute + minutes)
        intent = Intent(id=intent_id, tenant_id=tenant_id, project_id=project_id,
                        external_reference=external_reference, snapshot=snapshot,
                        client_secret_ref=f"cs_{intent_id}")
        self.intents[intent_id] = intent
        return intent

    def get(self, intent_id: str) -> Intent:
        intent = self.intents.get(intent_id)
        if intent is None:
            raise IntentRefused(UNKNOWN_INTENT, intent_id)
        return intent

    # -- the amount is frozen ---------------------------------------------
    def amend(self, intent: Intent, **changes) -> Intent:
        for name in changes:
            if name in self.model["amount_snapshot"]["fields"]:
                raise IntentRefused(AMOUNT_IMMUTABLE, name)
            if name == "expires_at_minute":
                raise IntentRefused(EXPIRY_NOT_EXTENDABLE, name)
        for name, value in changes.items():
            setattr(intent, name, value)
        return intent

    def extend_expiry(self, intent: Intent, minutes: int) -> Intent:
        """The helpful-looking method that does not exist."""
        raise IntentRefused(EXPIRY_NOT_EXTENDABLE,
                            "open a new intent instead of charging a stale price")

    def narrow_methods(self, intent: Intent, methods: tuple[str, ...]) -> Intent:
        """Risk may remove a method before confirmation. Nobody may add one."""
        widened = set(methods) - set(intent.snapshot.allowed_methods)
        if widened and not self.method_policy["widen_after_creation_allowed"]:
            raise IntentRefused(METHOD_WIDENED, ",".join(sorted(widened)))
        intent.snapshot = Snapshot(amount_minor=intent.snapshot.amount_minor,
                                   currency=intent.snapshot.currency,
                                   allowed_methods=tuple(methods),
                                   expires_at_minute=intent.snapshot.expires_at_minute)
        return intent

    # -- expiry ------------------------------------------------------------
    def is_expired(self, intent: Intent, now_minute: int) -> bool:
        return now_minute >= intent.snapshot.expires_at_minute

    def expire(self, intent: Intent, *, now_minute: int, actor: str) -> Intent:
        if actor != self.expiry["expiry_actor"]:
            raise IntentRefused(NOT_SCHEDULER, actor)
        if not self.is_expired(intent, now_minute):
            raise IntentRefused(ILLEGAL_TRANSITION, "not yet expired")
        return self.transition(intent, EXPIRED, source="server_side_query")

    # -- confirmation ------------------------------------------------------
    def confirm(self, intent: Intent, *, method: str, idempotency_key: str,
                now_minute: int) -> str:
        if not idempotency_key:
            raise IntentRefused(NO_IDEMPOTENCY_KEY, intent.id)
        if idempotency_key in intent.confirmations:
            # A retry is the same request, not a second payment.
            return intent.confirmations[idempotency_key]
        if intent.state in TERMINAL:
            raise IntentRefused(ALREADY_TERMINAL, intent.state)
        if self.is_expired(intent, now_minute):
            raise IntentRefused(INTENT_EXPIRED, str(now_minute))
        if method not in intent.snapshot.allowed_methods:
            raise IntentRefused(METHOD_NOT_ALLOWED, method)
        if intent.confirmations and self.confirmation["single_success"]:
            # A different key against an intent already being confirmed.
            raise IntentRefused(IDEMPOTENCY_KEY_REUSED, idempotency_key)
        result = f"confirming:{method}"
        intent.confirmations[idempotency_key] = result
        intent.history.append({"event": "confirm", "method": method, "minute": now_minute})
        return result

    # -- state -------------------------------------------------------------
    def transition(self, intent: Intent, target: str, *, source: str) -> Intent:
        if source not in self.confirmation["authoritative_sources"]:
            raise IntentRefused(UNTRUSTED_SOURCE, source)
        if intent.state in TERMINAL:
            raise IntentRefused(ALREADY_TERMINAL, intent.state)
        if (intent.state, target) not in TRANSITIONS:
            raise IntentRefused(ILLEGAL_TRANSITION, f"{intent.state} -> {target}")
        intent.history.append({"from": intent.state, "to": target, "source": source})
        intent.state = target
        return intent

    def succeed_from_return_page(self, intent: Intent) -> Intent:
        """The shortcut that does not exist."""
        raise IntentRefused(RETURN_PAGE_NOT_EVIDENCE,
                            "the return page is a request from the payer's own machine")

    # -- amounts -----------------------------------------------------------
    def capture(self, intent: Intent, amount_minor: int, *, source: str) -> int:
        if isinstance(amount_minor, bool) or not isinstance(amount_minor, int):
            raise IntentRefused(AMOUNT_NOT_INTEGER, repr(amount_minor))
        if amount_minor <= 0:
            raise IntentRefused(AMOUNT_NOT_POSITIVE, str(amount_minor))
        if intent.captured_minor + amount_minor > intent.amount_minor:
            raise IntentRefused(OVER_CAPTURE,
                                f"{intent.captured_minor + amount_minor} > "
                                f"{intent.amount_minor}")
        self.transition(intent, CAPTURED, source=source)
        intent.captured_minor += amount_minor
        return intent.captured_minor

    def refund(self, intent: Intent, amount_minor: int) -> int:
        if intent.refunded_minor + amount_minor > intent.captured_minor:
            raise IntentRefused(OVER_REFUND,
                                f"{intent.refunded_minor + amount_minor} > "
                                f"{intent.captured_minor}")
        intent.refunded_minor += amount_minor
        return intent.refunded_minor
