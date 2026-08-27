"""B34 — the executable form of the capture lifecycle.

The governance model says an authorisation leaves the active state through one
of three explicit doors: captured to the full amount, closed at a partial
amount, or voided at zero. This module is that sentence in code, and it exists
so the same sentence can be checked twice — once here, once by the Java
implementation replaying ``contracts/capture/vectors.json``.

The rule that carries the batch is ``CLOSE_REQUIRED_FOR_REMAINDER``. After a
partial capture the uncaptured remainder is still a hold on the payer's money.
A system with no close operation has exactly one way to release it — wait for
the authorisation to expire — and that is not a design, it is an omission with
a timer on it.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

ACTIVE = "active"
CAPTURED = "captured"
CANCELED = "canceled"
EXPIRED = "expired"

TERMINAL_STATES = frozenset({CAPTURED, CANCELED, EXPIRED})

# Refusal codes. They are part of the contract: the Java implementation must
# refuse the same inputs for the same reason, not merely refuse them.
CAPTURE_AMOUNT_NOT_POSITIVE = "CAPTURE_AMOUNT_NOT_POSITIVE"
CAPTURE_EXCEEDS_AUTHORIZED = "CAPTURE_EXCEEDS_AUTHORIZED"
CAPTURE_PARTIAL_NOT_SUPPORTED = "CAPTURE_PARTIAL_NOT_SUPPORTED"
VOID_AFTER_CAPTURE = "VOID_AFTER_CAPTURE"
CLOSE_WITHOUT_CAPTURE = "CLOSE_WITHOUT_CAPTURE"
AUTH_NOT_ACTIVE = "AUTH_NOT_ACTIVE"
UNKNOWN_UNRESOLVED = "UNKNOWN_UNRESOLVED"


class CaptureRefused(Exception):
    """A refusal carrying the contract code, never a bare boolean."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


@dataclass(frozen=True)
class Capability:
    """The provider-side facts this lifecycle is allowed to rely on.

    Sourced from ``governance/provider-capabilities.json``; never inferred from
    a successful call, because one provider accepting a partial capture today
    is not a capability, it is an observation.
    """

    supports_authorization_capture: bool
    partial_capture: bool
    authorization_valid_hours: int


@dataclass(frozen=True)
class Authorization:
    """An authorisation and everything captured against it so far."""

    authorized_minor: int
    captured_minor: int = 0
    state: str = ACTIVE
    unresolved_unknown: bool = False

    @property
    def remaining_minor(self) -> int:
        return self.authorized_minor - self.captured_minor

    @property
    def closed_below_authorized(self) -> bool:
        """True when the capture phase ended without taking the whole hold."""
        return self.state == CAPTURED and self.captured_minor < self.authorized_minor


def _require_active(auth: Authorization) -> None:
    if auth.state != ACTIVE:
        raise CaptureRefused(
            AUTH_NOT_ACTIVE,
            f"authorisation is {auth.state}; a terminal authorisation takes no further action")
    if auth.unresolved_unknown:
        raise CaptureRefused(
            UNKNOWN_UNRESOLVED,
            "an unresolved unknown blocks the next provider call; resolve it by query first")


def capture(auth: Authorization, amount_minor: int, capability: Capability) -> Authorization:
    """Capture ``amount_minor`` against an active authorisation."""
    _require_active(auth)
    if amount_minor <= 0:
        raise CaptureRefused(CAPTURE_AMOUNT_NOT_POSITIVE, "capture amount must be a positive integer")
    total = auth.captured_minor + amount_minor
    if total > auth.authorized_minor:
        raise CaptureRefused(
            CAPTURE_EXCEEDS_AUTHORIZED,
            f"cumulative capture {total} exceeds the authorised {auth.authorized_minor}")
    partial = total < auth.authorized_minor or auth.captured_minor > 0
    if partial and not capability.partial_capture:
        raise CaptureRefused(
            CAPTURE_PARTIAL_NOT_SUPPORTED,
            "this provider does not support partial or multiple captures")
    state = CAPTURED if total == auth.authorized_minor else ACTIVE
    return replace(auth, captured_minor=total, state=state)


def void(auth: Authorization) -> Authorization:
    """Release the whole authorisation. Legal only before any capture."""
    _require_active(auth)
    if auth.captured_minor > 0:
        raise CaptureRefused(
            VOID_AFTER_CAPTURE,
            "money has already been captured; release the remainder with close and return "
            "the captured part with a refund")
    return replace(auth, state=CANCELED)


def close(auth: Authorization) -> Authorization:
    """Give up the uncaptured remainder after a partial capture.

    This is the operation whose absence the batch exists to fix. Without it the
    remainder is released only by expiry, which holds the payer's funds for as
    long as the provider's authorisation window and leaves the platform unable
    to state its own exposure.
    """
    _require_active(auth)
    if auth.captured_minor <= 0:
        raise CaptureRefused(
            CLOSE_WITHOUT_CAPTURE,
            "nothing has been captured; releasing the whole hold is a void, not a close")
    return replace(auth, state=CAPTURED)


def expire(auth: Authorization) -> Authorization:
    """The fallback path, modelled so it can be counted — never chosen."""
    if auth.state != ACTIVE:
        raise CaptureRefused(AUTH_NOT_ACTIVE, f"authorisation is already {auth.state}")
    return replace(auth, state=EXPIRED)


def query(auth: Authorization, provider_says: str) -> Authorization:
    """Resolve an unknown by asking the provider, not by assuming.

    ``provider_says`` is one of ``captured``/``not_captured``/``unknown``. An
    unknown answer leaves the unknown standing: the call did not become a
    success because we asked twice.
    """
    if provider_says == "unknown":
        return replace(auth, unresolved_unknown=True)
    if provider_says == "captured":
        return replace(auth, unresolved_unknown=False)
    if provider_says == "not_captured":
        return replace(auth, unresolved_unknown=False)
    raise CaptureRefused(UNKNOWN_UNRESOLVED, f"unrecognised provider answer {provider_says!r}")
