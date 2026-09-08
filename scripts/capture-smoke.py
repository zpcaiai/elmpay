#!/usr/bin/env python3
"""B34 runtime proof — the 400 nobody talks about.

An authorisation of 1000 is partially captured for 600. The merchant is paid,
the ledger balances, the customer's statement looks right. The remaining 400 is
still a hold on the payer's money, and the only question that matters is what
releases it.

Scenario 2 is why this batch exists: with no close operation the answer is
"the authorisation's own expiry", which on a card is days. Scenario 3 is the
same authorisation with close available. The difference between them is not a
state name — it is 400 units of someone else's money and the number of days we
keep it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.capture.reference.capture import (  # noqa: E402
    ACTIVE, AUTH_NOT_ACTIVE, CANCELED, CAPTURE_AMOUNT_NOT_POSITIVE,
    CAPTURE_EXCEEDS_AUTHORIZED, CAPTURED, CLOSE_WITHOUT_CAPTURE, EXPIRED,
    VOID_AFTER_CAPTURE, Authorization, Capability, CaptureRefused,
    capture, close, expire, void)

MODEL = json.loads((ROOT / "governance/capture-lifecycle.json").read_text(encoding="utf-8"))
CAPS = json.loads((ROOT / "governance/provider-capabilities.json").read_text(encoding="utf-8"))

AUTHORIZED = 1000
TAKEN = 600

checks = 0
failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    global checks
    checks += 1
    status = "OK " if condition else "FAIL"
    if not condition:
        failures.append(label)
    print(f"[{status}] {label}{(' — ' + detail) if detail else ''}")


def refusal(label: str, expected: str, fn) -> None:
    try:
        fn()
    except CaptureRefused as refused:
        check(label, refused.code == expected, f"code={refused.code}")
        return
    check(label, False, "not refused at all")


def _partial_capable_provider() -> dict:
    """The capability facts come from B27, never from a hopeful default."""
    for entry in CAPS["capabilities"]:
        if entry.get("partial_capture") and entry.get("supports_authorization_capture"):
            return entry
    raise SystemExit("no provider in the B27 matrix supports partial capture")


provider = _partial_capable_provider()
capability = Capability(
    supports_authorization_capture=True,
    partial_capture=True,
    authorization_valid_hours=int(provider["authorization_valid_hours"]))
print(f"provider={provider['provider']}:{provider['method']} "
      f"authorization_valid_hours={capability.authorization_valid_hours}")

# 1 — a partial capture pays the merchant and leaves the rest held.
partial = capture(Authorization(AUTHORIZED), TAKEN, capability)
check("partial capture pays 600 and leaves the authorisation active",
      partial.state == ACTIVE and partial.captured_minor == TAKEN
      and partial.remaining_minor == AUTHORIZED - TAKEN,
      f"captured={partial.captured_minor} remaining={partial.remaining_minor}")

# 2 — without close, the remainder is released by a clock we do not control.
lapsed = expire(partial)
check("without close the remaining 400 is held until the authorisation expires",
      lapsed.state == EXPIRED and lapsed.remaining_minor == AUTHORIZED - TAKEN,
      f"held={lapsed.remaining_minor} for up to "
      f"{capability.authorization_valid_hours}h")
check("the model refuses to call that a release path",
      MODEL["authorization"]["expiry_is_release_path"] is False
      and MODEL["authorization"]["expiry_requires_exposure_alert"] is True)

# 3 — with close, the same 400 is released now.
closed = close(partial)
check("close releases the remaining 400 immediately",
      closed.state == CAPTURED and closed.captured_minor == TAKEN
      and closed.closed_below_authorized,
      f"state={closed.state} captured={closed.captured_minor} "
      f"released={AUTHORIZED - closed.captured_minor}")

# 4 — money is conserved in every ending: nothing is captured twice, nothing vanishes.
for name, auth, released, held in (
        ("closed after partial", closed, AUTHORIZED - TAKEN, 0),
        ("expired after partial", lapsed, 0, AUTHORIZED - TAKEN),
        ("voided before capture", void(Authorization(AUTHORIZED)), AUTHORIZED, 0),
        ("captured in full", capture(Authorization(AUTHORIZED), AUTHORIZED, capability), 0, 0)):
    total = auth.captured_minor + released + held
    check(f"exposure adds up: {name}", total == AUTHORIZED,
          f"captured={auth.captured_minor} released={released} held={held}")

# 5 — multi capture reaches the full amount without needing a close.
first = capture(Authorization(AUTHORIZED), TAKEN, capability)
second = capture(first, AUTHORIZED - TAKEN, capability)
check("two captures reaching the full amount close the authorisation on their own",
      second.state == CAPTURED and second.captured_minor == AUTHORIZED
      and not second.closed_below_authorized)

# 6 — the refusals, each for its own reason.
refusal("a void after money moved is refused", VOID_AFTER_CAPTURE, lambda: void(partial))
refusal("closing an untouched authorisation is refused", CLOSE_WITHOUT_CAPTURE,
        lambda: close(Authorization(AUTHORIZED)))
refusal("cumulative capture past the authorised amount is refused",
        CAPTURE_EXCEEDS_AUTHORIZED, lambda: capture(partial, AUTHORIZED, capability))
refusal("capturing after the authorisation ended is refused", AUTH_NOT_ACTIVE,
        lambda: capture(closed, 1, capability))
refusal("closing an already ended authorisation is refused", AUTH_NOT_ACTIVE,
        lambda: close(closed))
refusal("a zero capture is refused", CAPTURE_AMOUNT_NOT_POSITIVE,
        lambda: capture(Authorization(AUTHORIZED), 0, capability))

# 7 — a provider that cannot do partial capture must not be sent one.
narrow = Capability(supports_authorization_capture=True, partial_capture=False,
                    authorization_valid_hours=0)
refusal("a partial capture is refused for a provider that does not support it",
        "CAPTURE_PARTIAL_NOT_SUPPORTED",
        lambda: capture(Authorization(AUTHORIZED), TAKEN, narrow))

print()
print(f"checks={checks} failures={len(failures)}")
for name in failures:
    print("  FAILED", name)
raise SystemExit(1 if failures else 0)
