#!/usr/bin/env python3
"""B35 runtime proof — the four lists, and the field that walked between them.

Before this batch the repository held four independent answers to "what must
never be stored or logged". The interesting thing is not that they were four.
It is that they disagreed in a way nobody could see from inside any one of them:
the Java guard watched ``pan``, the audit chain watched ``card_pan``, and each
looked complete from where it stood.

Scenario 1 replays that gap against the merged catalogue. Scenario 2 shows the
same field under six spellings — the spellings are the whole point, because an
attacker does not need a new field, only a new way to write an old one.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.audit.reference.chain import (  # noqa: E402
    AuditRefused, FORBIDDEN_FIELD, Ledger, field_is_forbidden, normalize_field)

MODEL = json.loads((ROOT / "governance/payment-method.json").read_text(encoding="utf-8"))
CONTRACT = json.loads(
    (ROOT / "contracts/payment-method/sensitive-fields.json").read_text(encoding="utf-8"))

# The four lists as they stood before B35, transcribed from the commit that this
# batch replaced. They are the test input, not the specification.
LEGACY_JAVA_GUARD = ("pan", "card_number", "cardnumber", "cvv", "cvc", "cid", "track1",
                     "track2", "pin", "private_key", "privatekey", "api_key", "apikey",
                     "authorization", "apple_pay_token", "paymentdata")
LEGACY_AUDIT_CHAIN = ("card_pan", "card_cvv", "password", "authorization_header")
# Transcribed in full from apps/checkout-web/src/provider-sdk-policy.mjs:
#   /(?:secret|private|password|credential|token|pan|cvv|cvc|authorization)/i
# `token` is handled separately below: it is a deliberate scope divergence, not a
# gap, and the difference between those two is the whole point of this batch.
LEGACY_CHECKOUT_REGEX_TERMS = ("secret", "private", "password", "credential", "token",
                               "pan", "cvv", "cvc", "authorization")
CHECKOUT_OUT_OF_SCOPE = ("token",)
LEGACY_COMMERCE_SUBSTRING = ("cvv",)

checks = 0
failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    global checks
    checks += 1
    if not condition:
        failures.append(label)
    print(f"[{'OK ' if condition else 'FAIL'}] {label}{(' — ' + detail) if detail else ''}")


# 1 — every name any of the four lists ever guarded is now guarded by all of them.
for legacy, source in ((LEGACY_JAVA_GUARD, "java guard"),
                       (LEGACY_AUDIT_CHAIN, "audit chain"),
                       (LEGACY_CHECKOUT_REGEX_TERMS, "checkout regex"),
                       (LEGACY_COMMERCE_SUBSTRING, "commerce substring")):
    in_scope = [name for name in legacy if name not in CHECKOUT_OUT_OF_SCOPE]
    missed = sorted(name for name in in_scope if not field_is_forbidden(name))
    check(f"the merged catalogue covers everything the {source} covered",
          not missed, f"missed={missed}" if missed else f"{len(in_scope)} names")

# 1b — the one term that is deliberately NOT merged, asserted rather than omitted.
#
# The checkout regex screens browser SDK parameter names; this catalogue screens
# what reaches storage and logs. The platform legitimately holds a field called
# `token_reference`, so forbidding a bare `token` here would make the audit log
# refuse legitimate records — and a rule that misfires is a rule people route
# around. The divergence is recorded in the model, and this check fails if
# somebody "tidies" it away in either direction.
check("`token` is deliberately out of this catalogue's scope",
      not field_is_forbidden("token")
      and "token" in MODEL["conformance"].get("scope_divergence", {}),
      "screened at the checkout boundary, not at the storage boundary")
check("the field the platform actually holds is not blocked",
      not field_is_forbidden("token_reference")
      and "token_reference" in MODEL["custody"]["platform_holds"])

# 2 — the gap that actually existed: one list's name was invisible to the other.
check("`card_pan` was invisible to a guard watching `pan` — both are caught now",
      field_is_forbidden("card_pan") and field_is_forbidden("pan")
      and normalize_field("card_pan") != normalize_field("pan"),
      "two distinct names, one catalogue")

# 2b — the gap this smoke test found on its first run.
check("a bare `private` is refused",
      field_is_forbidden("private"),
      "the checkout regex caught it; this catalogue did not, until it was told to")

# 3 — spelling is not a bypass.
for spelling in ("pan", "PAN", "card_pan", "card-pan", "Card.Pan", "CARDPAN"):
    check(f"spelling `{spelling}` is refused", field_is_forbidden(spelling))

# 4 — the allowlisted display fields stay allowed. A guard that refuses everything
#     is not a guard, it is an outage, and it gets switched off within a week.
for allowed in MODEL["display_allowlist"]:
    check(f"display field `{allowed}` is still permitted", not field_is_forbidden(allowed))

# 5 — the immutable audit log refuses a forbidden field under any spelling.
for spelling in ("card_pan", "CVV2", "apple_pay_token", "authorization-header"):
    chain = Ledger(tenant_id="t-smoke")
    try:
        chain.append(occurred_at=1, event_class="payment", actor="svc", action="referenced",
                     decision="allow", rule_version="v1", payload={spelling: "…"})
        check(f"audit log refuses `{spelling}`", False, "it was accepted")
    except AuditRefused as refused:
        check(f"audit log refuses `{spelling}`", refused.code == FORBIDDEN_FIELD,
              f"code={refused.code}")

# 6 — a clean payload still gets written, and the chain still links.
chain = Ledger(tenant_id="t-smoke")
first = chain.append(occurred_at=1, event_class="payment", actor="svc", action="referenced",
                     decision="allow", rule_version="v1",
                     payload={"method": "card", "brand": "visa", "last4": "4242"})
second = chain.append(occurred_at=2, event_class="payment", actor="svc", action="referenced",
                      decision="allow", rule_version="v1",
                      payload={"method": "card", "brand": "visa", "last4": "4242"})
check("a non-sensitive payload is still recorded and stays linked",
      first.sequence == 1 and second.sequence == 2
      and second.previous_hash == first.record_hash,
      f"sequences={[r.sequence for r in chain.records]}")

# 7 — the projection and the model agree on the size of the catalogue.
model_names = set()
rules = MODEL["normalization"]
for family in MODEL["forbidden_fields"]:
    for name in [family["canonical"], *family["aliases"]]:
        text = name.lower() if rules.get("lowercase", True) else name
        for character in rules.get("strip_characters") or []:
            text = text.replace(character, "")
        model_names.add(text)
check("the generated contract carries exactly the model's names",
      set(CONTRACT["normalized_names"]) == model_names,
      f"{len(model_names)} names")

print()
print(f"checks={checks} failures={len(failures)}")
for name in failures:
    print("  FAILED", name)
raise SystemExit(1 if failures else 0)
