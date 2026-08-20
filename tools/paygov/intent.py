"""B32 — the payment intent: an immutable amount snapshot with an expiry.

The brief asks for an immutable amount snapshot, an expiry, a confirmation
policy, payment-method constraints and a link to the business order. The first
of those carries the rest: ``INTENT_AMOUNT_MUTABLE``. A payer authorises a
specific number. If that number can be edited afterwards, then "what they agreed
to" and "what was taken" are allowed to differ and nothing in the record shows
where. Changing the amount is not an edit — it is a second payment.

The rest are the mistakes this area repeats:

* ``INTENT_EXPIRY_EXTENDABLE`` — extending an intent's deadline. It is always
  done to be helpful and it is how a price from last week gets charged today;
* ``INTENT_OWNS_ORDER`` — copying the order lines, the address and the customer
  email into the payment platform. Now there are two order systems, they will
  disagree, and support will believe the wrong one;
* ``INTENT_ORDER_NOT_UNIQUE`` — allowing two live intents against one business
  order, which is the cheapest double-charge there is;
* ``INTENT_RETURN_PAGE_EVIDENCE`` — treating the browser's return page as proof
  of payment (NN-01). It is a request from the payer's own machine.
"""
from __future__ import annotations

from pathlib import Path

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

INTENT = Path("governance/payment-intent.json")
STATES = Path("governance/state-machines.json")
DOMAIN = Path("governance/domain-model.json")
CAPS = Path("governance/provider-capabilities.json")
CURRENCY = Path("governance/currency-metadata.json")
AUDIT = Path("governance/audit-log.json")

SNAPSHOT_FIELDS = {"amount_minor", "currency"}
ORDER_FIELDS = {"project_id", "external_reference"}
FORBIDDEN_ORDER_CONTENT = {"line_items", "shipping_address", "customer_email"}
AUTHORITATIVE_SOURCES = {"verified_provider_event", "server_side_query"}
MAX_EXPIRY_MINUTES = 1440


VALIDATOR = ("payment-intent", "B32")


def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    where = str(INTENT)
    budget.check(where)
    try:
        model = load_json(root / INTENT)
    except Exception as exc:
        return [Problem("INTENT_UNREADABLE", where,
                        f"cannot read the payment intent model: {exc}", "NN-14")]
    if not isinstance(model, dict):
        return [Problem("INTENT_SHAPE", where, "the model must be an object", "NN-12")]

    problems = list(expect(SEMVER.match(str(model.get("schema_version", ""))),
                           "INTENT_VERSION_FIELD", where, "schema_version must be semver",
                           "NN-12"))
    problems += expect(len(str(model.get("principle") or "")) >= 20, "INTENT_PRINCIPLE", where,
                       "say what the amount snapshot means", "NN-14")
    problems += _snapshot(model, root, where, budget)
    problems += _lifecycle(model, root, where, budget)
    problems += _expiry(model, where)
    problems += _confirmation(model, where)
    problems += _methods(model, root, where, budget)
    problems += _order(model, root, where, budget)
    problems += _invariants(model, where)
    problems += _client_secret(model, where)
    problems += _audit_binding(model, root, where, budget)
    problems += _generated(root, budget)
    return problems


def _snapshot(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    snapshot = model.get("amount_snapshot")
    if not isinstance(snapshot, dict):
        return [Problem("INTENT_AMOUNT_MUTABLE", where,
                        "without a snapshot policy the amount is whatever the last write left "
                        "behind", "NN-05")]
    problems = list(expect(snapshot.get("immutable") is True, "INTENT_AMOUNT_MUTABLE", where,
                           "the amount snapshot must be immutable; a payer authorised one "
                           "number", "NN-05"))
    problems += expect(snapshot.get("change_requires_new_intent") is True,
                       "INTENT_AMOUNT_MUTABLE", where,
                       "changing the amount must create a new intent, not edit this one",
                       "NN-05")
    fields = set(snapshot.get("fields") or [])
    problems += expect(SNAPSHOT_FIELDS <= fields, "INTENT_SNAPSHOT_INCOMPLETE", where,
                       f"the snapshot is missing {sorted(SNAPSHOT_FIELDS - fields)}; a frozen "
                       f"amount with a floating currency is not frozen", "NN-05")
    problems += expect(snapshot.get("minor_units_only") is True, "INTENT_AMOUNT_NOT_MINOR",
                       where, "amounts are integer minor units", "NN-05")
    source = str(snapshot.get("exponent_source") or "")
    problems += expect(source == str(CURRENCY), "INTENT_EXPONENT_SOURCE", where,
                       f"the minor-unit exponent must come from {CURRENCY}; a second copy of "
                       f"the precision table is how one currency ends up with two", "NN-05")
    budget.check(str(DOMAIN))
    try:
        domain = load_json(root / DOMAIN)
        entity = next((e for e in (domain.get("entities") or [])
                       if isinstance(e, dict) and e.get("name") == "PaymentIntent"), {})
        known = {str(f.get("name")) for f in (entity.get("fields") or [])
                 if isinstance(f, dict)}
    except Exception:
        entity, known = {}, set()
    if known:
        unknown = sorted(fields - known)
        problems += expect(not unknown, "INTENT_FIELD_UNKNOWN", where,
                           f"the snapshot names {unknown}, which the B08 PaymentIntent entity "
                           f"does not define", "NN-12")
    problems += expect(len(str(snapshot.get("notes") or "")) >= 8, "INTENT_SNAPSHOT_NOTES",
                       where, "say where the currency precision comes from", "NN-14")
    return problems


def _lifecycle(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    lifecycle = model.get("lifecycle")
    if not isinstance(lifecycle, dict):
        return [Problem("INTENT_SHAPE", where, "lifecycle must be an object", "NN-14")]
    budget.check(str(STATES))
    try:
        machines = load_json(root / STATES)
        machine = next((m for m in (machines.get("machines") or [])
                        if isinstance(m, dict) and m.get("entity") == "PaymentIntent"), {})
        success = (machines.get("success_states") or {}).get("PaymentIntent") or []
    except Exception:
        machine, success = {}, []
    problems: list[Problem] = []
    if machine:
        problems += expect(lifecycle.get("states") == machine.get("states"),
                           "INTENT_STATES_DIVERGE", where,
                           "the states here must be exactly the B10 payment-intent machine; two "
                           "copies of a state list eventually disagree and nobody notices the "
                           "day they do", "NN-12")
        problems += expect(lifecycle.get("initial") == machine.get("initial"),
                           "INTENT_STATES_DIVERGE", where,
                           f"initial state must be '{machine.get('initial')}' as in B10",
                           "NN-12")
        problems += expect(lifecycle.get("terminal") == machine.get("terminal"),
                           "INTENT_STATES_DIVERGE", where,
                           "terminal states must match B10", "NN-12")
    if success:
        problems += expect(lifecycle.get("success_states") == success,
                           "INTENT_SUCCESS_DIVERGE", where,
                           f"success states must match B10's {success}; disagreeing about what "
                           f"counts as paid is how a merchant ships against a payment that has "
                           f"not settled", "NN-01")
    problems += expect(str(lifecycle.get("source") or "").startswith(str(STATES)),
                       "INTENT_LIFECYCLE_UNSOURCED", where,
                       "the lifecycle must name the B10 machine it comes from", "NN-12")
    problems += expect(len(str(lifecycle.get("notes") or "")) >= 8, "INTENT_LIFECYCLE_NOTES",
                       where, "say why the states are referenced and not redefined", "NN-14")
    return problems


def _expiry(model: dict, where: str) -> list[Problem]:
    expiry = model.get("expiry")
    if not isinstance(expiry, dict):
        return [Problem("INTENT_NO_EXPIRY", where,
                        "an intent that never expires can be confirmed against a price from "
                        "last month", "NN-01")]
    default = int(expiry.get("default_minutes") or 0)
    maximum = int(expiry.get("max_minutes") or 0)
    problems = list(expect(0 < default <= maximum, "INTENT_NO_EXPIRY", where,
                           f"the default expiry must be positive and within the maximum, got "
                           f"{default}/{maximum}", "NN-01"))
    problems += expect(0 < maximum <= MAX_EXPIRY_MINUTES, "INTENT_EXPIRY_TOO_LONG", where,
                       f"the maximum expiry must be at most {MAX_EXPIRY_MINUTES} minutes, got "
                       f"{maximum}", "NN-01")
    problems += expect(expiry.get("recorded_at_creation") is True, "INTENT_EXPIRY_LATE", where,
                       "the expiry must be written at creation, not computed on read", "NN-01")
    problems += expect(expiry.get("extension_allowed") is False, "INTENT_EXPIRY_EXTENDABLE",
                       where,
                       "extending an expiry is how a stale price gets charged; open a new "
                       "intent instead", "NN-01")
    problems += expect(expiry.get("expired_can_be_confirmed") is False, "INTENT_EXPIRED_LIVES",
                       where, "an expired intent must not be confirmable", "NN-01")
    problems += expect(str(expiry.get("expiry_actor") or "") == "scheduler",
                       "INTENT_EXPIRY_LAZY", where,
                       "expiry must be driven by a scheduler; discovering it on the next "
                       "request leaves an untouched intent confirmable for days", "NN-01")
    problems += expect(len(str(expiry.get("notes") or "")) >= 8, "INTENT_EXPIRY_NOTES", where,
                       "say who expires an intent", "NN-14")
    return problems


def _confirmation(model: dict, where: str) -> list[Problem]:
    confirmation = model.get("confirmation")
    if not isinstance(confirmation, dict):
        return [Problem("INTENT_NO_IDEMPOTENCY", where,
                        "without a confirmation policy, a retried confirm is a second payment",
                        "NN-03")]
    problems = list(expect(confirmation.get("idempotency_key_required") is True,
                           "INTENT_NO_IDEMPOTENCY", where,
                           "confirmation must carry an idempotency key", "NN-03"))
    scope = set(confirmation.get("key_unique_per") or [])
    problems += expect({"tenant_id", "intent_id"} <= scope, "INTENT_IDEMPOTENCY_SCOPE", where,
                       "the idempotency key must be unique per tenant and intent; a globally "
                       "unique key lets one tenant's retry collide with another's", "NN-03")
    problems += expect(confirmation.get("single_success") is True, "INTENT_MULTI_SUCCESS",
                       where, "an intent must succeed at most once", "NN-03")
    problems += expect(confirmation.get("concurrent_confirmations_serialized") is True,
                       "INTENT_CONCURRENT_CONFIRM", where,
                       "two confirmations arriving together must be serialised, not both "
                       "attempted", "NN-03")
    problems += expect(confirmation.get("client_return_page_is_evidence") is False,
                       "INTENT_RETURN_PAGE_EVIDENCE", where,
                       "the client return page is not evidence of payment", "NN-01")
    sources = set(confirmation.get("authoritative_sources") or [])
    problems += expect(AUTHORITATIVE_SOURCES <= sources, "INTENT_NO_AUTHORITATIVE_SOURCE",
                       where,
                       f"success must come from {sorted(AUTHORITATIVE_SOURCES)}", "NN-01")
    problems += expect(len(str(confirmation.get("notes") or "")) >= 8,
                       "INTENT_CONFIRMATION_NOTES", where,
                       "say what proves a payment succeeded", "NN-14")
    return problems


def _methods(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    methods = model.get("method_constraints")
    if not isinstance(methods, dict):
        return [Problem("INTENT_SHAPE", where, "method_constraints must be an object", "NN-14")]
    problems = list(expect(methods.get("snapshot_at_creation") is True,
                           "INTENT_METHODS_UNFROZEN", where,
                           "the allowed methods must be frozen at creation, computed from the "
                           "capability matrix", "NN-14"))
    problems += expect(methods.get("confirm_method_must_be_in_snapshot") is True,
                       "INTENT_METHODS_UNFROZEN", where,
                       "confirming with a method outside the snapshot must be refused",
                       "NN-14")
    problems += expect(methods.get("widen_after_creation_allowed") is False,
                       "INTENT_METHODS_WIDENED", where,
                       "nobody may add a method to an intent already shown to a payer", "NN-14")
    source = str(methods.get("source") or "")
    problems += expect(source == str(CAPS), "INTENT_METHODS_UNSOURCED", where,
                       f"the method snapshot must come from {CAPS}", "NN-12")
    budget.check(str(CAPS))
    try:
        caps = load_json(root / CAPS)
        declared = {str(m.get("id")) for m in (caps.get("payment_methods") or [])
                    if isinstance(m, dict)}
    except Exception:
        declared = set()
    problems += expect(bool(declared), "INTENT_METHODS_UNSOURCED", where,
                       "the B27 capability matrix declares no payment methods to snapshot",
                       "NN-12")
    problems += expect(len(str(methods.get("notes") or "")) >= 8, "INTENT_METHOD_NOTES", where,
                       "say why widening is refused but narrowing is not", "NN-14")
    return problems


def _order(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    order = model.get("order_link")
    if not isinstance(order, dict):
        return [Problem("INTENT_OWNS_ORDER", where,
                        "without an order-link policy the platform grows a second order system",
                        "NN-09")]
    problems = list(expect(str(order.get("owner") or "") == "originating_project",
                           "INTENT_OWNS_ORDER", where,
                           "the business order belongs to the originating project; the payment "
                           "platform owns payment facts only", "NN-09"))
    fields = set(order.get("reference_fields") or [])
    problems += expect(ORDER_FIELDS <= fields, "INTENT_ORDER_REFERENCE", where,
                       f"the order reference must be {sorted(ORDER_FIELDS)}", "NN-12")
    problems += expect(order.get("unique_live_intent_per_order") is True,
                       "INTENT_ORDER_NOT_UNIQUE", where,
                       "one business order may have at most one live intent; two is the "
                       "cheapest double charge there is", "NN-03")
    problems += expect(order.get("stores_order_content") is False, "INTENT_OWNS_ORDER", where,
                       "the platform must not store order content", "NN-09")
    forbidden = set(order.get("forbidden_fields") or [])
    problems += expect(FORBIDDEN_ORDER_CONTENT <= forbidden, "INTENT_ORDER_CONTENT_ALLOWED",
                       where,
                       f"the forbidden list is missing {sorted(FORBIDDEN_ORDER_CONTENT - forbidden)}; "
                       f"those are the fields people copy across first", "NN-06")
    budget.check(str(DOMAIN))
    try:
        domain = load_json(root / DOMAIN)
        entity = next((e for e in (domain.get("entities") or [])
                       if isinstance(e, dict) and e.get("name") == "PaymentIntent"), {})
        known = {str(f.get("name")) for f in (entity.get("fields") or [])
                 if isinstance(f, dict)}
    except Exception:
        known = set()
    if known:
        leaked = sorted(forbidden & known)
        problems += expect(not leaked, "INTENT_ORDER_CONTENT_ALLOWED", where,
                           f"the B08 PaymentIntent entity already carries {leaked}, which this "
                           f"model forbids", "NN-09")
        problems += expect("external_reference" in known, "INTENT_ORDER_REFERENCE", where,
                           "the B08 entity must carry external_reference", "NN-12")
    problems += expect(len(str(order.get("notes") or "")) >= 8, "INTENT_ORDER_NOTES", where,
                       "say what happens with two order systems", "NN-14")
    return problems


def _invariants(model: dict, where: str) -> list[Problem]:
    invariants = model.get("amount_invariants")
    if not isinstance(invariants, dict):
        return [Problem("INTENT_SHAPE", where, "amount_invariants must be an object", "NN-05")]
    problems = list(expect(invariants.get("captured_cannot_exceed_amount") is True,
                           "INTENT_OVER_CAPTURE", where,
                           "captured must never exceed the snapshot amount", "NN-05"))
    problems += expect(invariants.get("refunded_cannot_exceed_captured") is True,
                       "INTENT_OVER_REFUND", where,
                       "refunded must never exceed captured", "NN-05")
    problems += expect(invariants.get("negative_amounts_forbidden") is True,
                       "INTENT_NEGATIVE_AMOUNT", where,
                       "a negative amount is a refund wearing a payment's clothes", "NN-05")
    problems += expect(invariants.get("zero_amount_intent_allowed") is False,
                       "INTENT_ZERO_AMOUNT", where,
                       "a zero-amount intent is a placeholder; use a mechanism that is honest "
                       "about being one", "NN-05")
    problems += expect(len(str(invariants.get("notes") or "")) >= 8, "INTENT_INVARIANT_NOTES",
                       where, "say why zero is refused", "NN-14")
    return problems


def _client_secret(model: dict, where: str) -> list[Problem]:
    secret = model.get("client_secret")
    if not isinstance(secret, dict):
        return [Problem("INTENT_SHAPE", where, "client_secret must be an object", "NN-04")]
    problems = list(expect(secret.get("contains_credentials") is False,
                           "INTENT_CLIENT_SECRET_CREDENTIAL", where,
                           "the client-facing reference must contain no credential", "NN-04"))
    problems += expect(secret.get("scoped_to_single_intent") is True,
                       "INTENT_CLIENT_SECRET_BROAD", where,
                       "the client reference must be valid for one intent only", "NN-04")
    problems += expect(secret.get("expires_with_intent") is True,
                       "INTENT_CLIENT_SECRET_ETERNAL", where,
                       "the client reference must expire with the intent", "NN-04")
    problems += expect(len(str(secret.get("notes") or "")) >= 8, "INTENT_CLIENT_SECRET_NOTES",
                       where, "say what the client reference may carry", "NN-14")
    return problems


def _audit_binding(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    event_class = str(model.get("audit_event_class") or "")
    budget.check(str(AUDIT))
    try:
        audit = load_json(root / AUDIT)
        classes = {str(c.get("id")) for c in (audit.get("event_classes") or [])
                   if isinstance(c, dict)}
    except Exception:
        classes = set()
    problems = list(expect(event_class in classes, "INTENT_AUDIT_CLASS_UNKNOWN", where,
                           f"intent events are recorded as '{event_class}', which "
                           f"governance/audit-log.json does not define", "NN-13"))
    problems += expect(event_class == "money.movement", "INTENT_AUDIT_CLASS_TOO_WEAK", where,
                       "an intent is the entry point of a money movement and must be recorded "
                       "as one", "NN-13")
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .intentgen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("INTENT_GENERATED", rel, f"cannot generate {rel}: {exc}",
                                    "NN-12"))
            continue
        if not path.is_file():
            problems.append(Problem("INTENT_GENERATED_MISSING", rel,
                                    f"{rel} is generated from governance/payment-intent.json "
                                    f"but does not exist; run scripts/render-intent.py",
                                    "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("INTENT_GENERATED_DRIFT", rel,
                                    f"{rel} differs from what the model generates", "NN-12"))
    return problems
