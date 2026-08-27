"""B34 — authorise, capture, void and close.

The brief asks for immediate capture, deferred capture, partial capture, void,
close and an indeterminate-result query. Five of those six are usually built.
The one that is not is ``close``, and that is the rule this batch carries:
``CAPTURE_NO_EXPLICIT_CLOSE``.

After a partial capture the uncaptured remainder is still a hold on the payer's
money. If nothing can release it, the only exit is the authorisation's own
expiry — days on a card, and on some providers a hold the payer's bank keeps
until it feels like letting go. It never looks like a bug: the captured amount
is right, the ledger balances, the merchant got paid. What is wrong is off the
books — someone else's money, held by us, with no operation that gives it back
and no number that says how much of it there is.

The rest are the mistakes this area repeats:

* ``CAPTURE_EXPIRY_AS_RELEASE`` — writing expiry down as the release path. That
  is not a design decision, it is the omission with a timer on it, promoted to
  policy;
* ``CAPTURE_VOID_AFTER_CAPTURE`` — allowing a void once money has moved, so the
  same payment can be both voided at the provider and refunded from the ledger;
* ``CAPTURE_EXCEEDS_AUTHORIZED`` — dropping the cumulative ceiling, usually when
  multi-capture is added and each call is checked alone;
* ``CAPTURE_UNKNOWN_IS_SUCCESS`` — letting a query that answered "I don't know"
  settle the payment, which is how a timeout becomes a double capture.
"""
from __future__ import annotations

from pathlib import Path

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json, read_text
from .structs import SEMVER, expect

MODEL = Path("governance/capture-lifecycle.json")
CAPS = Path("governance/provider-capabilities.json")
STATES = Path("governance/state-machines.json")
VECTORS = Path("contracts/capture/vectors.json")

REQUIRED_OPERATIONS = ("authorize", "capture", "void", "close", "query")
MONEY_OPERATIONS = ("authorize", "capture", "void", "close")
AUTHORITATIVE_SOURCES = {"verified_provider_event", "server_side_query"}
PARTIAL_MODES = ("partial", "multi")

# Every code this module can emit. An invariant may only delegate enforcement to
# a code that actually exists here: "enforced_by" pointing at a rule nobody
# emits is a control that reads as present and fires never.
EMITTED_CODES = frozenset({
    "CAPTURE_UNREADABLE", "CAPTURE_SHAPE", "CAPTURE_VERSION_FIELD", "CAPTURE_PRINCIPLE",
    "CAPTURE_OPERATION_MISSING", "CAPTURE_NO_EXPLICIT_CLOSE", "CAPTURE_EXPIRY_AS_RELEASE",
    "CAPTURE_VOID_AFTER_CAPTURE", "CAPTURE_AFTER_TERMINAL", "CAPTURE_EXCEEDS_AUTHORIZED",
    "CAPTURE_UNKNOWN_IS_SUCCESS", "CAPTURE_NOT_IDEMPOTENT", "CAPTURE_UNAUDITED",
    "CAPTURE_CAPABILITY_UNCHECKED", "CAPTURE_CAPABILITY_SOURCE", "CAPTURE_AUTHORITY_WEAK",
    "CAPTURE_INVARIANT_UNENFORCED", "CAPTURE_TERMINAL_OUTCOME", "CAPTURE_VECTORS_DRIFT",
    "CAPTURE_JAVA_UNBOUND",
})

VALIDATOR = ("capture-lifecycle", "B34")


def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    where = str(MODEL)
    budget.check(where)
    try:
        model = load_json(root / MODEL, budget)
    except Exception as exc:
        return [Problem("CAPTURE_UNREADABLE", where,
                        f"cannot read the capture lifecycle model: {exc}", "NN-14")]
    if not isinstance(model, dict):
        return [Problem("CAPTURE_SHAPE", where, "the model must be an object", "NN-12")]

    problems = list(expect(SEMVER.match(str(model.get("schema_version", ""))),
                           "CAPTURE_VERSION_FIELD", where,
                           "schema_version must be semver", "NN-12"))
    problems += expect(len(str(model.get("principle") or "")) >= 20, "CAPTURE_PRINCIPLE", where,
                       "say what an authorisation is and what releasing it costs", "NN-14")
    operations = _operations(model)
    problems += _required_operations(operations, where)
    problems += _close(operations, where)
    problems += _expiry(model, where)
    problems += _void(operations, where)
    problems += _terminality(operations, where)
    problems += _query(operations, where)
    problems += _idempotency_and_audit(operations, where)
    problems += _authority(operations, where)
    problems += _capture_modes(model, root, where, budget)
    problems += _invariants(model, where)
    problems += _terminal_outcomes(model, root, where, budget)
    problems += _conformance(model, root, where, budget)
    return problems


def _operations(model: dict) -> dict[str, dict]:
    found: dict[str, dict] = {}
    for entry in model.get("operations") or []:
        if isinstance(entry, dict) and isinstance(entry.get("id"), str):
            found[entry["id"]] = entry
    return found


def _required_operations(operations: dict, where: str) -> list[Problem]:
    missing = [name for name in REQUIRED_OPERATIONS if name not in operations]
    return expect(not missing, "CAPTURE_OPERATION_MISSING", where,
                  f"the lifecycle does not declare {missing}; an operation the model does not "
                  f"name is one nobody has to implement", "NN-12", missing=missing)


def _close(operations: dict, where: str) -> list[Problem]:
    close = operations.get("close")
    if not isinstance(close, dict):
        return [Problem("CAPTURE_NO_EXPLICIT_CLOSE", where,
                        "there is no close operation, so the remainder of a partial capture can "
                        "only be released by waiting for the authorisation to expire", "NN-12")]
    problems = list(expect(close.get("releases") == "remainder", "CAPTURE_NO_EXPLICIT_CLOSE",
                           where, "close must release the uncaptured remainder; anything else "
                           "leaves the payer's funds held", "NN-12",
                           releases=close.get("releases")))
    preconditions = set(close.get("preconditions") or [])
    problems += expect("captured_amount_positive" in preconditions,
                       "CAPTURE_NO_EXPLICIT_CLOSE", where,
                       "close must require that something was captured; closing at zero is a "
                       "void and must say so", "NN-12")
    return problems


def _expiry(model: dict, where: str) -> list[Problem]:
    authorization = model.get("authorization")
    if not isinstance(authorization, dict):
        return [Problem("CAPTURE_EXPIRY_AS_RELEASE", where,
                        "the model says nothing about what an authorisation holds or how it is "
                        "released", "NN-12")]
    problems = list(expect(authorization.get("expiry_is_release_path") is False,
                           "CAPTURE_EXPIRY_AS_RELEASE", where,
                           "expiry is the fallback, never the release path: making it policy "
                           "means the payer's funds are freed by a timeout we do not control",
                           "NN-12"))
    problems += expect(authorization.get("expiry_requires_exposure_alert") is True,
                       "CAPTURE_EXPIRY_AS_RELEASE", where,
                       "an authorisation that reaches expiry is an operational failure and must "
                       "raise exposure, not pass silently", "NN-12")
    return problems


def _void(operations: dict, where: str) -> list[Problem]:
    void = operations.get("void")
    if not isinstance(void, dict):
        return []
    preconditions = set(void.get("preconditions") or [])
    problems = list(expect("captured_amount_is_zero" in preconditions,
                           "CAPTURE_VOID_AFTER_CAPTURE", where,
                           "void must be refused once anything is captured; otherwise the same "
                           "money is released at the provider and refunded from the ledger",
                           "NN-05"))
    problems += expect(void.get("releases") == "full", "CAPTURE_VOID_AFTER_CAPTURE", where,
                       "void releases the whole authorisation by definition", "NN-05",
                       releases=void.get("releases"))
    return problems


def _terminality(operations: dict, where: str) -> list[Problem]:
    problems: list[Problem] = []
    for name in ("void", "close"):
        entry = operations.get(name)
        if not isinstance(entry, dict):
            continue
        problems += expect(entry.get("terminal") is True, "CAPTURE_AFTER_TERMINAL", where,
                           f"{name} must be terminal; an authorisation that can be captured "
                           f"after it was released is a second payment", "NN-05")
    capture = operations.get("capture")
    if isinstance(capture, dict):
        problems += expect(capture.get("terminal") is False, "CAPTURE_AFTER_TERMINAL", where,
                           "capture is not terminal on its own: a partial capture leaves the "
                           "authorisation active and awaiting close", "NN-12")
    return problems


def _query(operations: dict, where: str) -> list[Problem]:
    query = operations.get("query")
    if not isinstance(query, dict):
        return []
    problems = list(expect(query.get("settles_success") is False, "CAPTURE_UNKNOWN_IS_SUCCESS",
                           where, "a query reports what the provider says; it never turns an "
                           "unknown into a success", "NN-01"))
    problems += expect(query.get("mutates_money_state") is False, "CAPTURE_UNKNOWN_IS_SUCCESS",
                       where, "a query must not move money state", "NN-01")
    return problems


def _idempotency_and_audit(operations: dict, where: str) -> list[Problem]:
    problems: list[Problem] = []
    for name in MONEY_OPERATIONS:
        entry = operations.get(name)
        if not isinstance(entry, dict):
            continue
        problems += expect(entry.get("requires_idempotency_key") is True,
                           "CAPTURE_NOT_IDEMPOTENT", where,
                           f"{name} moves money state and must carry an idempotency key; a "
                           f"retried capture without one is a second capture", "NN-06")
        problems += expect(bool(str(entry.get("audit_event") or "").strip()),
                           "CAPTURE_UNAUDITED", where,
                           f"{name} must emit an audit event; an unrecorded release is "
                           f"indistinguishable from a release that never happened", "NN-07")
    return problems


def _authority(operations: dict, where: str) -> list[Problem]:
    problems: list[Problem] = []
    for name in MONEY_OPERATIONS:
        entry = operations.get(name)
        if not isinstance(entry, dict):
            continue
        authority = set(entry.get("authority") or [])
        problems += expect(bool(authority) and authority <= AUTHORITATIVE_SOURCES,
                          "CAPTURE_AUTHORITY_WEAK", where,
                          f"{name} may only be settled by {sorted(AUTHORITATIVE_SOURCES)}; a "
                          f"client return page is a request from the payer's own machine",
                          "NN-01", declared=sorted(authority))
    return problems


def _capture_modes(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    modes = {entry["id"]: entry for entry in (model.get("capture_modes") or [])
             if isinstance(entry, dict) and isinstance(entry.get("id"), str)}
    problems: list[Problem] = []
    for name in PARTIAL_MODES:
        entry = modes.get(name)
        if not isinstance(entry, dict):
            problems.append(Problem("CAPTURE_CAPABILITY_UNCHECKED", where,
                                    f"capture mode '{name}' is not declared", "NN-12"))
            continue
        problems += expect(bool(entry.get("requires_capability")),
                           "CAPTURE_CAPABILITY_UNCHECKED", where,
                           f"'{name}' must be gated on a declared provider capability; sending a "
                           f"partial capture to a provider that does not support one is how a "
                           f"full capture happens by accident", "NN-12")
        problems += expect(entry.get("requires_close_for_remainder") is True,
                           "CAPTURE_NO_EXPLICIT_CLOSE", where,
                           f"'{name}' leaves a remainder and must require close", "NN-12")

    authorization = model.get("authorization") if isinstance(model.get("authorization"), dict) else {}
    source = str(authorization.get("validity_source") or "")
    field = str(authorization.get("validity_field") or "")
    problems += expect(source == str(CAPS), "CAPTURE_CAPABILITY_SOURCE", where,
                       f"authorisation validity must come from {CAPS}; a second copy of the "
                       f"window is how one provider ends up with two", "NN-12", declared=source)
    budget.check(str(CAPS))
    declared_fields: set[str] = set()
    try:
        caps = load_json(root / CAPS, budget)
        for entry in caps.get("capabilities") or []:
            if isinstance(entry, dict):
                declared_fields |= set(entry)
    except BudgetExceeded:
        raise
    except Exception:
        declared_fields = set()
    if declared_fields:
        required = {field} | {str(modes[m].get("requires_capability")) for m in PARTIAL_MODES
                              if isinstance(modes.get(m), dict)
                              and modes[m].get("requires_capability")}
        unknown = sorted(name for name in required if name and name not in declared_fields)
        problems += expect(not unknown, "CAPTURE_CAPABILITY_SOURCE", where,
                           f"{unknown} are not declared by the B27 capability matrix", "NN-12",
                           unknown=unknown)
    return problems


def _invariants(model: dict, where: str) -> list[Problem]:
    invariants = [entry for entry in (model.get("invariants") or []) if isinstance(entry, dict)]
    statements = " ".join(str(entry.get("statement") or "") for entry in invariants)
    problems = list(expect("累计捕获" in statements or "cumulative" in statements.lower(),
                           "CAPTURE_EXCEEDS_AUTHORIZED", where,
                           "no invariant states the cumulative capture ceiling; checking each "
                           "capture alone lets multi-capture walk past the authorised amount",
                           "NN-05"))
    ceiling = next((entry for entry in invariants
                    if "CAPTURE_EXCEEDS_AUTHORIZED" in (entry.get("enforced_by") or [])), None)
    problems += expect(ceiling is not None, "CAPTURE_EXCEEDS_AUTHORIZED", where,
                       "the cumulative ceiling is stated but no rule enforces it", "NN-05")
    if ceiling is not None:
        problems += expect(str(ceiling.get("unit")) == "integer_minor",
                           "CAPTURE_EXCEEDS_AUTHORIZED", where,
                           "the ceiling is an integer minor-unit invariant, not an approximation",
                           "NN-05")
    for entry in invariants:
        unknown = sorted(code for code in (entry.get("enforced_by") or [])
                         if code not in EMITTED_CODES)
        problems += expect(not unknown, "CAPTURE_INVARIANT_UNENFORCED", where,
                           f"invariant {entry.get('id')} delegates to {unknown}, which this "
                           f"validator never emits", "NN-12", invariant=entry.get("id"))
    return problems


def _terminal_outcomes(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    outcomes = model.get("terminal_outcomes")
    if not isinstance(outcomes, dict):
        return [Problem("CAPTURE_TERMINAL_OUTCOME", where,
                        "the model does not say what state each ending leaves behind", "NN-12")]
    required = ("captured_in_full", "closed_after_partial", "voided_before_capture",
                "expired_without_action")
    missing = [key for key in required if not str(outcomes.get(key) or "").strip()]
    problems = list(expect(not missing, "CAPTURE_TERMINAL_OUTCOME", where,
                           f"no state declared for {missing}", "NN-12", missing=missing))
    budget.check(str(STATES))
    known: set[str] = set()
    try:
        machines = load_json(root / STATES, budget)
        for machine in machines.get("machines") or []:
            if isinstance(machine, dict) and "authorized" in (machine.get("states") or []):
                known = {str(state) for state in machine.get("states") or []}
                break
    except BudgetExceeded:
        raise
    except Exception:
        known = set()
    if known:
        named = {str(outcomes.get(key)) for key in required if outcomes.get(key)}
        unknown = sorted(state for state in named if state not in known)
        problems += expect(not unknown, "CAPTURE_TERMINAL_OUTCOME", where,
                           f"{unknown} are not states of the B10 payment intent machine; a "
                           f"lifecycle that ends somewhere the state machine cannot represent "
                           f"ends nowhere", "NN-12", unknown=unknown)
    return problems


def _conformance(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    conformance = model.get("conformance")
    if not isinstance(conformance, dict):
        return [Problem("CAPTURE_JAVA_UNBOUND", where,
                        "the model declares no conformance binding, so no implementation is "
                        "obliged to agree with it", "NN-12")]
    problems: list[Problem] = []
    java_rel = str(conformance.get("java_test") or "")
    java_path = root / java_rel if java_rel else None
    problems += expect(bool(java_rel) and java_path is not None and java_path.is_file(),
                       "CAPTURE_JAVA_UNBOUND", where,
                       f"the declared Java conformance test {java_rel!r} does not exist; vectors "
                       f"nothing replays are documentation", "NN-12")
    if java_path is not None and java_path.is_file():
        budget.check(java_rel)
        try:
            source = read_text(java_path, budget)
        except BudgetExceeded:
            raise
        except Exception:
            source = ""
        problems += expect(str(VECTORS) in source, "CAPTURE_JAVA_UNBOUND", where,
                           f"{java_rel} does not read {VECTORS}; a conformance test that does "
                           f"not load the vectors is testing something else", "NN-12")

    vectors_rel = str(conformance.get("vectors") or "")
    problems += expect(vectors_rel == str(VECTORS), "CAPTURE_VECTORS_DRIFT", where,
                       f"the model must bind to {VECTORS}", "NN-12", declared=vectors_rel)
    budget.check(str(VECTORS))
    try:
        from .capturegen import vectors_json
        expected = vectors_json(root, budget)
        current = read_text(root / VECTORS, budget) if (root / VECTORS).is_file() else None
    except BudgetExceeded:
        raise
    except Exception as exc:
        return problems + [Problem("CAPTURE_VECTORS_DRIFT", str(VECTORS),
                                   f"cannot rebuild the conformance vectors: {exc}", "NN-12")]
    problems += expect(current == expected, "CAPTURE_VECTORS_DRIFT", str(VECTORS),
                       "the committed vectors are not what the model and the reference produce "
                       "right now", "NN-12")
    return problems
