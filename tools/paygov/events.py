"""B12 — event catalogue, outbox and inbox.

The batch's goal is an exactly-once *business effect* on top of an at-least-once
transport. That is not a middleware feature; it is a set of design decisions that
have to be checked, because each of them is quietly reversible:

* publishing before committing emits events for state changes that never
  happened -- so the outbox write must be in the same transaction as the state
  change, and this file refuses a catalogue that says otherwise;
* deduplicating on an event id is only half of it: the same id arriving with a
  *different* payload is a contradiction, not a replay, and must fail loudly;
* ordering tolerance based on ``occurred_at`` breaks the first time a producer's
  clock drifts backwards, so a monotonic revision is mandatory;
* an event that carries a PAN puts card data into every consumer, every log and
  every backup at once (NN-02, NN-14).

The catalogue is data (``governance/event-catalog.json``); this file is the gate.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

CATALOG = Path("governance/event-catalog.json")
STATES = Path("governance/state-machines.json")
MODULES = Path("governance/module-registry.json")
DOMAIN = Path("governance/domain-model.json")

EVENT_NAME = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
FIELD_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
TABLE = re.compile(r"^[a-z][a-z0-9_]*$")
MONEY_FIELD = re.compile(r"(amount|price|fee|balance|total)")


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("event-catalog", "B12")

def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    where = str(CATALOG)
    budget.check(where)
    try:
        catalog = load_json(root / CATALOG)
    except Exception as exc:
        return [Problem("EVENT_UNREADABLE", where,
                        f"cannot read the event catalogue: {exc}", "NN-12")]

    problems += expect(SEMVER.match(str(catalog.get("schema_version", ""))), "EVENT_VERSION_FIELD",
                       where, "schema_version must be semver", "NN-12")

    events = catalog.get("events")
    consumers = catalog.get("consumers")
    if not isinstance(events, list) or not events:
        return problems + [Problem("EVENT_SHAPE", where, "'events' must be a non-empty list",
                                   "NN-12")]
    if not isinstance(consumers, list) or not consumers:
        return problems + [Problem("EVENT_SHAPE", where, "'consumers' must be a non-empty list",
                                   "NN-12")]

    problems += _delivery(catalog, where)
    problems += _envelope(catalog, where)
    problems += _outbox(catalog, where)
    problems += _inbox(catalog, where)
    problems += _ordering(catalog, where)
    problems += _versioning(catalog, where)

    modules = _modules(root)
    transitions = _transitions(root)
    aggregates = _aggregates(root)
    forbidden = {str(f).lower() for f in catalog.get("forbidden_payload_fields") or []}
    problems += expect({"pan", "cvv"} <= forbidden, "EVENT_FORBIDDEN_LIST", where,
                       "the forbidden payload list must at least name 'pan' and 'cvv'; an empty "
                       "denylist is a denylist in name only", "NN-02")
    classifications = set(catalog.get("classifications") or [])
    problems += expect(classifications, "EVENT_SHAPE", where,
                       "'classifications' must not be empty", "NN-14")

    names: set = set()
    keys: set = set()
    for index, event in enumerate(events):
        problems += _event(event, f"{where}#{index}", modules, transitions, aggregates,
                           forbidden, classifications, catalog, names, keys, budget)

    subscribed: set = set()
    problems += _consumers(consumers, where, modules, names, catalog, subscribed, budget)

    for name in sorted(names):
        problems += expect(name in subscribed, "EVENT_UNCONSUMED", where,
                           f"event '{name}' is published but nothing subscribes to it; an event "
                           f"with no consumer is a write nobody reads", "NN-12")

    problems += _transition_coverage(root, events, where)
    problems += _generated(root, budget)
    return problems


def _delivery(catalog: dict, where: str) -> list[Problem]:
    delivery = catalog.get("delivery") or {}
    problems = list(expect(delivery.get("transport_guarantee") == "at_least_once",
                           "EVENT_DELIVERY", where,
                           "the transport guarantee must be stated as at_least_once; a design "
                           "that assumes the network delivers exactly once is a design that "
                           "loses money the first time it is wrong", "NN-04"))
    problems += expect(delivery.get("business_guarantee") == "effectively_once",
                       "EVENT_DELIVERY", where,
                       "the business guarantee must be effectively_once, achieved by inbox "
                       "deduplication plus idempotent consumers", "NN-04")
    problems += expect(len(str(delivery.get("policy") or "")) >= 20, "EVENT_DELIVERY", where,
                       "the delivery policy must be written down, not implied", "NN-12")
    return problems


def _envelope(catalog: dict, where: str) -> list[Problem]:
    envelope = catalog.get("envelope") or {}
    required = set(envelope.get("required_fields") or [])
    problems: list[Problem] = []
    for field in ("event_id", "event_name", "event_version", "tenant_id", "project_id",
                  "aggregate_type", "aggregate_id", "revision", "occurred_at", "recorded_at",
                  "trace_id", "payload"):
        problems += expect(field in required, "EVENT_ENVELOPE", where,
                           f"the envelope must carry '{field}'", "NN-12")
    problems += expect(envelope.get("revision_field") == "revision", "EVENT_ENVELOPE", where,
                       "the ordering sequence must be a monotonic revision field", "NN-12")
    problems += expect("tenant_id" in required, "EVENT_TENANT", where,
                       "every event must carry tenant_id; an event without a tenant cannot be "
                       "authorised, routed or deleted on request", "NN-09")
    problems += expect({"tenant_id", "project_id", "aggregate_type", "aggregate_id"}
                       <= required, "EVENT_SCOPE", where,
                       "every envelope must bind tenant, project and aggregate identity", "NN-09")
    return problems


def _outbox(catalog: dict, where: str) -> list[Problem]:
    outbox = catalog.get("outbox") or {}
    problems = list(expect(outbox.get("same_transaction_as_state_change") is True,
                           "OUTBOX_NOT_TRANSACTIONAL", where,
                           "the outbox write must share the state change's transaction; "
                           "publishing first emits events for things that never happened, and "
                           "committing first only delays them", "NN-04"))
    problems += expect(TABLE.match(str(outbox.get("table") or "")), "OUTBOX_SHAPE", where,
                       "the outbox needs a snake_case table", "NN-12")
    unique = outbox.get("unique_key") or []
    problems += expect({"tenant_id", "aggregate_type", "aggregate_id", "revision"}
                       <= set(unique), "OUTBOX_UNIQUE_KEY", where,
                       "the outbox must be unique on tenant aggregate identity plus revision; without "
                       "it a retried producer writes the same event twice", "NN-04")
    dispatch = outbox.get("dispatch") or {}
    problems += expect(dispatch.get("mode") == "poll_then_publish", "OUTBOX_DISPATCH", where,
                       "dispatch must read committed rows and then publish", "NN-04")
    problems += expect(dispatch.get("backoff") == "exponential", "OUTBOX_DISPATCH", where,
                       "retries must back off exponentially; a fixed retry loop against a "
                       "struggling provider is a self-inflicted outage", "NN-04")
    problems += expect(int(dispatch.get("max_attempts") or 0) >= 5, "OUTBOX_DISPATCH", where,
                       "give up too early and a transient provider blip loses an event", "NN-04")
    problems += expect(bool(dispatch.get("dead_letter_table")), "OUTBOX_DEAD_LETTER", where,
                       "there must be a dead-letter destination; an event that can never be "
                       "delivered and is silently dropped is an unexplainable ledger difference "
                       "six months later", "NN-12")
    problems += expect(int(dispatch.get("max_delay_ms") or 0)
                       > int(dispatch.get("initial_delay_ms") or 0), "OUTBOX_DISPATCH", where,
                       "the backoff ceiling must exceed its floor", "NN-12")
    return problems


def _inbox(catalog: dict, where: str) -> list[Problem]:
    inbox = catalog.get("inbox") or {}
    problems = list(expect(TABLE.match(str(inbox.get("table") or "")), "INBOX_SHAPE", where,
                           "the inbox needs a snake_case table", "NN-12"))
    unique = set(inbox.get("unique_key") or [])
    problems += expect({"source", "source_event_id"} <= unique, "INBOX_UNIQUE_KEY", where,
                       "the inbox must be unique on (source, source_event_id); that uniqueness "
                       "*is* the exactly-once business effect", "NN-04")
    problems += expect(bool(inbox.get("payload_hash_field")), "INBOX_PAYLOAD_HASH", where,
                       "the inbox must record a payload hash; the same event id arriving with a "
                       "different body is a contradiction, not a replay, and silently keeping "
                       "the first one hides a provider bug", "NN-04")
    problems += expect(int(inbox.get("retention_hours") or 0) >= 168, "INBOX_RETENTION", where,
                       "the inbox must remember an event for at least as long as a provider may "
                       "resend it, otherwise deduplication expires before the duplicates do",
                       "NN-04")
    problems += expect(bool(inbox.get("conflict_error")), "INBOX_CONFLICT", where,
                       "a payload-hash conflict must map to a named error", "NN-12")
    return problems


def _ordering(catalog: dict, where: str) -> list[Problem]:
    ordering = catalog.get("ordering") or {}
    problems = list(expect(ordering.get("sequence_field") == "revision", "EVENT_ORDERING", where,
                           "out-of-order tolerance must be based on a monotonic revision, not on "
                           "a timestamp; clocks drift backwards and revisions do not", "NN-12"))
    tolerances = set(ordering.get("tolerances") or [])
    problems += expect(tolerances, "EVENT_ORDERING", where,
                       "the allowed out-of-order tolerances must be enumerated", "NN-12")
    problems += expect(int(ordering.get("revision_gap_limit") or 0) > 0, "EVENT_ORDERING", where,
                       "buffering must be bounded; an unbounded reorder buffer is an outage "
                       "waiting for one lost event", "NN-12")
    return problems


def _versioning(catalog: dict, where: str) -> list[Problem]:
    versioning = catalog.get("versioning") or {}
    problems = list(expect(int(versioning.get("parallel_days") or 0) >= 180,
                           "EVENT_VERSION_POLICY", where,
                           "two event versions must run in parallel for at least 180 days; "
                           "consumers are other teams and other companies", "NN-12"))
    problems += expect(len(str(versioning.get("policy") or "")) >= 20, "EVENT_VERSION_POLICY",
                       where, "the event versioning policy must be written down", "NN-12")
    return problems


def _modules(root: Path) -> dict:
    try:
        registry = load_json(root / MODULES)
    except Exception:
        return {}
    return {m["name"]: m for m in registry.get("modules", [])}


def _transitions(root: Path) -> dict:
    try:
        model = load_json(root / STATES)
    except Exception:
        return {}
    out: dict = {}
    for machine in model.get("machines", []):
        for tr in machine.get("transitions", []):
            out.setdefault((machine.get("name"), tr.get("event")), []).append(
                dict(tr, _entity=machine.get("entity"), _machine=machine.get("name")))
    return out


def _aggregates(root: Path) -> set:
    try:
        domain = load_json(root / DOMAIN)
    except Exception:
        return set()
    return {e["name"] for e in domain.get("entities", [])}


def _event(event: Any, scope: str, modules: dict, transitions: dict, aggregates: set,
           forbidden: set, classifications: set, catalog: dict, names: set, keys: set,
           budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    if not isinstance(event, dict):
        return [Problem("EVENT_SHAPE", scope, "each event must be an object", "NN-12")]
    budget.check(scope)

    name = event.get("name")
    problems += expect(isinstance(name, str) and EVENT_NAME.match(name or ""), "EVENT_NAME",
                       scope, f"event name '{name}' must be 'aggregate.past_tense'", "NN-12")
    version = event.get("version")
    key = (name, version)
    problems += expect(key not in keys, "EVENT_DUPLICATE", scope,
                       f"duplicate event '{name}' v{version}", "NN-12")
    keys.add(key)
    names.add(name)
    problems += expect(isinstance(version, int) and version >= 1, "EVENT_VERSION", scope,
                       "event version must be a positive integer", "NN-12")

    producer = event.get("producer")
    problems += expect(producer in modules, "EVENT_PRODUCER", scope,
                       f"producer '{producer}' is not a registered module", "NN-01")
    if producer in modules:
        problems += expect(modules[producer].get("layer") == "service", "EVENT_PRODUCER", scope,
                           f"'{producer}' is a {modules[producer].get('layer')}; only services "
                           f"own facts and may publish them", "NN-01")

    problems += expect(event.get("aggregate") in aggregates, "EVENT_AGGREGATE", scope,
                       f"aggregate '{event.get('aggregate')}' is not a domain entity", "NN-12")

    emitted = event.get("emitted_by")
    if emitted:
        matches = transitions.get((emitted.get("machine"), emitted.get("event"))) or []
        problems += expect(matches, "EVENT_TRANSITION_UNKNOWN", scope,
                           f"event claims to be emitted by '{emitted.get('event')}' on machine "
                           f"'{emitted.get('machine')}', which is not a declared transition",
                           "NN-12")
        for match in matches:
            # A transition on one aggregate may legitimately create another (a
            # reconciliation run produces reconciliation exceptions). What is not
            # legitimate is doing it by accident, so the mismatch has to be
            # declared and justified rather than silently allowed.
            if match["_entity"] != event.get("aggregate"):
                problems += expect(
                    len(str(event.get("cross_aggregate_reason") or "")) >= 8,
                    "EVENT_TRANSITION_AGGREGATE", scope,
                    f"the transition belongs to '{match['_entity']}' but the event claims "
                    f"aggregate '{event.get('aggregate')}'; a cross-aggregate emission must "
                    f"state why in 'cross_aggregate_reason'", "NN-12")
    else:
        problems.append(Problem("EVENT_TRANSITION_MISSING", scope,
                                "every event must name the state transition that produces it; an "
                                "event with no cause cannot be replayed or reconciled", "NN-12"))

    problems += expect(int(event.get("retention_days") or 0) >= 365, "EVENT_RETENTION", scope,
                       "payment facts must be retained for at least a year; reconciliation and "
                       "disputes both reach back further than a quarter", "NN-06")
    problems += expect(event.get("partition_key") == "tenant_id", "EVENT_TENANT", scope,
                       "events must be partitioned by tenant so one tenant's volume cannot "
                       "starve another's, and so deletion stays possible", "NN-09")

    fields = event.get("fields")
    if not isinstance(fields, list) or not fields:
        return problems + [Problem("EVENT_SHAPE", scope, "'fields' must be a non-empty list",
                                   "NN-12")]
    seen_fields: set = set()
    has_amount = False
    for field in fields:
        if not isinstance(field, dict):
            problems.append(Problem("EVENT_SHAPE", scope, "each field must be an object",
                                    "NN-12"))
            continue
        fname = field.get("name")
        problems += expect(isinstance(fname, str) and FIELD_NAME.match(fname or ""),
                           "EVENT_FIELD", scope, f"field '{fname}' must be snake_case", "NN-12")
        problems += expect(fname not in seen_fields, "EVENT_FIELD_DUPLICATE", scope,
                           f"duplicate field '{fname}'", "NN-12")
        seen_fields.add(fname)
        problems += expect(field.get("classification") in classifications,
                           "EVENT_CLASSIFICATION", scope,
                           f"field '{fname}' must declare a known data classification; an "
                           f"unclassified field cannot be redacted or retained correctly",
                           "NN-14")
        if str(fname).lower() in forbidden:
            problems.append(Problem("EVENT_FORBIDDEN_FIELD", scope,
                                    f"field '{fname}' is on the forbidden list; putting it in an "
                                    f"event copies it into every consumer, log and backup at "
                                    f"once", "NN-02"))
        if MONEY_FIELD.search(str(fname or "")):
            has_amount = True
            problems += expect(field.get("type") == "int64" and str(fname).endswith("_minor"),
                               "EVENT_MONEY_TYPE", scope,
                               f"monetary field '{fname}' must be an int64 named '*_minor'",
                               "NN-05")
    if has_amount:
        problems += expect("currency" in seen_fields, "EVENT_MONEY_CURRENCY", scope,
                           "an event carrying an amount must carry its currency; a bare number "
                           "is not money", "NN-05")

    ordering_key = event.get("ordering_key")
    problems += expect(ordering_key in seen_fields
                       or ordering_key in set((catalog.get("envelope") or {})
                                              .get("required_fields") or []),
                       "EVENT_ORDERING_KEY", scope,
                       f"ordering key '{ordering_key}' is neither an envelope field nor a payload "
                       f"field", "NN-12")

    subscribers = event.get("consumers")
    problems += expect(isinstance(subscribers, list) and subscribers, "EVENT_NO_CONSUMER", scope,
                       "an event must declare at least one consumer", "NN-12")
    for module in subscribers or []:
        problems += expect(module in modules, "EVENT_CONSUMER_MODULE", scope,
                           f"consumer '{module}' is not a registered module", "NN-01")
    return problems


def _consumers(consumers: list, where: str, modules: dict, names: set, catalog: dict,
               subscribed: set, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    tolerances = set((catalog.get("ordering") or {}).get("tolerances") or [])
    seen: set = set()
    for consumer in consumers:
        if not isinstance(consumer, dict):
            problems.append(Problem("EVENT_SHAPE", where, "each consumer must be an object",
                                    "NN-12"))
            continue
        module = consumer.get("module")
        scope = f"{where}#consumer:{module}"
        budget.check(scope)
        problems += expect(module in modules, "EVENT_CONSUMER_MODULE", scope,
                           f"consumer '{module}' is not a registered module", "NN-01")
        problems += expect(module not in seen, "EVENT_CONSUMER_DUPLICATE", scope,
                           f"duplicate consumer '{module}'", "NN-12")
        seen.add(module)
        problems += expect(consumer.get("order_tolerance") in tolerances,
                           "EVENT_ORDER_TOLERANCE", scope,
                           f"'{consumer.get('order_tolerance')}' is not a declared out-of-order "
                           f"tolerance; a consumer that has not said how it survives reordering "
                           f"has not thought about it", "NN-04")
        problems += expect(len(str(consumer.get("policy") or "")) >= 12, "EVENT_ORDER_TOLERANCE",
                           scope, "the consumer must describe how it applies events", "NN-04")
        subscriptions = consumer.get("subscribes") or []
        problems += expect(subscriptions, "EVENT_CONSUMER_EMPTY", scope,
                           "a consumer that subscribes to nothing should not be listed", "NN-12")
        for name in subscriptions:
            subscribed.add(name)
            problems += expect(name in names, "EVENT_SUBSCRIPTION_UNKNOWN", scope,
                               f"subscribes to '{name}', which is not in the catalogue", "NN-12")
    return problems


def _transition_coverage(root: Path, events: list, where: str) -> list[Problem]:
    """Every success transition must produce an event somebody can act on."""
    try:
        model = load_json(root / STATES)
    except Exception:
        return []
    emitted: dict = {}
    for event in events:
        # A malformed entry is already reported by _event; coverage must not crash on it.
        if not isinstance(event, dict):
            continue
        by = event.get("emitted_by") or {}
        emitted.setdefault(by.get("machine"), set()).add(by.get("event"))
    problems: list[Problem] = []
    for machine in model.get("machines", []):
        success = set(model.get("success_states", {}).get(machine.get("entity"), []))
        for tr in machine.get("transitions", []):
            if tr.get("to") in success:
                problems += expect(tr.get("event") in emitted.get(machine.get("name"), set()),
                                   "EVENT_SUCCESS_UNPUBLISHED", where,
                                   f"transition '{tr.get('event')}' on '{machine.get('name')}' "
                                   f"moves money into '{tr.get('to')}' but publishes no event; "
                                   f"the ledger and reconciliation would never hear about it",
                                   "NN-06")
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .eventgen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        if not path.is_file():
            problems.append(Problem("EVENT_GENERATED_MISSING", rel,
                                    "generated event artefact is missing; run "
                                    "scripts/render-events.py", "NN-12"))
            continue
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("EVENT_GENERATED", rel,
                                    f"the artefact cannot be derived from the catalogue: "
                                    f"{type(exc).__name__}: {exc}", "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("EVENT_GENERATED_DRIFT", rel,
                                    "the generated artefact differs from the catalogue; run "
                                    "scripts/render-events.py", "NN-12"))
    return problems
