"""B10 — payment state machines and business invariants.

B08 declared *which* states exist. This module governs *how* they may change.
The rules here exist because of how payment systems actually fail:

- a success state written by anything other than a verified provider event or a
  server-side query is how a forged browser redirect becomes free money (NN-03);
- a transition without an idempotency key is how one retried webhook becomes two
  refunds (NN-04);
- a backwards edge that is not declared compensating is how "we just set it back"
  quietly becomes an unauditable money movement;
- a compensating edge with no effects is a status change pretending to reverse money;
- an unreachable state is dead law, and a non-terminal dead end is a payment that
  can never be finished.

The model is data (``governance/state-machines.json``); this file is the gate.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

MODEL = Path("governance/state-machines.json")
DOMAIN = Path("governance/domain-model.json")

EVENT = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
MACHINE_NAME = re.compile(r"^[a-z][a-z0-9-]*$")
IDEMPOTENCY = re.compile(r"^[a-z][a-z0-9_]*(\+[a-z][a-z0-9_]*)*$")


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("state-machines", "B10")

def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    where = str(MODEL)
    budget.check(where)
    try:
        model = load_json(root / MODEL)
    except Exception as exc:
        return [Problem("STATE_UNREADABLE", where, f"cannot read the state model: {exc}", "NN-12")]

    problems += expect(SEMVER.match(str(model.get("schema_version", ""))), "STATE_VERSION",
                       where, "schema_version must be semver", "NN-12")

    machines = model.get("machines")
    problems += expect(isinstance(machines, list) and machines, "STATE_SHAPE", where,
                       "'machines' must be a non-empty list", "NN-12")
    if not isinstance(machines, list) or not machines:
        return problems

    actors = model.get("actors")
    if not isinstance(actors, list) or not actors:
        problems.append(Problem("STATE_SHAPE", where, "'actors' must be a non-empty list", "NN-12"))
        return problems
    actor_ids = {a.get("id") for a in actors}
    trusted = {a.get("id") for a in actors if a.get("trusted_for_success") is True}
    problems += expect(trusted, "STATE_SHAPE", where,
                       "at least one actor must be trusted to write a success state, otherwise "
                       "no payment could ever succeed", "NN-12")

    kinds = set(model.get("transition_kinds") or [])
    problems += expect({"forward", "compensating"} <= kinds, "STATE_SHAPE", where,
                       "transition_kinds must include 'forward' and 'compensating'", "NN-12")

    success_states = model.get("success_states") or {}
    problems += expect(isinstance(success_states, dict) and success_states, "STATE_SHAPE", where,
                       "'success_states' must name, per entity, the states that mean money moved",
                       "NN-03")

    try:
        domain = load_json(root / DOMAIN)
    except Exception as exc:
        return problems + [Problem("STATE_UNREADABLE", str(DOMAIN),
                                   f"cannot read the domain model: {exc}", "NN-12")]
    domain_states = {e["name"]: list(e.get("states") or [])
                     for e in domain.get("entities", []) if e.get("states")}

    seen_entities: set[str] = set()
    seen_names: set[str] = set()
    used_actors: set[str] = set()

    for machine in machines:
        problems += _machine(machine, where, domain_states, actor_ids, trusted, kinds,
                             success_states, seen_entities, seen_names, used_actors, budget)

    for entity in sorted(domain_states):
        problems += expect(entity in seen_entities, "STATE_MACHINE_COVERAGE", where,
                           f"'{entity}' declares states in the domain model but has no state "
                           f"machine; states without transitions are decoration", "NN-12")

    for actor in sorted(a for a in actor_ids if a):
        problems += expect(actor in used_actors, "STATE_ACTOR_UNUSED", where,
                           f"actor '{actor}' is declared but drives no transition", "NN-12")

    problems += _document(root, budget)
    return problems


def _document(root: Path, budget: Budget) -> list[Problem]:
    """The review diagram must be a pure function of the model."""
    rel = "docs/domain/STATE_MACHINES.md"
    path = root / rel
    if not path.is_file():
        return [Problem("STATE_DOC_MISSING", rel,
                        "the generated state-machine document is missing; run "
                        "scripts/render-states.py", "NN-12")]
    budget.check(rel)
    try:
        from .stategen import states_markdown
        expected = states_markdown(root, budget)
    except BudgetExceeded:
        raise
    except Exception as exc:
        return [Problem("STATE_DOC", rel,
                        f"the state document cannot be derived from the model: "
                        f"{type(exc).__name__}: {exc}", "NN-12")]
    if path.read_text(encoding="utf-8") != expected:
        return [Problem("STATE_DOC_DRIFT", rel,
                        "the generated state-machine document differs from the model; a diagram "
                        "that disagrees with the rules is worse than no diagram", "NN-12")]
    return []


def _machine(machine: Any, where: str, domain_states: dict, actor_ids: set, trusted: set,
             kinds: set, success_states: dict, seen_entities: set, seen_names: set,
             used_actors: set, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    if not isinstance(machine, dict):
        return [Problem("STATE_SHAPE", where, "each machine must be an object", "NN-12")]

    name = machine.get("name")
    scope = f"{where}#{name}"
    budget.check(scope)
    problems += expect(isinstance(name, str) and MACHINE_NAME.match(name or ""), "STATE_NAME",
                       scope, "machine name must be kebab-case", "NN-12")
    problems += expect(name not in seen_names, "STATE_DUPLICATE_MACHINE", scope,
                       f"duplicate machine name '{name}'", "NN-12")
    seen_names.add(name)

    entity = machine.get("entity")
    problems += expect(entity in domain_states, "STATE_ENTITY", scope,
                       f"'{entity}' is not an entity with states in the domain model", "NN-12")
    seen_entities.add(entity)

    states = machine.get("states")
    if not isinstance(states, list) or not states:
        return problems + [Problem("STATE_SHAPE", scope, "'states' must be a non-empty list",
                                   "NN-12")]
    if entity in domain_states:
        problems += expect(set(states) == set(domain_states[entity]), "STATE_SET", scope,
                           f"the machine's states {sorted(set(states))} do not match the domain "
                           f"model's {sorted(set(domain_states[entity]))}; two sources of truth "
                           f"for the same lifecycle is how they drift apart", "NN-12")

    notes = str(machine.get("notes") or "")
    problems += expect(len(notes.strip()) >= 20, "STATE_NOTES", scope,
                       "each machine must record why its shape is the way it is; an undocumented "
                       "lifecycle gets 'fixed' by the next person", "NN-12")

    initial = machine.get("initial")
    problems += expect(initial in states, "STATE_INITIAL", scope,
                       f"initial state '{initial}' is not in the state set", "NN-12")

    terminal = machine.get("terminal")
    if not isinstance(terminal, list) or not terminal:
        problems.append(Problem("STATE_TERMINAL", scope,
                                "'terminal' must list at least one terminal state; a lifecycle "
                                "that never ends cannot be reconciled", "NN-12"))
        terminal = []
    for state in terminal:
        problems += expect(state in states, "STATE_TERMINAL", scope,
                           f"terminal state '{state}' is not in the state set", "NN-12")

    transitions = machine.get("transitions")
    if not isinstance(transitions, list) or not transitions:
        return problems + [Problem("STATE_SHAPE", scope,
                                   "'transitions' must be a non-empty list", "NN-12")]

    outgoing: dict[str, list] = {s: [] for s in states}
    pairs: set = set()
    forward: dict[str, set] = {s: set() for s in states}

    entity_success = set(success_states.get(entity, []))
    for index, tr in enumerate(transitions):
        problems += _transition(tr, f"{scope}[{index}]", states, actor_ids, trusted, kinds,
                                entity_success, pairs, outgoing, forward, used_actors)

    reachable = _reach(initial, forward) if initial in states else set()
    for state in states:
        if state == initial:
            continue
        problems += expect(state in reachable, "STATE_UNREACHABLE", scope,
                           f"state '{state}' cannot be reached from '{initial}'; an unreachable "
                           f"state is dead law", "NN-12")
    for state in states:
        if state in terminal:
            problems += expect(not outgoing[state], "STATE_TERMINAL_EXIT", scope,
                               f"terminal state '{state}' has outgoing transitions "
                               f"{sorted(t['to'] for t in outgoing[state])}; it is not terminal",
                               "NN-12")
        else:
            problems += expect(outgoing[state], "STATE_DEAD_END", scope,
                               f"non-terminal state '{state}' has no outgoing transition; a "
                               f"payment stuck there can never be finished or reconciled", "NN-12")

    # Backwards edges must be declared compensating. An edge is backwards when its
    # target can reach its source using forward edges only -- i.e. it undoes progress.
    forward_only = {s: set() for s in states}
    for state, outs in outgoing.items():
        for tr in outs:
            if tr.get("kind") == "forward" and tr.get("to") in forward_only:
                forward_only[state].add(tr["to"])
    for state, outs in outgoing.items():
        for tr in outs:
            target = tr.get("to")
            if target not in states or target == state:
                continue
            backwards = state in _reach(target, forward_only)
            if backwards and tr.get("kind") != "compensating":
                problems.append(Problem(
                    "STATE_UNDECLARED_COMPENSATION", scope,
                    f"'{state}' -> '{target}' walks progress backwards but is declared "
                    f"'{tr.get('kind')}'; undoing a state without saying so hides a money "
                    f"movement from audit", "NN-06"))
            if tr.get("kind") == "compensating" and not tr.get("effects"):
                problems.append(Problem(
                    "STATE_COMPENSATION_WITHOUT_EFFECT", scope,
                    f"'{state}' -> '{target}' is declared compensating but lists no effects; "
                    f"compensation that does nothing is a status change wearing a costume, and "
                    f"it leaves the reversal invisible to the ledger", "NN-06"))
    return problems


def _transition(tr: Any, scope: str, states: list, actor_ids: set, trusted: set, kinds: set,
                entity_success: set, pairs: set, outgoing: dict, forward: dict,
                used_actors: set) -> list[Problem]:
    problems: list[Problem] = []
    if not isinstance(tr, dict):
        return [Problem("STATE_SHAPE", scope, "each transition must be an object", "NN-12")]

    frm, to = tr.get("from"), tr.get("to")
    ok_from = frm in states
    ok_to = to in states
    problems += expect(ok_from, "STATE_TRANSITION_STATE", scope,
                       f"unknown source state '{frm}'", "NN-12")
    problems += expect(ok_to, "STATE_TRANSITION_STATE", scope,
                       f"unknown target state '{to}'", "NN-12")
    problems += expect(frm != to, "STATE_SELF_LOOP", scope,
                       f"'{frm}' -> '{to}' is a self loop; a state change that changes nothing "
                       f"cannot be audited or made idempotent", "NN-12")

    event = tr.get("event")
    problems += expect(isinstance(event, str) and EVENT.match(event or ""), "STATE_EVENT", scope,
                       f"event '{event}' must be dotted lowercase, e.g. 'provider.authorized'",
                       "NN-12")

    actor = tr.get("actor")
    problems += expect(actor in actor_ids, "STATE_ACTOR", scope,
                       f"actor '{actor}' is not declared", "NN-12")
    used_actors.add(actor)

    problems += expect(tr.get("kind") in kinds, "STATE_KIND", scope,
                       f"kind '{tr.get('kind')}' is not a declared transition kind", "NN-12")

    guard = str(tr.get("guard") or "")
    problems += expect(len(guard.strip()) >= 6, "STATE_GUARD", scope,
                       "every transition must state the condition under which it is allowed; "
                       "an unguarded transition is an assertion that anything goes", "NN-12")

    key = tr.get("idempotency")
    problems += expect(isinstance(key, str) and IDEMPOTENCY.match(key or ""), "STATE_IDEMPOTENCY",
                       scope,
                       f"transition must declare an idempotency key (got {key!r}); a replayed "
                       f"event without one is a duplicate capture or a duplicate refund", "NN-04")

    if ok_to and to in entity_success:
        problems += expect(actor in trusted, "STATE_UNTRUSTED_SUCCESS", scope,
                           f"'{to}' means money moved, but it is written by actor '{actor}', "
                           f"which is not trusted for success; only a verified provider event or "
                           f"a server-side query may assert success", "NN-03")

    if ok_from and ok_to:
        pair = (frm, event)
        problems += expect(pair not in pairs, "STATE_NONDETERMINISTIC", scope,
                           f"'{frm}' already has a transition for event '{event}'; the same event "
                           f"in the same state must have exactly one outcome", "NN-12")
        pairs.add(pair)
        outgoing[frm].append(tr)
        if tr.get("kind") == "forward":
            forward[frm].add(to)
        else:
            forward[frm].add(to)
    return problems


def _reach(start: str, edges: dict) -> set:
    seen: set = set()
    stack = [start]
    while stack:
        node = stack.pop()
        for nxt in edges.get(node, ()):  # noqa: SIM118
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen
