"""B10 — executable reference interpreter for the payment state machines.

The model in ``governance/state-machines.json`` is the specification. This is
what makes it executable, so that "the transition table is correct" is a claim
something can actually be run against rather than a claim about a document.

Three behaviours are deliberately part of the interpreter rather than left to
each caller, because leaving them to callers is how they get forgotten:

* an event that is not allowed in the current state is *rejected*, not ignored;
* an actor not trusted for success cannot drive a transition into a success
  state, even if the transition table were edited to allow it (belt and braces
  with the gate in ``tools/paygov/states.py``);
* replaying an event whose idempotency token was already applied is a no-op that
  returns the same state, not a second state change.

Any production implementation (Java, from B11 on) must behave identically.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


class TransitionRejected(Exception):
    """Raised when an event may not be applied in the current state."""

    def __init__(self, reason: str, code: str) -> None:
        super().__init__(reason)
        self.code = code


@dataclass(frozen=True)
class Transition:
    source: str
    target: str
    event: str
    actor: str
    kind: str
    guard: str
    idempotency: str
    effects: tuple = ()


@dataclass
class Machine:
    name: str
    entity: str
    initial: str
    terminal: frozenset
    states: frozenset
    transitions: tuple
    success_states: frozenset
    trusted_actors: frozenset

    def transition_for(self, state: str, event: str) -> Transition:
        for tr in self.transitions:
            if tr.source == state and tr.event == event:
                return tr
        raise TransitionRejected(
            f"{self.name}: event '{event}' is not allowed in state '{state}'",
            "EVENT_NOT_ALLOWED")


@dataclass
class Instance:
    """One live object walking its machine, with a replay log."""

    machine: Machine
    state: str = ""
    applied: set = field(default_factory=set)
    history: list = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.state:
            self.state = self.machine.initial

    @property
    def is_terminal(self) -> bool:
        return self.state in self.machine.terminal

    def apply(self, event: str, actor: str, token: str) -> str:
        """Apply an event. Returns the resulting state.

        Replaying the same (event, token) pair is a no-op: payment providers
        retry webhooks by design, and a retry must never move money twice.
        """
        # The replay check comes first, before every other rule. A provider that
        # retries the very webhook which drove the object into its terminal state
        # must get the same answer, not a "that is terminal" error -- otherwise
        # retries turn into alerts and alerts turn into manual money movements.
        if (event, token) in self.applied:
            return self.state
        if self.is_terminal:
            raise TransitionRejected(
                f"{self.machine.name}: '{self.state}' is terminal; '{event}' cannot apply",
                "TERMINAL")
        tr = self.machine.transition_for(self.state, event)
        if tr.actor != actor:
            raise TransitionRejected(
                f"{self.machine.name}: '{event}' is driven by '{tr.actor}', not '{actor}'",
                "WRONG_ACTOR")
        if tr.target in self.machine.success_states and actor not in self.machine.trusted_actors:
            raise TransitionRejected(
                f"{self.machine.name}: '{actor}' may not assert success state '{tr.target}'",
                "UNTRUSTED_SUCCESS")
        self.applied.add((event, token))
        self.history.append((self.state, tr.target, event, actor))
        self.state = tr.target
        return self.state


def load(path: Path) -> dict:
    """Load every machine in the model, keyed by name."""
    model = json.loads(Path(path).read_text(encoding="utf-8"))
    trusted = frozenset(a["id"] for a in model["actors"] if a.get("trusted_for_success"))
    machines = {}
    for spec in model["machines"]:
        machines[spec["name"]] = Machine(
            name=spec["name"],
            entity=spec["entity"],
            initial=spec["initial"],
            terminal=frozenset(spec["terminal"]),
            states=frozenset(spec["states"]),
            transitions=tuple(Transition(
                source=t["from"], target=t["to"], event=t["event"], actor=t["actor"],
                kind=t["kind"], guard=t["guard"], idempotency=t["idempotency"],
                effects=tuple(t.get("effects") or ())) for t in spec["transitions"]),
            success_states=frozenset(model["success_states"].get(spec["entity"], [])),
            trusted_actors=trusted,
        )
    return machines
