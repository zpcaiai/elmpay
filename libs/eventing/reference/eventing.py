"""B12 — executable reference for the outbox/inbox pattern.

The catalogue states the design. This runs it, so that "exactly-once business
effect on an at-least-once transport" is a property something can be tested for
rather than a sentence in a document.

Modelled faithfully enough to be worth testing:

* ``Store`` is a toy database with a transaction that either commits both the
  state change and the outbox row, or neither. That coupling is the whole point
  of an outbox, so it is the one thing the model refuses to fake.
* ``crash_before_commit`` reproduces the failure the pattern exists for: the
  process dies mid-write. Nothing is published, because nothing was committed.
* ``Dispatcher`` reads *committed* rows and publishes them, with bounded retries
  and a dead-letter destination. It may publish the same row twice -- that is
  what at-least-once means, and the inbox is what makes it survivable.
* ``Inbox`` deduplicates on ``(source, source_event_id)`` and stores a payload
  hash, so a redelivery is a no-op while the same id carrying a *different* body
  raises: that is a contradiction, not a replay.
* ``RevisionGuardedConsumer`` drops events whose revision it has already passed,
  which is how a consumer survives reordering without buffering.

Not modelled: durability, isolation levels, partitions. Those belong to B13 and
a real database.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field


class CommitFailed(Exception):
    """Injected fault: the process died before the transaction committed."""


class PayloadConflict(Exception):
    """The same event id arrived with a different body."""


def payload_hash(payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


@dataclass
class OutboxRow:
    aggregate_type: str
    aggregate_id: str
    revision: int
    event_name: str
    payload: dict
    attempts: int = 0
    published: bool = False
    dead_lettered: bool = False

    @property
    def event_id(self) -> str:
        return f"{self.aggregate_type}:{self.aggregate_id}:{self.revision}"


@dataclass
class Store:
    """A toy database: state and outbox share one transaction, or nothing happens."""

    state: dict = field(default_factory=dict)
    outbox: list = field(default_factory=list)
    dead_letters: list = field(default_factory=list)

    def transact(self, aggregate_type: str, aggregate_id: str, revision: int,
                 new_state: str, event_name: str, payload: dict, *,
                 crash_before_commit: bool = False) -> OutboxRow | None:
        key = (aggregate_type, aggregate_id)
        # Staged, not applied: a real transaction is invisible until it commits.
        staged_state = dict(self.state)
        staged_outbox = list(self.outbox)

        current = staged_state.get(key, {"revision": 0})
        if revision <= current["revision"]:
            raise ValueError(
                f"revision {revision} is not ahead of {current['revision']}; the unique key "
                f"(aggregate_id, revision) is what stops a retried producer writing twice")
        staged_state[key] = {"revision": revision, "state": new_state}
        row = OutboxRow(aggregate_type, aggregate_id, revision, event_name, payload)
        staged_outbox.append(row)

        if crash_before_commit:
            raise CommitFailed(
                "process died before COMMIT: neither the state change nor the event exists")

        self.state = staged_state
        self.outbox = staged_outbox
        return row

    def unpublished(self) -> list:
        return [r for r in self.outbox if not r.published and not r.dead_lettered]


@dataclass
class Broker:
    """At-least-once transport: it may deliver twice, and it may deliver late."""

    delivered: list = field(default_factory=list)
    fail_next: int = 0

    def publish(self, row: OutboxRow) -> None:
        if self.fail_next > 0:
            self.fail_next -= 1
            raise ConnectionError("broker unavailable")
        self.delivered.append(row)


@dataclass
class Dispatcher:
    store: Store
    broker: Broker
    max_attempts: int = 12

    def run_once(self) -> dict:
        published, dead = 0, 0
        for row in self.store.unpublished():
            try:
                self.broker.publish(row)
                row.published = True
                published += 1
            except ConnectionError:
                row.attempts += 1
                if row.attempts >= self.max_attempts:
                    row.dead_lettered = True
                    self.store.dead_letters.append(row)
                    dead += 1
        return {"published": published, "dead_lettered": dead}


@dataclass
class Inbox:
    """Deduplication on (source, source_event_id) is the exactly-once effect."""

    seen: dict = field(default_factory=dict)

    def accept(self, source: str, source_event_id: str, payload: dict) -> bool:
        """Return True if this is the first time; False if it is a redelivery."""
        key = (source, source_event_id)
        digest = payload_hash(payload)
        if key in self.seen:
            if self.seen[key] != digest:
                raise PayloadConflict(
                    f"event '{source_event_id}' from '{source}' was seen with a different body; "
                    f"that is a contradiction, not a replay")
            return False
        self.seen[key] = digest
        return True


@dataclass
class RevisionGuardedConsumer:
    """Applies events monotonically; reordering costs a counter, not correctness."""

    inbox: Inbox = field(default_factory=Inbox)
    applied: dict = field(default_factory=dict)
    effects: list = field(default_factory=list)
    duplicates: int = 0
    stale: int = 0

    def handle(self, source: str, row: OutboxRow) -> str:
        if not self.inbox.accept(source, row.event_id, row.payload):
            self.duplicates += 1
            return "duplicate"
        key = (row.aggregate_type, row.aggregate_id)
        if row.revision <= self.applied.get(key, 0):
            self.stale += 1
            return "stale"
        self.applied[key] = row.revision
        self.effects.append((row.event_name, row.aggregate_id, row.revision, row.payload))
        return "applied"
