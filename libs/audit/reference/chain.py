"""B23 — an executable tamper-evident audit chain.

Three properties, and the third one is the interesting one:

1. **Edits, deletions and reorderings are detectable.** Each record hashes its
   own canonical bytes together with its sequence number and the previous
   record's hash, so any change downstream of it stops matching.

2. **Tail truncation is not detectable by the chain alone.** Delete the last N
   records and what remains verifies perfectly — this is a property of hash
   chains, not a bug in this one. :class:`Anchor` closes it: a signed checkpoint
   of the head, held by someone else, turns "the chain ends here" into a
   checkable claim. Everything after the most recent anchor stays deniable, and
   :meth:`Ledger.deniable_window` reports exactly how much that is rather than
   pretending otherwise.

3. **A payload can be erased without breaking the proof.** The chain binds the
   *hash* of the payload, so destroying the payload's key leaves the record, its
   position and its integrity intact while the content becomes unreadable. That
   is the only arrangement in which "this log is immutable" and "erase my
   personal data" are both true.

No real signatures: an :class:`Anchor` carries a MAC over the head hash using a
stand-in key. What is proven here is the protocol, not the cryptography.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from pathlib import Path

OK = "OK"
MODIFIED = "MODIFIED"
SEQUENCE_BROKEN = "SEQUENCE_BROKEN"
LINK_BROKEN = "LINK_BROKEN"
TRUNCATED = "TRUNCATED"
ANCHOR_INVALID = "ANCHOR_INVALID"
FORBIDDEN_FIELD = "FORBIDDEN_FIELD"
CLOCK_REVERSED = "CLOCK_REVERSED"

GENESIS = "0" * 64

# The forbidden-field list is not written here. It is derived from
# contracts/payment-method/sensitive-fields.json, which is generated from
# governance/payment-method.json (B35).
#
# It used to be a four-name tuple in this file, and one of those names was
# "card_pan" while the Java guard was watching "pan". Neither list was wrong;
# they were simply different, and nothing compared them — so the same field
# passed one layer under the spelling the other layer was guarding.
_CONTRACT = (Path(__file__).resolve().parents[3]
             / "contracts/payment-method/sensitive-fields.json")


def _catalogue() -> tuple[frozenset[str], dict]:
    data = json.loads(_CONTRACT.read_text(encoding="utf-8"))
    return frozenset(data["normalized_names"]), data["normalization"]


NEVER_LOGGED, _NORMALIZATION = _catalogue()


def normalize_field(name: str) -> str:
    """One field name is one name, whatever the caller spelled it as."""
    text = str(name)
    if _NORMALIZATION.get("lowercase", True):
        text = text.lower()
    for character in _NORMALIZATION.get("strip_characters") or []:
        text = text.replace(character, "")
    return text


def field_is_forbidden(name: str) -> bool:
    return normalize_field(name) in NEVER_LOGGED


class AuditRefused(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def canonical(payload: dict) -> bytes:
    """One record, one byte string. Two serialisations would mean two hashes."""
    return json.dumps(payload, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def content_hash(payload: dict) -> str:
    return hashlib.sha256(canonical(payload)).hexdigest()


@dataclass(frozen=True)
class Record:
    sequence: int
    tenant_id: str
    occurred_at: int
    event_class: str
    actor: str
    action: str
    decision: str
    rule_version: str
    payload_hash: str
    previous_hash: str
    record_hash: str
    payload: dict | None = None   # None once the payload has been shredded

    def header(self) -> dict:
        return {"sequence": self.sequence, "tenant_id": self.tenant_id,
                "occurred_at": self.occurred_at, "event_class": self.event_class,
                "actor": self.actor, "action": self.action, "decision": self.decision,
                "rule_version": self.rule_version, "payload_hash": self.payload_hash,
                "previous_hash": self.previous_hash}

    def recompute(self) -> str:
        return hashlib.sha256(canonical(self.header())).hexdigest()


@dataclass(frozen=True)
class Anchor:
    sequence: int
    head_hash: str
    at: int
    mac: str

    def valid(self, key: bytes) -> bool:
        expected = hmac.new(key, f"{self.sequence}:{self.head_hash}:{self.at}".encode(),
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.mac)


@dataclass
class Ledger:
    """One append-only chain per tenant."""

    tenant_id: str
    anchor_interval: int = 3600
    key: bytes = b"reference-anchor-key"
    records: list[Record] = field(default_factory=list)
    anchors: list[Anchor] = field(default_factory=list)

    # -- writing ----------------------------------------------------------
    def append(self, *, occurred_at: int, event_class: str, actor: str, action: str,
               decision: str, rule_version: str, payload: dict) -> Record:
        for key in payload:
            if field_is_forbidden(key):
                raise AuditRefused(FORBIDDEN_FIELD,
                                   f"{key} must never enter an immutable log")
        if self.records and occurred_at < self.records[-1].occurred_at:
            # The sequence stays monotonic even when a clock does not; refusing
            # here keeps "order" from becoming an opinion held by NTP.
            raise AuditRefused(CLOCK_REVERSED,
                               f"{occurred_at} precedes the previous record")
        sequence = len(self.records) + 1
        previous = self.records[-1].record_hash if self.records else GENESIS
        record = Record(sequence=sequence, tenant_id=self.tenant_id, occurred_at=occurred_at,
                        event_class=event_class, actor=actor, action=action, decision=decision,
                        rule_version=rule_version, payload_hash=content_hash(payload),
                        previous_hash=previous, record_hash="", payload=dict(payload))
        record = Record(**{**record.__dict__, "record_hash": record.recompute()})
        self.records.append(record)
        return record

    def anchor(self, at: int) -> Anchor:
        head = self.records[-1] if self.records else None
        sequence = head.sequence if head else 0
        head_hash = head.record_hash if head else GENESIS
        mac = hmac.new(self.key, f"{sequence}:{head_hash}:{at}".encode(),
                       hashlib.sha256).hexdigest()
        anchor = Anchor(sequence=sequence, head_hash=head_hash, at=at, mac=mac)
        self.anchors.append(anchor)
        return anchor

    def shred(self, sequence: int) -> Record:
        """Erase a payload, keep the proof.

        The record, its position and its hash all survive; only the readable
        content goes. This is what lets an immutable log honour an erasure
        request without lying about either promise.
        """
        for index, record in enumerate(self.records):
            if record.sequence == sequence:
                shredded = Record(**{**record.__dict__, "payload": None})
                self.records[index] = shredded
                return shredded
        raise AuditRefused("UNKNOWN_RECORD", str(sequence))

    # -- verifying --------------------------------------------------------
    def verify(self, *, anchors: list[Anchor] | None = None) -> tuple[str, int | None]:
        """Return ``(status, sequence)``; ``sequence`` names the first bad record."""
        previous = GENESIS
        expected_sequence = 1
        for record in self.records:
            if record.sequence != expected_sequence:
                return SEQUENCE_BROKEN, record.sequence
            if record.previous_hash != previous:
                return LINK_BROKEN, record.sequence
            if record.recompute() != record.record_hash:
                return MODIFIED, record.sequence
            if record.payload is not None and content_hash(record.payload) != record.payload_hash:
                return MODIFIED, record.sequence
            previous = record.record_hash
            expected_sequence += 1

        for anchor in anchors if anchors is not None else self.anchors:
            if not anchor.valid(self.key):
                return ANCHOR_INVALID, anchor.sequence
            if anchor.sequence > len(self.records):
                # The anchor witnesses records this chain no longer contains.
                return TRUNCATED, anchor.sequence
            if anchor.sequence >= 1:
                witnessed = self.records[anchor.sequence - 1]
                if witnessed.record_hash != anchor.head_hash:
                    return MODIFIED, anchor.sequence
        return OK, None

    def deniable_window(self, now: int) -> int:
        """Seconds of activity that no anchor yet witnesses. Honest, not zero."""
        if not self.anchors:
            return now
        return max(0, now - self.anchors[-1].at)

    def proof(self, sequence: int) -> dict:
        """The minimum a third party needs to check one record's position."""
        record = next((r for r in self.records if r.sequence == sequence), None)
        if record is None:
            raise AuditRefused("UNKNOWN_RECORD", str(sequence))
        covering = [a for a in self.anchors if a.sequence >= sequence]
        return {"header": record.header(), "record_hash": record.record_hash,
                "anchor": covering[0] if covering else None,
                "anchored": bool(covering)}
