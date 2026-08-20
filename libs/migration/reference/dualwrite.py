"""B15 — executable model of the strangler-fig migration.

The plan is a document. This runs it, because the two claims that matter are
easy to write down and easy to get wrong:

* **one provider call per payment, in every phase.** "Dual write" is the phrase
  under which a project accidentally charges twice. Here the provider is a
  counter, and the counter is the test.
* **rollback preserves payment facts.** Going back a phase flips which side is
  authoritative; it does not delete the other side's records. The model keeps
  both stores and asserts nothing disappears.

Also modelled: divergence detection between the two stores, and a backfill that
is idempotent and resumable, because both will be re-run and one of them will be
re-run after a crash.
"""
from __future__ import annotations

from dataclasses import dataclass, field

PHASES = ("legacy_only", "dual_write_legacy_authoritative",
          "dual_write_platform_authoritative", "platform_only")
AUTHORITY = {"legacy_only": "legacy",
             "dual_write_legacy_authoritative": "legacy",
             "dual_write_platform_authoritative": "platform",
             "platform_only": "platform"}

FORBIDDEN = ("sku", "item", "quantity", "inventory", "stock", "shipping_address",
             "product_name", "coupon")


class DoubleCharge(Exception):
    """The model refuses to represent a second provider call for one payment."""


class BusinessDataLeak(Exception):
    """Order line data tried to cross into the platform."""


@dataclass
class Provider:
    """Counts calls per payment. One is correct; two is the bug being prevented."""

    calls: dict = field(default_factory=dict)

    def charge(self, external_reference: str) -> str:
        self.calls[external_reference] = self.calls.get(external_reference, 0) + 1
        if self.calls[external_reference] > 1:
            raise DoubleCharge(
                f"provider called {self.calls[external_reference]} times for "
                f"'{external_reference}'; dual write means two records, not two charges")
        return f"auth-{external_reference}"


@dataclass
class Store:
    """One side's record of payment facts, keyed by (project, external reference)."""

    name: str
    rows: dict = field(default_factory=dict)

    def write(self, project: str, external_reference: str, payload: dict) -> None:
        for key in payload:
            if any(term in key.lower() for term in FORBIDDEN):
                raise BusinessDataLeak(
                    f"'{key}' is order line data and must not reach {self.name}")
        self.rows[(project, external_reference)] = dict(payload)

    def get(self, project: str, external_reference: str):
        return self.rows.get((project, external_reference))


@dataclass
class Migration:
    legacy: Store = field(default_factory=lambda: Store("legacy"))
    platform: Store = field(default_factory=lambda: Store("platform"))
    provider: Provider = field(default_factory=Provider)
    phase: str = PHASES[0]
    audit: list = field(default_factory=list)

    @property
    def authority(self) -> str:
        return AUTHORITY[self.phase]

    def advance(self) -> str:
        index = PHASES.index(self.phase)
        if index + 1 >= len(PHASES):
            raise ValueError("already at the final phase")
        self.phase = PHASES[index + 1]
        self.audit.append(("advance", self.phase))
        return self.phase

    def rollback(self) -> str:
        """Go back one phase. Records on both sides are kept, deliberately."""
        index = PHASES.index(self.phase)
        if index == 0:
            raise ValueError("already at the first phase")
        before = {"legacy": len(self.legacy.rows), "platform": len(self.platform.rows)}
        self.phase = PHASES[index - 1]
        self.audit.append(("rollback", self.phase))
        after = {"legacy": len(self.legacy.rows), "platform": len(self.platform.rows)}
        if after != before:
            raise AssertionError("rollback lost payment facts")
        return self.phase

    def pay(self, project: str, external_reference: str, amount_minor: int,
            currency: str) -> dict:
        """Take one payment in the current phase. Exactly one provider call."""
        authorisation = self.provider.charge(external_reference)
        fact = {"amount_minor": amount_minor, "currency": currency,
                "status": "captured", "external_reference": external_reference,
                "authorisation": authorisation}
        if self.phase == "legacy_only":
            self.legacy.write(project, external_reference, fact)
        elif self.phase == "platform_only":
            self.platform.write(project, external_reference, fact)
        else:
            # Both sides record the same fact. Which one is authoritative is a
            # flag, not a second charge.
            self.legacy.write(project, external_reference, fact)
            self.platform.write(project, external_reference, fact)
        return fact

    def divergences(self, compare_fields=("amount_minor", "currency", "status")) -> list:
        keys = set(self.legacy.rows) & set(self.platform.rows)
        out = []
        for key in sorted(keys):
            left, right = self.legacy.rows[key], self.platform.rows[key]
            differing = [f for f in compare_fields if left.get(f) != right.get(f)]
            if differing:
                out.append({"key": key, "fields": differing,
                            "legacy": {f: left.get(f) for f in differing},
                            "platform": {f: right.get(f) for f in differing}})
        return out


@dataclass
class Backfill:
    """Idempotent, resumable, read-only on the source."""

    source: list
    target: Store
    checkpoint: str = ""
    reads: int = 0
    writes: int = 0

    def run(self, limit=None, crash_after=None) -> str:
        written = 0
        for row in self.source:
            if self.checkpoint and row["legacy_payment_id"] <= self.checkpoint:
                continue
            self.reads += 1
            if crash_after is not None and written >= crash_after:
                raise RuntimeError("crashed mid-backfill")
            existing = self.target.get(row["project"], row["external_reference"])
            if existing is None:
                self.target.write(row["project"], row["external_reference"],
                                  {k: v for k, v in row.items()
                                   if k not in ("project", "legacy_payment_id")})
                self.writes += 1
            self.checkpoint = row["legacy_payment_id"]
            written += 1
            if limit is not None and written >= limit:
                break
        return self.checkpoint

    def verify(self) -> dict:
        expected_count = len({(r["project"], r["external_reference"]) for r in self.source})
        totals: dict = {}
        for row in self.source:
            totals[row["currency"]] = totals.get(row["currency"], 0) + row["amount_minor"]
        actual_totals: dict = {}
        for payload in self.target.rows.values():
            actual_totals[payload["currency"]] = (
                actual_totals.get(payload["currency"], 0) + payload["amount_minor"])
        return {"count_ok": len(self.target.rows) == expected_count,
                "totals_ok": totals == actual_totals,
                "expected_count": expected_count, "actual_count": len(self.target.rows),
                "expected_totals": totals, "actual_totals": actual_totals}
