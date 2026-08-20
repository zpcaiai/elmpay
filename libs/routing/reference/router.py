"""B28 — an executable, replayable router.

:meth:`Router.route` is deterministic by construction: it takes the payment, a
configuration version and a snapshot of provider scores, and returns a
:class:`Decision` that carries the version and the reasons. Feed the same three
things in again — next week, from a log — and the same decision comes out. That
is the whole design constraint, because the alternative is being unable to
answer "why did this payment go to that provider" in front of somebody who is
owed an answer.

Three details are deliberate and each is counter-intuitive:

* **an unranked provider is not a dead provider.** :meth:`allocation` never
  drops any capable target below the exploration floor, because a provider with
  no traffic can never produce the sample that would prove it recovered;
* **the canary splits on a stable hash of the payment**, so a retry lands in the
  branch it started in. A random split turns a retry into a second payment;
* **rollback is a switch to an existing version**, not an edit. Editing back is
  a new release, and a new release can fail in a new way.

Time is an integer second supplied by the caller; nothing reads the clock, and
nothing here calls ``random``.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

UNROUTABLE = "UNROUTABLE"
UNKNOWN_VERSION = "UNKNOWN_VERSION"
VERSION_IMMUTABLE = "VERSION_IMMUTABLE"
NOT_APPROVED = "NOT_APPROVED"
SELF_APPROVAL = "SELF_APPROVAL"
NO_PREVIOUS_VERSION = "NO_PREVIOUS_VERSION"
AMOUNT_ABOVE_CEILING = "AMOUNT_ABOVE_CEILING"
SHADOW_CANNOT_MOVE_MONEY = "SHADOW_CANNOT_MOVE_MONEY"
RETRY_KEY_CHANGED = "RETRY_KEY_CHANGED"
RETRY_PROVIDER_CHANGED = "RETRY_PROVIDER_CHANGED"
RETRIES_EXHAUSTED = "RETRIES_EXHAUSTED"
CANARY_TOO_LARGE = "CANARY_TOO_LARGE"
SCORE_NOT_INTEGER = "SCORE_NOT_INTEGER"
UNKNOWN_SPLIT_KEY = "UNKNOWN_SPLIT_KEY"


class RoutingRefused(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class Payment:
    intent_id: str
    region: str
    method: str
    currency: str
    amount_minor: int
    idempotency_key: str


@dataclass(frozen=True)
class Decision:
    provider: str
    rule_id: str
    config_version: str
    branch: str
    reasons: tuple[str, ...]


@dataclass
class Attempt:
    payment: Payment
    decision: Decision
    count: int = 1
    history: list[dict] = field(default_factory=list)


def stable_bucket(key: str, buckets: int = 100) -> int:
    """A stable hash, not a random number: the same payment always lands here."""
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % buckets


class Router:
    def __init__(self, model: dict, capabilities: dict) -> None:
        self.model = model
        self.capabilities = capabilities
        self.determinism = model["determinism"]
        self.scoring = model["scoring"]
        self.canary_policy = model["canary"]
        self.rollback_policy = model["rollback"]
        self.simulation_policy = model["simulation"]
        self.retry_policy = model["retry"]
        self.versions: dict[str, dict] = {}
        self.active: str | None = None
        self.previous: str | None = None
        self.decisions: list[Decision] = []

    # -- configuration versions -------------------------------------------
    def publish(self, version: str, rules: list[dict]) -> str:
        if version in self.versions:
            raise RoutingRefused(VERSION_IMMUTABLE, version)
        self.versions[version] = {"rules": sorted(rules, key=lambda r: r["priority"])}
        return version

    def activate(self, version: str, *, approvers: tuple[str, ...], actor: str) -> str:
        if version not in self.versions:
            raise RoutingRefused(UNKNOWN_VERSION, version)
        if actor in approvers:
            raise RoutingRefused(SELF_APPROVAL, actor)
        required = int(self.model["config_versioning"]["activation_approvers_required"])
        if len({a for a in approvers}) < required:
            raise RoutingRefused(NOT_APPROVED, f"{len(set(approvers))}/{required}")
        self.previous, self.active = self.active, version
        return version

    def rollback(self) -> str:
        """Switch back to a version that already exists. No approval, no edit."""
        if self.previous is None or self.previous not in self.versions:
            raise RoutingRefused(NO_PREVIOUS_VERSION, str(self.previous))
        self.active, self.previous = self.previous, self.active
        return self.active

    def rules(self, version: str | None = None) -> list[dict]:
        version = version or self.active
        if version is None or version not in self.versions:
            raise RoutingRefused(UNKNOWN_VERSION, str(version))
        return self.versions[version]["rules"]

    # -- capability ---------------------------------------------------------
    def serves(self, provider: str, payment: Payment) -> bool:
        return any(row["provider"] == provider and row["method"] == payment.method
                   and payment.region in row["regions"]
                   and payment.currency in row["currencies"]
                   for row in self.capabilities["capabilities"])

    def candidates(self, payment: Payment, version: str | None = None) -> tuple[dict, list[str]]:
        for rule in self.rules(version):
            when = rule["when"]
            if (when["region"], when["method"], when["currency"]) != (
                    payment.region, payment.method, payment.currency):
                continue
            if payment.amount_minor > when["max_amount_minor"]:
                raise RoutingRefused(AMOUNT_ABOVE_CEILING,
                                     f"{payment.amount_minor} > {when['max_amount_minor']}")
            targets = [p for p in list(rule["prefer"]) + list(rule["fallback"])
                       if self.serves(p, payment)]
            if not targets:
                continue
            return rule, targets
        raise RoutingRefused(UNROUTABLE,
                             f"{payment.method}/{payment.region}/{payment.currency}")

    # -- scoring ------------------------------------------------------------
    def score(self, provider: str, scores: dict) -> int:
        """Integer basis points in, integer score out.

        The money gate flagged the first version of this method for using
        floats, and it was right for a reason beyond its own rule: a score
        assembled from binary floating point can order two providers
        differently on two machines, which would break the determinism this
        whole batch is built on. Scores arrive as integer basis points
        (0-10000) and the weighted sum stays an integer.
        """
        entry = scores.get(provider) or {}
        total = 0
        for factor in self.scoring["factors"]:
            value = entry.get(factor["id"], 0)
            if not isinstance(value, int):
                raise RoutingRefused(SCORE_NOT_INTEGER, f"{provider}/{factor['id']}")
            total += value * int(factor["weight"])
        return total

    def rank(self, targets: list[str], scores: dict) -> list[str]:
        # The tie-break is part of the contract: equal scores must not
        # reintroduce randomness.
        if self.determinism["tie_break"] == "lowest_provider_id":
            return sorted(targets, key=lambda p: (-self.score(p, scores), p))
        return sorted(targets, key=lambda p: -self.score(p, scores))

    def allocation(self, targets: list[str], scores: dict) -> dict[str, int]:
        """Traffic share, with a floor nobody falls below."""
        if not targets:
            return {}
        floor = int(self.scoring["exploration_floor_percent"])
        ranked = self.rank(targets, scores)
        if len(ranked) == 1:
            return {ranked[0]: 100}
        share = {p: floor for p in ranked}
        share[ranked[0]] = 100 - floor * (len(ranked) - 1)
        return share

    def has_enough_sample(self, provider: str, scores: dict) -> bool:
        return int((scores.get(provider) or {}).get("sample", 0)) >= int(
            self.scoring["min_sample"])

    # -- canary -------------------------------------------------------------
    def split_value(self, payment: Payment) -> str:
        key = self.canary_policy["split_key"]
        if key != "payment_intent_id":
            raise RoutingRefused(UNKNOWN_SPLIT_KEY, key)
        return payment.intent_id

    def branch(self, payment: Payment, percent: int) -> str:
        if percent > int(self.canary_policy["max_percent"]):
            raise RoutingRefused(CANARY_TOO_LARGE, str(percent))
        return "canary" if stable_bucket(self.split_value(payment)) < percent else "stable"

    # -- routing ------------------------------------------------------------
    def route(self, payment: Payment, scores: dict, *, version: str | None = None,
              canary_percent: int = 0) -> Decision:
        version = version or self.active
        if version is None or version not in self.versions:
            raise RoutingRefused(UNKNOWN_VERSION, str(version))
        rule, targets = self.candidates(payment, version)
        ranked = self.rank(targets, scores)
        branch = self.branch(payment, canary_percent) if canary_percent else "stable"
        chosen = ranked[0]
        reasons = (f"rule={rule['id']}", f"targets={','.join(ranked)}",
                   f"score={self.score(chosen, scores)}", f"branch={branch}")
        decision = Decision(provider=chosen, rule_id=rule["id"], config_version=version,
                            branch=branch, reasons=reasons)
        self.decisions.append(decision)
        return decision

    def replay(self, payment: Payment, scores: dict, decision: Decision) -> bool:
        """Re-run a recorded decision against the version it names."""
        again = self.route(payment, scores, version=decision.config_version,
                           canary_percent=100 if decision.branch == "canary" else 0)
        return (again.provider, again.rule_id) == (decision.provider, decision.rule_id)

    # -- simulation ---------------------------------------------------------
    def simulate(self, payment: Payment, scores: dict, *, version: str) -> Decision:
        return self.route(payment, scores, version=version)

    def execute(self, decision: Decision, *, shadow: bool) -> str:
        if shadow and not self.simulation_policy["shadow_moves_money"]:
            raise RoutingRefused(SHADOW_CANNOT_MOVE_MONEY, decision.provider)
        return "SENT"

    # -- retries ------------------------------------------------------------
    def retry(self, attempt: Attempt, payment: Payment, *, provider: str | None = None) -> Attempt:
        if payment.idempotency_key != attempt.payment.idempotency_key:
            raise RoutingRefused(RETRY_KEY_CHANGED, payment.idempotency_key)
        if provider is not None and provider != attempt.decision.provider \
                and not self.retry_policy["change_provider_on_retry_allowed"]:
            # The first attempt has no final state yet. Sending the same money
            # to a second provider can succeed twice.
            raise RoutingRefused(RETRY_PROVIDER_CHANGED, provider)
        if attempt.count >= int(self.retry_policy["max_attempts"]):
            raise RoutingRefused(RETRIES_EXHAUSTED, str(attempt.count))
        attempt.count += 1
        attempt.history.append({"attempt": attempt.count,
                                "backoff": self.backoff(attempt.count)})
        return attempt

    def backoff(self, attempt_number: int) -> int:
        schedule = self.retry_policy["backoff_seconds"]
        index = min(max(attempt_number - 2, 0), len(schedule) - 1)
        return int(schedule[index])
