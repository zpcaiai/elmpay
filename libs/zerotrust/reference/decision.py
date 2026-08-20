"""B16 — executable policy decision point.

A zero-trust architecture is only as real as the thing that says no. This is
that thing, small enough to read in one sitting and strict enough to be worth
testing:

* **deny by default.** An unmatched request is denied with a reason, never
  allowed "because nothing forbade it".
* **network location grants nothing.** The context carries a network label
  because real requests do, and the decision function never reads it. The test
  that proves this flips the label between two otherwise identical requests and
  asserts the verdicts are identical.
* **every decision produces an audit record — including every allow.** The
  record is part of the return value, not a side effect a caller may forget.
* **step-up and four-eyes are checked, not advertised.** A high-risk action with
  a second approver equal to the requester is denied.

Not modelled: token formats, certificate validation, device attestation
protocols. Those are B17–B20. What is modelled is the shape of the decision, so
that the policy document and the code cannot drift apart quietly.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Context:
    """Everything a decision may look at. ``network`` is here to be ignored."""

    principal: str
    resource_class: str
    action: str
    factors: frozenset = frozenset()
    network: str = "unknown"
    requester: str = ""
    approver: str = ""
    session_age_minutes: int = 0
    step_up_completed: bool = False


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reasons: tuple
    audit: dict

    def __bool__(self) -> bool:  # pragma: no cover - convenience only
        return self.allowed


@dataclass
class PolicyDecisionPoint:
    rules: list
    session_limit_minutes: int = 60
    policy_version: str = "1.0.0"
    audit_log: list = field(default_factory=list)

    @classmethod
    def from_policy(cls, policy: dict) -> "PolicyDecisionPoint":
        session = policy.get("session") or {}
        return cls(rules=list(policy.get("decisions") or []),
                   session_limit_minutes=int(session.get("max_human_session_minutes") or 60),
                   policy_version=str(policy.get("schema_version") or "0.0.0"))

    def _match(self, context: Context):
        for rule in self.rules:
            if (rule.get("principal") == context.principal
                    and rule.get("resource_class") == context.resource_class
                    and rule.get("action") == context.action):
                return rule
        return None

    def decide(self, context: Context) -> Verdict:
        # NOTE: context.network is deliberately never read. Adding a branch on it
        # is the single change that would turn this back into perimeter security.
        rule = self._match(context)
        if rule is None:
            return self._record(context, False, ("no matching rule; denied by default",), None)

        reasons = []
        missing = [r for r in rule.get("requirements", []) if r not in context.factors]
        if missing:
            reasons.append(f"missing required factors: {sorted(missing)}")
        if context.session_age_minutes > self.session_limit_minutes:
            reasons.append(
                f"session is {context.session_age_minutes} minutes old, over the "
                f"{self.session_limit_minutes} minute limit")
        if rule.get("step_up") and not context.step_up_completed:
            reasons.append("step-up authentication was not completed")
        if rule.get("four_eyes"):
            if not context.approver:
                reasons.append("a second approver is required")
            elif context.approver == context.requester:
                reasons.append("the approver must not be the requester")
        allowed = not reasons
        if allowed:
            reasons.append("all requirements satisfied")
        return self._record(context, allowed, tuple(reasons), rule)

    def _record(self, context: Context, allowed: bool, reasons: tuple, rule) -> Verdict:
        audit = {
            "actor": context.requester or context.principal,
            "principal_kind": context.principal,
            "resource_class": context.resource_class,
            "action": context.action,
            "decision": "allow" if allowed else "deny",
            "reason": "; ".join(reasons),
            "policy_version": self.policy_version,
            "trace_id": f"trace-{len(self.audit_log) + 1}",
            "occurred_at": "recorded-by-caller",
            "rule": (rule or {}).get("id"),
            "audit_event": (rule or {}).get("audit_event"),
        }
        self.audit_log.append(audit)
        return Verdict(allowed=allowed, reasons=reasons, audit=audit)
