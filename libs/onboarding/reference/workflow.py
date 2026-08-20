"""B30 — a resumable onboarding workflow with four-eyes approval.

Three methods carry the batch.

:meth:`Workflow.execute` runs one step and records it. Running a completed step
again returns ``ALREADY_DONE`` and performs no side effect, so a retry, a resume
and an operator clicking twice are the same event.

:meth:`Workflow.resume` returns the next pending step. It never replays a
completed one, which is the difference between a workflow that survives a
failure at two in the morning and a workflow that gets finished by hand.

:meth:`Workflow.approve` binds the approval to a digest of the request. Change
the payout account afterwards and the approval is gone — because "approve, then
edit, then go live" is the bypass this control exists for, and it leaves an
audit trail that reads as a correctly approved onboarding.

There is deliberately no ``force_complete``. A manual completion path that
exists is used, and the moment it is used every approval above it stops meaning
anything.

Time is an integer hour supplied by the caller.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

PENDING = "pending"
RUNNING = "running"
COMPLETE = "complete"
SUSPENDED = "suspended"
EXPIRED = "expired"

UNKNOWN_STEP = "UNKNOWN_STEP"
OUT_OF_ORDER = "OUT_OF_ORDER"
ALREADY_LIVE = "ALREADY_LIVE"
NOT_APPROVED = "NOT_APPROVED"
APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
APPROVAL_STALE = "APPROVAL_STALE"
SELF_APPROVAL = "SELF_APPROVAL"
NOT_ENOUGH_EYES = "NOT_ENOUGH_EYES"
NO_EVIDENCE = "NO_EVIDENCE"
CASE_EXPIRED = "CASE_EXPIRED"
CREDENTIAL_NOT_READABLE = "CREDENTIAL_NOT_READABLE"
DOMAIN_TOKEN_USED = "DOMAIN_TOKEN_USED"
DOMAIN_TOKEN_EXPIRED = "DOMAIN_TOKEN_EXPIRED"
DOMAIN_WILDCARD = "DOMAIN_WILDCARD"
CALLBACK_NOT_HTTPS = "CALLBACK_NOT_HTTPS"
CALLBACK_PRIVATE_ADDRESS = "CALLBACK_PRIVATE_ADDRESS"
NO_LIMITS = "NO_LIMITS"
NOT_SUSPENDED = "NOT_SUSPENDED"
MANUAL_COMPLETION = "MANUAL_COMPLETION"

PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "169.254.", "172.16.", "localhost")


class WorkflowRefused(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class Approval:
    approvers: tuple[str, ...]
    digest: str
    granted_at_hour: int


@dataclass
class Case:
    id: str
    tenant_id: str
    provider: str
    requester: str
    payload: dict
    opened_at_hour: int
    completed: dict[str, str] = field(default_factory=dict)   # step -> evidence
    approval: Approval | None = None
    state: str = PENDING
    credential_reference: str | None = None
    used_domain_tokens: set[str] = field(default_factory=set)
    history: list[dict] = field(default_factory=list)


def digest_of(payload: dict, fields: list[str]) -> str:
    """A digest of exactly the fields the approval is meant to cover."""
    subset = {k: payload.get(k) for k in sorted(fields)}
    canonical = json.dumps(subset, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class Workflow:
    def __init__(self, model: dict) -> None:
        self.model = model
        self.steps = {s["id"]: s for s in model["steps"]}
        self.order = [s["id"] for s in sorted(model["steps"], key=lambda s: s["order"])]
        self.approval_policy = model["approval"]
        self.resumption = model["resumption"]
        self.domain_policy = model["domain_verification"]
        self.callback_policy = model["callback_verification"]
        self.credential_policy = model["credentials"]
        self.limit_policy = model["limits"]
        self.suspension_policy = model["suspension"]
        self.side_effects: list[str] = []

    # -- lifecycle ---------------------------------------------------------
    def start(self, case_id: str, *, tenant_id: str, provider: str, requester: str,
              payload: dict, hour: int) -> Case:
        return Case(id=case_id, tenant_id=tenant_id, provider=provider, requester=requester,
                    payload=dict(payload), opened_at_hour=hour)

    def digest(self, case: Case) -> str:
        return digest_of(case.payload, list(self.approval_policy["digest_fields"]))

    def amend(self, case: Case, **changes) -> Case:
        """Any change to an approved field drops the approval on the floor."""
        case.payload.update(changes)
        if case.approval is not None and self.approval_policy["reapproval_required_on_change"]:
            if case.approval.digest != self.digest(case):
                case.approval = None
                case.completed.pop("approve", None)
                case.history.append({"event": "approval_invalidated"})
        return case

    def require_fresh(self, case: Case, hour: int) -> str:
        if hour - case.opened_at_hour > int(self.resumption["max_resume_days"]) * 24:
            case.state = EXPIRED
            raise WorkflowRefused(CASE_EXPIRED, str(hour - case.opened_at_hour))
        return "OK"

    # -- resumption --------------------------------------------------------
    def next_step(self, case: Case) -> str | None:
        for step in self.order:
            if step not in case.completed:
                return step
        return None

    def resume(self, case: Case, hour: int) -> str | None:
        """Continue after the last completed step. Never replays one."""
        self.require_fresh(case, hour)
        if not self.resumption["resume_from_last_completed_step"]:  # pragma: no cover
            raise WorkflowRefused(MANUAL_COMPLETION, "policy forbids resumption")
        return self.next_step(case)

    def force_complete(self, case: Case) -> str:
        """The path that does not exist. Kept visible so its absence is testable."""
        raise WorkflowRefused(MANUAL_COMPLETION,
                              "there is no manual completion path; finish the steps")

    # -- steps -------------------------------------------------------------
    def execute(self, case: Case, step_id: str, *, evidence: str, hour: int) -> str:
        self.require_fresh(case, hour)
        step = self.steps.get(step_id)
        if step is None:
            raise WorkflowRefused(UNKNOWN_STEP, step_id)
        if step_id in case.completed:
            # Idempotent by construction: no side effect is emitted a second time.
            return "ALREADY_DONE"
        expected = self.next_step(case)
        if expected != step_id:
            raise WorkflowRefused(OUT_OF_ORDER, f"expected {expected}, got {step_id}")
        if not evidence:
            raise WorkflowRefused(NO_EVIDENCE, step_id)
        if step["has_side_effect"]:
            self.side_effects.append(f"{case.id}:{step_id}")
        case.completed[step_id] = evidence
        case.history.append({"event": "step", "step": step_id, "hour": hour})
        return "DONE"

    def side_effect_count(self, case: Case, step_id: str) -> int:
        return self.side_effects.count(f"{case.id}:{step_id}")

    # -- individual step semantics ----------------------------------------
    def import_credentials(self, case: Case, secret_reference: str, *, hour: int) -> str:
        if case.credential_reference is not None and self.credential_policy["import_once"]:
            # Same reference, not a second stored copy that revocation would miss.
            return case.credential_reference
        case.credential_reference = secret_reference
        self.execute(case, "import_credentials", evidence=secret_reference, hour=hour)
        return secret_reference

    def read_credential(self, case: Case) -> str:
        if not self.credential_policy["echo_back_allowed"]:
            raise WorkflowRefused(CREDENTIAL_NOT_READABLE, case.id)
        return case.credential_reference or ""   # pragma: no cover - policy is false

    def verify_domain(self, case: Case, domain: str, token: str, *, issued_at_hour: int,
                      hour: int) -> str:
        if domain.startswith("*."):
            raise WorkflowRefused(DOMAIN_WILDCARD, domain)
        if token in case.used_domain_tokens and self.domain_policy["token_single_use"]:
            raise WorkflowRefused(DOMAIN_TOKEN_USED, token)
        if hour - issued_at_hour > int(self.domain_policy["token_expires_hours"]):
            raise WorkflowRefused(DOMAIN_TOKEN_EXPIRED, token)
        case.used_domain_tokens.add(token)
        return self.execute(case, "verify_domain", evidence=token, hour=hour)

    def verify_callback(self, case: Case, url: str, *, roundtrip_id: str,
                        signature_valid: bool, hour: int) -> str:
        if self.callback_policy["https_required"] and not url.startswith("https://"):
            raise WorkflowRefused(CALLBACK_NOT_HTTPS, url)
        host = url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        if not self.callback_policy["private_address_allowed"] \
                and host.startswith(PRIVATE_PREFIXES):
            raise WorkflowRefused(CALLBACK_PRIVATE_ADDRESS, host)
        if not (roundtrip_id and signature_valid):
            raise WorkflowRefused(NO_EVIDENCE, "callback round trip")
        return self.execute(case, "verify_callback", evidence=roundtrip_id, hour=hour)

    def set_limits(self, case: Case, limits: dict, *, hour: int) -> str:
        if not limits:
            raise WorkflowRefused(NO_LIMITS, case.id)
        case.payload["limits"] = limits
        return self.execute(case, "set_limits", evidence=json.dumps(limits, sort_keys=True),
                            hour=hour)

    # -- approval ----------------------------------------------------------
    def approve(self, case: Case, *, approvers: tuple[str, ...], hour: int) -> Approval:
        if case.requester in approvers \
                and self.approval_policy["approver_differs_from_requester"]:
            raise WorkflowRefused(SELF_APPROVAL, case.requester)
        if len(set(approvers)) < int(self.approval_policy["eyes_required"]):
            raise WorkflowRefused(NOT_ENOUGH_EYES,
                                  f"{len(set(approvers))}/"
                                  f"{self.approval_policy['eyes_required']}")
        approval = Approval(approvers=tuple(sorted(set(approvers))), digest=self.digest(case),
                            granted_at_hour=hour)
        case.approval = approval
        case.completed["approve"] = approval.digest
        case.history.append({"event": "approved", "hour": hour})
        return approval

    def approval_valid(self, case: Case, hour: int) -> bool:
        approval = case.approval
        if approval is None:
            return False
        if hour - approval.granted_at_hour > int(self.approval_policy["expires_hours"]):
            return False
        return approval.digest == self.digest(case)

    def require_approval(self, case: Case, hour: int) -> str:
        approval = case.approval
        if approval is None:
            raise WorkflowRefused(NOT_APPROVED, case.id)
        if hour - approval.granted_at_hour > int(self.approval_policy["expires_hours"]):
            raise WorkflowRefused(APPROVAL_EXPIRED, str(hour - approval.granted_at_hour))
        if approval.digest != self.digest(case):
            raise WorkflowRefused(APPROVAL_STALE, "the request changed after it was approved")
        return "OK"

    # -- go live and stop --------------------------------------------------
    def go_live(self, case: Case, *, hour: int) -> str:
        if case.state == COMPLETE:
            raise WorkflowRefused(ALREADY_LIVE, case.id)
        self.require_fresh(case, hour)
        for step in self.order:
            if step in ("go_live", "approve"):
                # The approval is checked below, where the refusal can say
                # *why* — missing, expired or stale are three different
                # problems and an operator needs to be told which one.
                continue
            if step not in case.completed:
                raise WorkflowRefused(OUT_OF_ORDER, f"{step} is not done")
        if self.limit_policy["must_be_set_before_go_live"] and not case.payload.get("limits"):
            raise WorkflowRefused(NO_LIMITS, case.id)
        self.require_approval(case, hour)
        self.execute(case, "go_live", evidence="binding:active", hour=hour)
        case.state = COMPLETE
        return "LIVE"

    def suspend(self, case: Case, *, actor: str, hour: int) -> str:
        """One person, immediately. No approval, no waiting."""
        case.state = SUSPENDED
        case.history.append({"event": "suspended", "actor": actor, "hour": hour})
        return SUSPENDED

    def reinstate(self, case: Case, *, actor: str, approvers: tuple[str, ...],
                  hour: int) -> str:
        if case.state != SUSPENDED:
            raise WorkflowRefused(NOT_SUSPENDED, case.state)
        required = int(self.suspension_policy["reinstatement_approvals_required"])
        distinct = {a for a in approvers if a != actor}
        if len(distinct) < required:
            raise WorkflowRefused(NOT_ENOUGH_EYES, f"{len(distinct)}/{required}")
        case.state = COMPLETE
        case.history.append({"event": "reinstated", "actor": actor, "hour": hour})
        return COMPLETE
