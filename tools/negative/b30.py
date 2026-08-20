"""B30 negative controls — the four ways an approval workflow stops approving."""
from __future__ import annotations

from . import EXIT_PROBLEMS

REL = "governance/onboarding-workflow.json"
AUTHZ = "governance/authorization.json"
ACCOUNTS = "governance/provider-accounts.json"


def _step(d, sid):
    return next(s for s in d["steps"] if s["id"] == sid)


EXPECTED_CODES = {
    "B30 a manual completion path appears": "ONB_MANUAL_COMPLETION",
    "B30 resuming replays completed side effects": "ONB_REPLAYS_SIDE_EFFECTS",
    "B30 workflow state stops surviving a restart": "ONB_NOT_RESUMABLE",
    "B30 a step stops being idempotent": "ONB_STEP_NOT_IDEMPOTENT",
    "B30 a step produces no evidence": "ONB_STEP_NO_EVIDENCE",
    "B30 approval stops being bound to the request content": "ONB_APPROVAL_UNBOUND",
    "B30 the approval digest drops the payout account": "ONB_DIGEST_INCOMPLETE",
    "B30 an approval never expires": "ONB_APPROVAL_NEVER_EXPIRES",
    "B30 an approval survives a change to the request": "ONB_APPROVAL_SURVIVES_CHANGE",
    "B30 one person approves an onboarding": "ONB_SINGLE_EYE",
    "B30 the approval permission drops dual control": "ONB_SINGLE_EYE",
    "B30 the requester may approve their own request": "ONB_SELF_APPROVAL",
    "B30 approval moves after go-live": "ONB_APPROVAL_AFTER_GO_LIVE",
    "B30 limits are set after go-live": "ONB_LIMITS_AFTER_GO_LIVE",
    "B30 a merchant may go live with no limits": "ONB_NO_LIMITS_AT_GO_LIVE",
    "B30 raising a limit needs no approval": "ONB_LIMIT_RAISE_UNGATED",
    "B30 an imported credential can be read back": "ONB_CREDENTIAL_ECHO",
    "B30 reimporting stores a second copy": "ONB_CREDENTIAL_REIMPORT",
    "B30 credentials are stored outside the binding": "ONB_CREDENTIAL_SIDE_PATH",
    "B30 a wildcard domain proof is accepted": "ONB_DOMAIN_WILDCARD",
    "B30 the domain token becomes reusable": "ONB_DOMAIN_TOKEN_REUSABLE",
    "B30 a callback endpoint may be plaintext": "ONB_CALLBACK_PLAINTEXT",
    "B30 a callback may point at a private address": "ONB_CALLBACK_SSRF",
    "B30 the callback is proven by typing a URL": "ONB_CALLBACK_UNPROVEN",
    "B30 suspending starts requiring approval": "ONB_SUSPEND_NEEDS_APPROVAL",
    "B30 reinstating takes one person": "ONB_REINSTATE_SINGLE_PERSON",
    "B30 go-live no longer needs a proven round trip": "ONB_GO_LIVE_UNPROVEN",
    "B30 onboarding events map to a nonexistent audit class": "ONB_AUDIT_CLASS_UNKNOWN",
    "B30 onboarding document hand-edited": "ONB_GENERATED_DRIFT",
}

SCENARIOS = [
    ("B30 a manual completion path appears", REL,
     lambda d: d["resumption"].__setitem__("manual_completion_allowed", True), EXIT_PROBLEMS),
    ("B30 resuming replays completed side effects", REL,
     lambda d: d["resumption"].__setitem__("replay_completed_side_effects", True),
     EXIT_PROBLEMS),
    ("B30 workflow state stops surviving a restart", REL,
     lambda d: d["resumption"].__setitem__("state_persisted", False), EXIT_PROBLEMS),
    ("B30 a step stops being idempotent", REL,
     lambda d: _step(d, "go_live").__setitem__("idempotent", False), EXIT_PROBLEMS),
    ("B30 a step produces no evidence", REL,
     lambda d: _step(d, "verify_domain").__setitem__("evidence_required", ""), EXIT_PROBLEMS),
    ("B30 approval stops being bound to the request content", REL,
     lambda d: d["approval"].__setitem__("bound_to_digest", False), EXIT_PROBLEMS),
    ("B30 the approval digest drops the payout account", REL,
     lambda d: d["approval"].__setitem__("digest_fields", ["tenant_id", "provider"]),
     EXIT_PROBLEMS),
    ("B30 an approval never expires", REL,
     lambda d: d["approval"].__setitem__("expires_hours", 0), EXIT_PROBLEMS),
    ("B30 an approval survives a change to the request", REL,
     lambda d: d["approval"].__setitem__("reapproval_required_on_change", False),
     EXIT_PROBLEMS),
    ("B30 one person approves an onboarding", REL,
     lambda d: d["approval"].__setitem__("eyes_required", 1), EXIT_PROBLEMS),
    ("B30 the approval permission drops dual control", AUTHZ,
     lambda d: next(p for p in d["permissions"] if p["id"] == "config.write")
     .__setitem__("dual_control", False), EXIT_PROBLEMS),
    ("B30 the requester may approve their own request", REL,
     lambda d: d["approval"].__setitem__("approver_differs_from_requester", False),
     EXIT_PROBLEMS),
    ("B30 approval moves after go-live", REL,
     lambda d: _step(d, "approve").__setitem__("order", 999), EXIT_PROBLEMS),
    ("B30 limits are set after go-live", REL,
     lambda d: _step(d, "set_limits").__setitem__("order", 998), EXIT_PROBLEMS),
    ("B30 a merchant may go live with no limits", REL,
     lambda d: d["limits"].__setitem__("must_be_set_before_go_live", False), EXIT_PROBLEMS),
    ("B30 raising a limit needs no approval", REL,
     lambda d: d["limits"].__setitem__("raise_requires_approval", False), EXIT_PROBLEMS),
    ("B30 an imported credential can be read back", REL,
     lambda d: d["credentials"].__setitem__("echo_back_allowed", True), EXIT_PROBLEMS),
    ("B30 reimporting stores a second copy", REL,
     lambda d: d["credentials"].__setitem__("import_once", False), EXIT_PROBLEMS),
    ("B30 credentials are stored outside the binding", REL,
     lambda d: d["credentials"].__setitem__("stored_via_binding", False), EXIT_PROBLEMS),
    ("B30 a wildcard domain proof is accepted", REL,
     lambda d: d["domain_verification"].__setitem__("wildcard_allowed", True), EXIT_PROBLEMS),
    ("B30 the domain token becomes reusable", REL,
     lambda d: d["domain_verification"].__setitem__("token_single_use", False),
     EXIT_PROBLEMS),
    ("B30 a callback endpoint may be plaintext", REL,
     lambda d: d["callback_verification"].__setitem__("https_required", False), EXIT_PROBLEMS),
    ("B30 a callback may point at a private address", REL,
     lambda d: d["callback_verification"].__setitem__("private_address_allowed", True),
     EXIT_PROBLEMS),
    ("B30 the callback is proven by typing a URL", REL,
     lambda d: d["callback_verification"].__setitem__("roundtrip_required", False),
     EXIT_PROBLEMS),
    ("B30 suspending starts requiring approval", REL,
     lambda d: d["suspension"].__setitem__("approvals_required", 2), EXIT_PROBLEMS),
    ("B30 reinstating takes one person", REL,
     lambda d: d["suspension"].__setitem__("reinstatement_approvals_required", 1),
     EXIT_PROBLEMS),
    ("B30 go-live no longer needs a proven round trip", ACCOUNTS,
     lambda d: d["activation"].__setitem__("callback_roundtrip_required", False),
     EXIT_PROBLEMS),
    ("B30 onboarding events map to a nonexistent audit class", REL,
     lambda d: d.__setitem__("audit_event_class", "onboarding.vanished"), EXIT_PROBLEMS),
]

TEXT_SCENARIOS = [
    ("B30 onboarding document hand-edited",
     "docs/onboarding/ONBOARDING_WORKFLOW.md", "必须**可恢复**", "尽量可恢复", EXIT_PROBLEMS),
]
