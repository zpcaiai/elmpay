"""B30 — merchant onboarding as a resumable four-eyes workflow.

The brief asks for credential import, domain verification, callback
verification, limits, go-live and suspension as a **resumable** approval
workflow, and that word is the whole batch. A workflow that cannot resume is
finished by hand: step four of six fails at two in the morning, restarting from
step one means re-importing credentials and re-verifying domains, so somebody
sets the state directly in the database instead. At that moment every approval
record above it stops meaning anything. Hence ``ONB_MANUAL_COMPLETION``: there
is no manual path, because a manual path that exists gets used.

The rest are the mistakes this area repeats:

* ``ONB_APPROVAL_UNBOUND`` — approving "the request" rather than a digest of its
  contents. Approve, then change the payout account, then go live: the classic
  bypass, and the audit trail shows a correctly approved onboarding;
* ``ONB_APPROVAL_NEVER_EXPIRES`` — an approval from six months ago approved a
  different world;
* ``ONB_SUSPEND_NEEDS_APPROVAL`` — symmetric approvals for going live and for
  stopping. Stopping should take one person and no waiting; the asymmetry is the
  point;
* ``ONB_CREDENTIAL_ECHO`` — letting an operator read back an imported
  credential. The request is reasonable and satisfying it builds an endpoint
  that returns every provider secret you hold.
"""
from __future__ import annotations

import re
from pathlib import Path

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

ONBOARDING = Path("governance/onboarding-workflow.json")
ACCOUNTS = Path("governance/provider-accounts.json")
MERCHANT = Path("governance/merchant-profile.json")
AUTHZ = Path("governance/authorization.json")
AUDIT = Path("governance/audit-log.json")

CODE = re.compile(r"^[a-z][a-z0-9_]*$")
REQUIRED_STEPS = ("import_credentials", "verify_domain", "verify_callback", "set_limits",
                  "approve", "go_live")
DIGEST_FIELDS = {"payout_account", "limits"}
MAX_APPROVAL_HOURS = 168
MAX_RESUME_DAYS = 90
DOMAIN_METHODS = {"dns_txt", "https_file"}


VALIDATOR = ("onboarding-workflow", "B30")


def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    where = str(ONBOARDING)
    budget.check(where)
    try:
        model = load_json(root / ONBOARDING)
    except Exception as exc:
        return [Problem("ONB_UNREADABLE", where,
                        f"cannot read the onboarding workflow: {exc}", "NN-14")]
    if not isinstance(model, dict):
        return [Problem("ONB_SHAPE", where, "the model must be an object", "NN-12")]

    problems = list(expect(SEMVER.match(str(model.get("schema_version", ""))),
                           "ONB_VERSION_FIELD", where, "schema_version must be semver",
                           "NN-12"))
    problems += expect(len(str(model.get("principle") or "")) >= 20, "ONB_PRINCIPLE", where,
                       "say what happens when the workflow cannot resume", "NN-14")
    problems += _steps(model, where, budget)
    problems += _approval(model, root, where, budget)
    problems += _resumption(model, where)
    problems += _domain(model, where)
    problems += _callback(model, where)
    problems += _credentials(model, where)
    problems += _limits(model, root, where, budget)
    problems += _suspension(model, where)
    problems += _audit_binding(model, root, where, budget)
    problems += _generated(root, budget)
    return problems


def _steps(model: dict, where: str, budget: Budget) -> list[Problem]:
    entries = model.get("steps")
    if not isinstance(entries, list) or not entries:
        return [Problem("ONB_NO_STEPS", where,
                        "an onboarding with no declared steps is an onboarding done by hand",
                        "NN-14")]
    problems: list[Problem] = []
    seen: set[str] = set()
    orders: dict[int, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("ONB_SHAPE", where, "each step must be an object", "NN-12"))
            continue
        sid = str(entry.get("id") or "")
        scope = f"{where}#{sid or '<anonymous>'}"
        budget.check(scope)
        problems += expect(bool(CODE.match(sid)), "ONB_STEP_ID", scope,
                           f"step id '{sid}' must be snake_case", "NN-12")
        problems += expect(sid not in seen, "ONB_STEP_DUPLICATE", scope,
                           f"step '{sid}' is declared twice", "NN-12")
        seen.add(sid)
        order = entry.get("order")
        problems += expect(isinstance(order, int) and order > 0, "ONB_STEP_NO_ORDER", scope,
                           f"step '{sid}' needs a positive integer order", "NN-12")
        if isinstance(order, int):
            problems += expect(order not in orders, "ONB_STEP_ORDER_COLLISION", scope,
                               f"step '{sid}' shares order {order} with '{orders.get(order)}'; "
                               f"two steps at one position make execution order accidental",
                               "NN-12")
            orders.setdefault(order, sid)
        problems += expect(isinstance(entry.get("has_side_effect"), bool),
                           "ONB_STEP_EFFECT_UNSTATED", scope,
                           f"'{sid}' must say whether it has a side effect; a resume that does "
                           f"not know cannot avoid repeating it", "NN-03")
        problems += expect(entry.get("idempotent") is True, "ONB_STEP_NOT_IDEMPOTENT", scope,
                           f"'{sid}' must be idempotent: a resume, a retry and an operator "
                           f"clicking twice are the same event to this workflow", "NN-03")
        problems += expect(entry.get("resumable") is True, "ONB_STEP_NOT_RESUMABLE", scope,
                           f"'{sid}' must be resumable, or the whole workflow is not", "NN-14")
        problems += expect(bool(entry.get("evidence_required")), "ONB_STEP_NO_EVIDENCE", scope,
                           f"'{sid}' produces no evidence, so nothing later can show it "
                           f"actually happened", "NN-13")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "ONB_STEP_NOTES", scope,
                           f"say what '{sid}' proves", "NN-14")
    for required in REQUIRED_STEPS:
        problems += expect(required in seen, "ONB_STEP_MISSING", where,
                           f"the workflow has no '{required}' step", "NN-14")

    by_id = {str(e.get("id")): e for e in entries if isinstance(e, dict)}
    approve = by_id.get("approve") or {}
    go_live = by_id.get("go_live") or {}
    if approve and go_live:
        problems += expect(int(approve.get("order") or 0) < int(go_live.get("order") or 0),
                           "ONB_APPROVAL_AFTER_GO_LIVE", where,
                           "approval must come before go-live, not after it", "NN-03")
        problems += expect(approve.get("requires_approval") is True, "ONB_APPROVAL_UNBOUND",
                           where, "the approval step must actually require an approval",
                           "NN-03")
    limits = by_id.get("set_limits") or {}
    if limits and go_live:
        problems += expect(int(limits.get("order") or 0) < int(go_live.get("order") or 0),
                           "ONB_LIMITS_AFTER_GO_LIVE", where,
                           "limits must exist before the merchant can take money", "NN-01")
    return problems


def _approval(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    approval = model.get("approval")
    if not isinstance(approval, dict):
        return [Problem("ONB_APPROVAL_UNBOUND", where,
                        "without an approval policy, 'approved' is a boolean somebody set",
                        "NN-03")]
    eyes = int(approval.get("eyes_required") or 0)
    problems = list(expect(eyes >= 2, "ONB_SINGLE_EYE", where,
                           f"onboarding a merchant needs four eyes, got {eyes}", "NN-03"))
    problems += expect(approval.get("approver_differs_from_requester") is True,
                       "ONB_SELF_APPROVAL", where,
                       "the approver must not be the requester", "NN-03")
    problems += expect(approval.get("bound_to_digest") is True, "ONB_APPROVAL_UNBOUND", where,
                       "an approval must be bound to a digest of what was approved; otherwise "
                       "the payout account can change between approval and go-live and the "
                       "trail still reads as correctly approved", "NN-03")
    fields = set(approval.get("digest_fields") or [])
    problems += expect(DIGEST_FIELDS <= fields, "ONB_DIGEST_INCOMPLETE", where,
                       f"the approval digest is missing {sorted(DIGEST_FIELDS - fields)}; "
                       f"those are exactly the fields worth changing after approval", "NN-03")
    hours = int(approval.get("expires_hours") or 0)
    problems += expect(0 < hours <= MAX_APPROVAL_HOURS, "ONB_APPROVAL_NEVER_EXPIRES", where,
                       f"an approval must expire within {MAX_APPROVAL_HOURS} hours, got "
                       f"{hours}", "NN-03")
    problems += expect(approval.get("reapproval_required_on_change") is True,
                       "ONB_APPROVAL_SURVIVES_CHANGE", where,
                       "changing the request must invalidate the approval", "NN-03")
    permission = str(approval.get("permission") or "")
    budget.check(str(AUTHZ))
    try:
        authz = load_json(root / AUTHZ)
        permissions = {str(p.get("id")): p for p in (authz.get("permissions") or [])
                       if isinstance(p, dict)}
    except Exception:
        permissions = {}
    problems += expect(permission in permissions, "ONB_PERMISSION_UNKNOWN", where,
                       f"approval is guarded by '{permission}', which B19 does not define",
                       "NN-12")
    entry = permissions.get(permission) or {}
    if entry:
        problems += expect(entry.get("dual_control") is True, "ONB_SINGLE_EYE", where,
                           f"'{permission}' must be dual control in B19", "NN-03")
    problems += expect(len(str(approval.get("notes") or "")) >= 8, "ONB_APPROVAL_NOTES", where,
                       "say what exactly is being approved", "NN-14")
    return problems


def _resumption(model: dict, where: str) -> list[Problem]:
    resumption = model.get("resumption")
    if not isinstance(resumption, dict):
        return [Problem("ONB_NOT_RESUMABLE", where,
                        "without a resumption policy, a failure halfway through is finished by "
                        "hand", "NN-14")]
    problems = list(expect(resumption.get("state_persisted") is True, "ONB_NOT_RESUMABLE",
                           where,
                           "workflow state must survive a restart, or resuming is guesswork",
                           "NN-14"))
    problems += expect(resumption.get("resume_from_last_completed_step") is True,
                       "ONB_NOT_RESUMABLE", where,
                       "resuming must continue after the last completed step", "NN-14")
    problems += expect(resumption.get("replay_completed_side_effects") is False,
                       "ONB_REPLAYS_SIDE_EFFECTS", where,
                       "a resume must not repeat a completed side effect: re-importing a "
                       "credential stores a second copy and re-running go-live emits the event "
                       "twice", "NN-03")
    problems += expect(resumption.get("manual_completion_allowed") is False,
                       "ONB_MANUAL_COMPLETION", where,
                       "there must be no manual completion path; one that exists is used at "
                       "two in the morning and voids every approval above it", "NN-03")
    days = int(resumption.get("max_resume_days") or 0)
    problems += expect(0 < days <= MAX_RESUME_DAYS, "ONB_RESUME_UNBOUNDED", where,
                       f"a half-finished onboarding must expire, got {days} days", "NN-14")
    problems += expect(len(str(resumption.get("notes") or "")) >= 8, "ONB_RESUMPTION_NOTES",
                       where, "say why there is no manual path", "NN-14")
    return problems


def _domain(model: dict, where: str) -> list[Problem]:
    domain = model.get("domain_verification")
    if not isinstance(domain, dict):
        return [Problem("ONB_SHAPE", where, "domain_verification must be an object", "NN-14")]
    problems = list(expect(domain.get("method") in DOMAIN_METHODS, "ONB_DOMAIN_METHOD", where,
                           f"domain verification must use one of {sorted(DOMAIN_METHODS)}",
                           "NN-14"))
    problems += expect(domain.get("token_single_use") is True, "ONB_DOMAIN_TOKEN_REUSABLE",
                       where,
                       "a reusable verification token proves control once and forever after",
                       "NN-03")
    hours = int(domain.get("token_expires_hours") or 0)
    problems += expect(0 < hours <= 720, "ONB_DOMAIN_TOKEN_ETERNAL", where,
                       f"the verification token must expire, got {hours} hours", "NN-03")
    problems += expect(domain.get("wildcard_allowed") is False, "ONB_DOMAIN_WILDCARD", where,
                       "a wildcard proof admits every subdomain, including ones the merchant "
                       "does not control yet", "NN-07")
    problems += expect(len(str(domain.get("notes") or "")) >= 8, "ONB_DOMAIN_NOTES", where,
                       "say what the proof actually proves", "NN-14")
    return problems


def _callback(model: dict, where: str) -> list[Problem]:
    callback = model.get("callback_verification")
    if not isinstance(callback, dict):
        return [Problem("ONB_SHAPE", where, "callback_verification must be an object", "NN-01")]
    problems = list(expect(callback.get("roundtrip_required") is True, "ONB_CALLBACK_UNPROVEN",
                           where,
                           "the callback must be proven by an actual round trip, not by a URL "
                           "somebody typed", "NN-01"))
    problems += expect(callback.get("signature_required") is True, "ONB_CALLBACK_UNSIGNED",
                       where, "the verification callback must verify its signature", "NN-01")
    problems += expect(callback.get("https_required") is True, "ONB_CALLBACK_PLAINTEXT", where,
                       "callback endpoints must be HTTPS", "NN-04")
    problems += expect(callback.get("private_address_allowed") is False, "ONB_CALLBACK_SSRF",
                       where,
                       "a callback URL pointing at a private address asks the platform to "
                       "fetch its own metadata service on the merchant's behalf", "NN-07")
    problems += expect(len(str(callback.get("notes") or "")) >= 8, "ONB_CALLBACK_NOTES", where,
                       "say why a private address is refused", "NN-14")
    return problems


def _credentials(model: dict, where: str) -> list[Problem]:
    credentials = model.get("credentials")
    if not isinstance(credentials, dict):
        return [Problem("ONB_SHAPE", where, "credentials must be an object", "NN-04")]
    problems = list(expect(credentials.get("echo_back_allowed") is False, "ONB_CREDENTIAL_ECHO",
                           where,
                           "an imported credential must never be readable again; the feature "
                           "request is reasonable and the endpoint it produces returns every "
                           "provider secret held", "NN-04"))
    problems += expect(credentials.get("import_once") is True, "ONB_CREDENTIAL_REIMPORT", where,
                       "importing twice must return the same reference, not store a second "
                       "copy that revocation will miss", "NN-04")
    problems += expect(credentials.get("stored_via_binding") is True, "ONB_CREDENTIAL_SIDE_PATH",
                       where,
                       "credentials must go through the B26 binding, not into a table this "
                       "workflow owns", "NN-04")
    problems += expect(len(str(credentials.get("notes") or "")) >= 8, "ONB_CREDENTIAL_NOTES",
                       where, "say why there is no read-back", "NN-14")
    return problems


def _limits(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    limits = model.get("limits")
    if not isinstance(limits, dict):
        return [Problem("ONB_SHAPE", where, "limits must be an object", "NN-01")]
    problems = list(expect(limits.get("must_be_set_before_go_live") is True,
                           "ONB_NO_LIMITS_AT_GO_LIVE", where,
                           "a merchant must not be able to take money before its limits exist",
                           "NN-01"))
    problems += expect(limits.get("raise_requires_approval") is True, "ONB_LIMIT_RAISE_UNGATED",
                       where, "raising a limit is itself a change worth approving", "NN-03")
    if limits.get("default_from_risk_level"):
        budget.check(str(MERCHANT))
        try:
            merchant = load_json(root / MERCHANT)
            levels = {str(r.get("id")) for r in (merchant.get("risk_levels") or [])
                      if isinstance(r, dict)}
        except Exception:
            levels = set()
        problems += expect(bool(levels), "ONB_RISK_LEVELS_UNKNOWN", where,
                           "limits claim to default from the B25 risk levels, but none are "
                           "readable", "NN-12")
    problems += expect(len(str(limits.get("notes") or "")) >= 8, "ONB_LIMIT_NOTES", where,
                       "say when limits must exist", "NN-14")
    return problems


def _suspension(model: dict, where: str) -> list[Problem]:
    suspension = model.get("suspension")
    if not isinstance(suspension, dict):
        return [Problem("ONB_SHAPE", where, "suspension must be an object", "NN-14")]
    approvals = int(suspension.get("approvals_required") or 0)
    problems = list(expect(approvals == 1, "ONB_SUSPEND_NEEDS_APPROVAL", where,
                           f"suspending must take exactly one person, got {approvals}: an "
                           f"approval gate on stopping is time spent waiting during an "
                           f"incident", "NN-14"))
    problems += expect(suspension.get("immediate") is True, "ONB_SUSPEND_DELAYED", where,
                       "suspension must take effect immediately", "NN-14")
    reinstate = int(suspension.get("reinstatement_approvals_required") or 0)
    problems += expect(reinstate >= 2, "ONB_REINSTATE_SINGLE_PERSON", where,
                       f"reinstating must take at least two people, got {reinstate}; the "
                       f"asymmetry with suspension is the point", "NN-03")
    problems += expect(len(str(suspension.get("notes") or "")) >= 8, "ONB_SUSPENSION_NOTES",
                       where, "say why stopping and restarting are not symmetric", "NN-14")
    return problems


def _audit_binding(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    event_class = str(model.get("audit_event_class") or "")
    budget.check(str(AUDIT))
    try:
        audit = load_json(root / AUDIT)
        classes = {str(c.get("id")) for c in (audit.get("event_classes") or [])
                   if isinstance(c, dict)}
    except Exception:
        classes = set()
    problems = list(expect(event_class in classes, "ONB_AUDIT_CLASS_UNKNOWN", where,
                           f"onboarding events are recorded as '{event_class}', which "
                           f"governance/audit-log.json does not define", "NN-13"))
    budget.check(str(ACCOUNTS))
    try:
        accounts = load_json(root / ACCOUNTS)
        activation = accounts.get("activation") or {}
    except Exception:
        activation = {}
    problems += expect(activation.get("callback_roundtrip_required") is True,
                       "ONB_GO_LIVE_UNPROVEN", where,
                       "B26 must still require a callback round trip before a binding becomes "
                       "active; this workflow's go-live step is that transition", "NN-01")
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .onboardinggen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("ONB_GENERATED", rel, f"cannot generate {rel}: {exc}",
                                    "NN-12"))
            continue
        if not path.is_file():
            problems.append(Problem("ONB_GENERATED_MISSING", rel,
                                    f"{rel} is generated from "
                                    f"governance/onboarding-workflow.json but does not exist; "
                                    f"run scripts/render-onboarding.py", "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("ONB_GENERATED_DRIFT", rel,
                                    f"{rel} differs from what the model generates", "NN-12"))
    return problems
