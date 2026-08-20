"""B19 — authorisation: RBAC, ABAC, separation of duties and time-boxed elevation.

B16 said every request must be authorised. B17 and B18 said who the requester
is and how strongly that was proven. This batch answers the remaining question:
**what may that person actually do, and to which row, and to which field.**

Four layers decide it, and the default answer at every layer is deny:

1. the permission must be *granted* (RBAC);
2. the request must stay inside the principal's tenant (ABAC, row level);
3. the object must belong to that tenant (object level);
4. the field must be readable at all (field level — a card PAN never is).

Money moves add a fifth: **the person who asks may not be the person who
approves**. Separation of duties is not an org chart nicety; ``SOD-02``
(``payout_account.write`` + ``payout.approve``) is exactly the pair that lets a
single account redirect any payout to itself without ever changing an amount.

This module is also where the programme's **privileged-role registry** lives.
B16, B17 and B18 each hard-coded their own idea of which roles are privileged,
and each of them wrote that gap down as a known defect. Here the list is a
single fact, and the cross-checks below fail closed if a role declared
privileged has no phishing-resistant MFA requirement, no account-recovery path,
or no zero-trust principal to be authorised as.
"""
from __future__ import annotations

import re
from pathlib import Path

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

AUTHZ = Path("governance/authorization.json")
MFA = Path("governance/mfa.json")
IDENTITY = Path("governance/identity.json")
ZEROTRUST = Path("governance/zero-trust.json")

ROLE_ID = re.compile(r"^[a-z][a-z0-9-]*$")
PERMISSION_ID = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
FIELD_ID = re.compile(r"^[a-z][a-z0-9_]*$")
SOD_ID = re.compile(r"^SOD-[0-9]{2}$")

KINDS = {"human", "service"}
SCOPES = {"self", "tenant", "platform"}
PERMISSION_SCOPES = {"tenant", "object", "field", "platform"}
SENSITIVITIES = {"normal", "high", "money"}
# Card data is not an access-control question. There is no role, no elevation
# and no approval that makes a PAN or a CVV readable on this platform (NN-04).
NEVER_READABLE = {"card_pan", "card_cvv"}


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("authz", "B19")

def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    where = str(AUTHZ)
    budget.check(where)
    try:
        model = load_json(root / AUTHZ)
    except Exception as exc:
        return [Problem("AUTHZ_UNREADABLE", where,
                        f"cannot read the authorisation model: {exc}", "NN-12")]
    if not isinstance(model, dict):
        return [Problem("AUTHZ_SHAPE", where, "the authorisation model must be an object",
                        "NN-12")]

    problems = list(expect(SEMVER.match(str(model.get("schema_version", ""))),
                           "AUTHZ_VERSION_FIELD", where, "schema_version must be semver", "NN-12"))
    problems += expect(len(str(model.get("principle") or "")) >= 20, "AUTHZ_PRINCIPLE", where,
                       "state what the authorisation model actually decides", "NN-11")
    problems += expect(model.get("default_decision") == "deny", "AUTHZ_DEFAULT_DECISION", where,
                       "the default decision must be 'deny'; an allow-by-default model is not an "
                       "authorisation model", "NN-11")

    permissions, problems_ = _permissions(model, where, budget)
    problems += problems_
    roles, problems_ = _roles(model, where, permissions, budget)
    problems += problems_
    problems += _fields(model, where, roles, budget)
    problems += _sod(model, where, permissions, roles, budget)
    problems += _dual_control(model, where)
    problems += _elevation(model, where, permissions, roles)
    problems += _audit(model, where)
    problems += _cross_checks(model, root, where, roles, budget)
    problems += _generated(root, budget)
    return problems


def _permissions(model: dict, where: str, budget: Budget) -> tuple[dict, list[Problem]]:
    problems: list[Problem] = []
    permissions: dict[str, dict] = {}
    entries = model.get("permissions")
    if not isinstance(entries, list) or not entries:
        return {}, [Problem("AUTHZ_SHAPE", where, "permissions must be a non-empty list", "NN-12")]
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("AUTHZ_SHAPE", where, "each permission must be an object",
                                    "NN-12"))
            continue
        pid = str(entry.get("id") or "")
        scope = f"{where}#{pid or '<anonymous>'}"
        budget.check(scope)
        problems += expect(PERMISSION_ID.match(pid), "AUTHZ_PERMISSION_ID", scope,
                           f"permission id '{pid}' must look like 'resource.verb'", "NN-12")
        problems += expect(pid not in permissions, "AUTHZ_PERMISSION_DUPLICATE", scope,
                           f"permission '{pid}' is declared twice", "NN-12")
        problems += expect(entry.get("scope") in PERMISSION_SCOPES, "AUTHZ_PERMISSION_SCOPE",
                           scope, f"scope must be one of {sorted(PERMISSION_SCOPES)}", "NN-11")
        problems += expect(entry.get("sensitivity") in SENSITIVITIES, "AUTHZ_PERMISSION_SENSITIVITY",
                           scope, f"sensitivity must be one of {sorted(SENSITIVITIES)}", "NN-11")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "AUTHZ_PERMISSION_NOTES",
                           scope, "say what this permission really lets someone do", "NN-11")
        if entry.get("sensitivity") == "money" and entry.get("verb") in {"approve", "adjust",
                                                                        "write"}:
            problems += expect(entry.get("dual_control") is True, "AUTHZ_MONEY_NO_DUAL_CONTROL",
                               scope,
                               f"'{pid}' moves money or redirects it and must require a second "
                               f"person; single-approver money movement is how one compromised "
                               f"account becomes a loss", "NN-03")
        if pid:
            permissions[pid] = entry
    return permissions, problems


def _roles(model: dict, where: str, permissions: dict,
           budget: Budget) -> tuple[dict, list[Problem]]:
    problems: list[Problem] = []
    roles: dict[str, dict] = {}
    entries = model.get("roles")
    if not isinstance(entries, list) or not entries:
        return {}, [Problem("AUTHZ_SHAPE", where, "roles must be a non-empty list", "NN-12")]
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("AUTHZ_SHAPE", where, "each role must be an object", "NN-12"))
            continue
        rid = str(entry.get("id") or "")
        scope = f"{where}#{rid or '<anonymous>'}"
        budget.check(scope)
        problems += expect(ROLE_ID.match(rid), "AUTHZ_ROLE_ID", scope,
                           f"role id '{rid}' must be kebab-case", "NN-12")
        problems += expect(rid not in roles, "AUTHZ_ROLE_DUPLICATE", scope,
                           f"role '{rid}' is declared twice", "NN-12")
        problems += expect(entry.get("kind") in KINDS, "AUTHZ_ROLE_KIND", scope,
                           f"kind must be one of {sorted(KINDS)}", "NN-12")
        problems += expect(entry.get("scope") in SCOPES, "AUTHZ_ROLE_SCOPE", scope,
                           f"scope must be one of {sorted(SCOPES)}", "NN-11")
        problems += expect(isinstance(entry.get("privileged"), bool), "AUTHZ_ROLE_PRIVILEGED_FLAG",
                           scope, "privileged must be an explicit boolean; this list is the "
                                  "programme's only registry of privileged roles", "NN-11")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "AUTHZ_ROLE_NOTES", scope,
                           "say what this role is for and what it deliberately cannot do", "NN-11")
        granted = entry.get("permissions")
        if not isinstance(granted, list):
            problems.append(Problem("AUTHZ_SHAPE", scope, "permissions must be a list", "NN-12"))
            granted = []
        for pid in granted:
            problems += expect(pid in permissions, "AUTHZ_ROLE_PERMISSION_UNKNOWN", scope,
                               f"role '{rid}' is granted unknown permission '{pid}'", "NN-12")
        if rid:
            roles[rid] = {**entry, "permissions": [p for p in granted if isinstance(p, str)]}

    used = {pid for role in roles.values() for pid in role["permissions"]}
    elevatable = set((model.get("elevation") or {}).get("elevatable_permissions") or [])
    for pid in sorted(permissions):
        problems += expect(pid in used or pid in elevatable, "AUTHZ_PERMISSION_UNUSED", where,
                           f"permission '{pid}' is granted to nobody and cannot be elevated to; "
                           f"a permission nobody can hold is a rule nobody enforces", "NN-12")
    return roles, problems


def _fields(model: dict, where: str, roles: dict, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    seen: set[str] = set()
    entries = model.get("field_rules")
    if not isinstance(entries, list) or not entries:
        return [Problem("AUTHZ_SHAPE", where, "field_rules must be a non-empty list", "NN-12")]
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("AUTHZ_SHAPE", where, "each field rule must be an object",
                                    "NN-12"))
            continue
        field = str(entry.get("field") or "")
        scope = f"{where}#{field or '<anonymous>'}"
        budget.check(scope)
        problems += expect(FIELD_ID.match(field), "AUTHZ_FIELD_NAME", scope,
                           f"field name '{field}' must be snake_case", "NN-12")
        problems += expect(field not in seen, "AUTHZ_FIELD_DUPLICATE", scope,
                           f"field '{field}' is declared twice", "NN-12")
        problems += expect(bool(entry.get("classification")), "AUTHZ_FIELD_CLASSIFICATION", scope,
                           "every governed field needs a classification", "NN-04")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "AUTHZ_FIELD_NOTES", scope,
                           "say why this field is masked and for whom", "NN-04")
        readers = entry.get("readable_by")
        if not isinstance(readers, list):
            readers = []
            problems.append(Problem("AUTHZ_SHAPE", scope, "readable_by must be a list", "NN-12"))
        for role in readers:
            problems += expect(role in roles, "AUTHZ_FIELD_READER_UNKNOWN", scope,
                               f"field '{field}' is readable by unknown role '{role}'", "NN-12")
        if field in NEVER_READABLE:
            problems += expect(entry.get("never_readable") is True, "AUTHZ_FIELD_PAN_READABLE",
                               scope,
                               f"'{field}' must be never_readable; no role, no approval and no "
                               f"elevation makes card data readable here", "NN-04")
            problems += expect(not readers, "AUTHZ_FIELD_PAN_READABLE", scope,
                               f"'{field}' must have an empty readable_by list, got {readers}",
                               "NN-04")
        elif entry.get("never_readable") is not True:
            problems += expect(entry.get("masked_by_default") is True, "AUTHZ_FIELD_MASK", scope,
                               f"'{field}' must be masked by default; a field that is only masked "
                               f"when someone remembers to mask it is not masked", "NN-04")
        seen.add(field)
    for field in sorted(NEVER_READABLE):
        problems += expect(field in seen, "AUTHZ_FIELD_UNGOVERNED", where,
                           f"'{field}' has no field rule at all; the most dangerous field on the "
                           f"platform must not be governed by omission", "NN-04")
    return problems


def _sod(model: dict, where: str, permissions: dict, roles: dict,
         budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    seen: set[str] = set()
    covered: set[str] = set()
    entries = model.get("separation_of_duties")
    if not isinstance(entries, list) or not entries:
        return [Problem("AUTHZ_SHAPE", where,
                        "separation_of_duties must be a non-empty list", "NN-03")]
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("AUTHZ_SHAPE", where, "each SoD rule must be an object",
                                    "NN-12"))
            continue
        sid = str(entry.get("id") or "")
        scope = f"{where}#{sid or '<anonymous>'}"
        budget.check(scope)
        problems += expect(SOD_ID.match(sid), "AUTHZ_SOD_ID", scope,
                           f"SoD id '{sid}' must look like 'SOD-01'", "NN-12")
        problems += expect(sid not in seen, "AUTHZ_SOD_DUPLICATE", scope,
                           f"SoD rule '{sid}' is declared twice", "NN-12")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "AUTHZ_SOD_NOTES", scope,
                           "say what someone holding both sides could actually do", "NN-03")
        left, right = entry.get("left"), entry.get("right")
        known = True
        for side in (left, right):
            if side not in permissions:
                known = False
                problems.append(Problem("AUTHZ_SOD_UNKNOWN_PERMISSION", scope,
                                        f"SoD rule '{sid}' names unknown permission '{side}'",
                                        "NN-12"))
        if known:
            covered.update({left, right})
            for rid, role in sorted(roles.items()):
                held = set(role["permissions"])
                if left in held and right in held:
                    problems.append(Problem(
                        "AUTHZ_SOD_VIOLATION", f"{where}#{rid}",
                        f"role '{rid}' holds both sides of {sid} ('{left}' and '{right}'); "
                        f"one person can then complete the whole flow alone", "NN-03"))
        seen.add(sid)

    for pid, entry in sorted(permissions.items()):
        if entry.get("sensitivity") == "money" and entry.get("dual_control") is True:
            problems += expect(pid in covered, "AUTHZ_SOD_MISSING", where,
                               f"'{pid}' requires two people but appears in no separation-of-duties "
                               f"rule; dual control without SoD only means the same person clicks "
                               f"twice from two accounts", "NN-03")
    return problems


def _dual_control(model: dict, where: str) -> list[Problem]:
    dual = model.get("dual_control")
    if not isinstance(dual, dict):
        return [Problem("AUTHZ_SHAPE", where, "dual_control must be an object", "NN-03")]
    problems = list(expect(int(dual.get("minimum_approvals") or 0) >= 1, "AUTHZ_DUAL_APPROVALS",
                           where, "at least one approval is required for dual-control actions",
                           "NN-03"))
    problems += expect(dual.get("approver_must_differ_from_requester") is True,
                       "AUTHZ_DUAL_SELF_APPROVAL", where,
                       "the approver must differ from the requester; self-approval is dual "
                       "control in name only", "NN-03")
    ttl = int(dual.get("approval_ttl_seconds") or 0)
    problems += expect(0 < ttl <= 3600, "AUTHZ_DUAL_TTL", where,
                       f"an approval must expire within an hour, got {ttl}s; an approval that "
                       f"never expires is a standing permission held by someone else", "NN-03")
    problems += expect(dual.get("approval_bound_to_request_digest") is True,
                       "AUTHZ_DUAL_BINDING", where,
                       "an approval must be bound to the digest of the request it approves, "
                       "otherwise it can be replayed onto a different payout", "NN-03")
    return problems


def _elevation(model: dict, where: str, permissions: dict, roles: dict) -> list[Problem]:
    elev = model.get("elevation")
    if not isinstance(elev, dict):
        return [Problem("AUTHZ_SHAPE", where, "elevation must be an object", "NN-11")]
    problems = list(expect(elev.get("standing_privileged_access") is False,
                           "AUTHZ_STANDING_PRIVILEGE", where,
                           "standing privileged access must be disallowed; a privilege held all "
                           "day is a privilege an attacker inherits at any hour", "NN-11"))
    minutes = int(elev.get("max_duration_minutes") or 0)
    problems += expect(0 < minutes <= 240, "AUTHZ_ELEVATION_DURATION", where,
                       f"an elevation must be short-lived, got {minutes} minutes", "NN-11")
    problems += expect(elev.get("requires_approval") is True, "AUTHZ_ELEVATION_APPROVAL", where,
                       "elevation must be approved by someone else", "NN-03")
    problems += expect(elev.get("approver_must_differ_from_requester") is True,
                       "AUTHZ_ELEVATION_APPROVAL", where,
                       "self-approved elevation is just permanent privilege with extra steps",
                       "NN-03")
    problems += expect(elev.get("requires_ticket_reference") is True, "AUTHZ_ELEVATION_TICKET",
                       where, "every elevation must reference a ticket so the reason survives "
                              "the incident", "NN-13")
    problems += expect(elev.get("auto_revoke") is True, "AUTHZ_ELEVATION_AUTO_REVOKE", where,
                       "elevation must be revoked automatically; a privilege that relies on "
                       "someone remembering to hand it back is permanent", "NN-11")

    elevatable = elev.get("elevatable_permissions")
    if not isinstance(elevatable, list) or not elevatable:
        problems.append(Problem("AUTHZ_SHAPE", where,
                                "elevatable_permissions must be a non-empty list", "NN-11"))
        elevatable = []
    for pid in elevatable:
        problems += expect(pid in permissions, "AUTHZ_ELEVATION_UNKNOWN_PERMISSION", where,
                           f"unknown elevatable permission '{pid}'", "NN-12")

    for pid, entry in sorted(permissions.items()):
        if entry.get("elevation_required") is not True:
            continue
        problems += expect(pid in elevatable, "AUTHZ_ELEVATION_UNKNOWN_PERMISSION", where,
                           f"'{pid}' requires elevation but is not listed as elevatable, so "
                           f"nobody can ever obtain it", "NN-12")
        for rid, role in sorted(roles.items()):
            if pid in role["permissions"]:
                problems.append(Problem(
                    "AUTHZ_STANDING_ELEVATED", f"{where}#{rid}",
                    f"'{pid}' requires elevation but role '{rid}' holds it standing; the "
                    f"elevation flow is then decorative", "NN-11"))

    non_elevatable = elev.get("non_elevatable_roles")
    if not isinstance(non_elevatable, list):
        non_elevatable = []
        problems.append(Problem("AUTHZ_SHAPE", where, "non_elevatable_roles must be a list",
                                "NN-12"))
    for rid in non_elevatable:
        problems += expect(rid in roles, "AUTHZ_ELEVATION_UNKNOWN_ROLE", where,
                           f"unknown non-elevatable role '{rid}'", "NN-12")
    problems += expect("auditor" not in roles or "auditor" in non_elevatable,
                       "AUTHZ_AUDITOR_ELEVATABLE", where,
                       "the auditor role must not be elevatable; an auditor who can change what "
                       "they audit is not an auditor", "NN-03")

    glass = elev.get("break_glass")
    if not isinstance(glass, dict):
        return problems + [Problem("AUTHZ_SHAPE", where, "break_glass must be an object", "NN-11")]
    glass_minutes = int(glass.get("max_duration_minutes") or 0)
    problems += expect(0 < glass_minutes <= minutes, "AUTHZ_BREAK_GLASS_DURATION", where,
                       f"break-glass access ({glass_minutes} min) must not outlast ordinary "
                       f"elevation ({minutes} min)", "NN-11")
    problems += expect(0 < int(glass.get("post_use_review_hours") or 0) <= 72,
                       "AUTHZ_BREAK_GLASS_REVIEW", where,
                       "every break-glass use must be reviewed by a human within days; an "
                       "unreviewed emergency path is a permanent back door", "NN-13")
    problems += expect(len(glass.get("notify_channels") or []) >= 2,
                       "AUTHZ_BREAK_GLASS_NOTIFY", where,
                       "break-glass use must notify more than one channel", "NN-13")
    return problems


def _audit(model: dict, where: str) -> list[Problem]:
    audit = model.get("audit")
    if not isinstance(audit, dict):
        return [Problem("AUTHZ_SHAPE", where, "audit must be an object", "NN-13")]
    problems = list(expect(audit.get("record_every_decision") is True, "AUTHZ_AUDIT_DECISIONS",
                           where, "every authorisation decision must be recorded", "NN-13"))
    problems += expect(audit.get("record_denials") is True, "AUTHZ_AUDIT_DENIALS", where,
                       "denials must be recorded too; the attempts are the signal", "NN-13")
    problems += expect(audit.get("include_rule_version") is True, "AUTHZ_AUDIT_RULE_VERSION",
                       where, "record which rule version decided, so 'why was this allowed' is "
                              "answerable later", "NN-13")
    problems += expect(audit.get("immutable") is True, "AUTHZ_AUDIT_IMMUTABLE", where,
                       "the authorisation audit trail must be append-only", "NN-13")
    return problems


def _cross_checks(model: dict, root: Path, where: str, roles: dict,
                  budget: Budget) -> list[Problem]:
    """The privileged-role registry, enforced against B16, B17 and B18.

    B16 (``ZT_HIGH_RISK``), B17 (``ID_RECOVERY_UNCOVERED``) and B18
    (``MFA_ROLE_UNCOVERED``) each hard-coded their own privileged-role list and
    recorded the gap honestly. This is the backfill: declaring a role
    privileged here is what makes those three obligations real.
    """
    problems: list[Problem] = []
    privileged = sorted(rid for rid, role in roles.items() if role.get("privileged") is True)
    problems += expect(privileged, "AUTHZ_NO_PRIVILEGED_ROLE", where,
                       "no role is marked privileged; either the model is wrong or nobody can "
                       "operate the platform", "NN-11")

    def _read(rel: Path) -> dict:
        budget.check(str(rel))
        try:
            data = load_json(root / rel)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    mfa = _read(MFA)
    requirements = {str(r.get("role")): r for r in (mfa.get("requirements") or [])
                    if isinstance(r, dict)}
    identity = _read(IDENTITY)
    recovery = {str(r.get("subject")) for r in (identity.get("recovery") or [])
                if isinstance(r, dict)}
    zerotrust = _read(ZEROTRUST)
    principals = {str(p.get("id")) for p in (zerotrust.get("principals") or [])
                  if isinstance(p, dict)}

    for rid in privileged:
        scope = f"{where}#{rid}"
        requirement = requirements.get(rid)
        problems += expect(requirement is not None, "AUTHZ_ROLE_NO_MFA", scope,
                           f"privileged role '{rid}' has no MFA requirement in "
                           f"governance/mfa.json", "NN-11")
        if requirement is not None:
            problems += expect(requirement.get("required_class") == "phishing_resistant",
                               "AUTHZ_ROLE_NO_MFA", scope,
                               f"privileged role '{rid}' must require phishing-resistant MFA, "
                               f"got '{requirement.get('required_class')}'", "NN-11")
        problems += expect(rid in recovery, "AUTHZ_ROLE_NO_RECOVERY", scope,
                           f"privileged role '{rid}' has no account-recovery path in "
                           f"governance/identity.json; recovery is how privileged accounts are "
                           f"actually taken over", "NN-11")

    for rid, role in sorted(roles.items()):
        principal = role.get("zero_trust_principal")
        problems += expect(principal in principals, "AUTHZ_ROLE_NO_ZT_PRINCIPAL",
                           f"{where}#{rid}",
                           f"role '{rid}' maps to zero-trust principal '{principal}', which "
                           f"governance/zero-trust.json does not define", "NN-11")
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .authzgen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("AUTHZ_GENERATED", rel,
                                    f"cannot generate {rel} from the authorisation model: {exc}",
                                    "NN-12"))
            continue
        if not path.is_file():
            problems.append(Problem("AUTHZ_GENERATED_MISSING", rel,
                                    f"{rel} is generated from governance/authorization.json but "
                                    f"does not exist; run scripts/render-authz.py", "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("AUTHZ_GENERATED_DRIFT", rel,
                                    f"{rel} differs from what the authorisation model generates; "
                                    f"edit governance/authorization.json, not the artefact",
                                    "NN-12"))
    return problems
