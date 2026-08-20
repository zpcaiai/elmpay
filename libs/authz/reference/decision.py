"""B19 — an executable authorisation decision function.

The point of this module is the **order** in which it says no, and the fact
that it never returns data on the way to saying no. Reading it top to bottom is
the specification:

1. is the permission a permission at all?
2. is it granted — standing, or through an elevation that is still alive?
3. does the request stay inside the caller's tenant?
4. does the *object* belong to that tenant?
5. for money movement: is the approver a different person, holding the right
   permission, with an approval that is fresh and bound to *this* request?
6. which of the requested fields may be returned, and which come back masked?

Step 5 contains the rule this whole batch exists for: **the person who asked
may not be the person who approves**, and an approval that is not bound to the
digest of the request it approves can be replayed onto a different payout.

There is no cryptography here. Approvals carry an opaque ``request_digest``
string; whether that digest is computed and signed correctly belongs to the
implementation batches. What is proven here is that the decision function
*requires* the binding, and that it refuses in the right order.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ALLOW = "ALLOW"
DENY_UNKNOWN_PERMISSION = "DENY_UNKNOWN_PERMISSION"
DENY_UNKNOWN_ROLE = "DENY_UNKNOWN_ROLE"
DENY_NOT_GRANTED = "DENY_NOT_GRANTED"
DENY_ELEVATION_REQUIRED = "DENY_ELEVATION_REQUIRED"
DENY_ELEVATION_EXPIRED = "DENY_ELEVATION_EXPIRED"
DENY_ELEVATION_REVOKED = "DENY_ELEVATION_REVOKED"
DENY_CROSS_TENANT = "DENY_CROSS_TENANT"
DENY_OBJECT_OWNERSHIP = "DENY_OBJECT_OWNERSHIP"
DENY_MISSING_APPROVAL = "DENY_MISSING_APPROVAL"
DENY_SELF_APPROVAL = "DENY_SELF_APPROVAL"
DENY_APPROVER_NOT_PERMITTED = "DENY_APPROVER_NOT_PERMITTED"
DENY_APPROVAL_EXPIRED = "DENY_APPROVAL_EXPIRED"
DENY_APPROVAL_NOT_BOUND = "DENY_APPROVAL_NOT_BOUND"
DENY_SEPARATION_OF_DUTIES = "DENY_SEPARATION_OF_DUTIES"
DENY_FORBIDDEN_FIELD = "DENY_FORBIDDEN_FIELD"


@dataclass(frozen=True)
class Elevation:
    permission: str
    approved_by: str
    ticket: str
    expires_at: int
    revoked: bool = False


@dataclass(frozen=True)
class Principal:
    id: str
    role: str
    tenant: str
    elevations: tuple[Elevation, ...] = ()


@dataclass(frozen=True)
class Approval:
    approver: str
    approver_role: str
    request_digest: str
    issued_at: int


@dataclass(frozen=True)
class Resource:
    id: str
    tenant: str
    created_by: str | None = None


@dataclass(frozen=True)
class Request:
    permission: str
    tenant: str
    now: int
    digest: str = ""
    resource: Resource | None = None
    fields: tuple[str, ...] = ()
    approval: Approval | None = None


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    masked_fields: tuple[str, ...] = ()
    audit: dict[str, Any] = field(default_factory=dict)


class Model:
    """The authorisation model, loaded from governance/authorization.json."""

    def __init__(self, document: dict) -> None:
        self.version = document["schema_version"]
        self.default_decision = document["default_decision"]
        self.roles = {r["id"]: r for r in document["roles"]}
        self.permissions = {p["id"]: p for p in document["permissions"]}
        self.fields = {f["field"]: f for f in document["field_rules"]}
        self.sod = document["separation_of_duties"]
        self.dual_control = document["dual_control"]
        self.elevation = document["elevation"]

    # -- grants -----------------------------------------------------------
    def grants(self, role: str) -> set[str]:
        entry = self.roles.get(role)
        return set(entry["permissions"]) if entry else set()

    def may_approve(self, role: str, permission: str) -> bool:
        """Could this role legitimately exercise the permission it is approving?

        Holding it standing is the ordinary case. An elevation-only permission
        is held by nobody standing, so the test there is whether the role is one
        that may be elevated to it at all — otherwise an elevation-gated action
        could be approved by someone who would never be allowed to perform it.
        """
        if permission in self.grants(role):
            return True
        if permission not in self.elevation["elevatable_permissions"]:
            return False
        if role not in self.roles or role in self.elevation["non_elevatable_roles"]:
            return False
        return bool(self.roles[role].get("privileged"))

    def conflicting(self, permission: str) -> set[str]:
        """Permissions that may not be exercised on the same object by one person."""
        other: set[str] = set()
        for rule in self.sod:
            if rule["left"] == permission:
                other.add(rule["right"])
            elif rule["right"] == permission:
                other.add(rule["left"])
        return other

    def grant_elevation(self, *, requester: Principal, permission: str, approver: str,
                        ticket: str, minutes: int, now: int) -> Elevation:
        """Issue a time-boxed grant, or refuse to.

        Refusing here matters as much as refusing in :func:`decide`: an
        elevation that should never have been issued is indistinguishable from
        standing privilege for as long as it lives.
        """
        elev = self.elevation
        if permission not in self.permissions:
            raise ValueError(f"unknown permission {permission!r}")
        if permission not in elev["elevatable_permissions"]:
            raise ValueError(f"{permission!r} is not elevatable")
        if requester.role in elev["non_elevatable_roles"]:
            raise ValueError(f"role {requester.role!r} may never be elevated")
        if elev["approver_must_differ_from_requester"] and approver == requester.id:
            raise ValueError("an elevation may not be approved by its requester")
        if elev["requires_ticket_reference"] and not ticket:
            raise ValueError("an elevation requires a ticket reference")
        limit = elev["max_duration_minutes"]
        if requester.role == elev["break_glass"]["role"]:
            limit = min(limit, elev["break_glass"]["max_duration_minutes"])
        if minutes <= 0 or minutes > limit:
            raise ValueError(f"elevation of {minutes} minutes exceeds the {limit} minute limit")
        return Elevation(permission=permission, approved_by=approver, ticket=ticket,
                         expires_at=now + minutes * 60)

    def active_elevation(self, principal: Principal, permission: str,
                         now: int) -> tuple[Elevation | None, str | None]:
        found: Elevation | None = None
        reason: str | None = None
        for grant in principal.elevations:
            if grant.permission != permission:
                continue
            if grant.revoked:
                reason = DENY_ELEVATION_REVOKED
                continue
            if grant.expires_at <= now:
                reason = DENY_ELEVATION_EXPIRED
                continue
            return grant, None
        return found, reason


def decide(model: Model, principal: Principal, request: Request) -> Decision:
    audit: dict[str, Any] = {
        "principal": principal.id,
        "role": principal.role,
        "permission": request.permission,
        "tenant": request.tenant,
        "resource": request.resource.id if request.resource else None,
        "rule_version": model.version,
    }

    def deny(reason: str) -> Decision:
        return Decision(False, reason, (), {**audit, "decision": "deny", "reason": reason})

    permission = model.permissions.get(request.permission)
    if permission is None:
        return deny(DENY_UNKNOWN_PERMISSION)
    if principal.role not in model.roles:
        return deny(DENY_UNKNOWN_ROLE)

    granted = request.permission in model.grants(principal.role)
    if not granted:
        grant, failure = model.active_elevation(principal, request.permission, request.now)
        if grant is None:
            return deny(failure or DENY_NOT_GRANTED)
        audit["elevation_ticket"] = grant.ticket
    elif permission.get("elevation_required"):
        # A standing grant of an elevation-only permission is a modelling error;
        # refuse it at runtime too rather than trusting the model to be right.
        return deny(DENY_ELEVATION_REQUIRED)

    role = model.roles[principal.role]
    cross_tenant = request.tenant != principal.tenant
    if cross_tenant:
        may_cross = role["scope"] == "platform" and (
            "cross_tenant_data.read" in model.grants(principal.role)
            or model.active_elevation(principal, "cross_tenant_data.read", request.now)[0]
            is not None)
        if not may_cross:
            return deny(DENY_CROSS_TENANT)

    if request.resource is not None and request.resource.tenant != request.tenant:
        return deny(DENY_OBJECT_OWNERSHIP)

    if permission.get("dual_control"):
        approval = request.approval
        if approval is None:
            return deny(DENY_MISSING_APPROVAL)
        if model.dual_control["approver_must_differ_from_requester"] and \
                approval.approver == principal.id:
            return deny(DENY_SELF_APPROVAL)
        if not model.may_approve(approval.approver_role, request.permission):
            return deny(DENY_APPROVER_NOT_PERMITTED)
        age = request.now - approval.issued_at
        if age < 0 or age > model.dual_control["approval_ttl_seconds"]:
            return deny(DENY_APPROVAL_EXPIRED)
        if model.dual_control["approval_bound_to_request_digest"] and \
                approval.request_digest != request.digest:
            return deny(DENY_APPROVAL_NOT_BOUND)
        # Maker/checker on the *instance*: whoever created the thing may not be
        # the one who approves it, no matter which permissions they hold.
        if request.resource is not None and request.resource.created_by in {principal.id,
                                                                            approval.approver}:
            return deny(DENY_SEPARATION_OF_DUTIES)
        held = model.grants(principal.role)
        if model.conflicting(request.permission) & held:
            return deny(DENY_SEPARATION_OF_DUTIES)

    masked: list[str] = []
    for name in request.fields:
        rule = model.fields.get(name)
        if rule is None:
            continue
        if rule.get("never_readable"):
            return deny(DENY_FORBIDDEN_FIELD)
        if rule.get("masked_by_default") and principal.role not in rule.get("readable_by", []):
            masked.append(name)

    return Decision(True, ALLOW, tuple(masked),
                    {**audit, "decision": "allow", "reason": ALLOW,
                     "masked_fields": tuple(masked)})
