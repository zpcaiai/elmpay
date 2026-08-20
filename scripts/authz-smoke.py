#!/usr/bin/env python3
"""B19 runtime proof — try to move money alone.

Every scenario below is one person attempting to complete, by themselves, a
flow the model says takes two. The interesting ones are 5 and 6: the maker
holds a perfectly valid approval — it is simply an approval of a *different*
request, or one they gave themselves — and the decision function still refuses.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.authz.reference.decision import (  # noqa: E402
    ALLOW, Approval, DENY_APPROVAL_EXPIRED, DENY_APPROVAL_NOT_BOUND,
    DENY_APPROVER_NOT_PERMITTED, DENY_CROSS_TENANT, DENY_ELEVATION_EXPIRED,
    DENY_ELEVATION_REVOKED, DENY_FORBIDDEN_FIELD, DENY_MISSING_APPROVAL,
    DENY_NOT_GRANTED, DENY_OBJECT_OWNERSHIP, DENY_SELF_APPROVAL,
    DENY_SEPARATION_OF_DUTIES, Model, Principal, Request, Resource, decide)

MODEL = Model(json.loads((ROOT / "governance/authorization.json").read_text(encoding="utf-8")))
NOW = 1_760_000_000

CHECKS: list[str] = []
FAILURES: list[str] = []


def check(label: str, condition: bool, detail: object = "") -> None:
    CHECKS.append(label)
    detail = "" if detail == "" else str(detail)
    status = "OK " if condition else "FAIL"
    print(f"[{status}] {label}{(' — ' + detail) if detail else ''}")
    if not condition:
        FAILURES.append(label)


def refund(created_by: str = "alice", tenant: str = "t-1") -> Resource:
    return Resource(id="rfd-1", tenant=tenant, created_by=created_by)


def approval(approver: str = "carol", role: str = "merchant-finance",
             digest: str = "digest-1", issued_at: int = NOW - 60) -> Approval:
    return Approval(approver=approver, approver_role=role, request_digest=digest,
                    issued_at=issued_at)


def main() -> int:
    finance = Principal(id="bob", role="merchant-finance", tenant="t-1")
    admin = Principal(id="alice", role="merchant-admin", tenant="t-1")
    support = Principal(id="sam", role="support-agent", tenant="t-1")
    operator = Principal(id="opal", role="platform-operator", tenant="platform")

    # 1. happy path: a different person approves, with a bound, fresh approval.
    ok = decide(MODEL, finance, Request(permission="refund.approve", tenant="t-1", now=NOW,
                                        digest="digest-1", resource=refund(),
                                        approval=approval()))
    check("正常路径：财务批准由管理员发起的退款", ok.allowed and ok.reason == ALLOW, ok.reason)
    check("每一次判定都留下审计记录（含规则版本）",
          ok.audit.get("rule_version") == MODEL.version and ok.audit.get("decision") == "allow")

    # 2. default deny.
    denied = decide(MODEL, support, Request(permission="refund.approve", tenant="t-1", now=NOW,
                                            digest="digest-1", resource=refund(),
                                            approval=approval()))
    check("默认拒绝：客服没有批准权限", denied.reason == DENY_NOT_GRANTED, denied.reason)
    check("拒绝也要留审计", denied.audit.get("decision") == "deny")

    # 3. tenant and object boundaries.
    cross = decide(MODEL, finance, Request(permission="payment.read", tenant="t-2", now=NOW))
    check("跨租户读取被拒", cross.reason == DENY_CROSS_TENANT, cross.reason)
    stolen = decide(MODEL, finance, Request(permission="refund.approve", tenant="t-1", now=NOW,
                                            digest="digest-1",
                                            resource=refund(tenant="t-2"),
                                            approval=approval()))
    check("对象属于别的租户时被拒", stolen.reason == DENY_OBJECT_OWNERSHIP, stolen.reason)

    # 4. dual control: no approval at all.
    alone = decide(MODEL, finance, Request(permission="refund.approve", tenant="t-1", now=NOW,
                                           digest="digest-1", resource=refund()))
    check("没有审批的资金动作被拒", alone.reason == DENY_MISSING_APPROVAL, alone.reason)

    # 5. self-approval, and the maker acting as checker.
    myself = decide(MODEL, finance, Request(permission="refund.approve", tenant="t-1", now=NOW,
                                            digest="digest-1", resource=refund(),
                                            approval=approval(approver="bob")))
    check("自己批准自己被拒", myself.reason == DENY_SELF_APPROVAL, myself.reason)
    maker = decide(MODEL, finance, Request(permission="refund.approve", tenant="t-1", now=NOW,
                                           digest="digest-1", resource=refund(created_by="bob"),
                                           approval=approval(approver="carol")))
    check("发起人不能同时是复核人（对象级职责分离）",
          maker.reason == DENY_SEPARATION_OF_DUTIES, maker.reason)

    # 6. the approval is real, but it is not this request's approval.
    replayed = decide(MODEL, finance, Request(permission="refund.approve", tenant="t-1", now=NOW,
                                              digest="digest-2", resource=refund(),
                                              approval=approval(digest="digest-1")))
    check("审批未绑定本次请求时被拒（防重放到另一笔）",
          replayed.reason == DENY_APPROVAL_NOT_BOUND, replayed.reason)
    stale = decide(MODEL, finance, Request(permission="refund.approve", tenant="t-1", now=NOW,
                                           digest="digest-1", resource=refund(),
                                           approval=approval(issued_at=NOW - 4000)))
    check("过期审批被拒", stale.reason == DENY_APPROVAL_EXPIRED, stale.reason)
    unqualified = decide(MODEL, finance,
                         Request(permission="refund.approve", tenant="t-1", now=NOW,
                                 digest="digest-1", resource=refund(),
                                 approval=approval(approver="sam", role="support-agent")))
    check("审批人本身没有该权限时被拒",
          unqualified.reason == DENY_APPROVER_NOT_PERMITTED, unqualified.reason)

    # 7. field level.
    pan = decide(MODEL, admin, Request(permission="customer_pii.read", tenant="t-1", now=NOW,
                                       resource=Resource(id="cus-1", tenant="t-1"),
                                       fields=("card_pan",)))
    check("卡号对任何角色都不可读", pan.reason == DENY_FORBIDDEN_FIELD, pan.reason)
    masked = decide(MODEL, support, Request(permission="payment.read", tenant="t-1", now=NOW,
                                            resource=Resource(id="pay-1", tenant="t-1"),
                                            fields=("customer_email", "bank_account_number")))
    check("客服看到脱敏后的银行账号，联系方式按角色放行",
          masked.allowed and masked.masked_fields == ("bank_account_number",),
          masked.masked_fields)
    full = decide(MODEL, Principal(id="fay", role="merchant-finance", tenant="t-1"),
                  Request(permission="bank_account.read", tenant="t-1", now=NOW,
                          resource=Resource(id="acc-1", tenant="t-1"),
                          fields=("bank_account_number",)))
    check("财务可以看到银行账号全文", full.allowed and full.masked_fields == (), full.masked_fields)

    # 8. elevation.
    before = decide(MODEL, operator, Request(permission="config.write", tenant="platform",
                                             now=NOW, digest="d", approval=approval(
                                                 approver="opa", role="platform-operator")))
    check("没有提权时改配置被拒", before.reason == DENY_NOT_GRANTED, before.reason)
    grant = MODEL.grant_elevation(requester=operator, permission="config.write",
                                  approver="ivan", ticket="OPS-42", minutes=30, now=NOW)
    elevated = Principal(id="opal", role="platform-operator", tenant="platform",
                         elevations=(grant,))
    after = decide(MODEL, elevated, Request(permission="config.write", tenant="platform",
                                            now=NOW, digest="d",
                                            approval=Approval(approver="ivan",
                                                              approver_role="platform-operator",
                                                              request_digest="d",
                                                              issued_at=NOW - 10)))
    check("提权后改配置放行，且审计里带着票据",
          after.allowed and after.audit.get("elevation_ticket") == "OPS-42", after.reason)
    expired = decide(MODEL, elevated, Request(permission="config.write", tenant="platform",
                                              now=NOW + 3600, digest="d",
                                              approval=Approval(approver="ivan",
                                                                approver_role="platform-operator",
                                                                request_digest="d",
                                                                issued_at=NOW + 3590)))
    check("提权到点后自动失效", expired.reason == DENY_ELEVATION_EXPIRED, expired.reason)
    revoked = Principal(id="opal", role="platform-operator", tenant="platform",
                        elevations=(Elevated := grant.__class__(**{**grant.__dict__,
                                                                  "revoked": True}),))
    pulled = decide(MODEL, revoked, Request(permission="config.write", tenant="platform",
                                            now=NOW, digest="d"))
    check("提权被撤销后立即失效", pulled.reason == DENY_ELEVATION_REVOKED, pulled.reason)

    refused = []
    for label, kwargs in (
            ("超过时限", dict(minutes=600)),
            ("自己批准自己提权", dict(approver="opal")),
            ("没有票据", dict(ticket="")),
            ("不可提权的权限", dict(permission="refund.approve")),
    ):
        args = dict(requester=operator, permission="config.write", approver="ivan",
                    ticket="OPS-42", minutes=30, now=NOW)
        args.update(kwargs)
        try:
            MODEL.grant_elevation(**args)
            refused.append(f"{label}: 未被拒绝")
        except ValueError:
            pass
    check("非法提权申请在签发环节就被拒", not refused, refused)

    auditor = Principal(id="ann", role="auditor", tenant="platform")
    try:
        MODEL.grant_elevation(requester=auditor, permission="config.write", approver="ivan",
                              ticket="OPS-42", minutes=10, now=NOW)
        check("审计员不可提权", False)
    except ValueError:
        check("审计员不可提权", True)

    glass = Principal(id="gus", role="break-glass", tenant="platform")
    try:
        MODEL.grant_elevation(requester=glass, permission="cross_tenant_data.read",
                              approver="ivan", ticket="SEC-9", minutes=45, now=NOW)
        check("紧急通道时限比常规提权更短", False)
    except ValueError:
        check("紧急通道时限比常规提权更短", True)

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
