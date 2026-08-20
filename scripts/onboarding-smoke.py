#!/usr/bin/env python3
"""B30 runtime proof — the workflow survives a failure at step four.

Scenario 2 is why this batch exists. Go-live fails halfway; the case is resumed
the next morning and continues from where it stopped, without re-importing the
credential or re-emitting the side effect. The alternative — restart from step
one, or set the state by hand — is how approval trails become decoration.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.onboarding.reference.workflow import (  # noqa: E402
    ALREADY_LIVE, APPROVAL_EXPIRED, APPROVAL_STALE, CALLBACK_NOT_HTTPS,
    CALLBACK_PRIVATE_ADDRESS, CASE_EXPIRED, COMPLETE, CREDENTIAL_NOT_READABLE,
    DOMAIN_TOKEN_EXPIRED, DOMAIN_TOKEN_USED, DOMAIN_WILDCARD, MANUAL_COMPLETION,
    NOT_APPROVED, NOT_ENOUGH_EYES, NOT_SUSPENDED, NO_LIMITS, OUT_OF_ORDER, SELF_APPROVAL,
    SUSPENDED, UNKNOWN_STEP, Workflow, WorkflowRefused)

MODEL = json.loads((ROOT / "governance/onboarding-workflow.json").read_text(encoding="utf-8"))

CHECKS: list[str] = []
FAILURES: list[str] = []
HOUR = 1000


def check(label: str, condition: bool, detail: object = "") -> None:
    CHECKS.append(label)
    detail = "" if detail == "" else str(detail)
    status = "OK " if condition else "FAIL"
    print(f"[{status}] {label}{(' — ' + detail) if detail else ''}")
    if not condition:
        FAILURES.append(label)


def refuses(fn, code: str) -> bool:
    try:
        fn()
        return False
    except WorkflowRefused as exc:
        return exc.code == code


def payload() -> dict:
    return {"tenant_id": "ten_1", "provider": "stripe",
            "payout_account": "acct_original", "limits": {}, "domains": ["shop.example.com"]}


def opened(flow: Workflow, hour: int = HOUR):
    return flow.start("case_1", tenant_id="ten_1", provider="stripe", requester="ops",
                      payload=payload(), hour=hour)


def through_limits(flow: Workflow, case, hour: int = HOUR) -> None:
    flow.import_credentials(case, "kms://binding/1", hour=hour)
    flow.verify_domain(case, "shop.example.com", "tok_1", issued_at_hour=hour, hour=hour)
    flow.verify_callback(case, "https://shop.example.com/hook", roundtrip_id="rt_1",
                         signature_valid=True, hour=hour)
    flow.set_limits(case, {"daily_limit_minor": 100000}, hour=hour)


def main() -> int:
    flow = Workflow(MODEL)
    case = opened(flow)

    # 1. steps run in order, produce evidence, and are idempotent
    check("乱序执行被拒",
          refuses(lambda: flow.execute(case, "go_live", evidence="x", hour=HOUR),
                  OUT_OF_ORDER))
    check("未知步骤被拒",
          refuses(lambda: flow.execute(case, "make_coffee", evidence="x", hour=HOUR),
                  UNKNOWN_STEP))
    flow.import_credentials(case, "kms://binding/1", hour=HOUR)
    check("凭证导入产生一次副作用",
          flow.side_effect_count(case, "import_credentials") == 1)
    check("重复导入返回同一引用且不再产生副作用",
          flow.import_credentials(case, "kms://binding/2", hour=HOUR) == "kms://binding/1"
          and flow.side_effect_count(case, "import_credentials") == 1)
    check("导入的凭证不能被读回",
          refuses(lambda: flow.read_credential(case), CREDENTIAL_NOT_READABLE))

    # 2. THE scenario — resume after a failure, without replaying
    check("恢复时指向下一个未完成步骤",
          flow.resume(case, HOUR) == "verify_domain")
    flow.verify_domain(case, "shop.example.com", "tok_1", issued_at_hour=HOUR, hour=HOUR)
    check("重复执行已完成步骤返回 ALREADY_DONE 而不是重跑",
          flow.execute(case, "verify_domain", evidence="tok_1", hour=HOUR) == "ALREADY_DONE")
    check("重复执行没有产生第二次副作用",
          flow.side_effect_count(case, "import_credentials") == 1)
    check("**没有手工完成路径**",
          refuses(lambda: flow.force_complete(case), MANUAL_COMPLETION))
    check("模型禁止手工完成", MODEL["resumption"]["manual_completion_allowed"] is False)
    check("模型禁止重放已完成的副作用",
          MODEL["resumption"]["replay_completed_side_effects"] is False)

    # 3. domain and callback verification refuse the dangerous shapes
    check("通配符域名被拒",
          refuses(lambda: flow.verify_domain(case, "*.example.com", "tok_2",
                                             issued_at_hour=HOUR, hour=HOUR), DOMAIN_WILDCARD))
    check("令牌重用被拒",
          refuses(lambda: flow.verify_domain(case, "other.example.com", "tok_1",
                                             issued_at_hour=HOUR, hour=HOUR),
                  DOMAIN_TOKEN_USED))
    check("过期令牌被拒",
          refuses(lambda: flow.verify_domain(case, "other.example.com", "tok_3",
                                             issued_at_hour=HOUR - 1000, hour=HOUR),
                  DOMAIN_TOKEN_EXPIRED))
    check("非 HTTPS 回调地址被拒",
          refuses(lambda: flow.verify_callback(case, "http://shop.example.com/hook",
                                               roundtrip_id="rt", signature_valid=True,
                                               hour=HOUR), CALLBACK_NOT_HTTPS))
    check("指向内网的回调地址被拒——这是让平台替人访问自己元数据服务的请求",
          refuses(lambda: flow.verify_callback(case, "https://169.254.169.254/latest",
                                               roundtrip_id="rt", signature_valid=True,
                                               hour=HOUR), CALLBACK_PRIVATE_ADDRESS))
    flow.verify_callback(case, "https://shop.example.com/hook", roundtrip_id="rt_1",
                         signature_valid=True, hour=HOUR)

    # 4. limits before go-live, and approval bound to content
    check("没有限额不能上线",
          refuses(lambda: flow.go_live(case, hour=HOUR), OUT_OF_ORDER))
    flow.set_limits(case, {"daily_limit_minor": 100000}, hour=HOUR)
    check("未批准不能上线",
          refuses(lambda: flow.go_live(case, hour=HOUR), NOT_APPROVED))
    check("申请人不能批准自己",
          refuses(lambda: flow.approve(case, approvers=("ops", "risk"), hour=HOUR),
                  SELF_APPROVAL))
    check("一个人批准不够",
          refuses(lambda: flow.approve(case, approvers=("risk",), hour=HOUR),
                  NOT_ENOUGH_EYES))
    approval = flow.approve(case, approvers=("risk", "finance"), hour=HOUR)
    check("批准绑定内容摘要", approval.digest == flow.digest(case))
    check("批准后立即有效", flow.approval_valid(case, HOUR))

    # 5. THE bypass — approve, then change the payout account
    flow.amend(case, payout_account="acct_attacker")
    check("改收款账户后批准作废", case.approval is None)
    check("作废后不能上线",
          refuses(lambda: flow.go_live(case, hour=HOUR), NOT_APPROVED))
    flow.amend(case, payout_account="acct_original")
    flow.approve(case, approvers=("risk", "finance"), hour=HOUR)
    stale = Workflow(MODEL)
    stale_case = opened(stale)
    through_limits(stale, stale_case)
    stale.approve(stale_case, approvers=("risk", "finance"), hour=HOUR)
    stale_case.payload["payout_account"] = "acct_attacker"   # bypassing amend()
    check("即使绕过 amend()，上线时也会发现摘要不符",
          refuses(lambda: stale.go_live(stale_case, hour=HOUR), APPROVAL_STALE))
    expired = Workflow(MODEL)
    expired_case = opened(expired)
    through_limits(expired, expired_case)
    expired.approve(expired_case, approvers=("risk", "finance"), hour=HOUR)
    check("批准会过期",
          refuses(lambda: expired.go_live(expired_case,
                                          hour=HOUR + MODEL["approval"]["expires_hours"] + 1),
                  APPROVAL_EXPIRED))

    # 6. go live once, stop easily, restart with two people
    check("上线成功", flow.go_live(case, hour=HOUR) == "LIVE")
    check("重复上线被拒", refuses(lambda: flow.go_live(case, hour=HOUR), ALREADY_LIVE))
    check("停用一个人就能做且立即生效",
          flow.suspend(case, actor="risk", hour=HOUR) == SUSPENDED)
    check("恢复一个人不够",
          refuses(lambda: flow.reinstate(case, actor="risk", approvers=("risk",), hour=HOUR),
                  NOT_ENOUGH_EYES))
    check("恢复需要两个人",
          flow.reinstate(case, actor="ops", approvers=("risk", "finance"), hour=HOUR)
          == COMPLETE)
    check("未停用时不能恢复",
          refuses(lambda: flow.reinstate(case, actor="ops", approvers=("risk", "finance"),
                                         hour=HOUR), NOT_SUSPENDED))

    # 7. a half-finished case expires
    old = Workflow(MODEL)
    old_case = opened(old, hour=0)
    check("半途而废的接入会过期",
          refuses(lambda: old.resume(old_case, MODEL["resumption"]["max_resume_days"] * 24 + 1),
                  CASE_EXPIRED))

    # 8. the model itself
    check("审批步骤在上线之前",
          next(s for s in MODEL["steps"] if s["id"] == "approve")["order"]
          < next(s for s in MODEL["steps"] if s["id"] == "go_live")["order"])
    check("每个步骤都幂等且可恢复",
          all(s["idempotent"] and s["resumable"] for s in MODEL["steps"]))
    check("每个步骤都产出证据", all(s["evidence_required"] for s in MODEL["steps"]))
    check("摘要覆盖收款账户与限额",
          {"payout_account", "limits"} <= set(MODEL["approval"]["digest_fields"]))
    check("停用一人、恢复两人",
          MODEL["suspension"]["approvals_required"] == 1
          and MODEL["suspension"]["reinstatement_approvals_required"] >= 2)

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
