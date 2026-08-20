#!/usr/bin/env python3
"""B25 runtime proof — a payout-account change must not strand the payers.

Scenario 4 is why this batch exists. Changing the payout account is the first
move of an account takeover, so it holds settlement and forces re-verification.
The obvious implementation — suspend the merchant — strands every payer whose
money has already left. Holding only the outbound leg keeps the funds on the
platform until an external authority has looked at the new account.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.merchant.reference.profile import (  # noqa: E402
    DENY_APPROVERS, DENY_AUTHORITY_INCOMPLETE, DENY_CURRENCY, DENY_DOCUMENT_EXPIRED,
    DENY_DOCUMENT_MISSING, DENY_LIMIT, DENY_NOT_ATTESTABLE, DENY_PERMISSION,
    DENY_PROHIBITED_CATEGORY,
    DENY_REVERIFICATION_REQUIRED, DENY_SCREENING_HIT, DENY_SCREENING_STALE,
    DENY_SELF_APPROVAL, DENY_SELF_VERIFIED, DENY_SETTLEMENT_HELD, DENY_UBO_DEPTH,
    DENY_UBO_INCOMPLETE, DENY_VALIDITY_TOO_LONG, MANUAL_REVIEW,
    PENDING_REVIEW, VERIFIED,
    Authority, Document, Onboarding, Owner, ProfileRefused)

MODEL = json.loads((ROOT / "governance/merchant-profile.json").read_text(encoding="utf-8"))

CHECKS: list[str] = []
FAILURES: list[str] = []

DAY = 1000
MERCHANT = "mch_0000000000000001"


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
    except ProfileRefused as exc:
        return exc.code == code


def owners(**overrides) -> tuple[Owner, ...]:
    base = dict(id="ubo_1", percent=60.0, depth=2, has_identity_document=True,
                screened_on=DAY - 10, screening_hit=False)
    base.update(overrides)
    return (Owner(**base), Owner(id="ubo_2", percent=10.0, depth=1, screened_on=DAY - 10),)


def documents(day: int = DAY) -> tuple[Document, ...]:
    return (Document("business_licence", day - 30, "registry"),
            Document("ubo_declaration", day - 30, "merchant"),
            Document("director_identity", day - 30, "government"),
            Document("bank_account_proof", day - 30, "bank"))


def onboarded(engine: Onboarding, *, risk: str = "low", day: int = DAY,
              docs: tuple[Document, ...] | None = None,
              people: tuple[Owner, ...] | None = None) -> None:
    engine.register(MERCHANT, entity_kind="company", category="retail_goods",
                    region="HK", risk=risk)
    for document in (docs if docs is not None else documents(day)):
        engine.attach(MERCHANT, document)
    engine.set_owners(MERCHANT, people if people is not None else owners())


def authority(day: int = DAY) -> Authority:
    return Authority("hk-companies-registry", "CR-2026-000188", day - 5, day + 700)


def main() -> int:
    # 1. the platform cannot verify itself
    engine = Onboarding(MODEL)
    onboarded(engine)
    check("平台不能自己把状态写成「已核验」",
          refuses(lambda: engine.mark_verified(MERCHANT), DENY_SELF_VERIFIED))
    check("没有外部机构决定就不能通过",
          refuses(lambda: engine.decide(MERCHANT, today=DAY, authority=None,
                                        decider="ops", approvers=("risk",)),
                  DENY_SELF_VERIFIED))
    check("机构决定缺字段被拒",
          refuses(lambda: engine.decide(MERCHANT, today=DAY,
                                        authority=Authority("", "CR-1", DAY - 5, DAY + 700),
                                        decider="ops", approvers=("risk",)),
                  DENY_AUTHORITY_INCOMPLETE))
    check("有效期超过上限被拒",
          refuses(lambda: engine.decide(
              MERCHANT, today=DAY,
              authority=Authority("hk", "CR-1", DAY, DAY + MODEL["verification"]
                                  ["max_validity_days"] + 1),
              decider="ops", approvers=("risk",)), DENY_VALIDITY_TOO_LONG))
    check("商户只能自证展示字段",
          refuses(lambda: engine.attest(MERCHANT, "legal_name", "X"), DENY_NOT_ATTESTABLE))
    engine.attest(MERCHANT, "display_name", "示例商店")
    check("材料齐全才能提交复核",
          engine.submit(MERCHANT, DAY).status == PENDING_REVIEW)
    bare = Onboarding(MODEL)
    bare.register("mch_bare", entity_kind="company", category="retail_goods", region="HK")
    check("材料不齐不能提交复核",
          refuses(lambda: bare.submit("mch_bare", DAY), DENY_DOCUMENT_MISSING))
    merchant = engine.decide(MERCHANT, today=DAY, authority=authority(),
                             decider="ops", approvers=("risk",))
    check("引用外部机构决定后才是已核验", merchant.status == VERIFIED)
    check("批准人不能是决定人",
          refuses(lambda: engine.decide(MERCHANT, today=DAY, authority=authority(),
                                        decider="ops", approvers=("ops",)),
                  DENY_SELF_APPROVAL))

    # 2. documents expire, and the payout-account proof expires first
    shortest = min(MODEL["documents"], key=lambda d: d["expires_days"])
    check("有效期最短的是收款账户证明", shortest["id"] == "bank_account_proof", shortest["expires_days"])
    stale = Onboarding(MODEL)
    onboarded(stale, docs=(Document("business_licence", DAY - 30, "registry"),
                           Document("ubo_declaration", DAY - 30, "merchant"),
                           Document("director_identity", DAY - 30, "government"),
                           Document("bank_account_proof", DAY - 200, "bank")))
    check("账户证明过期即视为缺失",
          refuses(lambda: stale.decide(MERCHANT, today=DAY, authority=authority(),
                                       decider="ops", approvers=("risk",)),
                  DENY_DOCUMENT_EXPIRED))

    # 3. ownership must be pierced, and screening must be current
    deep = Onboarding(MODEL)
    onboarded(deep, people=(Owner("ubo_1", 60.0, depth=6, screened_on=DAY - 10),))
    check("股权穿透超过上限被拒",
          refuses(lambda: deep.decide(MERCHANT, today=DAY, authority=authority(),
                                      decider="ops", approvers=("risk",)), DENY_UBO_DEPTH))
    shell = Onboarding(MODEL)
    onboarded(shell, people=(Owner("ubo_1", 10.0, depth=1, screened_on=DAY - 10),
                             Owner("ubo_2", 10.0, depth=1, screened_on=DAY - 10)))
    check("没有人达到 25% 门槛说明穿透没做完",
          refuses(lambda: shell.decide(MERCHANT, today=DAY, authority=authority(),
                                       decider="ops", approvers=("risk",)),
                  DENY_UBO_INCOMPLETE))
    old = Onboarding(MODEL)
    onboarded(old, people=owners(screened_on=DAY - 200))
    check("筛查过期被拒",
          refuses(lambda: old.decide(MERCHANT, today=DAY, authority=authority(),
                                     decider="ops", approvers=("risk",)),
                  DENY_SCREENING_STALE))
    hit = Onboarding(MODEL)
    onboarded(hit, people=owners(screening_hit=True))
    check("命中制裁名单不能自动放行",
          refuses(lambda: hit.decide(MERCHANT, today=DAY, authority=authority(),
                                     decider="ops", approvers=("risk",)), DENY_SCREENING_HIT))
    check("命中后转人工而不是自动拒绝", hit.screen(MERCHANT, DAY) == MANUAL_REVIEW)
    check("模型不允许命中后自动放行", MODEL["screening"]["auto_approve_on_hit"] is False)

    # 4. the payout-account change — hold settlement, keep taking payments
    live = Onboarding(MODEL)
    onboarded(live)
    live.decide(MERCHANT, today=DAY, authority=authority(), decider="ops",
                approvers=("risk",))
    check("核验后可以结算", live.settle(MERCHANT, "HKD", today=DAY) == DAY + 1)
    live.apply_change(MERCHANT, "payout_account_change", actor="attacker",
                      permissions={"payout_account.write"}, today=DAY)
    check("改收款账户后挂起重新核验",
          live.reverification_pending(MERCHANT) == ("payout_account_change",))
    check("改收款账户后结算被暂停",
          refuses(lambda: live.settle(MERCHANT, "HKD", today=DAY), DENY_SETTLEMENT_HELD))
    check("改收款账户后仍然可以收款——不能把在途的付款人晾在半路",
          live.accept_payment(MERCHANT, 1000, today=DAY) == 1000)
    check("发起变更的人不能自己解除暂停",
          refuses(lambda: live.release_hold(MERCHANT, actor="attacker", today=DAY),
                  DENY_SELF_APPROVAL))
    check("未重新核验前别人也解不了",
          refuses(lambda: live.release_hold(MERCHANT, actor="ops", today=DAY),
                  DENY_REVERIFICATION_REQUIRED))
    live.decide(MERCHANT, today=DAY, authority=authority(), decider="ops",
                approvers=("risk",))
    check("重新核验后结算恢复", live.settle(MERCHANT, "HKD", today=DAY) == DAY + 1)
    # 4b. a change that does not hold settlement must not hold settlement
    other = Onboarding(MODEL)
    onboarded(other)
    other.decide(MERCHANT, today=DAY, authority=authority(), decider="ops",
                 approvers=("risk",))
    other.apply_change(MERCHANT, "ubo_change", actor="ops",
                       permissions={"config.write"}, today=DAY)
    check("实际控制人变更挂起复核但不暂停结算",
          other.reverification_pending(MERCHANT) == ("ubo_change",)
          and other.settle(MERCHANT, "HKD", today=DAY) == DAY + 1)
    draft = Onboarding(MODEL)
    draft.register("mch_new", entity_kind="individual", category="retail_goods", region="HK")
    check("未核验的商户不能收款",
          refuses(lambda: draft.accept_payment("mch_new", 1000, today=DAY),
                  DENY_REVERIFICATION_REQUIRED))

    check("没有权限不能发起重大变更",
          refuses(lambda: live.apply_change(MERCHANT, "ubo_change", actor="support",
                                            permissions=set(), today=DAY), DENY_PERMISSION))

    # 5. limits, currency and category
    check("超过单笔限额被拒",
          refuses(lambda: live.accept_payment(MERCHANT, 10 ** 12, today=DAY), DENY_LIMIT))
    check("地区不支持的币种不能结算",
          refuses(lambda: live.settle(MERCHANT, "EUR", today=DAY), DENY_CURRENCY))
    check("禁止类目不能进件",
          refuses(lambda: Onboarding(MODEL).register("mch_x", entity_kind="company",
                                                     category="crypto_exchange", region="HK"),
                  DENY_PROHIBITED_CATEGORY))

    # 6. high risk needs two people, and a rejection can be appealed
    high = Onboarding(MODEL)
    onboarded(high, risk="high")
    check("高风险一个批准人不够",
          refuses(lambda: high.decide(MERCHANT, today=DAY, authority=authority(),
                                      decider="ops", approvers=("risk",)), DENY_APPROVERS))
    check("高风险两个批准人可以通过",
          high.decide(MERCHANT, today=DAY, authority=authority(), decider="ops",
                      approvers=("risk", "compliance")).status == VERIFIED)
    high.reject(MERCHANT, decider="ops", reasons=("材料与登记不一致",), today=DAY)
    check("原判人不能复核自己的拒绝",
          refuses(lambda: high.appeal(MERCHANT, reviewer="ops", today=DAY), DENY_SELF_APPROVAL))
    check("换人复核可以受理",
          high.appeal(MERCHANT, reviewer="compliance", today=DAY).status == MANUAL_REVIEW)

    # 7. the model itself
    check("平台没有把自己声明成持牌核验机构",
          MODEL["verification"]["platform_is_licensed_verifier"] is False)
    check("每一项重大变更都要求重新核验",
          all(c["requires_reverification"] for c in MODEL["material_changes"]))
    check("留存期覆盖五年", MODEL["retention"]["after_offboarding_days"] >= 1825)
    check("留存到期日按离场日推算",
          live.purge_day(DAY) == DAY + MODEL["retention"]["after_offboarding_days"])

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
