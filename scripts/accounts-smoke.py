#!/usr/bin/env python3
"""B26 runtime proof — two tenants, one amount, one second, no guessing.

Scenario 3 is why this batch exists. Two tenants hold provider accounts that
look identical from outside — same provider, same amount, same second. A
callback arrives whose attribution field matches both. Every "helpful" fallback
(closest amount, nearest timestamp, most recent binding) books one merchant's
money against the other. This model quarantines instead, and there is no
argument to make it choose.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.provider.reference.binding import (  # noqa: E402
    ACTIVE, ATTRIBUTION_AMBIGUOUS, ATTRIBUTION_NONE, CALLBACK_STALE, DENY_BLIND_REPLAY,
    DENY_CREDENTIAL_DESTROYED, DENY_CROSS_TENANT, DENY_DUPLICATE_BINDING, DENY_IMMUTABLE,
    DENY_LEASE_EXPIRED, DENY_NOT_ALLOWED, DENY_REQUIREMENT, DENY_RETURN_PAGE,
    DENY_SELF_APPROVAL, DENY_SHARED_CREDENTIAL, REVOKED, SIGNATURE_INVALID, SUSPENDED,
    Binding, BindingRefused, Bindings, Callback, Credential, sign)

MODEL = json.loads((ROOT / "governance/provider-accounts.json").read_text(encoding="utf-8"))

CHECKS: list[str] = []
FAILURES: list[str] = []
NOW = 1_700_000_000


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
    except BindingRefused as exc:
        return exc.code == code


def binding(tenant="ten_1", project="prj_1", environment="live", provider="wechat",
            mid="mch_provider_1", endpoint="ep_1") -> Binding:
    return Binding(tenant_id=tenant, project_id=project, environment=environment,
                   provider=provider, provider_merchant_id=mid, endpoint_id=endpoint)


def credential(secret: bytes, cid="cred_1") -> Credential:
    return Credential(id=cid, secret=secret, issued_at=NOW - 86400, rotates_after=90)


def callback(secret: bytes, *, mid="mch_provider_1", event="evt_1", provider="wechat",
             environment="live", sent_at=NOW, source="provider", amount=9900) -> Callback:
    payload = {"amount_minor": amount, "currency": "CNY", "event": event}
    return Callback(provider=provider, environment=environment, provider_event_id=event,
                    payload=payload, signature=sign(secret, payload), sent_at=sent_at,
                    attribution={"provider_merchant_id": mid, "endpoint_id": "ep_1"},
                    source=source)


def main() -> int:
    registry = Bindings(MODEL)
    secret_a = b"tenant-a-secret"
    first = registry.bind(binding())
    registry.install(first, credential(secret_a))

    # 1. an unproven binding cannot take money, and cannot be talked into it
    check("待验证的绑定不能发起支付", registry.may(first, "initiate_payment") is False)
    check("填个表单不算激活",
          refuses(lambda: registry.activate(first, test_transaction_settled=True,
                                            callback_roundtrip_verified=False, actor="ops"),
                  DENY_REQUIREMENT))
    registry.activate(first, test_transaction_settled=True, callback_roundtrip_verified=True,
                      actor="ops")
    check("往返验证通过后才激活", first.state == ACTIVE)

    # 2. the binding is immutable and the credential is not shareable
    check("绑定的身份维度不可修改",
          refuses(lambda: registry.rebind(first, tenant_id="ten_2"), DENY_IMMUTABLE))
    check("同一租户同一渠道不能有两条绑定",
          refuses(lambda: registry.bind(binding()), DENY_DUPLICATE_BINDING))
    second = registry.bind(binding(tenant="ten_2", mid="mch_provider_2", endpoint="ep_2"))
    check("同一份凭证不能装在两个绑定上",
          refuses(lambda: registry.install(second, credential(secret_a, "cred_dup")),
                  DENY_SHARED_CREDENTIAL))
    secret_b = b"tenant-b-secret"
    registry.install(second, credential(secret_b, "cred_2"))
    registry.activate(second, test_transaction_settled=True, callback_roundtrip_verified=True,
                      actor="ops")

    # 3. THE scenario — two tenants, same amount, same second
    check("正常回调被唯一归属",
          registry.deliver(callback(secret_a), now=NOW) == "DELIVERED")
    check("渠道重发不会重复记账",
          registry.deliver(callback(secret_a), now=NOW) == "DUPLICATE")
    collision = Bindings(MODEL)
    left = collision.bind(binding(tenant="ten_1", mid="shared_mid"))
    right = collision.bind(binding(tenant="ten_2", mid="shared_mid"))
    collision.install(left, credential(secret_a))
    collision.install(right, credential(secret_b, "cred_2"))
    for entry in (left, right):
        collision.activate(entry, test_transaction_settled=True,
                           callback_roundtrip_verified=True, actor="ops")
    ambiguous = callback(secret_a, mid="shared_mid", event="evt_collision")
    check("两个绑定都匹配时**隔离而不是猜**",
          refuses(lambda: collision.deliver(ambiguous, now=NOW), ATTRIBUTION_AMBIGUOUS))
    check("隔离区记录了原因",
          collision.quarantine and collision.quarantine[-1].reason == ATTRIBUTION_AMBIGUOUS)
    check("没有任何一方被记账", collision.delivered == {})
    check("无法归属的回调也进隔离区",
          refuses(lambda: registry.deliver(callback(secret_a, mid="nobody", event="evt_x"),
                                           now=NOW), ATTRIBUTION_NONE))
    check("自动重放不存在——人工重放必须指名绑定",
          refuses(lambda: collision.replay(collision.quarantine[-1], binding=None, now=NOW),
                  DENY_BLIND_REPLAY))
    check("人工指名归属后可以重放",
          collision.replay(collision.quarantine[-1], binding=left, now=NOW) == "DELIVERED")
    check("模型禁止歧义时猜测", MODEL["callback"]["guess_on_ambiguity"] is False)
    check("模型禁止按金额与时间归属",
          MODEL["forbidden"]["attribution_by_amount_or_time"] is True)

    # 4. signatures, staleness and the return page
    check("验签失败的回调被拒",
          refuses(lambda: registry.deliver(callback(b"wrong-secret", event="evt_2"), now=NOW),
                  SIGNATURE_INVALID))
    check("另一个租户的密钥签的回调也验不过——凭证只对自己的绑定有效",
          refuses(lambda: registry.deliver(callback(secret_b, event="evt_3"), now=NOW),
                  SIGNATURE_INVALID))
    check("超出时窗的回调被拒",
          refuses(lambda: registry.deliver(
              callback(secret_a, event="evt_4",
                       sent_at=NOW - MODEL["callback"]["replay_window_seconds"] - 1), now=NOW),
              CALLBACK_STALE))
    check("客户端回跳页不是支付证据",
          refuses(lambda: registry.deliver(
              callback(secret_a, event="evt_5", source="client_return_page"), now=NOW),
              DENY_RETURN_PAGE))
    check("回调不会投递给别的租户",
          refuses(lambda: registry.deliver(callback(secret_a, event="evt_6"), now=NOW,
                                           to_tenant="ten_2"), DENY_CROSS_TENANT))

    # 5. rotation keeps the in-flight callbacks
    rotated = Bindings(MODEL)
    entry = rotated.bind(binding())
    rotated.install(entry, credential(secret_a))
    rotated.activate(entry, test_transaction_settled=True, callback_roundtrip_verified=True,
                     actor="ops")
    check("一个人不能自己轮换凭证",
          refuses(lambda: rotated.rotate(entry, credential(b"new-secret", "cred_new"), now=NOW,
                                         actor="ops", approver="ops"), DENY_SELF_APPROVAL))
    rotated.rotate(entry, credential(b"new-secret", "cred_new"), now=NOW, actor="ops",
                   approver="sec")
    check("轮换后新密钥可用",
          rotated.deliver(callback(b"new-secret", event="evt_new"), now=NOW) == "DELIVERED")
    check("重叠期内旧密钥签的在途回调仍然收得下",
          rotated.deliver(callback(secret_a, event="evt_old"), now=NOW) == "DELIVERED")
    after = NOW + MODEL["credentials"]["rotation_overlap_days"] * 86400 + 1
    check("重叠期结束后旧密钥失效",
          refuses(lambda: rotated.deliver(callback(secret_a, event="evt_older",
                                                   sent_at=after), now=after),
                  SIGNATURE_INVALID))

    # 6. leases expire
    secret, expires = rotated.lease(entry, now=NOW)
    check("解密租约有期限", rotated.use_lease(expires, now=NOW) == "OK", expires - NOW)
    check("租约过期后不能再用",
          refuses(lambda: rotated.use_lease(expires, now=expires + 1), DENY_LEASE_EXPIRED))
    check("租约拿到的是绑定自己的凭证", secret == b"new-secret")

    # 7. suspension stops new money without dropping the evidence
    suspended = Bindings(MODEL)
    entry = suspended.bind(binding())
    suspended.install(entry, credential(secret_a))
    suspended.activate(entry, test_transaction_settled=True, callback_roundtrip_verified=True,
                       actor="ops")
    suspended.transition(entry, SUSPENDED, satisfied={"reason", "actor"}, actor="risk")
    check("停用后不能发起新支付",
          refuses(lambda: suspended.require(entry, "initiate_payment"), DENY_NOT_ALLOWED))
    check("停用后**仍然接收回调**——否则平台丢掉自己收过钱的证据",
          suspended.deliver(callback(secret_a, event="evt_susp"), now=NOW) == "DELIVERED")
    check("停用后退款与结算仍然放行",
          suspended.may(entry, "issue_refund") and suspended.may(entry, "settle"))
    check("单人无法恢复",
          refuses(lambda: suspended.transition(entry, ACTIVE, satisfied={"reason", "actor"},
                                               actor="ops"), DENY_REQUIREMENT))
    check("在途未结清不能吊销",
          refuses(lambda: suspended.transition(entry, REVOKED,
                                               satisfied={"credential_destroyed"}, actor="ops"),
                  DENY_REQUIREMENT))
    suspended.transition(entry, REVOKED,
                         satisfied={"in_flight_settled", "credential_destroyed"}, actor="ops")
    check("吊销后凭证被销毁", entry.credential is None)
    check("吊销后连回调都收不了",
          refuses(lambda: suspended.deliver(callback(secret_a, event="evt_rev"), now=NOW),
                  DENY_CREDENTIAL_DESTROYED))

    # 8. the model itself
    check("凭证不跨租户、不跨环境、不跨项目",
          not any(MODEL["credentials"][k] for k in
                  ("shared_across_tenants", "shared_across_environments",
                   "shared_across_projects")))
    check("每个渠道都声明了回调归属字段",
          all(p["callback_attribution_field"] for p in MODEL["providers"]))
    check("凭证轮换不慢于包裹它的密钥", MODEL["credentials"]["rotation_max_days"] <= 90)

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
