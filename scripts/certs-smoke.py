#!/usr/bin/env python3
"""B21 runtime proof — rotate without dropping anyone, then expire on purpose.

Scenario 2 is the one that matters: on the day of a rotation, the *old* key must
still verify. Everything that holds the old material — in-flight tokens, a
provider's cached key set, a pod that has not restarted — switches over some
minutes or hours later, and a rotation that refuses them all at the instant of
the switch is indistinguishable from an outage.

Scenario 5 is its counterweight: revocation must ignore the overlap window
entirely. "Still inside its window" is exactly the excuse an attacker's stolen
certificate would rely on.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.pki.reference.lifecycle import (  # noqa: E402
    EXPIRED, OK, RENEW_DUE, REVOKED, UNAUTHORISED_ISSUER, Estate, LifecycleError)

MODEL = json.loads((ROOT / "governance/certificates.json").read_text(encoding="utf-8"))

CHECKS: list[str] = []
FAILURES: list[str] = []


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
    except LifecycleError as exc:
        return exc.code == code


def main() -> int:
    estate = Estate(MODEL)
    estate.issue_all(day=0)
    token = estate.materials["token-signing"]
    validity = token.validity_days
    margin = token.renew_before_days
    overlap = token.overlap_days

    # 1. ordinary life
    check("刚签发时状态正常", token.status(1) == OK, token.status(1))
    check("进入提前量后提示续期",
          token.status(validity - margin) == RENEW_DUE, token.status(validity - margin))
    check("到期后不再接受", token.status(validity) == EXPIRED, token.status(validity))

    # 2. the overlap window
    rotate_day = validity - margin
    new = token.rotate(rotate_day)
    accepting = token.accepting(rotate_day)
    check("轮换当天新旧两个版本都能验签", accepting == [1, 2], accepting)
    check("重叠期内旧版本仍可验签",
          estate.verify("token-signing", 1, rotate_day + overlap - 1) == OK)
    check("重叠期结束后旧版本被拒",
          refuses(lambda: estate.verify("token-signing", 1, rotate_day + overlap), EXPIRED))
    check("新版本继续可用",
          estate.verify("token-signing", new.serial, rotate_day + overlap) == OK)
    check("轮换后整体状态恢复正常", token.status(rotate_day + overlap) == OK,
          token.status(rotate_day + overlap))

    # 3. rotation never extends past the old material's own expiry
    edge = estate.materials["edge-tls"]
    edge.rotate(edge.validity_days - 1)
    check("重叠期不会把旧材料的寿命拖过它自己的到期日",
          refuses(lambda: estate.verify("edge-tls", 1, edge.validity_days), EXPIRED))

    # 4. renewal failures escalate
    mtls = "internal-mtls"
    escalate = estate.escalate_after
    outcomes = [estate.renewal_failed(mtls) for _ in range(escalate)]
    check("连续续期失败达到阈值即升级人工",
          outcomes[:-1] == [False] * (escalate - 1) and outcomes[-1] is True, outcomes)
    estate.materials[mtls].record_renewal_success()
    check("续期成功后计数归零", estate.materials[mtls].failed_renewals == 0)

    # 5. revocation beats the overlap window
    webhook = estate.materials["webhook-verification"]
    webhook.rotate(10)
    check("撤销前重叠期内可验签", estate.verify("webhook-verification", 1, 11) == OK)
    webhook.revoke(1, 11)
    check("撤销立即生效，重叠期不保护它",
          refuses(lambda: estate.verify("webhook-verification", 1, 11), REVOKED))
    check("撤销只影响那一个版本", estate.verify("webhook-verification", 2, 11) == OK)

    # 6. domains
    check("CAA 之外的签发方被拒",
          refuses(lambda: estate.accept_issued_certificate("internal.pay.example.invalid",
                                                           "public_ca"), UNAUTHORISED_ISSUER))
    check("CAA 之内的签发方被接受",
          estate.accept_issued_certificate("pay.example.invalid", "public_ca") == OK)
    check("全部域名都有注册商锁与 DNSSEC",
          all(d.registrar_lock and d.dnssec for d in estate.domains.values()))

    # 7. what is due — on a fresh estate, so earlier rotations do not mask it
    fresh = Estate(MODEL)
    fresh.issue_all(day=0)
    due = fresh.due(validity - margin)
    check("到期清单包含需要处理的材料（未轮换的实例）", "token-signing" in due, due)
    check("刚签发时没有任何材料到期", fresh.due(1) == [], fresh.due(1))

    # 8. recovery
    check("恢复需要法定人数",
          refuses(lambda: estate.recover(approvals=1, quorum=2), "QUORUM_NOT_MET"))
    check("法定人数满足时可恢复", estate.recover(approvals=2, quorum=2) == OK)

    # 9. every short-lived material renews itself
    short = [m for m in MODEL["materials"] if m["validity_days"] <= 30]
    check("短寿命材料全部自动续期", all(m["automated_renewal"] for m in short),
          [m["id"] for m in short])
    manual = [m for m in MODEL["materials"] if not m["automated_renewal"]]
    check("人工续期材料的提前量都不少于 30 天",
          all(m["renew_before_days"] >= 30 for m in manual), [m["id"] for m in manual])

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
