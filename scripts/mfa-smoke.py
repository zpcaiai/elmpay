#!/usr/bin/env python3
"""B18 runtime proof — run the ceremony, including the phishing attempt.

The centrepiece is scenario 2: a convincing phishing site relays a real
challenge to a real user with a real security key, and still cannot produce an
assertion the platform accepts, because the authenticator signed over the origin
*it* saw. That is the entire difference between WebAuthn and a six-digit code,
and it is why this batch classifies SMS and TOTP the way it does.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.mfa.reference.webauthn import (  # noqa: E402
    Assertion, CeremonyRejected, RelyingParty, transaction_hash)

POLICY = json.loads((ROOT / "governance/mfa.json").read_text(encoding="utf-8"))

CHECKS: list[str] = []
FAILURES: list[str] = []


def check(label: str, condition: bool, detail: object = "") -> None:
    CHECKS.append(label)
    detail = "" if detail == "" else str(detail)
    status = "OK " if condition else "FAIL"
    print(f"[{status}] {label}{(' — ' + detail) if detail else ''}")
    if not condition:
        FAILURES.append(label)


def party(counter: int = 0) -> RelyingParty:
    rp = RelyingParty.from_policy(POLICY)
    rp.register("cred-1", counter)
    return rp


def assertion(rp: RelyingParty, challenge: str, **overrides) -> Assertion:
    kwargs = {"credential_id": "cred-1",
              "origin": sorted(rp.allowed_origins)[0],
              "relying_party_id": rp.relying_party_id,
              "challenge": challenge, "user_verified": True, "sign_count": 1}
    kwargs.update(overrides)
    return Assertion(**kwargs)


def rejects(rp, a, code, **kwargs) -> bool:
    try:
        rp.verify(a, **kwargs)
        return False
    except CeremonyRejected as exc:
        return exc.code == code


def main() -> int:
    print("== 1. 正常仪式")
    rp = party()
    rp.issue_challenge("c1")
    verified = rp.verify(assertion(rp, "c1"))
    check("合法断言被接受", verified.credential_id == "cred-1")

    print()
    print("== 2. 钓鱼站点：拿到了用户的一切，唯独拿不到我们的 origin")
    rp = party()
    rp.issue_challenge("c2")
    phishing = assertion(rp, "c2", origin="https://pay-example.invalid.attacker.com",
                         sign_count=2)
    check("**钓鱼 origin 的断言被拒**", rejects(rp, phishing, "WRONG_ORIGIN"),
          "认证器签的是它看到的 origin，钓鱼站点改不了这一点")
    lookalike = assertion(rp, "c2", origin="https://pay.example.invalid.evil.co", sign_count=2)
    check("形似域名同样被拒", rejects(rp, lookalike, "WRONG_ORIGIN"))
    wrong_rp = assertion(rp, "c2", relying_party_id="evil.invalid", sign_count=2)
    check("RP ID 不符被拒", rejects(rp, wrong_rp, "WRONG_RP_ID"))

    print()
    print("== 3. 重放")
    rp = party()
    rp.issue_challenge("c3")
    good = assertion(rp, "c3")
    rp.verify(good)
    check("同一挑战不能用第二次", rejects(rp, assertion(rp, "c3", sign_count=2),
                                          "REPLAYED_CHALLENGE"))
    check("我们没发过的挑战被拒",
          rejects(rp, assertion(rp, "never-issued", sign_count=3), "UNKNOWN_CHALLENGE"))
    rp.issue_challenge("c4", expires_at=10)
    check("过期挑战被拒", rejects(rp, assertion(rp, "c4", sign_count=4), "STALE_CHALLENGE",
                                   now=1000))

    print()
    print("== 4. 用户验证与克隆检测")
    rp = party()
    rp.issue_challenge("c5")
    check("未做用户验证的断言被拒",
          rejects(rp, assertion(rp, "c5", user_verified=False), "NO_USER_VERIFICATION"),
          "否则「密钥被偷」就等于「账号被盗」")
    rp = party(counter=10)
    rp.issue_challenge("c6")
    check("签名计数器回退 → 判定为认证器被克隆",
          rejects(rp, assertion(rp, "c6", sign_count=5), "CLONED_AUTHENTICATOR"))
    rp.issue_challenge("c7")
    check("计数器前进则正常通过",
          rp.verify(assertion(rp, "c7", sign_count=11)).sign_count == 11)
    rp = party()
    rp.issue_challenge("c8")
    check("签名无效被拒",
          rejects(rp, assertion(rp, "c8", signature_valid=False), "BAD_SIGNATURE"))
    rp.issue_challenge("c9")
    check("未注册的凭据被拒",
          rejects(rp, assertion(rp, "c9", credential_id="cred-unknown"), "UNKNOWN_CREDENTIAL"))
    rp.issue_challenge("c10")
    check("不被接受的算法被拒",
          rejects(rp, assertion(rp, "c10", algorithm=-65535), "BAD_ALGORITHM"))

    print()
    print("== 5. Step-up 必须绑定这一笔操作")
    rp = party()
    rp.issue_challenge("c11")
    wanted = transaction_hash("refund.approve", "refund_id=rf_1;amount_minor=19999")
    other = transaction_hash("refund.approve", "refund_id=rf_2;amount_minor=19999")
    check("绑定到别的操作的断言被拒",
          rejects(rp, assertion(rp, "c11", transaction_hash=other), "TRANSACTION_NOT_BOUND",
                  expect_transaction=wanted),
          "否则只证明「刚才有人验证过」")
    rp.issue_challenge("c12")
    check("绑定到本次操作的断言被接受",
          rp.verify(assertion(rp, "c12", sign_count=2, transaction_hash=wanted),
                    expect_transaction=wanted).transaction_hash == wanted)

    print()
    print("== 6. 分类与角色要求")
    by_id = {a["id"]: a for a in POLICY["authenticators"]}
    relayable = [a["id"] for a in POLICY["authenticators"]
                 if a["kind"] in ("otp", "push")]
    check("所有可被转述的因素都不算抗钓鱼",
          all(not by_id[a]["phishing_resistant"] for a in relayable), relayable)
    check("所有可被转述的因素都不能单独使用",
          all(not by_id[a]["allowed_as_sole_factor"] for a in relayable))
    privileged = [r for r in POLICY["requirements"]
                  if r["role"] in ("platform-operator", "break-glass", "merchant-admin")]
    check("特权角色只允许抗钓鱼认证器",
          all(by_id[a]["phishing_resistant"] for r in privileged
              for a in r["allowed_authenticators"]),
          [r["role"] for r in privileged])
    check("特权角色至少注册两个认证器",
          all(r["minimum_registered_authenticators"] >= 2 for r in privileged))
    check("不存在降级回退", POLICY["fallback"]["downgrade_allowed"] is False)
    check("step-up 绑定操作", POLICY["step_up"]["transaction_binding"] is True)

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
