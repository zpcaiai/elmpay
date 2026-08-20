#!/usr/bin/env python3
"""B10 runtime proof — replay real payment lifecycles against the state model.

The unit tests prove the model is well formed. This proves it is *usable*: a
real card payment, a real refund with separation of duties, a real timeout that
must not be read as a failure, and the three attacks the model exists to stop.

Every check is an assertion with a business sentence attached, and the script
exits non-zero the moment one fails.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.statemachine.reference.machine import (  # noqa: E402
    Instance, TransitionRejected, load)

MODEL = ROOT / "governance/state-machines.json"

CHECKS: list[str] = []
FAILURES: list[str] = []


def check(label: str, condition: bool, detail: object = "") -> None:
    CHECKS.append(label)
    detail = "" if detail == "" else str(detail)
    status = "OK " if condition else "FAIL"
    print(f"[{status}] {label}{(' — ' + detail) if detail else ''}")
    if not condition:
        FAILURES.append(label)


def rejects(label: str, fn, expected_code: str) -> None:
    try:
        fn()
        check(label, False, "本应被拒绝，却通过了")
    except TransitionRejected as exc:
        check(label, exc.code == expected_code, f"{exc.code}: {exc}")


def replace_actor(machine, event: str, actor: str):
    """Return a copy of ``machine`` with one transition's actor swapped.

    Used only to exercise the interpreter's own success-state guard, which the
    governance gate makes unreachable in the real model.
    """
    from dataclasses import replace
    transitions = tuple(replace(tr, actor=actor) if tr.event == event else tr
                        for tr in machine.transitions)
    return replace(machine, transitions=transitions)


def main() -> int:
    machines = load(MODEL)

    print("== 场景 1：一笔需要 3DS 的卡支付，走完 created → captured")
    intent = Instance(machines["payment-intent"])
    check("初始状态是 created", intent.state == "created", intent.state)
    intent.apply("provider.action_required", "provider-event", "evt_3ds_1")
    check("渠道要求持卡人验证", intent.state == "requires_action", intent.state)
    intent.apply("provider.authorized", "provider-event", "evt_auth_1")
    check("已验签事件写入授权", intent.state == "authorized", intent.state)
    intent.apply("provider.captured", "provider-event", "evt_cap_1")
    check("捕获后进入终态 captured", intent.state == "captured" and intent.is_terminal,
          f"{intent.state} terminal={intent.is_terminal}")

    print()
    print("== 场景 2：渠道重发 webhook（幂等）")
    before = list(intent.history)
    same = intent.apply("provider.captured", "provider-event", "evt_cap_1")
    check("重放同一事件是无操作，不是错误", same == "captured" and intent.history == before,
          f"history={len(intent.history)}")

    print()
    print("== 场景 3：模型要挡住的三种攻击")
    forged = Instance(machines["payment-intent"])
    rejects("created 状态下不能直接跳到捕获",
            lambda: forged.apply("provider.captured", "provider-event", "skip_1"),
            "EVENT_NOT_ALLOWED")
    forged.apply("provider.authorized", "provider-event", "auth_f")
    rejects("商户不能冒充渠道事件写入捕获（NN-03：回跳不是凭据）",
            lambda: forged.apply("provider.captured", "merchant", "forged_1"),
            "WRONG_ACTOR")

    # Defence in depth: the gate already forbids a success state whose declared
    # actor is untrusted, so this can only be reached with a doctored machine.
    # Exercising it here keeps the interpreter's own guard from rotting into
    # unreachable code that nobody notices is broken.
    doctored = replace_actor(machines["payment-intent"], "provider.captured", "merchant")
    tampered = Instance(doctored)
    tampered.apply("provider.authorized", "provider-event", "auth_t")
    rejects("即使转移表被改坏，未受信参与者也写不进成功状态",
            lambda: tampered.apply("provider.captured", "merchant", "tamper_1"),
            "UNTRUSTED_SUCCESS")
    done = Instance(machines["payment-intent"])
    done.apply("provider.authorized", "provider-event", "e1")
    done.apply("provider.captured", "provider-event", "e2")
    rejects("终态之后不能再被推动",
            lambda: done.apply("merchant.void", "merchant", "late_1"),
            "TERMINAL")

    print()
    print("== 场景 4：超时不等于失败（AC-01）")
    attempt = Instance(machines["payment-attempt"])
    attempt.apply("network.timeout", "system", "att_1")
    check("超时落到 unknown 而不是 failed", attempt.state == "unknown", attempt.state)
    check("unknown 不是终态，必须被定责", not attempt.is_terminal)
    attempt.apply("reconciliation.matched_success", "reconciliation", "recon_1")
    check("对账把 unknown 定责为成功", attempt.state == "succeeded", attempt.state)

    print()
    print("== 场景 5：退款的职责分离（NN-11）")
    refund = Instance(machines["refund"])
    refund.apply("operator.approve", "operator", "rf_1")
    check("退款需要审批", refund.state == "approved", refund.state)
    refund.apply("provider.accepted", "provider-event", "rf_2")
    refund.apply("provider.refunded", "provider-event", "rf_3")
    check("退款成功是终态", refund.state == "succeeded" and refund.is_terminal, refund.state)
    rejects("钱已离开后不能靠改状态收回",
            lambda: refund.apply("merchant.cancel_refund", "merchant", "rf_4"),
            "TERMINAL")

    print()
    print("== 场景 6：争议举证超时视同败诉（AC-06）")
    dispute = Instance(machines["dispute"])
    dispute.apply("provider.evidence_requested", "provider-event", "dp_1")
    dispute.apply("clock.evidence_deadline_elapsed", "scheduler", "dp_2")
    check("沉默不是中立：举证超时判负", dispute.state == "lost" and dispute.is_terminal,
          dispute.state)

    print()
    print("== 场景 7：订阅的补偿式回边")
    sub = Instance(machines["subscription"])
    sub.apply("billing.trial_converted", "scheduler", "sb_1")
    sub.apply("billing.charge_failed", "scheduler", "sb_2")
    check("扣款失败进入 past_due", sub.state == "past_due", sub.state)
    sub.apply("billing.charge_recovered", "scheduler", "sb_3")
    check("补扣成功可以回到 active（唯一的补偿式回边）", sub.state == "active", sub.state)

    print()
    print("== 场景 8：每台机器都能从初始状态走到某个终态")
    for name, machine in sorted(machines.items()):
        reachable, frontier = {machine.initial}, [machine.initial]
        while frontier:
            state = frontier.pop()
            for tr in machine.transitions:
                if tr.source == state and tr.target not in reachable:
                    reachable.add(tr.target)
                    frontier.append(tr.target)
        check(f"{name} 可以走到终态", bool(reachable & machine.terminal),
              f"terminal={sorted(machine.terminal)}")

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
