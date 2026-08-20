#!/usr/bin/env python3
"""B23 runtime proof — tamper with the log and watch the chain notice.

Scenario 5 is the one worth reading, and it is the honest one: the chain
**cannot** detect its own tail being cut off. Delete the last records and what
remains verifies perfectly. The anchor is what closes that hole, and the
anchoring interval is exactly the size of the window that stays deniable — so
this script measures that window instead of claiming it is zero.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.audit.reference.chain import (  # noqa: E402
    ANCHOR_INVALID, CLOCK_REVERSED, FORBIDDEN_FIELD, LINK_BROKEN, MODIFIED, OK,
    SEQUENCE_BROKEN, TRUNCATED, Anchor, AuditRefused, Ledger, Record, content_hash)

POLICY = json.loads((ROOT / "governance/audit-log.json").read_text(encoding="utf-8"))

CHECKS: list[str] = []
FAILURES: list[str] = []


def check(label: str, condition: bool, detail: object = "") -> None:
    CHECKS.append(label)
    detail = "" if detail == "" else str(detail)
    status = "OK " if condition else "FAIL"
    print(f"[{status}] {label}{(' — ' + detail) if detail else ''}")
    if not condition:
        FAILURES.append(label)


def build(count: int = 5) -> Ledger:
    ledger = Ledger(tenant_id="t-1")
    for index in range(count):
        ledger.append(occurred_at=1000 + index * 10, event_class="authz.decision",
                      actor=f"user-{index}", action="refund.approve", decision="allow",
                      rule_version="1.0.0", payload={"amount_minor": 100 + index})
    return ledger


def main() -> int:
    ledger = build()
    check("干净的链验证通过", ledger.verify() == (OK, None), ledger.verify())

    # 1. modification
    tampered = build()
    victim = tampered.records[2]
    tampered.records[2] = Record(**{**victim.__dict__,
                                    "payload": {"amount_minor": 999999}})
    check("改一条记录的负载会被发现", tampered.verify()[0] == MODIFIED, tampered.verify())

    header_tampered = build()
    victim = header_tampered.records[1]
    header_tampered.records[1] = Record(**{**victim.__dict__, "actor": "somebody-else"})
    check("改一条记录的头部会被发现", header_tampered.verify()[0] == MODIFIED,
          header_tampered.verify())

    # 2. deletion in the middle
    deleted = build()
    del deleted.records[2]
    check("删掉中间一条会被发现", deleted.verify()[0] in {SEQUENCE_BROKEN, LINK_BROKEN},
          deleted.verify())

    # 3. reordering
    reordered = build()
    reordered.records[1], reordered.records[2] = reordered.records[2], reordered.records[1]
    check("调换顺序会被发现", reordered.verify()[0] in {SEQUENCE_BROKEN, LINK_BROKEN},
          reordered.verify())

    # 4. re-writing a record and rebuilding its hash still breaks the link
    forged = build()
    victim = forged.records[2]
    rebuilt = Record(**{**victim.__dict__, "actor": "mallory", "record_hash": ""})
    forged.records[2] = Record(**{**rebuilt.__dict__, "record_hash": rebuilt.recompute()})
    check("伪造者重算自己那条的哈希，仍然会在下一条断链",
          forged.verify()[0] == LINK_BROKEN, forged.verify())

    # 5. tail truncation — the honest limit
    anchored = build()
    anchor = anchored.anchor(at=2000)
    kept = list(anchored.records)
    anchored.records = anchored.records[:3]
    check("锚定之后截断尾部会被发现", anchored.verify()[0] == TRUNCATED, anchored.verify())

    unanchored = Ledger(tenant_id="t-2")
    for index in range(5):
        unanchored.append(occurred_at=1000 + index, event_class="authz.decision",
                          actor="u", action="refund.approve", decision="allow",
                          rule_version="1.0.0", payload={"n": index})
    unanchored.records = unanchored.records[:3]
    check("**没有锚点时截断尾部无法被发现**（这是哈希链的性质，不是缺陷）",
          unanchored.verify() == (OK, None), unanchored.verify())

    window = POLICY["anchoring"]["interval_minutes"] * 60
    fresh = build()
    fresh.anchor(at=1000)
    check("可被否认的窗口被如实报告，而不是假装为零",
          fresh.deniable_window(1000 + window) == window,
          fresh.deniable_window(1000 + window))

    # 6. forged anchor
    bad_anchor = build()
    bad_anchor.anchor(at=2000)
    bad_anchor.anchors[0] = Anchor(sequence=5, head_hash="0" * 64, at=2000, mac="deadbeef")
    check("伪造的锚点会被发现", bad_anchor.verify()[0] == ANCHOR_INVALID, bad_anchor.verify())

    # 7. crypto shredding keeps the proof
    shredded = build()
    shredded.anchor(at=2000)
    before = shredded.records[1].record_hash
    record = shredded.shred(2)
    check("销毁负载后记录仍在", record.payload is None and record.record_hash == before)
    check("销毁负载后链依然验证通过", shredded.verify() == (OK, None), shredded.verify())
    check("内容哈希仍然绑定原内容",
          record.payload_hash == content_hash({"amount_minor": 101}))

    # 8. what a third party gets
    proof = shredded.proof(2)
    check("单条记录的证明包含锚点", proof["anchored"] and proof["anchor"] is not None)
    check("未被锚定的记录如实标注为未锚定",
          Ledger(tenant_id="t-3", records=list(kept)).proof(1)["anchored"] is False)

    # 9. write-time refusals
    refused = Ledger(tenant_id="t-4")
    try:
        refused.append(occurred_at=1, event_class="data.access", actor="a", action="x",
                       decision="allow", rule_version="1.0.0",
                       payload={"card_pan": "4111111111111111"})
        check("禁止字段在写入时被拒", False)
    except AuditRefused as exc:
        check("禁止字段在写入时被拒", exc.code == FORBIDDEN_FIELD, exc.code)
    refused.append(occurred_at=100, event_class="data.access", actor="a", action="x",
                   decision="allow", rule_version="1.0.0", payload={})
    try:
        refused.append(occurred_at=50, event_class="data.access", actor="a", action="x",
                       decision="allow", rule_version="1.0.0", payload={})
        check("时钟倒退的写入被拒", False)
    except AuditRefused as exc:
        check("时钟倒退的写入被拒", exc.code == CLOCK_REVERSED, exc.code)

    # 10. policy agrees with the implementation
    check("策略要求的锚定间隔有界",
          0 < POLICY["anchoring"]["interval_minutes"] <= 1440)
    check("策略禁止的字段与实现一致",
          set(POLICY["records"]["forbidden_fields"]) >= {"card_pan", "card_cvv"})

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
