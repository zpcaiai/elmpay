#!/usr/bin/env python3
"""Summarise the ADR set and the threat model as runtime evidence.

Reports abuse-case coverage per control and per batch, and the residual-risk
ledger with days-to-expiry. Exits non-zero if any exception has expired or any
abuse case has no mitigating batch — the same conditions the gate enforces, so
the evidence file cannot show a healthier picture than reality.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
META = re.compile(r"^- ([^：]+)：(.*)$", re.MULTILINE)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--today", default=date.today().isoformat())
    args = parser.parse_args()
    today = date.fromisoformat(args.today)

    model = json.loads((ROOT / "governance/threat-model.json").read_text("utf-8"))

    adrs = []
    for path in sorted((ROOT / "docs/adr").glob("*.md")):
        if path.name == "README.md":
            continue
        text = path.read_text(encoding="utf-8")
        meta = {k.strip(): v.strip() for k, v in META.findall(text)}
        adrs.append({"file": path.name, "status": meta.get("状态"),
                     "requirements": meta.get("关联需求"), "controls": meta.get("关联控制")})

    by_control: dict[str, list[str]] = defaultdict(list)
    by_batch: dict[str, list[str]] = defaultdict(list)
    unmitigated = []
    for case in model["abuse_cases"]:
        for control in case["controls"]:
            by_control[control].append(case["id"])
        for batch in case["mitigating_batches"]:
            by_batch[batch].append(case["id"])
        if not case["mitigating_batches"]:
            unmitigated.append(case["id"])

    risks = []
    expired = []
    for risk in model["residual_risks"]:
        due = date.fromisoformat(risk["due_date"])
        days = (due - today).days
        risks.append({"id": risk["id"], "severity": risk["severity"], "owner": risk["owner"],
                      "due_date": risk["due_date"], "days_to_expiry": days,
                      "review_batch": risk["review_batch"],
                      "compensating_controls": len(risk["compensating_controls"])})
        if days < 0:
            expired.append(risk["id"])

    report = {
        "as_of": today.isoformat(),
        "adr_count": len(adrs),
        "adrs": adrs,
        "zones": len(model["zones"]),
        "assets": len(model["assets"]),
        "trust_boundaries": len(model["trust_boundaries"]),
        "adversaries": len(model["adversaries"]),
        "abuse_cases": len(model["abuse_cases"]),
        "abuse_cases_per_control": {k: sorted(v) for k, v in sorted(by_control.items())},
        "abuse_cases_per_batch": {k: sorted(v) for k, v in sorted(by_batch.items())},
        "unmitigated_abuse_cases": sorted(unmitigated),
        "residual_risks": risks,
        "expired_exceptions": sorted(expired),
    }
    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items()
                      if not isinstance(v, (dict, list)) or k.endswith("exceptions")
                      or k == "unmitigated_abuse_cases"},
                     ensure_ascii=False, indent=2))
    return 1 if expired or unmitigated else 0


if __name__ == "__main__":
    raise SystemExit(main())
