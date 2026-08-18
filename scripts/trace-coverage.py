#!/usr/bin/env python3
"""Emit a coverage report over the requirement/capability/module graph.

Used as runtime evidence: it shows, per module and per control, how many
requirements exist and which batches are expected to verify them. Any zero in
``uncovered_*`` is a governance defect, so the script exits non-zero.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    requirements = json.loads((ROOT / "governance/requirements.json").read_text("utf-8"))
    boundaries = json.loads((ROOT / "governance/service-boundaries.json").read_text("utf-8"))
    modules = json.loads((ROOT / "governance/module-registry.json").read_text("utf-8"))

    reqs = requirements["requirements"]
    by_module: dict[str, list[str]] = defaultdict(list)
    by_control: dict[str, list[str]] = defaultdict(list)
    by_batch: dict[str, list[str]] = defaultdict(list)
    for req in reqs:
        by_module[req["owner_module"]].append(req["id"])
        for control in req["controls"]:
            by_control[control].append(req["id"])
        for batch in req["verified_by_batches"]:
            by_batch[batch].append(req["id"])

    claimed = {rid for cap in boundaries["capabilities"] for rid in cap["requirements"]}
    all_ids = {req["id"] for req in reqs}
    declared_modules = [m["name"] for m in modules["modules"]]

    report = {
        "requirements_total": len(reqs),
        "requirements_must": sum(1 for r in reqs if r["priority"] == "MUST"),
        "capabilities_total": len(boundaries["capabilities"]),
        "forbidden_flows_total": len(boundaries["forbidden_flows"]),
        "modules_total": len(declared_modules),
        "requirements_per_module": {m: sorted(by_module.get(m, [])) for m in sorted(declared_modules)},
        "requirements_per_control": {c: sorted(v) for c, v in sorted(by_control.items())},
        "requirements_per_batch": {b: sorted(v) for b, v in sorted(by_batch.items())},
        "uncovered_modules": sorted(m for m in declared_modules if not by_module.get(m)),
        "unclaimed_requirements": sorted(all_ids - claimed),
        "dangling_capability_requirements": sorted(claimed - all_ids),
    }
    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if not isinstance(v, dict)},
                     ensure_ascii=False, indent=2))
    bad = (report["uncovered_modules"] or report["unclaimed_requirements"]
           or report["dangling_capability_requirements"])
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
