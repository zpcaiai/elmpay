#!/usr/bin/env python3
"""Runtime proof that the governance gate fails closed.

The unit tests exercise validators in-process. This script goes one step
further and runs the *shipped CLI* against deliberately corrupted copies of the
governance surface, asserting the real exit codes. If any violation slipped
through with exit code 0 the batch must not be marked passed.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

COPIED = (
    "governance/project-config.json",
    "governance/non-negotiables.json",
    "governance/module-registry.json",
    "governance/requirements.json",
    "governance/service-boundaries.json",
    "docs/charter/PROGRAM_CHARTER.md",
    "docs/charter/RISK_ACCEPTANCE_POLICY.md",
    "docs/charter/DELIVERY_MODEL.md",
    "docs/requirements/REQUIREMENTS_BASELINE.md",
    "docs/requirements/SERVICE_BOUNDARIES.md",
    ".payment-platform/skill-package/policies/non-negotiables.md",
    ".payment-platform/skill-package/manifest.json",
    ".payment-platform/skill-package/compliance/controls-matrix.csv",
)

EXIT_OK, EXIT_PROBLEMS, EXIT_ERROR = 0, 2, 3


def build(tmp: Path) -> Path:
    root = tmp / "repo"
    (root / "tools" / "paygov").mkdir(parents=True)
    (root / "tools" / "tests").mkdir(parents=True)
    for rel in COPIED:
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, dst)
    for module in sorted((ROOT / "tools" / "tests").glob("test_*.py")):
        (root / "tools" / "tests" / module.name).write_text("", encoding="utf-8")
    registry = json.loads((root / "governance/module-registry.json").read_text("utf-8"))
    for module in registry["modules"]:
        (root / module["path"]).mkdir(parents=True, exist_ok=True)
    return root


def patch(root: Path, rel: str, mutate) -> None:
    path = root / rel
    data = json.loads(path.read_text(encoding="utf-8"))
    mutate(data)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def gate(root: Path, extra: list[str] | None = None) -> tuple[int, str]:
    cmd = [sys.executable, "-m", "tools.paygov.cli", "verify-all", "--repo", str(root)]
    proc = subprocess.run(cmd + (extra or []), cwd=ROOT, capture_output=True, text=True)
    return proc.returncode, proc.stdout


SCENARIOS = [
    ("NN-13 fund pool enabled", "governance/project-config.json",
     lambda d: d["regulated_features"].__setitem__("fund_pool", True), EXIT_PROBLEMS),
    ("NN-02 raw card data allowed", "governance/project-config.json",
     lambda d: d["security"].__setitem__("raw_card_data", "allowed"), EXIT_PROBLEMS),
    ("NN-05 float money model", "governance/project-config.json",
     lambda d: d["money"].__setitem__("representation", "double"), EXIT_PROBLEMS),
    ("NN-07 literal provider secret", "governance/project-config.json",
     lambda d: d["providers"]["wechat"].__setitem__("credentials", "plain-merchant-key-value"),
     EXIT_PROBLEMS),
    ("NN-11 executor equals reviewer", "governance/project-config.json",
     lambda d: d["evidence"].__setitem__("reviewer", d["evidence"]["executor"]), EXIT_PROBLEMS),
    ("NN-01 connector reaches a service", "governance/module-registry.json",
     lambda d: next(m for m in d["modules"] if m["name"] == "stripe")["depends_on"].append("payment-core"),
     EXIT_PROBLEMS),
    ("NN-01 business order table claimed", "governance/module-registry.json",
     lambda d: next(m for m in d["modules"] if m["name"] == "payment-core")["owned_tables"].append("business_order"),
     EXIT_PROBLEMS),
    ("red line silently removed", "governance/non-negotiables.json",
     lambda d: d["rules"].pop(7), EXIT_PROBLEMS),
    ("B01 requirement loses its verifying batch", "governance/requirements.json",
     lambda d: d["requirements"][0].__setitem__("verified_by_batches", []), EXIT_PROBLEMS),
    ("B01 requirement points at a non-existent control", "governance/requirements.json",
     lambda d: d["requirements"][1].__setitem__("controls", ["CTRL-999"]), EXIT_PROBLEMS),
    ("B01 requirement becomes an orphan", "governance/service-boundaries.json",
     lambda d: d["capabilities"][0]["requirements"].clear(), EXIT_PROBLEMS),
    ("B01 forbidden flow loses its enforcement", "governance/service-boundaries.json",
     lambda d: d["forbidden_flows"][4].__setitem__("enforced_by", []), EXIT_PROBLEMS),
    ("B01 generated document drifts from source", "governance/requirements.json",
     lambda d: d["requirements"][2].__setitem__("title", "被悄悄改掉的标题"), EXIT_PROBLEMS),
]


def main() -> int:
    failures = []
    with tempfile.TemporaryDirectory(prefix="paygov-negative-") as tmpdir:
        tmp = Path(tmpdir)

        baseline_root = build(tmp / "baseline")
        code, _ = gate(baseline_root)
        print(f"[baseline    ] exit={code} expected={EXIT_OK}")
        if code != EXIT_OK:
            failures.append("baseline fixture is not clean")

        for index, (name, rel, mutate, expected) in enumerate(SCENARIOS):
            root = build(tmp / f"case{index}")
            patch(root, rel, mutate)
            code, _ = gate(root)
            status = "OK " if code == expected else "FAIL"
            print(f"[{status}] {name}: exit={code} expected={expected}")
            if code != expected:
                failures.append(name)

        timeout_root = build(tmp / "timeout")
        code, out = gate(timeout_root, ["--budget-seconds", "0"])
        status = "OK " if code == EXIT_ERROR else "FAIL"
        print(f"[{status}] exhausted budget fails closed: exit={code} expected={EXIT_ERROR}")
        if code != EXIT_ERROR or '"ok": true' in out:
            failures.append("timeout did not fail closed")

    print()
    print(f"scenarios={len(SCENARIOS) + 2} failures={len(failures)}")
    for failure in failures:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
