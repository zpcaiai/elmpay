#!/usr/bin/env python3
"""Runtime proof that the governance gate fails closed.

The unit tests exercise validators in-process. This script goes one step
further and runs the *shipped CLI* against deliberately corrupted copies of the
governance surface, asserting the real exit codes. If any violation slipped
through with exit code 0 the batch must not be marked passed.
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
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
    "governance/threat-model.json",
    "governance/version-catalog.json",
    "governance/dev-platform.json",
    "governance/ci-pipeline.json",
    "gradle/libs.versions.toml",
    "settings.gradle.kts",
    "build.gradle.kts",
    ".tool-versions",
    "platform/toolchain/versions.env",
    "platform/dev/compose.yaml",
    "platform/dev/.env.example",
    "platform/dev/README.md",
    "platform/dev/simulators/wechat/Dockerfile",
    "platform/dev/simulators/alipay/Dockerfile",
    "platform/dev/simulators/stripe/Dockerfile",
    "platform/dev/simulators/paypal/Dockerfile",
    "platform/dev/simulators/apple-pay/Dockerfile",
    ".github/workflows/ci.yml",
    "scripts/sign-artifacts.sh",
    "docs/charter/PROGRAM_CHARTER.md",
    "docs/charter/RISK_ACCEPTANCE_POLICY.md",
    "docs/charter/DELIVERY_MODEL.md",
    "docs/requirements/REQUIREMENTS_BASELINE.md",
    "docs/requirements/SERVICE_BOUNDARIES.md",
    ".payment-platform/skill-package/policies/non-negotiables.md",
    ".payment-platform/skill-package/security/THREAT_MODEL.md",
    ".payment-platform/skill-package/manifest.json",
    ".payment-platform/skill-package/compliance/controls-matrix.csv",
)

COPIED_DIRS = ("docs/adr", "docs/security", "docs/toolchain")

EXIT_OK, EXIT_PROBLEMS, EXIT_ERROR = 0, 2, 3


def build(tmp: Path) -> Path:
    root = tmp / "repo"
    (root / "tools" / "paygov").mkdir(parents=True)
    (root / "tools" / "tests").mkdir(parents=True)
    for rel in COPIED:
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, dst)
    for rel in COPIED_DIRS:
        shutil.copytree(ROOT / rel, root / rel, dirs_exist_ok=True)
    for module in sorted((ROOT / "tools" / "tests").glob("test_*.py")):
        (root / "tools" / "tests" / module.name).write_text("", encoding="utf-8")
    registry = json.loads((root / "governance/module-registry.json").read_text("utf-8"))
    for module in registry["modules"]:
        (root / module["path"]).mkdir(parents=True, exist_ok=True)
    dev = json.loads((root / "governance/dev-platform.json").read_text("utf-8"))
    for simulator in dev["simulators"]:
        (root / simulator["build_context"]).mkdir(parents=True, exist_ok=True)
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
    ("B02 security exception silently expires", "governance/threat-model.json",
     lambda d: d["residual_risks"][0].__setitem__("due_date", "2020-01-01"), EXIT_PROBLEMS),
    ("B02 critical risk accepted instead of fixed", "governance/threat-model.json",
     lambda d: d["residual_risks"][1].__setitem__("severity", "critical"), EXIT_PROBLEMS),
    ("B02 residual risk loses its owner", "governance/threat-model.json",
     lambda d: d["residual_risks"][2].__setitem__("owner", "TBD"), EXIT_PROBLEMS),
    ("B02 abuse case dropped from the model", "governance/threat-model.json",
     lambda d: d["abuse_cases"].pop(3), EXIT_PROBLEMS),
    ("B03 dependency floats to a dynamic version", "governance/version-catalog.json",
     lambda d: d["entries"][1].__setitem__("version", "4.1.+"), EXIT_PROBLEMS),
    ("B03 container image pinned by tag only", "governance/version-catalog.json",
     lambda d: next(e for e in d["entries"] if e["category"] == "container")
        .__setitem__("digest", ""), EXIT_PROBLEMS),
    ("B03 dependency loses its owner", "governance/version-catalog.json",
     lambda d: d["entries"][0].__setitem__("owner", ""), EXIT_PROBLEMS),
    ("B03 module left without a build system", "governance/version-catalog.json",
     lambda d: d["modules_by_build_system"]["gradle"].pop(), EXIT_PROBLEMS),
    ("B03 Java baseline silently downgraded", "governance/version-catalog.json",
     lambda d: next(e for e in d["entries"] if e["id"] == "jdk")
        .__setitem__("version", "21.0.10"), EXIT_PROBLEMS),
    ("B04 inline password in the local platform", "governance/dev-platform.json",
     lambda d: d["services"][0]["environment"].__setitem__("POSTGRES_PASSWORD", "hunter2hunter2"),
     EXIT_PROBLEMS),
    ("B04 local service points at a production value", "governance/dev-platform.json",
     lambda d: d["services"][3]["environment"].__setitem__("KC_BOOTSTRAP_ADMIN_USERNAME",
                                                           "production-admin"), EXIT_PROBLEMS),
    ("B04 local data declared non-synthetic", "governance/dev-platform.json",
     lambda d: d["services"][0].__setitem__("data_classification", "real"), EXIT_PROBLEMS),
    ("B04 enabled provider loses its offline simulator", "governance/dev-platform.json",
     lambda d: d["simulators"].pop(0), EXIT_PROBLEMS),
    ("B04 required service removed", "governance/dev-platform.json",
     lambda d: d["services"].pop(2), EXIT_PROBLEMS),
    ("B04 host port collision", "governance/dev-platform.json",
     lambda d: d["simulators"][1]["ports"].__setitem__(
         0, {"host": d["simulators"][0]["ports"][0]["host"], "container": "8080"}), EXIT_PROBLEMS),
    ("B04 service health check removed", "governance/dev-platform.json",
     lambda d: d["services"][1].__setitem__("healthcheck", ""), EXIT_PROBLEMS),
    ("B05 required CI stage turned fail-open", "governance/ci-pipeline.json",
     lambda d: next(s for s in d["stages"] if s["id"] == "secret-scan")
        .__setitem__("fail_closed", False), EXIT_PROBLEMS),
    ("B05 action pinned to a movable tag", "governance/ci-pipeline.json",
     lambda d: d["actions"][0].__setitem__("ref", "v5"), EXIT_PROBLEMS),
    ("B05 dependency scanning removed from the pipeline", "governance/ci-pipeline.json",
     lambda d: d["required_stages"].remove("dependency-scan") or
               d["stages"].__setitem__(slice(None),
                   [s for s in d["stages"] if s["id"] != "dependency-scan"]), EXIT_PROBLEMS),
    ("B05 blocking security findings allowed above zero", "governance/ci-pipeline.json",
     lambda d: d["quality_gates"].__setitem__("blocking_security_findings_max", 3),
     EXIT_PROBLEMS),
    ("B05 evidence blocking condition removed", "governance/ci-pipeline.json",
     lambda d: d["blocking_conditions"].__setitem__(slice(None),
         [c for c in d["blocking_conditions"] if c["id"] != "BLOCK-04"]), EXIT_PROBLEMS),
    ("B05 pipeline granted write access to contents", "governance/ci-pipeline.json",
     lambda d: d["permissions"].__setitem__("contents", "write"), EXIT_PROBLEMS),
]

TEXT_SCENARIOS = [
    ("B02 ADR loses its alternatives section",
     "docs/adr/0001-monorepo-modular-boundaries.md", "## 备选方案", "## 闲聊", EXIT_PROBLEMS),
    ("B02 ADR points at a non-existent requirement",
     "docs/adr/0003-integer-minor-units.md", "PAY-REQ-0028", "PAY-REQ-9999", EXIT_PROBLEMS),
]


def _json_case(tmp: Path, index: int, spec) -> tuple[str, int, int]:
    name, rel, mutate, expected = spec
    root = build(tmp / f"case{index}")
    patch(root, rel, mutate)
    code, _ = gate(root)
    return name, code, expected


def _text_case(tmp: Path, index: int, spec) -> tuple[str, int, int]:
    name, rel, find, replace, expected = spec
    root = build(tmp / f"text{index}")
    path = root / rel
    path.write_text(path.read_text(encoding="utf-8").replace(find, replace), encoding="utf-8")
    code, _ = gate(root)
    return name, code, expected


def main() -> int:
    failures = []
    with tempfile.TemporaryDirectory(prefix="paygov-negative-") as tmpdir:
        tmp = Path(tmpdir)

        baseline_root = build(tmp / "baseline")
        code, _ = gate(baseline_root)
        print(f"[baseline    ] exit={code} expected={EXIT_OK}")
        if code != EXIT_OK:
            failures.append("baseline fixture is not clean")

        # Scenarios are independent; running them concurrently keeps the proof
        # affordable enough to execute on every batch. Results are printed in
        # declaration order so the log stays deterministic.
        with ThreadPoolExecutor(max_workers=8) as pool:
            json_results = list(pool.map(lambda item: _json_case(tmp, item[0], item[1]),
                                         list(enumerate(SCENARIOS))))
            text_results = list(pool.map(lambda item: _text_case(tmp, item[0], item[1]),
                                         list(enumerate(TEXT_SCENARIOS))))

        for name, code, expected in json_results + text_results:
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
    print(f"scenarios={len(SCENARIOS) + len(TEXT_SCENARIOS) + 2} failures={len(failures)}")
    for failure in failures:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
