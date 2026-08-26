#!/usr/bin/env python3
"""Audit runnable implementation surfaces without converting them into certification evidence.

This is intentionally separate from rebaseline.py. It answers whether declared modules contain
source, tests and migrations/control code. It never writes evidence, review attestations,
traceability or completion markers, and its success does not mean a batch is certified.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / ".payment-platform/skill-package/manifest.json"
MODULES = ROOT / "governance/module-registry.json"

SURFACES: tuple[tuple[str, int, int, tuple[str, ...]], ...] = (
    ("foundation", 0, 31, ("governance", "contracts", "scripts", "libs")),
    ("payment-core", 32, 36, ("services/payment-core", "services/merchant-config", "apps/edge-gateway")),
    ("providers-webhooks", 37, 55, ("connectors", "services/webhook-ingress", "services/webhook-delivery")),
    ("checkout-sdks", 56, 69, ("apps/checkout-web", "sdks", "services/payment-core/src/main/java/com/elmpay/payment/checkout")),
    ("finance-lifecycle", 70, 79, ("services/ledger-service", "services/reconciliation-service", "services/payment-core/src/main/java/com/elmpay/payment/refund", "services/payment-core/src/main/java/com/elmpay/payment/billing")),
    ("risk-access", 80, 89, ("services/risk-engine", "apps/admin-web")),
    ("reliability-operations", 90, 111, ("services/worker-scheduler", "platform", "tools/runtime")),
    ("release-commercial", 112, 127, ("platform", "runbooks", "testing", "tools/runtime")),
)

SOURCE_SUFFIXES = {".java", ".py", ".mjs", ".js", ".ts", ".go", ".swift", ".dart", ".cs", ".sql", ".yaml", ".yml", ".json"}
IGNORED_PARTS = {"build", "node_modules", "__pycache__", ".gradle", ".dart_tool", ".build", "bin", "obj"}

VERIFY_COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("generated-build", (sys.executable, "scripts/render-build.py", "--check")),
    ("skill-package", ("make", "skills-verify")),
    ("java", ("./gradlew", "--no-daemon", "--console=plain", "test")),
    ("runtime-controls", (sys.executable, "tools/runtime/control.py", "validate")),
    ("python-controls", (sys.executable, "-m", "unittest", "discover", "-s", "testing", "-p", "test_*.py", "-v")),
    ("admin-web", ("node", "--test", "apps/admin-web/test/admin-domain.test.mjs")),
    ("checkout-web", ("npm", "--prefix", "apps/checkout-web", "test")),
    ("node-sdk", ("node", "--test", "sdks/server/node/elmpay-client.test.mjs")),
    ("python-sdk", (sys.executable, "-m", "unittest", "discover", "-s", "sdks/server/python", "-p", "test_*.py", "-v")),
    ("go-sdk", ("go", "-C", "sdks/server/go", "test", "./...")),
)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def files_under(relative: str) -> list[Path]:
    base = ROOT / relative
    if not base.exists():
        return []
    return sorted(
        path.relative_to(ROOT)
        for path in base.rglob("*")
        if path.is_file()
        and path.suffix.lower() in SOURCE_SUFFIXES
        and not IGNORED_PARTS.intersection(path.relative_to(ROOT).parts)
    )


def is_test(path: Path) -> bool:
    lowered = str(path).lower()
    return "/test/" in f"/{lowered}" or "/tests/" in f"/{lowered}" or Path(lowered).name.startswith("test_") or ".test." in lowered


def manifest_batches() -> list[str]:
    document = load_json(MANIFEST)
    result: list[str] = []
    for wave in document.get("waves", []):
        result.extend(wave.get("batches", []))
    return result


def audit(*, run_checks: bool = False, timeout_seconds: int = 900) -> dict[str, Any]:
    issues: list[str] = []
    batches = manifest_batches()
    expected = [f"B{number:02d}" for number in range(128)]
    if batches != expected:
        issues.append("manifest must contain contiguous B00-B127 exactly once")

    registry = load_json(MODULES)
    module_results: list[dict[str, Any]] = []
    for module in registry.get("modules", []):
        relative = module["path"]
        files = files_under(relative)
        production = [path for path in files if not is_test(path)]
        tests = [path for path in files if is_test(path)]
        build_system = "node" if relative.startswith("apps/") and (ROOT / relative / "package.json").is_file() else "java"
        module_issue: list[str] = []
        if not production:
            module_issue.append("no production source/configuration")
        if not tests:
            module_issue.append("no automated test source")
        if build_system == "node" and not (ROOT / relative / "package.json").is_file():
            module_issue.append("missing package.json")
        if module_issue:
            issues.append(f"{module['name']}: " + ", ".join(module_issue))
        module_results.append({
            "name": module["name"],
            "path": relative,
            "production_files": len(production),
            "test_files": len(tests),
            "issues": module_issue,
        })

    surface_results: list[dict[str, Any]] = []
    for name, start, end, roots in SURFACES:
        files = sorted({path for root in roots for path in files_under(root)})
        production = [path for path in files if not is_test(path)]
        tests = [path for path in files if is_test(path)]
        migrations = [path for path in files if path.suffix == ".sql"]
        surface_issue: list[str] = []
        if not production:
            surface_issue.append("no implementation files")
        if not tests:
            surface_issue.append("no test files")
        if name in {"payment-core", "providers-webhooks", "finance-lifecycle"} and not migrations:
            surface_issue.append("no durable migration")
        if surface_issue:
            issues.append(f"surface {name}: " + ", ".join(surface_issue))
        surface_results.append({
            "name": name,
            "batches": f"B{start:02d}-B{end:02d}",
            "roots": list(roots),
            "production_files": len(production),
            "test_files": len(tests),
            "migration_files": len(migrations),
            "issues": surface_issue,
        })

    required_controls = (
        "apps/edge-gateway/src/main/resources/db/migration/V032__payment_runtime.sql",
        "services/webhook-ingress/src/main/resources/db/migration/V037__provider_webhook_inbox.sql",
        "services/webhook-delivery/src/main/resources/db/migration/V038__business_webhook_delivery.sql",
        "services/ledger-service/src/main/resources/db/migration/V001__immutable_ledger.sql",
        "services/reconciliation-service/src/main/resources/db/migration/V001__reconciliation.sql",
        "tools/runtime/elmpay_runtime/release.py",
        "platform/kubernetes/workload-policy.json",
    )
    for relative in required_controls:
        if not (ROOT / relative).is_file():
            issues.append(f"missing required control: {relative}")

    inventory_status = "PASS" if not issues else "FAIL"
    checks = verify_commands(timeout_seconds) if run_checks and not issues else []
    checks_pass = bool(run_checks) and not issues and all(check["exit_code"] == 0 for check in checks)
    return {
        "schema_version": 1,
        "git_head": git_head(),
        "inventory_status": inventory_status,
        "implementation_surface": "PASS" if checks_pass else ("FAIL" if issues or run_checks else "NOT_RUN"),
        "verification_executed": run_checks,
        "verification_checks": checks,
        "certification_status": "NOT_CERTIFIED",
        "certified_batches_changed": False,
        "batch_count": len(batches),
        "module_count": len(module_results),
        "modules": module_results,
        "surfaces": surface_results,
        "issues": issues,
        "external_gates": [
            "independent human review",
            "provider sandbox and official certification",
            "production Kubernetes and multi-region DR runtime evidence",
            "PCI, legal, finance UAT and penetration approvals",
            "production shadow, canary and merchant acceptance",
        ],
    }


def verify_commands(timeout_seconds: int) -> list[dict[str, Any]]:
    if timeout_seconds < 1:
        raise ValueError("timeout_seconds must be positive")
    results: list[dict[str, Any]] = []
    for name, command in VERIFY_COMMANDS:
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            output = completed.stdout[-16_384:]
            exit_code = completed.returncode
            timed_out = False
        except subprocess.TimeoutExpired as exception:
            raw = exception.stdout or ""
            output = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
            output = output[-16_384:]
            exit_code = 124
            timed_out = True
        results.append({
            "name": name,
            "command": list(command),
            "exit_code": exit_code,
            "timed_out": timed_out,
            "duration_seconds": round(time.monotonic() - started, 3),
            "output_tail": output,
        })
        if exit_code != 0:
            break
    return results


def git_head() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    return result.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit the full machine-readable report")
    parser.add_argument("--verify", action="store_true", help="execute the declared local verification commands")
    parser.add_argument("--timeout-seconds", type=int, default=900, help="per-command verification timeout")
    arguments = parser.parse_args(argv)
    report = audit(run_checks=arguments.verify, timeout_seconds=arguments.timeout_seconds)
    if arguments.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"implementation_surface={report['implementation_surface']}")
        print(f"inventory_status={report['inventory_status']}")
        print(f"certification_status={report['certification_status']}")
        print(f"batches={report['batch_count']} modules={report['module_count']}")
        for check in report["verification_checks"]:
            print(f"check={check['name']} exit={check['exit_code']} duration={check['duration_seconds']}")
        for issue in report["issues"]:
            print(f"issue={issue}")
    if report["inventory_status"] != "PASS":
        return 2
    return 0 if not arguments.verify or report["implementation_surface"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
