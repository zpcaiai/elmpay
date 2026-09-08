#!/usr/bin/env python3
"""Fail-closed composite runner for executable batch test slices.

Every local matrix suite enters through this runner. The checked-in mapping is
also a completeness contract for ``testing/test_*.py``: a module must belong to
exactly one slice, and an added, removed, or multiply assigned module stops the
run before any test command is executed.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys
from typing import Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


class SuiteConfigurationError(RuntimeError):
    """The executable suite map no longer matches the repository tests."""


@dataclass(frozen=True)
class SuiteSpec:
    commands: tuple[tuple[str, ...], ...]
    test_modules: tuple[str, ...] = ()


def _command(*tokens: str) -> tuple[str, ...]:
    return tokens


def _unittest(*modules: str) -> tuple[str, ...]:
    return _command(PYTHON, "-m", "unittest", *modules, "-v")


SUITES: dict[str, SuiteSpec] = {
    "governance": SuiteSpec(
        commands=(
            _command(PYTHON, "-m", "tools.paygov.cli", "verify-all", "--repo", "."),
            _unittest("testing.test_matrix_runner"),
        ),
        test_modules=("testing.test_matrix_runner",),
    ),
    "domain": SuiteSpec(commands=(
        _unittest(
            "tools.tests.test_b08_domain", "tools.tests.test_b09_money",
            "tools.tests.test_b10_states", "tools.tests.test_b11_api",
        ),
    )),
    "data": SuiteSpec(
        commands=(
            _unittest(
                "tools.tests.test_b12_events", "tools.tests.test_b13_data",
                "tools.tests.test_b14_topology", "tools.tests.test_b15_migration",
            ),
            _unittest("testing.test_b15_service_migration_runtime"),
        ),
        test_modules=("testing.test_b15_service_migration_runtime",),
    ),
    "security": SuiteSpec(
        commands=(
            _unittest(
                "tools.tests.test_b16_zerotrust", "tools.tests.test_b17_identity",
                "tools.tests.test_b18_mfa", "tools.tests.test_b19_authz",
                "tools.tests.test_b20_keys", "tools.tests.test_b21_certs",
                "tools.tests.test_b22_baseline", "tools.tests.test_b23_audit",
                "testing.test_mounted_secrets",
            ),
            _unittest("testing.test_b16_b21_identity_security"),
        ),
        test_modules=("testing.test_b16_b21_identity_security", "testing.test_mounted_secrets"),
    ),
    "merchant": SuiteSpec(
        commands=(
            _unittest(
                "tools.tests.test_b24_tenants", "tools.tests.test_b25_merchant",
                "tools.tests.test_b26_accounts", "tools.tests.test_b27_capabilities",
                "tools.tests.test_b28_routing", "tools.tests.test_b29_fees",
                "tools.tests.test_b30_onboarding", "tools.tests.test_b31_isolation",
            ),
            _unittest("testing.test_b31_tenant_isolation_probe"),
        ),
        test_modules=("testing.test_b31_tenant_isolation_probe",),
    ),
    "payment": SuiteSpec(commands=(
        _command(
            "./gradlew", "--no-daemon", "--console=plain",
            ":services:payment-core:test", ":apps:edge-gateway:test",
        ),
    )),
    "webhook": SuiteSpec(commands=(
        _command(
            "./gradlew", "--no-daemon", "--console=plain",
            ":services:webhook-ingress:test", ":services:webhook-delivery:test",
            ":apps:edge-gateway:test",
        ),
    )),
    "cn-providers": SuiteSpec(
        commands=(
            _command(
                "./gradlew", "--no-daemon", "--console=plain",
                ":connectors:wechat-pay:test", ":connectors:alipay:test",
            ),
            _command(PYTHON, "scripts/provider-contract-matrix.py"),
        ),
    ),
    "global-providers": SuiteSpec(
        commands=(
            _command(
                "./gradlew", "--no-daemon", "--console=plain",
                ":connectors:stripe:test", ":connectors:paypal:test",
                ":connectors:apple-pay:test", ":libs:domain-events:test",
            ),
            _command(PYTHON, "scripts/provider-contract-matrix.py"),
        ),
    ),
    "checkout-sdk": SuiteSpec(commands=(
        _command(PYTHON, "scripts/sdk-contract-smoke.py"),
    )),
    "lifecycle": SuiteSpec(commands=(
        _command("./gradlew", "--no-daemon", "--console=plain", ":services:payment-core:test"),
    )),
    "finance": SuiteSpec(commands=(
        _command(
            "./gradlew", "--no-daemon", "--console=plain",
            ":services:ledger-service:test", ":services:reconciliation-service:test",
            ":services:payment-core:test",
        ),
    )),
    "risk": SuiteSpec(
        commands=(
            _command("./gradlew", "--no-daemon", "--console=plain", ":services:risk-engine:test"),
            _unittest(
                "testing.test_b80_b83_b87_risk_control",
                "testing.test_b80_product_risk_runtime",
                "testing.test_risk_engine_deployment",
                "testing.test_b84_b86_cli",
                "testing.test_b84_b86_security",
            ),
        ),
        test_modules=(
            "testing.test_b80_b83_b87_risk_control",
            "testing.test_b80_product_risk_runtime",
            "testing.test_risk_engine_deployment",
            "testing.test_b84_b86_cli",
            "testing.test_b84_b86_security",
        ),
    ),
    "platform": SuiteSpec(
        commands=(
            _command(
                "./gradlew", "--no-daemon", "--console=plain",
                ":apps:edge-gateway:test", ":services:worker-scheduler:test",
            ),
            _unittest(
                "testing.test_b88_edge_security",
                "testing.test_b89_b95_infrastructure",
                "testing.test_b89_egress_policy",
                "testing.test_admin_action_runtime",
                "testing.test_product_oci",
                "testing.test_platform_control_cli",
                "testing.test_runtime_controls",
            ),
        ),
        test_modules=(
            "testing.test_b88_edge_security",
            "testing.test_b89_b95_infrastructure",
            "testing.test_b89_egress_policy",
            "testing.test_admin_action_runtime",
            "testing.test_product_oci",
            "testing.test_platform_control_cli",
            "testing.test_runtime_controls",
        ),
    ),
    "operations": SuiteSpec(
        commands=(
            _command(
                "./gradlew", "--no-daemon", "--console=plain",
                ":services:payment-core:test",
                "--tests", "com.elmpay.payment.provider.AccountAwareProviderAdapterFactoryTest",
                "--tests", "com.elmpay.payment.provider.JdbcProviderCallCircuitBreakerTest",
            ),
            _unittest(
                "testing.test_b96_b103_operations",
                "testing.test_b96_b99_monitoring_runtime",
                "testing.test_b98_b117_runtime_entrypoints",
            ),
        ),
        test_modules=(
            "testing.test_b96_b103_operations",
            "testing.test_b96_b99_monitoring_runtime",
            "testing.test_b98_b117_runtime_entrypoints",
        ),
    ),
    "assurance": SuiteSpec(
        commands=(
            _command(PYTHON, "-m", "tools.paygov.cli", "verify-all", "--repo", "."),
            _unittest(
                "testing.test_b104_b111_assurance",
                "testing.test_b118_b127_controls",
                "testing.test_china_mvp_launch_profile",
                "testing.test_ci_release_evidence_gate",
                "testing.test_external_boundary",
                "testing.test_external_evidence",
            ),
        ),
        test_modules=(
            "testing.test_b104_b111_assurance",
            "testing.test_b118_b127_controls",
            "testing.test_china_mvp_launch_profile",
            "testing.test_ci_release_evidence_gate",
            "testing.test_external_boundary",
            "testing.test_external_evidence",
        ),
    ),
    "quality-core": SuiteSpec(
        commands=(
            _unittest(
                "testing.test_b112_b117_quality",
                "testing.test_b40_b55_provider_contract_matrix",
                "testing.test_sota_faults",
            ),
            _command(PYTHON, "tools/quality_gate.py", "model", "--seed", "127", "--cases", "10000"),
        ),
        test_modules=(
            "testing.test_b112_b117_quality",
            "testing.test_b40_b55_provider_contract_matrix",
            "testing.test_sota_faults",
        ),
    ),
    "security-performance": SuiteSpec(
        commands=(
            _unittest(
                "testing.test_b116_security_orchestration",
                "testing.test_b117_http_load_profile",
                "testing.test_runtime_scale",
            ),
        ),
        test_modules=(
            "testing.test_b116_security_orchestration",
            "testing.test_b117_http_load_profile",
            "testing.test_runtime_scale",
        ),
    ),
}


def discover_testing_modules(root: Path = ROOT) -> tuple[str, ...]:
    """Return every importable ``testing/test_*.py`` module in stable order."""
    testing_root = root / "testing"
    if not testing_root.is_dir():
        raise SuiteConfigurationError(f"testing directory is missing: {testing_root}")
    modules: list[str] = []
    for path in testing_root.rglob("test_*.py"):
        relative = path.relative_to(root).with_suffix("")
        if "__pycache__" in relative.parts or any(part.startswith(".") for part in relative.parts):
            continue
        modules.append(".".join(relative.parts))
    return tuple(sorted(modules))


def validate_testing_module_coverage(
    root: Path = ROOT,
    suites: Mapping[str, SuiteSpec] = SUITES,
) -> tuple[str, ...]:
    """Require an exact, single-owner mapping for all discovered test modules."""
    discovered = set(discover_testing_modules(root))
    owners: dict[str, list[str]] = {}
    not_executed: dict[str, list[str]] = {}
    undeclared_executed: dict[str, list[str]] = {}
    for suite_name, suite in suites.items():
        command_tokens = {token for command in suite.commands for token in command}
        executed_test_modules = {
            token for token in command_tokens if token.startswith("testing.test_")
        }
        undeclared = sorted(executed_test_modules - set(suite.test_modules))
        if undeclared:
            undeclared_executed[suite_name] = undeclared
        for module in suite.test_modules:
            owners.setdefault(module, []).append(suite_name)
            if module not in command_tokens:
                not_executed.setdefault(suite_name, []).append(module)
    assigned = set(owners)
    missing = sorted(discovered - assigned)
    stale = sorted(assigned - discovered)
    duplicates = {
        module: names for module, names in sorted(owners.items()) if len(names) != 1
    }
    if missing or stale or duplicates or not_executed or undeclared_executed:
        raise SuiteConfigurationError(
            "testing module coverage mismatch: "
            f"missing={missing}, stale={stale}, duplicate_owners={duplicates}, "
            f"not_executed={not_executed}, undeclared_executed={undeclared_executed}"
        )
    return tuple(sorted(discovered))


def _run_commands(commands: Iterable[tuple[str, ...]]) -> int:
    for command in commands:
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode != 0:
            return result.returncode
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one ELMPay code-level test slice")
    parser.add_argument("suite", nargs="?", choices=sorted(SUITES))
    parser.add_argument(
        "--check-coverage", action="store_true",
        help="validate exact ownership of every testing/test_*.py module and exit",
    )
    args = parser.parse_args(argv)
    if args.suite is None and not args.check_coverage:
        parser.error("a suite or --check-coverage is required")
    try:
        modules = validate_testing_module_coverage()
    except SuiteConfigurationError as exc:
        print(f"run-code-suite: INVALID: {exc}", file=sys.stderr)
        return 3
    if args.check_coverage:
        print(f"run-code-suite: coverage PASS suites={len(SUITES)} modules={len(modules)}")
        return 0
    assert args.suite is not None
    return _run_commands(SUITES[args.suite].commands)


if __name__ == "__main__":
    sys.exit(main())
