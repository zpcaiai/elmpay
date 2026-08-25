"""B05 — continuous integration and quality baseline gate.

The pipeline is only a control if it cannot be softened quietly. This validator
enforces that:

* every required stage exists, is marked ``required`` and ``fail_closed``;
* the stage graph is acyclic and every ``needs`` reference resolves;
* every GitHub Action is pinned to a 40-character commit SHA, never a tag;
* the workflow requests least-privilege permissions and never uses
  ``pull_request_target`` or ``continue-on-error`` on a required stage;
* the blocking conditions demanded by the batch document — severe security
  finding, ledger imbalance, unrecoverable state, missing evidence — are each
  declared and attached to a stage that can actually detect them;
* the vendored skill package and both installed skill mirrors are verified
  before repository governance runs;
* the generated workflow matches the declaration.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import cigen
from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

PATH = Path("governance/ci-pipeline.json")
WORKFLOW = Path(".github/workflows/ci.yml")
ACTION_SHA = re.compile(r"^[0-9a-f]{40}$")
RELEASE_GATES = {"RG0", "RG1", "RG2", "RG3", "RG4", "RG5", "RG6", "RG7"}
EXPECTED_RUNNER = "ubuntu-24.04"
EXPECTED_REQUIRED_STAGES = {
    "governance", "python-floor", "build", "unit-test", "static-analysis", "secret-scan",
    "dependency-scan", "container-scan", "iac-scan", "sbom", "sign",
    "negative-controls", "evidence-archive", "rule-knockout",
}
FORBIDDEN_IN_WORKFLOW = ("pull_request_target", "continue-on-error: true",
                         "permissions: write-all", "${{ secrets.")
REQUIRED_BLOCKING_TOPICS = {
    "BLOCK-01": "security",
    "BLOCK-02": "ledger",
    "BLOCK-03": "recovery",
    "BLOCK-04": "evidence",
}
MAX_ZERO_GATES = ("unit_test_failed_max", "skipped_critical_max",
                  "blocking_security_findings_max", "governance_problems_max")
REQUIRED_SKILL_COMMANDS = {
    "python3 .payment-platform/skill-package/scripts/verify_package.py",
    "diff -qr .payment-platform/skill-package/skills .agents/skills",
    "diff -qr .payment-platform/skill-package/skills .claude/skills",
}
SUPPLY_CHAIN_STAGES = {
    "dependency-scan": {
        "commands": [
            "python3 -m tools.paygov.nvdfeed --repo .",
            "./gradlew --no-daemon dependencyCheckAggregate",
        ],
        "artifacts": ["build/reports/dependency-check-report.json"],
        "timeout_minutes": 45,
    },
    "sbom": {
        "commands": ["./gradlew --no-daemon cyclonedxBom"],
        "artifacts": ["build/reports/bom.json"],
    },
}
MACHINE_REPORT_STAGES = {
    "governance": {
        "command": ("python3 -m tools.paygov.cli verify-all --repo . "
                    "--out governance-report.json"),
        "artifact": "governance-report.json",
    },
    "python-floor": {
        "command": ("python3 -m tools.paygov.cli verify-all --repo . "
                    "--out python-floor-report.json"),
        "artifact": "python-floor-report.json",
    },
    "static-analysis": {
        "command": ("python3 -m tools.paygov.cli verify module-registry --repo . "
                    "--out build/static-analysis.json"),
        "artifact": "build/static-analysis.json",
    },
    "secret-scan": {
        "command": ("python3 -m tools.paygov.cli verify repo-hygiene --repo . "
                    "--out secret-scan.json"),
        "artifact": "secret-scan.json",
    },
    "container-scan": {
        "command": ("python3 -m tools.paygov.cli verify toolchain dev-platform --repo . "
                    "--out container-scan.json"),
        "artifact": "container-scan.json",
    },
    "iac-scan": {
        "command": ("python3 -m tools.paygov.cli verify dev-platform --repo . "
                    "--out iac-scan.json"),
        "artifact": "iac-scan.json",
    },
}
SIGNING_ACTION_PINS = {
    "actions/download-artifact": {
        "ref": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "version_comment": "v8.0.1",
    },
    "sigstore/cosign-installer": {
        "ref": "6f9f17788090df1f26f669e9d70d6ae9567deba6",
        "version_comment": "v4.1.2",
    },
}
PYTHON_ACTION_PIN = {
    "ref": "5fda3b95a4ea91299a34e894583c3862153e4b97",
    "version_comment": "v7.0.0",
}
CACHE_ACTION_PIN = {
    "ref": "27d5ce7f107fe9357f9df03efb73ab90386fccae",
    "version_comment": "v5.0.5",
}
EXPECTED_PYTHON_REFERENCE = "3.12.7"
EXPECTED_PYTHON_FLOOR = "3.10.12"
EXPECTED_SIGNING_POLICY = {
    "trusted_event": "push",
    "trusted_repository": "zpcaiai/elmpay",
    "trusted_ref": "refs/heads/main",
    "trusted_workflow": ".github/workflows/ci.yml",
    "public_sigstore_opt_in_variable":
        "ELMPAY_PUBLIC_SIGSTORE_METADATA_DISCLOSURE_OPT_IN",
    "cosign_release": "v3.0.6",
    "oidc_issuer": "https://token.actions.githubusercontent.com",
    "slsa_build_level": 1,
    "predicate_type": "https://slsa.dev/provenance/v1",
    "build_type": "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
    "validation_only_skipped_stages": ["sign", "evidence-archive"],
    "validation_only_outcome": "validated-not-release-eligible",
    "artifact_project_source":
        "governance/version-catalog.json#modules_by_build_system.gradle",
    "artifact_manifest": "build/signing-inputs/artifact-manifest.json",
    "artifact_manifest_sha256": "build/signing-inputs/artifact-manifest.sha256",
}
EXPECTED_SIGNING_PERMISSIONS = {
    "actions": "none",
    "contents": "read",
    "id-token": "write",
    "packages": "none",
}
EXPECTED_GLOBAL_PERMISSIONS = {
    "actions": "none",
    "contents": "read",
    "id-token": "none",
    "packages": "none",
}
EXPECTED_GRADLE_CACHE_POLICY = {
    "writer_stage": "build",
    "trusted_event": "push",
    "trusted_repository": "zpcaiai/elmpay",
    "trusted_ref": "refs/heads/main",
    "all_other_stages_read_only": True,
    "dependency_data_stage": "dependency-scan",
    "dependency_data_cache_path": "~/.gradle/dependency-check-data/11.0",
    "dependency_data_cache_key": (
        "dependency-check-13.0.0-data-11.0-${{ runner.os }}-${{ runner.arch }}-"
        "${{ github.run_id }}-${{ github.run_attempt }}"
    ),
    "dependency_data_restore_key": (
        "dependency-check-13.0.0-data-11.0-${{ runner.os }}-${{ runner.arch }}-"
    ),
    "dependency_data_restore_action": "actions/cache/restore",
    "dependency_data_save_action": "actions/cache/save",
}
EXPECTED_SIGNING_NEEDS = {
    "build",
    "sbom",
    "python-floor",
    "unit-test",
    "static-analysis",
    "dependency-scan",
    "container-scan",
    "iac-scan",
    "secret-scan",
    "negative-controls",
    "rule-knockout",
}
EXPECTED_SIGNING_DOWNLOADS = [
    {"name": "build-artifacts", "path": "build/signing-inputs"},
    {"name": "sbom-artifacts", "path": "build/reports"},
]


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("ci-pipeline", "B05")

def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget().start()
    where = str(PATH)
    try:
        doc: Any = load_json(root / PATH, budget)
    except BudgetExceeded:
        raise
    except Exception as exc:
        return [Problem("CI_UNREADABLE", where, str(exc), "NN-12")]

    problems: list[Problem] = []
    problems += expect(bool(SEMVER.match(str(doc.get("schema_version", "")))),
                       "CI_VERSION", where, "schema_version must be semantic version", "NN-12")

    stages = doc.get("stages")
    required = doc.get("required_stages")
    if not isinstance(stages, list) or not stages or not isinstance(required, list):
        return problems + [Problem("CI_SHAPE", where,
                                   "pipeline needs 'stages' and 'required_stages'", "NN-12")]
    problems += expect(doc.get("runner") == EXPECTED_RUNNER, "CI_RUNNER", where,
                       "keyless CI must use the audited GitHub-hosted runner label",
                       "NN-11")

    by_id: dict[str, dict] = {}
    for stage in stages:
        sid = stage.get("id", "?")
        scope = f"{where}#{sid}"
        if sid in by_id:
            problems.append(Problem("CI_DUPLICATE", scope, f"duplicate stage '{sid}'", "NN-12"))
            continue
        by_id[sid] = stage
        problems += expect(bool(stage.get("commands")), "CI_STAGE", scope,
                           "a stage without commands does not check anything", "NN-12")
        problems += expect(stage.get("gate") in RELEASE_GATES, "CI_STAGE", scope,
                           f"gate must be one of {sorted(RELEASE_GATES)}", "NN-12")
        problems += expect(isinstance(stage.get("timeout_minutes"), int)
                           and 0 < stage["timeout_minutes"] <= 120, "CI_STAGE", scope,
                           "every stage needs a bounded timeout", "NN-12")
        if stage.get("required"):
            problems += expect(stage.get("fail_closed") is True, "CI_FAIL_OPEN", scope,
                               "a required stage must be fail-closed", "NN-12")
            problems += expect(isinstance(stage.get("artifacts"), list)
                               and bool(stage["artifacts"])
                               and stage.get("if_no_files_found") == "error",
                               "CI_ARTIFACT_MISSING", scope,
                               "a required stage must retain evidence and fail when it is absent",
                               "NN-12")

    for name in required:
        problems += expect(name in by_id, "CI_REQUIRED_STAGE", where,
                           f"required stage '{name}' is not defined", "NN-12")
        if name in by_id:
            problems += expect(by_id[name].get("required") is True, "CI_REQUIRED_STAGE", where,
                               f"stage '{name}' is listed as required but not marked required",
                               "NN-12")
    problems += expect(len(required) == len(set(required)), "CI_REQUIRED_STAGE", where,
                       "required_stages must not contain duplicate stage ids", "NN-12")
    declared_required = {sid for sid, stage in by_id.items() if stage.get("required") is True}
    problems += expect(set(required) == declared_required, "CI_REQUIRED_STAGE", where,
                       "required_stages must exactly equal the stages marked required",
                       "NN-12")
    problems += expect(set(required) == EXPECTED_REQUIRED_STAGES
                       and len(required) == len(EXPECTED_REQUIRED_STAGES),
                       "CI_REQUIRED_STAGE", where,
                       "the complete audited required-stage set must remain present",
                       "NN-12")
    problems += expect(set(by_id) == EXPECTED_REQUIRED_STAGES,
                       "CI_REQUIRED_STAGE", where,
                       "stages must exactly match the audited required-stage set",
                       "NN-12")

    problems += _graph(by_id, where)
    problems += _actions(doc, where)
    problems += _permissions(doc, where)
    problems += _gradle_cache_policy(doc, by_id, where)
    problems += _quality_gates(doc, where)
    problems += _blocking(doc, by_id, where)
    problems += _skill_package(by_id, where)
    problems += _machine_reports(by_id, where)
    problems += _python_toolchain(root, budget, doc, by_id, where)
    problems += _supply_chain_stages(by_id, where)
    problems += _signing(doc, by_id, where)
    problems += _generated(root, budget, doc)
    return problems


def _graph(by_id: dict[str, dict], where: str) -> list[Problem]:
    problems: list[Problem] = []
    for sid, stage in sorted(by_id.items()):
        for need in stage.get("needs", []):
            problems += expect(need in by_id, "CI_NEEDS", f"{where}#{sid}",
                               f"stage depends on unknown stage '{need}'", "NN-12")
    colour: dict[str, int] = {sid: 0 for sid in by_id}

    def visit(node: str, path: list[str]) -> None:
        colour[node] = 1
        for need in by_id[node].get("needs", []):
            if need not in by_id:
                continue
            if colour[need] == 1:
                problems.append(Problem("CI_CYCLE", f"{where}#{node}",
                                        "stage cycle: " + " -> ".join(path + [need]), "NN-12"))
            elif colour[need] == 0:
                visit(need, path + [need])
        colour[node] = 2

    for sid in sorted(by_id):
        if colour[sid] == 0:
            visit(sid, [sid])
    return problems


def _actions(doc: dict, where: str) -> list[Problem]:
    problems: list[Problem] = []
    actions = doc.get("actions")
    if not isinstance(actions, list) or not actions:
        return [Problem("CI_ACTION", where, "'actions' must list every third-party action", "NN-12")]
    for action in actions:
        scope = f'{where}#{action.get("name", "?")}'
        problems += expect(bool(ACTION_SHA.match(str(action.get("ref", "")))), "CI_ACTION_PIN",
                           scope,
                           "third-party actions must be pinned to a full commit SHA, not a tag; "
                           "a tag can be moved to arbitrary code", "NN-12")
        problems += expect(len(str(action.get("version_comment", "")).strip()) >= 2,
                           "CI_ACTION", scope,
                           "record the human-readable version next to the pinned SHA", "NN-12")
    return problems


def _permissions(doc: dict, where: str) -> list[Problem]:
    permissions = doc.get("permissions")
    if not isinstance(permissions, dict) or not permissions:
        return [Problem("CI_PERMISSIONS", where, "'permissions' must be declared", "NN-12")]
    problems: list[Problem] = []
    problems += expect(permissions == EXPECTED_GLOBAL_PERMISSIONS,
                       "CI_PERMISSIONS", where,
                       "global permissions must be the exact audited read/none set",
                       "NN-11")
    problems += expect(permissions.get("contents") == "read", "CI_PERMISSIONS", where,
                       "the pipeline must not have write access to repository contents", "NN-11")
    problems += expect(permissions.get("id-token") == "none", "CI_PERMISSIONS", where,
                       "OIDC must be disabled globally and granted only to the signing job",
                       "NN-11")
    for key, value in sorted(permissions.items()):
        problems += expect(value != "write-all", "CI_PERMISSIONS", where,
                           f"'{key}' must not be write-all", "NN-11")
    return problems


def _gradle_cache_policy(doc: dict, by_id: dict[str, dict], where: str) -> list[Problem]:
    """Save Dependency-Check state only after a successful trusted scan.

    Cold, parallel Gradle jobs can otherwise hammer Maven Central while a
    blanket writable cache would let untrusted pull requests publish inputs
    consumed by later builds. The governed build is the only setup-gradle
    writer. The SCA job restores its isolated NVD database read-only, then an
    explicit save action persists it only after the aggregate scan succeeds on
    trusted main. A failed or cancelled scan therefore cannot publish a
    truncated database through setup-gradle's post action.
    """
    policy = doc.get("gradle_cache_policy")
    scope = f"{where}#gradle_cache_policy"
    problems = expect(policy == EXPECTED_GRADLE_CACHE_POLICY,
                      "CI_GRADLE_CACHE", scope,
                      "ordinary Gradle state and successful Dependency-Check data must use "
                      "separate governed write paths",
                      "NN-11")
    if not isinstance(policy, dict):
        return problems
    writer = policy.get("writer_stage")
    problems += expect(writer == "build"
                       and by_id.get("build", {}).get("needs") == ["governance"]
                       and by_id.get("dependency-scan", {}).get("needs") == ["build"],
                       "CI_GRADLE_CACHE", scope,
                       "setup-gradle must have one governed writer and the isolated scan must "
                       "remain ordered after it",
                       "NN-11")
    actions = doc.get("actions")
    cache_actions = [action for action in actions
                     if isinstance(action, dict)
                     and action.get("name") in {"actions/cache/restore", "actions/cache/save"}] \
        if isinstance(actions, list) else []
    expected_actions = [
        {"name": "actions/cache/restore", **CACHE_ACTION_PIN},
        {"name": "actions/cache/save", **CACHE_ACTION_PIN},
    ]
    problems += expect(cache_actions == expected_actions,
                       "CI_GRADLE_CACHE", scope,
                       "the isolated dependency cache must use the audited restore/save actions",
                       "NN-11")
    return problems


def _quality_gates(doc: dict, where: str) -> list[Problem]:
    gates = doc.get("quality_gates")
    if not isinstance(gates, dict):
        return [Problem("CI_QUALITY_GATE", where, "'quality_gates' must be declared", "NN-12")]
    problems: list[Problem] = []
    for key in MAX_ZERO_GATES:
        problems += expect(gates.get(key) == 0, "CI_QUALITY_GATE", where,
                           f"'{key}' must be 0; there is no 'passed with warnings' state", "NN-12")
    for key in ("line_coverage_min_percent", "mutation_score_min_percent"):
        value = gates.get(key)
        problems += expect(isinstance(value, int) and value > 0, "CI_QUALITY_GATE", where,
                           f"'{key}' must be a positive threshold", "NN-12")
    return problems


def _blocking(doc: dict, by_id: dict[str, dict], where: str) -> list[Problem]:
    conditions = doc.get("blocking_conditions")
    if not isinstance(conditions, list) or not conditions:
        return [Problem("CI_BLOCKING", where,
                        "'blocking_conditions' must declare what stops a release", "NN-12")]
    problems: list[Problem] = []
    seen: set[str] = set()
    for condition in conditions:
        cid = condition.get("id", "?")
        scope = f"{where}#{cid}"
        seen.add(cid)
        problems += expect(len(str(condition.get("description", "")).strip()) >= 6,
                           "CI_BLOCKING", scope, "blocking condition needs a description", "NN-12")
        problems += expect(condition.get("gate") in RELEASE_GATES, "CI_BLOCKING", scope,
                           f"gate must be one of {sorted(RELEASE_GATES)}", "NN-12")
        detectors = condition.get("detected_by")
        problems += expect(isinstance(detectors, list) and bool(detectors), "CI_BLOCKING", scope,
                           "a blocking condition nobody detects is not a control", "NN-12")
        for detector in detectors or []:
            problems += expect(detector in by_id, "CI_BLOCKING", scope,
                               f"unknown detecting stage '{detector}'", "NN-12")
    for cid in sorted(set(REQUIRED_BLOCKING_TOPICS) - seen):
        problems.append(Problem("CI_BLOCKING_MISSING", where,
                                f"the batch document requires a blocking condition for "
                                f"'{REQUIRED_BLOCKING_TOPICS[cid]}' ({cid})", "NN-12"))
    return problems


def _skill_package(by_id: dict[str, dict], where: str) -> list[Problem]:
    """The workflow must validate both the package and what agents execute.

    Verifying only the package leaves room for an installed mirror to drift;
    comparing only mirrors can faithfully install a corrupted package.  All
    three checks are therefore one fail-closed control.
    """
    commands = set(by_id.get("governance", {}).get("commands", []))
    missing = sorted(REQUIRED_SKILL_COMMANDS - commands)
    return [Problem("CI_SKILL_PACKAGE", f"{where}#governance",
                    f"required skill integrity command is missing: {command}", "NN-12")
            for command in missing]


def _supply_chain_stages(by_id: dict[str, dict], where: str) -> list[Problem]:
    """Keep SCA and SBOM stages tied to their aggregate, machine-readable gates.

    Merely having a stage named ``dependency-scan`` is not sufficient.  The
    single-project ``dependencyCheckAnalyze`` task silently omits dependencies
    declared by sibling projects, while an upload path that differs from the
    generated Gradle report turns a successful scan into missing evidence.
    These are governance semantics, so changing the declaration and regenerating
    the workflow together must still fail validation.
    """
    problems: list[Problem] = []
    for sid, expected in SUPPLY_CHAIN_STAGES.items():
        stage = by_id.get(sid)
        scope = f"{where}#{sid}"
        if not isinstance(stage, dict):
            problems.append(Problem("CI_SUPPLY_CHAIN_STAGE", scope,
                                    "required supply-chain stage is missing", "NN-12"))
            continue

        problems += expect(stage.get("required") is True
                           and stage.get("fail_closed") is True,
                           "CI_SUPPLY_CHAIN_GATE", scope,
                           "dependency and SBOM stages must remain required and fail-closed",
                           "NN-12")

        commands = stage.get("commands")
        problems += expect(commands == expected["commands"],
                           "CI_SUPPLY_CHAIN_TASK", scope,
                           "stage commands must exactly preserve the governed freshness "
                           "preflight and aggregate task order", "NN-12")
        if isinstance(commands, list):
            problems += expect(not any("dependencyCheckAnalyze" in str(command)
                                       for command in commands),
                               "CI_SUPPLY_CHAIN_TASK", scope,
                               "single-project dependencyCheckAnalyze cannot replace the "
                               "multi-project aggregate scan", "NN-12")

        artifacts = stage.get("artifacts")
        problems += expect(artifacts == expected["artifacts"],
                           "CI_SUPPLY_CHAIN_ARTIFACT", scope,
                           f"stage must retain exactly the machine-readable evidence "
                           f"{expected['artifacts']}", "NN-12")
        problems += expect("build" in stage.get("needs", []),
                           "CI_SUPPLY_CHAIN_COVERAGE", scope,
                           "supply-chain analysis must run after the complete multi-project "
                           "build graph", "NN-12")
        problems += expect(stage.get("if_no_files_found") == "error",
                           "CI_ARTIFACT_MISSING", scope,
                           "machine-readable supply-chain evidence must fail when absent",
                           "NN-12")
        if "timeout_minutes" in expected:
            problems += expect(stage.get("timeout_minutes") == expected["timeout_minutes"],
                               "CI_SUPPLY_CHAIN_TIMEOUT", scope,
                               f"stage timeout must remain exactly "
                               f"{expected['timeout_minutes']} minutes",
                               "NN-12")
    return problems


def _python_toolchain(root: Path, budget: Budget, doc: dict,
                      by_id: dict[str, dict], where: str) -> list[Problem]:
    """Execute the same governance surface on exact reference and floor Pythons."""
    scope = f"{where}#python-toolchain"
    problems: list[Problem] = []
    try:
        catalog = load_json(root / "governance/version-catalog.json", budget)
    except BudgetExceeded:
        raise
    except Exception as exc:
        return [Problem("CI_PYTHON_TOOLCHAIN", scope,
                        f"version catalogue is unreadable: {exc}", "NN-12")]

    entries = {entry.get("id"): entry for entry in catalog.get("entries", [])
               if isinstance(entry, dict)}
    interpreter = entries.get("python-toolchain")
    problems += expect(isinstance(interpreter, dict), "CI_PYTHON_TOOLCHAIN", scope,
                       "the CI interpreter must come from python-toolchain in the catalogue",
                       "NN-12")
    if isinstance(interpreter, dict):
        problems += expect(interpreter.get("version") == EXPECTED_PYTHON_REFERENCE,
                           "CI_PYTHON_TOOLCHAIN", scope,
                           f"the reference interpreter must remain exactly "
                           f"{EXPECTED_PYTHON_REFERENCE}", "NN-12")
        problems += expect(interpreter.get("minimum_supported") == EXPECTED_PYTHON_FLOOR,
                           "CI_PYTHON_TOOLCHAIN", scope,
                           f"the compatibility floor must remain exactly "
                           f"{EXPECTED_PYTHON_FLOOR}", "NN-12")

    listed_actions = doc.get("actions")
    python_actions = [action for action in listed_actions
                      if isinstance(action, dict)
                      and action.get("name") == "actions/setup-python"] \
        if isinstance(listed_actions, list) else []
    problems += expect(python_actions == [{"name": "actions/setup-python",
                                           **PYTHON_ACTION_PIN}],
                       "CI_PYTHON_ACTION", scope,
                       "actions/setup-python must appear once at the audited v7 commit",
                       "NN-12")

    stage = by_id.get("python-floor")
    stage_scope = f"{where}#python-floor"
    if not isinstance(stage, dict):
        return problems + [Problem("CI_PYTHON_FLOOR", stage_scope,
                                   "required Python floor stage is missing", "NN-12")]
    problems += expect(stage.get("needs") == ["governance"],
                       "CI_PYTHON_FLOOR", stage_scope,
                       "the floor gate must run immediately after governance", "NN-12")
    problems += expect(stage.get("required") is True and stage.get("fail_closed") is True,
                       "CI_PYTHON_FLOOR", stage_scope,
                       "the floor gate must remain required and fail-closed", "NN-12")
    problems += expect(stage.get("timeout_minutes") == 20,
                       "CI_PYTHON_FLOOR", stage_scope,
                       "the complete floor gate must retain its audited 20 minute bound",
                       "NN-12")
    return problems


def _machine_reports(by_id: dict[str, dict], where: str) -> list[Problem]:
    """Bind validator-backed CI stages to the JSON they claim to upload."""
    problems: list[Problem] = []
    for stage_id, expected in MACHINE_REPORT_STAGES.items():
        stage = by_id.get(stage_id)
        scope = f"{where}#{stage_id}"
        if not isinstance(stage, dict):
            problems.append(Problem("CI_MACHINE_REPORT", scope,
                                    "machine-report stage is missing", "NN-12"))
            continue
        problems += expect(expected["command"] in stage.get("commands", []),
                           "CI_MACHINE_REPORT", scope,
                           f"stage must atomically write '{expected['artifact']}'", "NN-12")
        problems += expect(stage.get("artifacts") == [expected["artifact"]],
                           "CI_MACHINE_REPORT", scope,
                           "uploaded report path must exactly match the validator output",
                           "NN-12")
    return problems


def _signing(doc: dict, by_id: dict[str, dict], where: str) -> list[Problem]:
    """Pin the narrow, consent-gated keyless signing trust boundary.

    This is intentionally a Build L1 blob-signing control.  It must not be
    broadened into an image-signing or stronger SLSA claim merely by editing
    the declaration and regenerating the workflow.
    """
    policy = doc.get("signing_policy")
    if not isinstance(policy, dict):
        return [Problem("CI_SIGNING_POLICY", where,
                        "'signing_policy' must declare the trusted signing boundary",
                        "NN-11")]

    problems: list[Problem] = []
    scope = f"{where}#signing_policy"
    for key, expected in EXPECTED_SIGNING_POLICY.items():
        problems += expect(policy.get(key) == expected, "CI_SIGNING_POLICY", scope,
                           f"'{key}' must remain {expected!r}", "NN-11")

    problems += expect(policy.get("job_permissions") == EXPECTED_SIGNING_PERMISSIONS,
                       "CI_SIGNING_PERMISSIONS", scope,
                       "only the signing job may request id-token: write, with all other "
                       "permissions explicitly read or none", "NN-11")
    problems += expect(policy.get("downloads") == EXPECTED_SIGNING_DOWNLOADS,
                       "CI_SIGNING_INPUT", scope,
                       "the signing job must download the exact build and SBOM artifacts",
                       "NN-12")

    build = by_id.get("build")
    build_scope = f"{where}#build"
    problems += expect(isinstance(build, dict)
                       and "scripts/stage-signing-artifacts.sh" in build.get("commands", []),
                       "CI_SIGNING_INPUT", build_scope,
                       "build must stage every declared Gradle artifact into a manifest",
                       "NN-12")
    problems += expect(isinstance(build, dict)
                       and build.get("artifacts") == ["build/signing-inputs/"],
                       "CI_SIGNING_INPUT", build_scope,
                       "build upload must preserve the manifested artifact paths",
                       "NN-12")

    listed_actions = doc.get("actions")
    actions = ({action.get("name"): action for action in listed_actions
                if isinstance(action, dict)}
               if isinstance(listed_actions, list) else {})
    for name, expected in SIGNING_ACTION_PINS.items():
        action = actions.get(name)
        action_scope = f"{where}#{name}"
        problems += expect(isinstance(action, dict), "CI_SIGNING_ACTION", action_scope,
                           f"required signing action '{name}' is missing", "NN-12")
        if isinstance(action, dict):
            problems += expect(action.get("ref") == expected["ref"],
                               "CI_SIGNING_ACTION", action_scope,
                               f"'{name}' must remain pinned to the audited commit",
                               "NN-12")
            problems += expect(action.get("version_comment") == expected["version_comment"],
                               "CI_SIGNING_ACTION", action_scope,
                               f"'{name}' version annotation must match the audited release",
                               "NN-12")

    sign = by_id.get("sign")
    sign_scope = f"{where}#sign"
    if not isinstance(sign, dict):
        return problems + [Problem("CI_SIGNING_STAGE", sign_scope,
                                   "required signing stage is missing", "NN-12")]

    required_stages = doc.get("required_stages", [])
    problems += expect("sign" in required_stages,
                       "CI_SIGNING_REQUIRED", sign_scope,
                       "the signing stage must remain in required_stages", "NN-12")
    problems += expect(sign.get("required") is True and sign.get("fail_closed") is True,
                       "CI_SIGNING_REQUIRED", sign_scope,
                       "the signing stage must remain required and fail-closed", "NN-12")

    needs = sign.get("needs")
    problems += expect(isinstance(needs, list) and set(needs) == EXPECTED_SIGNING_NEEDS
                       and len(needs) == len(EXPECTED_SIGNING_NEEDS),
                       "CI_SIGNING_INPUT", sign_scope,
                       "signing must depend on the exact complete pre-sign gate set",
                       "NN-12")
    problems += expect(sign.get("commands") == ["scripts/sign-artifacts.sh"],
                       "CI_SIGNING_COMMAND", sign_scope,
                       "signing must use the generated fail-closed signing script",
                       "NN-12")
    artifacts = sign.get("artifacts")
    problems += expect(isinstance(artifacts, list)
                       and "build/provenance.intoto.jsonl" in artifacts
                       and "build/signatures/" in artifacts,
                       "CI_SIGNING_OUTPUT", sign_scope,
                       "signing must retain the verified in-toto provenance and Sigstore bundles",
                       "NN-12")

    purpose = str(sign.get("purpose", ""))
    problems += expect("SLSA Build L1" in purpose,
                       "CI_SIGNING_CLAIM", sign_scope,
                       "the signing claim must be limited explicitly to SLSA Build L1",
                       "NN-12")
    problems += expect("image" not in purpose.lower() and "镜像" not in purpose,
                       "CI_SIGNING_CLAIM", sign_scope,
                       "the pipeline does not build or sign a container image and must not claim it",
                       "NN-12")

    archive = by_id.get("evidence-archive")
    archive_scope = f"{where}#evidence-archive"
    problems += expect(isinstance(archive, dict)
                       and archive.get("required") is True
                       and archive.get("fail_closed") is True
                       and "evidence-archive" in required_stages,
                       "CI_SIGNING_REQUIRED", archive_scope,
                       "evidence archive must remain a required, fail-closed release stage",
                       "NN-12")
    problems += expect(isinstance(archive, dict)
                       and "sign" in archive.get("needs", []),
                       "CI_SIGNING_CHAIN", archive_scope,
                       "evidence archive must depend directly on verified signing output",
                       "NN-12")

    for sid in ("build", "sbom", "sign"):
        stage = by_id.get(sid)
        missing_scope = f"{where}#{sid}"
        problems += expect(isinstance(stage, dict)
                           and stage.get("if_no_files_found") == "error",
                           "CI_ARTIFACT_MISSING", missing_scope,
                           "critical build, SBOM and signing evidence must fail when absent",
                           "NN-12")
    return problems


def _terminal_gate(text: str, doc: dict, where: str) -> list[Problem]:
    marker = "\n  release-gate:\n"
    if marker not in text:
        return [Problem("CI_RELEASE_GATE_CONTEXT", where,
                        "generated workflow has no terminal release gate", "NN-12")]
    gate = text.split(marker, 1)[1]
    run = gate.split("        run: |\n", 1)[1] if "        run: |\n" in gate else ""
    signing = doc["signing_policy"]
    required = doc["required_stages"]
    release_only = signing["validation_only_skipped_stages"]
    non_release = [stage for stage in required if stage not in set(release_only)]
    problems: list[Problem] = []
    required_snippets = [
        "    if: always()",
        "ELMPAY_GATE_EVENT_NAME: ${{ github.event_name }}",
        "ELMPAY_GATE_REPOSITORY: ${{ github.repository }}",
        "ELMPAY_GATE_REF: ${{ github.ref }}",
        f"ELMPAY_SIGNING_OPT_IN: "
        f"${{{{ vars.{signing['public_sigstore_opt_in_variable']} }}}}",
        f"REQUIRED_STAGES=({' '.join(required)})",
        f"RELEASE_ONLY_STAGES=({' '.join(release_only)})",
        f"NON_RELEASE_REQUIRED_STAGES=({' '.join(non_release)})",
        f"{signing['validation_only_outcome']}: validation succeeded",
        "release-eligible: trusted main push",
    ]
    for snippet in required_snippets:
        problems += expect(snippet in gate, "CI_RELEASE_GATE_CONTEXT", where,
                           f"terminal gate is missing fail-closed logic: {snippet}", "NN-12")
    for stage_id in required:
        env_name = _result_environment_name(stage_id)
        expression = f"${{{{ needs['{stage_id}'].result }}}}"
        problems += expect(f"{env_name}: {expression}" in gate,
                           "CI_RELEASE_GATE_CONTEXT", where,
                           f"terminal gate does not receive result for '{stage_id}' via env",
                           "NN-12")
    problems += expect(bool(run) and "${{" not in run,
                       "CI_RELEASE_GATE_INJECTION", where,
                       "GitHub expressions must enter through step env, never shell source",
                       "NN-11")
    return problems


def _result_environment_name(stage_id: str) -> str:
    return "ELMPAY_NEEDS_" + stage_id.upper().replace("-", "_")


def _generated(root: Path, budget: Budget, doc: dict) -> list[Problem]:
    problems: list[Problem] = []
    try:
        rendered = cigen.render_all(root)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, OSError) as exc:
        return [Problem(
            "CI_DRIFT",
            str(WORKFLOW),
            f"generated CI inputs are incomplete or invalid: {exc}",
            "NN-12",
        )]
    for rel, expected in sorted(rendered.items()):
        budget.check(rel)
        path = root / rel
        if not path.is_file():
            problems.append(Problem("CI_MISSING", rel,
                                    "generated CI file is missing; run scripts/render-ci.py",
                                    "NN-12"))
        elif path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("CI_DRIFT", rel,
                                    "generated CI file differs from governance/ci-pipeline.json",
                                    "NN-12"))
    text = rendered[str(WORKFLOW)]
    for forbidden in FORBIDDEN_IN_WORKFLOW:
        if forbidden in text:
            problems.append(Problem("CI_UNSAFE_WORKFLOW", str(WORKFLOW),
                                    f"workflow must not contain '{forbidden}'", "NN-11"))
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("- uses:") and "@" in stripped:
            ref = stripped.split("@", 1)[1].split()[0]
            if not ACTION_SHA.match(ref):
                problems.append(Problem("CI_ACTION_PIN", str(WORKFLOW),
                                        f"action reference '{ref}' is not a commit SHA", "NN-12"))
    problems += _terminal_gate(text, doc, str(WORKFLOW))
    return problems
