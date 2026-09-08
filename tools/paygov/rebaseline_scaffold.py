"""Generate non-certifying rebaseline inputs from repository SSOT files.

The generated files are plans and command specifications, never evidence of
execution or approval. Existing non-identical files are never overwritten.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Callable


MANIFEST = Path(".payment-platform/skill-package/manifest.json")
INVENTORY = Path(".ai/implementation_inventory.json")
TEST_MATRIX = Path("testing/test-matrix.json")
EXTERNAL_GATES = Path("platform/compliance/rebaseline-external-gates.json")
SCAFFOLD_FILES = ("plan.md", "commands.spec.json", "artifacts.json", "traceability.json")


class ScaffoldError(RuntimeError):
    """The SSOT inputs cannot safely produce a rebaseline scaffold."""


@dataclass(frozen=True)
class BatchSource:
    batch: dict[str, Any]
    inventory: dict[str, Any]
    suite: dict[str, Any]
    external_gate: dict[str, Any] | None


def _json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScaffoldError(f"cannot read {path}: {exc}") from exc


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _contained_file(root: Path, relative: str, batch: str) -> str:
    if not relative or Path(relative).is_absolute():
        raise ScaffoldError(f"{batch} has unsafe artifact path {relative!r}")
    try:
        target = (root / relative).resolve(strict=True)
        target.relative_to(root.resolve())
    except (OSError, ValueError) as exc:
        raise ScaffoldError(f"{batch} artifact is missing or escapes the repository: {relative}") from exc
    if not target.is_file():
        raise ScaffoldError(f"{batch} artifact is not a regular file: {relative}")
    return relative


def load_sources(root: Path) -> dict[str, BatchSource]:
    root = root.resolve()
    manifest = _json(root / MANIFEST)
    inventory_doc = _json(root / INVENTORY)
    matrix = _json(root / TEST_MATRIX)
    gates = _json(root / EXTERNAL_GATES)
    raw_batches = manifest.get("batches") if isinstance(manifest, dict) else None
    inventories = inventory_doc.get("batches") if isinstance(inventory_doc, dict) else None
    suites = matrix.get("suites") if isinstance(matrix, dict) else None
    gate_batches = gates.get("batches") if isinstance(gates, dict) else None
    if not isinstance(raw_batches, list) or len(raw_batches) != 128:
        raise ScaffoldError("manifest must contain exactly 128 batches")
    if not isinstance(inventories, dict) or set(inventories) != {
        item.get("id") for item in raw_batches if isinstance(item, dict)
    }:
        raise ScaffoldError("implementation inventory must cover every manifest batch exactly")
    if not isinstance(suites, list) or not isinstance(gate_batches, dict):
        raise ScaffoldError("test matrix or external gate policy is malformed")

    owners: dict[str, list[dict[str, Any]]] = {}
    for suite in suites:
        if not isinstance(suite, dict):
            raise ScaffoldError("test matrix suite must be an object")
        for batch in suite.get("batch_ids", []):
            owners.setdefault(batch, []).append(suite)
    expected = [item["id"] for item in raw_batches]
    mismatch = {batch: len(owners.get(batch, [])) for batch in expected if len(owners.get(batch, [])) != 1}
    if mismatch or set(owners) != set(expected):
        raise ScaffoldError(f"test matrix batch ownership is not exact: {mismatch}")

    result: dict[str, BatchSource] = {}
    for item in raw_batches:
        batch = item["id"]
        gate = gate_batches.get(batch)
        if gate is not None and not isinstance(gate, dict):
            raise ScaffoldError(f"{batch} external gate must be an object")
        result[batch] = BatchSource(item, inventories[batch], owners[batch][0], gate)
    return result


def _artifact_paths(root: Path, source: BatchSource) -> list[str]:
    batch = source.batch["id"]
    groups = source.inventory.get("artifacts")
    if not isinstance(groups, dict):
        raise ScaffoldError(f"{batch} inventory artifacts are malformed")
    paths: list[str] = []
    for role in ("executable", "runtime_entrypoint", "config", "migrations", "tests"):
        entries = groups.get(role)
        if not isinstance(entries, list):
            raise ScaffoldError(f"{batch} inventory role {role} is empty")
        if not entries:
            if (
                role == "migrations"
                and source.inventory.get("migration_required") is False
                and isinstance(source.inventory.get("migration_not_applicable_reason"), str)
                and source.inventory["migration_not_applicable_reason"].strip()
            ):
                continue
            raise ScaffoldError(f"{batch} inventory role {role} is empty")
        for entry in entries:
            relative = entry.get("path") if isinstance(entry, dict) else None
            if not isinstance(relative, str):
                raise ScaffoldError(f"{batch} inventory role {role} has no path")
            relative = _contained_file(root, relative, batch)
            if relative not in paths:
                paths.append(relative)
    paths.append(f"evidence/{batch}/traceability.json")
    return paths


def _command(batch: str, purpose: str, command: str, save_to: str, expect: int = 0) -> dict[str, Any]:
    if not save_to or Path(save_to).is_absolute() or ".." in Path(save_to).parts:
        raise ScaffoldError(f"{batch} command output is unsafe: {save_to}")
    return {"purpose": purpose, "expect": expect, "command": command, "save_to": save_to}


def _commands(source: BatchSource) -> dict[str, Any]:
    batch = source.batch["id"]
    commands = [
        _command(batch, "environment fingerprint", "python3 -VV && uname -a && git --version && echo repo=$(git rev-parse --short HEAD)", "runtime/environment.txt"),
        _command(batch, "vendored skill package checksum and inventory", "python3 .payment-platform/skill-package/scripts/verify_package.py", "runtime/skill-package.json"),
    ]
    for dependency in source.batch.get("depends_on", []):
        commands.append(_command(
            batch,
            f"dependency {dependency} evidence still validates",
            f"python3 .payment-platform/skill-package/scripts/orchestrate.py validate {dependency} --repo .",
            f"runtime/dependency-{dependency.lower()}.json",
        ))
    for index in range(1, 5):
        commands.append(_command(
            batch,
            f"full governance regression suite shard {index} of 4",
            f"python3 scripts/test-summary.py --shard {index}/4 --out evidence/{batch}/test-results/summary-{index}of4.json --log evidence/{batch}/test-results/unittest-{index}of4.log",
            f"test-results/summary-{index}of4.log",
        ))
    partials = " ".join(f"evidence/{batch}/test-results/summary-{index}of4.json" for index in range(1, 5))
    commands.append(_command(
        batch,
        "merge all test shards and refuse missing or duplicate units",
        f"python3 scripts/test-summary.py --merge {partials} --out evidence/{batch}/test-results/summary.json --log evidence/{batch}/test-results/unittest.log",
        "test-results/summary.log",
    ))
    suite_command = source.suite.get("command")
    if isinstance(suite_command, list) and suite_command and all(isinstance(token, str) for token in suite_command):
        rendered = " ".join(suite_command)
    else:
        rendered = "python3 scripts/run-code-suite.py assurance"
    commands.append(_command(batch, f"batch-owned code suite {source.suite.get('id')}", rendered, "runtime/batch-code-suite.log"))
    commands.append(_command(batch, "test module ownership is exact", "python3 scripts/run-code-suite.py --check-coverage", "runtime/test-coverage-map.log"))
    if source.external_gate is not None:
        commands.append(_command(
            batch,
            "independently signed external evidence for this release batch",
            f"python3 tools/runtime/external_batch_gate.py {batch} --bundle evidence/external/release-evidence.json --trust evidence/external/trust.json --manifest evidence/external/release-manifest.json",
            "runtime/external-evidence-gate.json",
        ))
    for index in range(1, 5):
        commands.append(_command(
            batch,
            f"runtime fail-closed proof shard {index} of 4",
            f"python3 scripts/negative-controls.py --shard {index}/4",
            f"security/negative-controls-{index}of4.log",
        ))
    commands.extend([
        _command(batch, "governance gate on the real repository", "python3 -m tools.paygov.cli verify-all --repo .", "security/governance-report.json"),
        _command(batch, "exhausted budget must exit 3, never 0", "python3 -m tools.paygov.cli verify repo-hygiene --repo . --budget-seconds 0", "runtime/timeout-fail-closed.log", 3),
        _command(batch, "duplicate governance invocation is byte-identical", f"python3 -m tools.paygov.cli verify-all --repo . > /tmp/{batch}-1.json && python3 -m tools.paygov.cli verify-all --repo . > /tmp/{batch}-2.json && diff /tmp/{batch}-1.json /tmp/{batch}-2.json && echo IDENTICAL", "runtime/idempotency.txt"),
        _command(batch, "registered validators", "python3 -m tools.paygov.cli list-validators --repo .", "runtime/validators.txt"),
    ])
    return {"batch": batch, "commands": commands}


def _traceability(source: BatchSource, artifacts: list[str]) -> dict[str, Any]:
    batch = source.batch["id"]
    requirement = f"{batch}-GOAL"
    grouped = source.inventory["artifacts"]
    code_paths = []
    for role in ("executable", "runtime_entrypoint", "config", "migrations"):
        for entry in grouped[role]:
            if entry["path"] not in code_paths:
                code_paths.append(entry["path"])
    test_paths = list(dict.fromkeys(entry["path"] for entry in grouped["tests"]))
    evidence = [
        {"path": f"evidence/{batch}/plan.md", "kind": "plan"},
        {"path": f"evidence/{batch}/commands.spec.json", "kind": "command-spec"},
        {"path": f"evidence/{batch}/artifacts.json", "kind": "artifact-manifest"},
        {"path": f"evidence/{batch}/traceability.json", "kind": "traceability"},
    ]
    return {
        "batch_id": batch,
        "requirements": [{
            "id": requirement,
            "statement": source.batch["goal"],
            "source": f".payment-platform/skill-package/batches/{batch}.md",
        }],
        "code": [{"ref": path, "requirements": [requirement]} for path in code_paths],
        "tests": [{"ref": path, "requirements": [requirement]} for path in test_paths],
        "controls": [{
            "id": "NN-12",
            "implemented_by": code_paths,
            "verified_by": test_paths,
        }],
        "evidence": evidence,
    }


def _plan(source: BatchSource) -> bytes:
    batch = source.batch["id"]
    gate_note = "无单独外部门禁；仍须 Ethan 独立复核。"
    if source.external_gate is not None:
        categories = ", ".join(source.external_gate["requiredCategories"])
        gate_note = f"必须验证真实签名外部材料：{categories}；缺失即阻断。"
    text = f"""# {batch} — {source.batch['title']} rebaseline 执行计划

状态：`PREPARE_ONLY / NOT_CERTIFIED`。本文件是执行规格，不是完成、审核或认证证据。

## 1. 范围

目标：{source.batch['goal']}

## 2. 受影响组件

以 `.ai/implementation_inventory.json` 中 {batch} 的精确路径和标记为准。

## 3. 领域接口与数据契约

执行前重新验证 manifest、实现清单、测试矩阵与批次依赖；任何漂移均 fail closed。

## 4. 命令

命令由 `tools.paygov.rebaseline_scaffold` 从受版本控制的 SSOT 确定性生成。

## 5. 测试策略

运行四分片全量回归、批次所属代码套件、完整负向控制和治理门禁；关键跳过不计通过。

## 6. 回滚

命令逐条记录；失败不写 completion。traceability 仅在完整命令记录和有效独立复核后原子定稿。

## 7. 威胁变化

证据不足、规格漂移、路径逃逸、自审、旧 HEAD、输出哈希漂移均阻断。

## 8. 数据迁移

是否需要迁移：{str(source.inventory.get('migration_required')).lower()}。迁移路径由实现清单绑定并纳入产物哈希。

## 9. 证据与审查

{gate_note} `review.json` 必须由配置中的独立人 Ethan 在命令执行后提供，并绑定当前 HEAD、命令规格、命令记录、输出和产物哈希。生成器绝不创建审核或完成材料。
"""
    return text.encode("utf-8")


def render_batch(root: Path, source: BatchSource) -> dict[str, bytes]:
    batch = source.batch["id"]
    artifacts = _artifact_paths(root, source)
    return {
        f"evidence/{batch}/plan.md": _plan(source),
        f"evidence/{batch}/commands.spec.json": _json_bytes(_commands(source)),
        f"evidence/{batch}/artifacts.json": _json_bytes(artifacts),
        f"evidence/{batch}/traceability.json": _json_bytes(_traceability(source, artifacts)),
    }


def scaffold(
    root: Path,
    batches: list[str],
    *,
    dry_run: bool,
    atomic_write: Callable[[Path, bytes], None],
) -> dict[str, Any]:
    root = root.resolve()
    sources = load_sources(root)
    unknown = [batch for batch in batches if batch not in sources]
    if unknown:
        raise ScaffoldError(f"unknown scaffold batches: {unknown}")
    planned: dict[Path, bytes] = {}
    results: list[dict[str, Any]] = []
    for batch in batches:
        rendered = render_batch(root, sources[batch])
        statuses = []
        for relative, payload in rendered.items():
            path = root / relative
            if path.exists():
                if not path.is_file() or path.read_bytes() != payload:
                    raise ScaffoldError(f"refusing to overwrite non-identical scaffold: {relative}")
                statuses.append({"path": relative, "action": "identical"})
            else:
                planned[path] = payload
                statuses.append({"path": relative, "action": "would-create" if dry_run else "create"})
        results.append({"batch": batch, "files": statuses})
    if not dry_run:
        for path, payload in planned.items():
            atomic_write(path, payload)
    return {
        "status": "planned" if dry_run else "scaffolded",
        "dry_run": dry_run,
        "batch_count": len(batches),
        "created_file_count": len(planned),
        "forbidden_outputs_created": False,
        "results": results,
    }
