"""B00 — program charter validation.

The charter is the human-readable half of the project boundary. It is only
credible if it stays structurally complete and stays in sync with the machine
readable registry, so both are checked here rather than trusted.
"""
from __future__ import annotations

from pathlib import Path

from .errors import BudgetExceeded, GovernanceError, Problem
from .repo import Budget, load_json, read_text

CHARTER_DIR = Path("docs/charter")

REQUIRED_DOCS: dict[str, tuple[str, ...]] = {
    "PROGRAM_CHARTER.md": (
        "## 1. 业务边界",
        "### 1.1 平台拥有",
        "### 1.2 平台不拥有",
        "### 1.3 明确排除的受监管能力",
        "## 2. 交付目标",
        "## 3. 默认部署模式",
        "## 4. 风险接受原则",
        "## 5. 不可绕过的安全红线",
        "## 6. 治理与批次门禁",
        "## 7. 变更控制",
    ),
    "RISK_ACCEPTANCE_POLICY.md": (
        "## 1. 风险分级",
        "## 2. 登记要求",
        "## 3. 禁止的风险接受",
        "## 4. 复审",
    ),
    "DELIVERY_MODEL.md": (
        "## 1. 环境阶梯",
        "## 2. 部署单元与合并策略",
        "## 3. 发布模型",
        "## 4. 就绪定义",
    ),
}

REQUIRED_FRONT_FIELDS = ("- 文档 ID：", "- 版本：", "- 批次：", "- 状态：", "- 负责人：")
MIN_CHARTER_BYTES = 3000


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("charter", "B00")

def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget().start()
    problems: list[Problem] = []
    charter_dir = root / CHARTER_DIR

    for name, sections in REQUIRED_DOCS.items():
        path = charter_dir / name
        where = str(CHARTER_DIR / name)
        try:
            text = read_text(path, budget)
        except BudgetExceeded:
            raise
        except GovernanceError as exc:
            problems.append(Problem("CHARTER_MISSING", where, str(exc), "NN-12"))
            continue
        for field in REQUIRED_FRONT_FIELDS:
            if field not in text:
                problems.append(Problem("CHARTER_HEADER", where,
                                        f"missing metadata line '{field.strip()}'", "NN-12"))
        for section in sections:
            if section not in text:
                problems.append(Problem("CHARTER_SECTION", where,
                                        f"missing required section '{section}'", "NN-12"))

    main = charter_dir / "PROGRAM_CHARTER.md"
    if main.is_file():
        text = read_text(main, budget)
        if len(text.encode("utf-8")) < MIN_CHARTER_BYTES:
            problems.append(Problem(
                "CHARTER_TOO_SHORT", str(CHARTER_DIR / "PROGRAM_CHARTER.md"),
                f"charter must be at least {MIN_CHARTER_BYTES} bytes to be reviewable", "NN-12"))
        problems.extend(_check_red_line_table(root, text, budget))
    return problems


def _check_red_line_table(root: Path, text: str, budget: Budget) -> list[Problem]:
    """Every NN rule in the registry must also appear in the charter table."""
    where = str(CHARTER_DIR / "PROGRAM_CHARTER.md")
    try:
        registry = load_json(root / "governance" / "non-negotiables.json", budget)
    except BudgetExceeded:
        raise
    except GovernanceError as exc:
        return [Problem("CHARTER_REGISTRY", where, str(exc), "NN-12")]
    problems: list[Problem] = []
    for rule in registry.get("rules", []):
        rid = rule.get("id", "?")
        if f"| {rid} |" not in text:
            problems.append(Problem("CHARTER_RED_LINE", where,
                                    f"non-negotiable {rid} is not listed in the charter red-line table",
                                    rid))
    return problems
