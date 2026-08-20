"""B02 — architecture decision record validation.

An ADR is only useful if it is findable, dated, owned, and connected to the
requirements and controls it constrains. These checks make an undecidable
"is the architecture documented?" question mechanical.
"""
from __future__ import annotations

import re
from pathlib import Path

from . import catalogue
from .errors import BudgetExceeded, GovernanceError, Problem
from .repo import Budget, load_json, read_text
from .structs import BATCH_ID, ISO_DATE, expect

ADR_DIR = Path("docs/adr")
FILENAME = re.compile(r"^(\d{4})-[a-z0-9]+(?:-[a-z0-9]+)*\.md$")
TITLE = re.compile(r"^# ADR-(\d{4}): (.+)$", re.MULTILINE)
META = re.compile(r"^- ([^：]+)：(.*)$", re.MULTILINE)
GENERATED = "README.md"

REQUIRED_META = ("状态", "日期", "批次", "决策者", "关联需求", "关联控制", "取代")
REQUIRED_SECTIONS = ("## 背景", "## 决策", "## 后果", "## 备选方案", "## 验证")
VALID_STATUS = {"proposed", "accepted", "superseded", "deprecated"}
MIN_BODY = 600
NONE_MARKERS = {"无", "-", "none"}


def _adr_files(root: Path) -> list[Path]:
    directory = root / ADR_DIR
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.glob("*.md") if p.name != GENERATED)


def parse(text: str) -> tuple[dict[str, str], str]:
    meta = {key.strip(): value.strip() for key, value in META.findall(text)}
    return meta, text


def _refs(value: str) -> list[str]:
    if value.strip() in NONE_MARKERS:
        return []
    return [part.strip() for part in re.split(r"[,，\s]+", value) if part.strip()]


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("adr", "B02")

def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget().start()
    problems: list[Problem] = []
    files = _adr_files(root)
    if not files:
        return [Problem("ADR_EMPTY", str(ADR_DIR),
                        "no architecture decision records found", "NN-12")]

    try:
        requirement_ids = {r["id"] for r in
                           load_json(root / "governance/requirements.json", budget)["requirements"]}
    except BudgetExceeded:
        raise
    except GovernanceError as exc:
        return [Problem("ADR_UNREADABLE", str(ADR_DIR), str(exc), "NN-12")]

    known_batches = catalogue.batch_ids(str(root))
    known_controls = catalogue.control_ids(str(root))
    known_rules = catalogue.non_negotiable_ids(str(root))

    numbers: list[int] = []
    superseded_by: dict[str, str] = {}
    statuses: dict[str, str] = {}

    for path in files:
        rel = str(ADR_DIR / path.name)
        budget.check(rel)
        match = FILENAME.match(path.name)
        if not match:
            problems.append(Problem("ADR_FILENAME", rel,
                                    "ADR files must be named NNNN-kebab-slug.md", "NN-12"))
            continue
        number = int(match.group(1))
        numbers.append(number)
        text = read_text(path, budget)

        title = TITLE.search(text)
        if not title:
            problems.append(Problem("ADR_TITLE", rel,
                                    "first line must be '# ADR-NNNN: <title>'", "NN-12"))
            continue
        problems += expect(int(title.group(1)) == number, "ADR_TITLE", rel,
                           "title number does not match the filename", "NN-12")
        problems += expect(len(title.group(2).strip()) >= 4, "ADR_TITLE", rel,
                           "ADR title is too short to be meaningful", "NN-12")
        problems += expect(len(text.encode("utf-8")) >= MIN_BODY, "ADR_TOO_SHORT", rel,
                           f"an ADR shorter than {MIN_BODY} bytes cannot justify a decision", "NN-12")

        meta, _ = parse(text)
        for key in REQUIRED_META:
            if key not in meta:
                problems.append(Problem("ADR_META", rel, f"missing metadata '{key}'", "NN-12"))
        for section in REQUIRED_SECTIONS:
            if section not in text:
                problems.append(Problem("ADR_SECTION", rel, f"missing section '{section}'", "NN-12"))

        adr_id = f"ADR-{number:04d}"
        status = meta.get("状态", "")
        statuses[adr_id] = status
        problems += expect(status in VALID_STATUS, "ADR_STATUS", rel,
                           f"status must be one of {sorted(VALID_STATUS)}", "NN-12")
        problems += expect(bool(ISO_DATE.match(meta.get("日期", ""))), "ADR_DATE", rel,
                           "date must be ISO-8601 (YYYY-MM-DD)", "NN-12")
        problems += expect(len(meta.get("决策者", "").strip()) >= 3, "ADR_DECIDER", rel,
                           "an ADR must name its deciders", "NN-11")
        batch = meta.get("批次", "")
        problems += expect(bool(BATCH_ID.match(batch)) and batch in known_batches,
                           "ADR_BATCH", rel, f"'{batch}' is not a batch in the manifest", "NN-12")

        reqs = _refs(meta.get("关联需求", ""))
        problems += expect(bool(reqs), "ADR_REQUIREMENT", rel,
                           "an ADR must reference at least one requirement it constrains", "NN-12")
        for rid in reqs:
            problems += expect(rid in requirement_ids, "ADR_REQUIREMENT", rel,
                               f"unknown requirement '{rid}'", "NN-12")

        controls = _refs(meta.get("关联控制", ""))
        problems += expect(bool(controls), "ADR_CONTROL", rel,
                           "an ADR must reference at least one control", "NN-12")
        for cid in controls:
            problems += expect(cid in known_rules or cid in known_controls, "ADR_CONTROL", rel,
                               f"unknown control '{cid}'", "NN-12")

        for replaced in _refs(meta.get("取代", "")):
            superseded_by[replaced] = adr_id

    expected = list(range(1, len(numbers) + 1))
    problems += expect(sorted(numbers) == expected, "ADR_NUMBERING", str(ADR_DIR),
                       "ADR numbers must be dense and start at 0001", "NN-12",
                       found=sorted(numbers))

    for adr_id, status in sorted(statuses.items()):
        if status == "superseded" and adr_id not in superseded_by:
            problems.append(Problem("ADR_SUPERSEDED_DANGLING", str(ADR_DIR / f"{adr_id}"),
                                    f"{adr_id} is marked superseded but no ADR supersedes it",
                                    "NN-12"))
    for replaced, replacing in sorted(superseded_by.items()):
        if replaced not in statuses:
            problems.append(Problem("ADR_SUPERSEDES_UNKNOWN", str(ADR_DIR),
                                    f"{replacing} supersedes unknown '{replaced}'", "NN-12"))
        elif statuses[replaced] != "superseded":
            problems.append(Problem("ADR_SUPERSEDE_STATUS", str(ADR_DIR),
                                    f"{replaced} is superseded by {replacing} but its status is "
                                    f"'{statuses[replaced]}'", "NN-12"))
    return problems
