"""A tiny structural validator.

Deliberately not JSON Schema: the repository must stay dependency free, and the
governance documents only need shape checks (required keys, types, enums,
patterns). Anything semantic lives in the domain validators.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Iterable

from .errors import Problem

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
# Batch ids are zero padded to two digits (B00..B99) and three digits above (B100..B127).
BATCH_ID = re.compile(r"^B(?:\d{2}|1[01]\d|12[0-7])$")
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
COUNTRY = re.compile(r"^[A-Z]{2}$")


def require_keys(obj: Any, keys: Iterable[str], where: str, code: str, rule: str = "") -> list[Problem]:
    problems: list[Problem] = []
    if not isinstance(obj, dict):
        return [Problem(code, where, "expected a JSON object", rule)]
    for key in keys:
        if key not in obj:
            problems.append(Problem(code, where, f"missing required key '{key}'", rule))
    return problems


def expect(condition: bool, code: str, where: str, message: str, rule: str = "",
           **context: Any) -> list[Problem]:
    return [] if condition else [Problem(code, where, message, rule, dict(context))]


def check_each(items: Any, where: str, code: str,
               fn: Callable[[int, Any], list[Problem]]) -> list[Problem]:
    if not isinstance(items, list):
        return [Problem(code, where, "expected a JSON array")]
    problems: list[Problem] = []
    for index, item in enumerate(items):
        problems.extend(fn(index, item))
    return problems
