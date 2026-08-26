from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping


class ValidationError(ValueError):
    """Raised when a control input is absent, ambiguous, or unsafe."""


@dataclass(frozen=True)
class GateReport:
    allowed: bool
    reasons: tuple[str, ...]
    checks: tuple[str, ...] = ()

    @classmethod
    def from_reasons(
        cls, reasons: Iterable[str], checks: Iterable[str] = ()
    ) -> "GateReport":
        normalized = tuple(sorted(set(reasons)))
        return cls(not normalized, normalized, tuple(sorted(set(checks))))


def require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be a non-empty string")
    return value


def require_mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"{field} must be an object")
    return value


def require_list(value: object, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValidationError(f"{field} must be an array")
    return value


def parse_instant(value: object, field: str) -> datetime:
    text = require_text(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{field} must be an RFC-3339 instant") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{field} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def read_json(path: Path) -> Any:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValidationError(f"duplicate JSON key in {path}: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValidationError(f"non-finite JSON number in {path}: {value}")

    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(
                handle,
                object_pairs_hook=reject_duplicate,
                parse_constant=reject_constant,
            )
    except FileNotFoundError as exc:
        raise ValidationError(f"required file is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(
            f"invalid JSON in {path}:{exc.lineno}:{exc.colno}: {exc.msg}"
        ) from exc


def require_exact_keys(
    value: Mapping[str, Any], *, required: set[str], optional: set[str], field: str
) -> None:
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        raise ValidationError(f"{field} missing keys: {sorted(missing)}")
    if unknown:
        raise ValidationError(f"{field} has unknown keys: {sorted(unknown)}")
