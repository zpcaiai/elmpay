"""Read-only access to the vendored skill-package catalogues.

The batch manifest and the control matrix are *inputs* to this repository: the
governance layer may reference them but must never rewrite them. Loading them
here keeps the "does this id actually exist" checks in one place.
"""
from __future__ import annotations

import csv
import io
from functools import lru_cache
from pathlib import Path

from .repo import Budget, load_json, read_text

MANIFEST = Path(".payment-platform/skill-package/manifest.json")
CONTROLS = Path(".payment-platform/skill-package/compliance/controls-matrix.csv")


@lru_cache(maxsize=8)
def batch_ids(root_str: str) -> frozenset[str]:
    manifest = load_json(Path(root_str) / MANIFEST, Budget(seconds=60).start())
    return frozenset(batch["id"] for batch in manifest["batches"])


@lru_cache(maxsize=8)
def batch_titles(root_str: str) -> dict[str, str]:
    manifest = load_json(Path(root_str) / MANIFEST, Budget(seconds=60).start())
    return {batch["id"]: batch["title"] for batch in manifest["batches"]}


@lru_cache(maxsize=8)
def control_ids(root_str: str) -> frozenset[str]:
    raw = read_text(Path(root_str) / CONTROLS, Budget(seconds=60).start())
    reader = csv.DictReader(io.StringIO(raw))
    return frozenset(row["control_id"].strip() for row in reader if row.get("control_id"))


@lru_cache(maxsize=8)
def module_names(root_str: str) -> frozenset[str]:
    registry = load_json(Path(root_str) / "governance/module-registry.json", Budget().start())
    return frozenset(module["name"] for module in registry["modules"])


@lru_cache(maxsize=8)
def non_negotiable_ids(root_str: str) -> frozenset[str]:
    registry = load_json(Path(root_str) / "governance/non-negotiables.json", Budget().start())
    return frozenset(rule["id"] for rule in registry["rules"])


def reset_cache() -> None:
    """Fixtures mutate files on disk; tests must be able to drop the caches."""
    for fn in (batch_ids, batch_titles, control_ids, module_names, non_negotiable_ids):
        fn.cache_clear()
