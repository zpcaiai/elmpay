"""Validator registry.

Each batch that adds governance rules registers its validator here, so
``paygov verify-all`` stays the single command CI and the batch evidence gate
call. Order is stable and alphabetical by name for reproducible output.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from .errors import Problem
from .repo import Budget

Validator = Callable[[Path, Budget], list[Problem]]

_REGISTRY: dict[str, tuple[str, Validator]] = {}


def register(name: str, batch: str, fn: Validator) -> None:
    if name in _REGISTRY:
        raise ValueError(f"validator '{name}' already registered")
    _REGISTRY[name] = (batch, fn)


def names() -> list[str]:
    return sorted(_REGISTRY)


def batch_of(name: str) -> str:
    return _REGISTRY[name][0]


def get(name: str) -> Validator:
    return _REGISTRY[name][1]


def load_all() -> None:
    """Import every batch module so its validators self-register."""
    from . import charter, config, hygiene, modules  # noqa: F401

    _register_once("charter", "B00", charter.validate)
    _register_once("project-config", "B00", config.validate)
    _register_once("module-registry", "B00", modules.validate)
    _register_once("repo-hygiene", "B00", hygiene.validate)

    from . import nonneg  # noqa: F401
    _register_once("non-negotiables", "B00", nonneg.validate)

    from . import boundaries, docs, requirements  # noqa: F401
    _register_once("requirements", "B01", requirements.validate)
    _register_once("service-boundaries", "B01", boundaries.validate)
    _register_once("generated-docs", "B01", docs.validate)

    from . import adr, threat  # noqa: F401
    _register_once("adr", "B02", adr.validate)
    _register_once("threat-model", "B02", threat.validate)

    from . import toolchain  # noqa: F401
    _register_once("toolchain", "B03", toolchain.validate)

    from . import devplatform  # noqa: F401
    _register_once("dev-platform", "B04", devplatform.validate)

    from . import ci  # noqa: F401
    _register_once("ci-pipeline", "B05", ci.validate)


def _register_once(name: str, batch: str, fn: Validator) -> None:
    if name not in _REGISTRY:
        register(name, batch, fn)
