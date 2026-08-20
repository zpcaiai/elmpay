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
    """Discover every validator module in this package.

    This used to be a hand-written list, and that list was the single most
    expensive line of code in the programme: it is an artefact of B00, so every
    new batch that added a validator changed B00's artefact digest, invalidated
    B00's evidence, and cascaded a full re-baseline through every batch that
    depends on it — which is all of them.

    A module joins the registry by declaring ``VALIDATOR = (name, batch)`` next
    to its ``validate`` function. Nothing shared is edited, so adding a batch
    costs one new file. Import failures are deliberately not swallowed: a
    validator that cannot be imported must break the gate, not quietly vanish
    from it.
    """
    import importlib
    import pkgutil

    found: list[tuple[str, str, Validator]] = []
    for info in sorted(pkgutil.iter_modules([str(Path(__file__).resolve().parent)]),
                       key=lambda i: i.name):
        if info.name in {"registry", "cli", "__main__"}:
            continue
        module = importlib.import_module(f"{__package__}.{info.name}")
        declared = getattr(module, "VALIDATOR", None)
        if declared is None:
            continue
        if (not isinstance(declared, tuple) or len(declared) != 2
                or not all(isinstance(x, str) for x in declared)):
            raise ValueError(f"{info.name}.VALIDATOR must be (name, batch), got {declared!r}")
        fn = getattr(module, "validate", None)
        if not callable(fn):
            raise ValueError(f"{info.name} declares VALIDATOR but has no validate()")
        found.append((declared[0], declared[1], fn))
    for name, batch, fn in sorted(found):
        _register_once(name, batch, fn)


def _register_once(name: str, batch: str, fn: Validator) -> None:
    if name not in _REGISTRY:
        register(name, batch, fn)
