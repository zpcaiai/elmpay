"""B09 — generate language-neutral conformance vectors for the money model.

Any implementation (Java first) must reproduce these outputs bit for bit. The
vectors are generated from the reference implementation and checked for drift,
so "the Java version rounds slightly differently" becomes a build failure
rather than a reconciliation exception.

Cases are chosen for where money models actually break: zero-decimal and
three-decimal currencies, half-way rounding, negative amounts, allocation
remainders, and cross-exponent foreign exchange.
"""
from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

from .repo import Budget

METADATA = Path("governance/currency-metadata.json")
REFERENCE = Path("libs/money/reference/money.py")


def _reference(root: Path):
    """Load the reference implementation *belonging to ``root``*.

    Deliberately not ``import libs.money.reference.money``: that resolves through
    ``sys.modules`` and would validate a fixture repository against whichever copy
    happened to be imported first. A gate that silently checks the wrong file is
    worse than no gate, so the module is loaded from ``root`` by path, under a name
    keyed to that path.
    """
    path = root / REFERENCE
    key = hashlib.sha256(str(path.resolve()).encode("utf-8")).hexdigest()[:16]
    spec = importlib.util.spec_from_file_location(f"paygov_money_reference_{key}", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load reference implementation from {path}")
    module = importlib.util.module_from_spec(spec)
    # ``dataclasses`` resolves annotations through ``sys.modules[cls.__module__]``,
    # so the module has to be registered before it executes.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.CurrencyRegistry, module.Money, module.divide_round


def build_vectors(root: Path, budget: Budget | None = None) -> dict:
    budget = budget or Budget(seconds=60).start()
    CurrencyRegistry, Money, divide_round = _reference(root)
    registry = CurrencyRegistry.from_file(root / METADATA)

    rounding = [
        {"numerator": n, "denominator": d, "mode": m, "expected": divide_round(n, d, m)}
        for n, d in ((5, 2), (15, 2), (25, 10), (35, 10), (-5, 2), (-15, 2), (1, 3), (2, 3),
                     (999, 1000), (1000, 3))
        for m in ("half_even", "half_up", "down", "up")
    ]

    parse_format = []
    for code, text in (("CNY", "19.99"), ("CNY", "0.01"), ("CNY", "-19.99"),
                       ("JPY", "1999"), ("JPY", "-1"), ("KWD", "1.234"), ("KWD", "0.001"),
                       ("USD", "1234567890.12"), ("BHD", "-0.500")):
        money = Money.parse(text, code, registry)
        parse_format.append({"currency": code, "text": text, "minor": money.minor,
                             "formatted": money.format(registry)})

    allocation = []
    for minor, code, weights in ((10000, "CNY", [1, 1, 1]), (10001, "CNY", [1, 1, 1]),
                                 (100, "JPY", [1, 1, 1]), (5, "JPY", [3, 1, 1]),
                                 (-10000, "CNY", [1, 1, 1]), (1234, "KWD", [7, 2, 1]),
                                 (7, "USD", [1, 1, 1, 1, 1, 1, 1, 1])):
        parts = [p.minor for p in Money(minor, code).allocate(weights)]
        allocation.append({"minor": minor, "currency": code, "weights": weights,
                           "parts": parts, "sum": sum(parts)})

    fees = []
    for minor, code, num, den, mode in ((10000, "CNY", 6, 1000, "half_even"),
                                        (10000, "CNY", 29, 1000, "half_even"),
                                        (1999, "CNY", 29, 1000, "half_even"),
                                        (1999, "CNY", 29, 1000, "half_up"),
                                        (1999, "JPY", 29, 1000, "half_even"),
                                        (1234, "KWD", 29, 1000, "half_even"),
                                        (-1999, "CNY", 29, 1000, "half_even")):
        fees.append({"minor": minor, "currency": code, "numerator": num, "denominator": den,
                     "mode": mode,
                     "expected": Money(minor, code).apply_rate(num, den, mode).minor})

    conversions = []
    for minor, source, target, rate, scale in ((10000, "CNY", "JPY", 195000, 4),
                                               (10000, "CNY", "USD", 13800, 5),
                                               (1999, "JPY", "CNY", 490000, 6),
                                               (1000, "KWD", "USD", 326000, 5),
                                               (10000, "USD", "KWD", 30670, 5),
                                               (1, "JPY", "KWD", 20000, 6)):
        conversions.append({"minor": minor, "from": source, "to": target,
                            "rate_numerator": rate, "rate_scale": scale,
                            "expected": Money(minor, source)
                            .convert(target, rate, scale, registry).minor})

    return {
        "_generated": "GENERATED FILE — scripts/render-money-vectors.py; do not edit by hand",
        "schema_version": "1.0.0",
        "note": "由 libs/money/reference 生成。任何语言实现必须逐条复现这些结果。",
        "rounding": rounding,
        "parse_format": parse_format,
        "allocation": allocation,
        "fees": fees,
        "conversions": conversions,
    }


def vectors_json(root: Path, budget: Budget | None = None) -> str:
    import json
    return json.dumps(build_vectors(root, budget), ensure_ascii=False, indent=2,
                      sort_keys=True) + "\n"


TARGETS = {"contracts/money/vectors.json": vectors_json}


def render_all(root: Path) -> dict[str, str]:
    return {rel: fn(root) for rel, fn in TARGETS.items()}
