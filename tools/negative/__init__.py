"""Per-batch negative-control scenarios, discovered rather than listed.

``scripts/negative-controls.py`` used to carry every scenario inline. That
script is one of B00's artefacts, so appending a scenario in batch N changed
B00's artefact digest, invalidated B00's evidence and forced every batch in
between to re-issue its own — the single largest recurring cost in the
programme. Scenarios now live in modules here, one per batch, and adding a
batch touches only that batch's own file.

A scenario module may define any of:

* ``EXPECTED_CODES``  — ``{scenario name: rule code that must fire}``
* ``SCENARIOS``       — ``(name, relative json path, mutate(dict), expected exit)``
* ``TEXT_SCENARIOS``  — ``(name, relative path, find, replace, expected exit)``

``load()`` merges them in module-name order and refuses duplicate scenario
names, because a silently shadowed scenario is a control that stopped running
without anyone noticing.
"""
from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

EXIT_OK, EXIT_PROBLEMS, EXIT_ERROR = 0, 2, 3


def load() -> tuple[dict, list, list]:
    expected: dict[str, str] = {}
    scenarios: list = []
    text_scenarios: list = []
    seen: set[str] = set()
    package = Path(__file__).resolve().parent
    for info in sorted(pkgutil.iter_modules([str(package)]), key=lambda i: i.name):
        module = importlib.import_module(f"{__package__}.{info.name}")
        for name in getattr(module, "EXPECTED_CODES", {}):
            if name in expected:
                raise ValueError(f"duplicate expected code entry: {name!r}")
        expected.update(getattr(module, "EXPECTED_CODES", {}))
        for spec in list(getattr(module, "SCENARIOS", ())) + \
                list(getattr(module, "TEXT_SCENARIOS", ())):
            if spec[0] in seen:
                raise ValueError(f"duplicate scenario name: {spec[0]!r}")
            seen.add(spec[0])
        scenarios.extend(getattr(module, "SCENARIOS", ()))
        text_scenarios.extend(getattr(module, "TEXT_SCENARIOS", ()))
    return expected, scenarios, text_scenarios
