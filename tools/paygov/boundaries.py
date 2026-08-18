"""B01 — service boundary validation.

Boundaries are only real if they are bidirectional: every capability points at
requirements that exist, and every requirement is claimed by exactly one
capability. An unclaimed requirement means nobody owns it; a capability
pointing at a missing requirement means the boundary drifted.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from . import catalogue
from .errors import Problem
from .repo import Budget, load_json
from .structs import BATCH_ID, SEMVER, expect

PATH = Path("governance/service-boundaries.json")
REQUIREMENTS = Path("governance/requirements.json")
TESTS_DIR = Path("tools/tests")
# Aggregate references allowed in inbound/outbound edges.
AGGREGATES = {"all-modules", "apps", "connectors", "services"}


def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget().start()
    where = str(PATH)
    try:
        doc: Any = load_json(root / PATH, budget)
        requirements = load_json(root / REQUIREMENTS, budget)
    except Exception as exc:
        return [Problem("BOUNDARY_UNREADABLE", where, str(exc), "NN-12")]

    problems: list[Problem] = []
    problems += expect(bool(SEMVER.match(str(doc.get("schema_version", "")))),
                       "BOUNDARY_VERSION", where, "schema_version must be semantic version", "NN-12")

    actors = doc.get("external_actors")
    capabilities = doc.get("capabilities")
    forbidden = doc.get("forbidden_flows")
    if not all(isinstance(x, list) and x for x in (actors, capabilities, forbidden)):
        return problems + [Problem("BOUNDARY_SHAPE", where,
                                   "external_actors, capabilities and forbidden_flows must all be "
                                   "non-empty arrays", "NN-12")]

    known_modules = catalogue.module_names(str(root))
    known_batches = catalogue.batch_ids(str(root))
    known_rules = catalogue.non_negotiable_ids(str(root))
    known_controls = catalogue.control_ids(str(root))
    all_requirements = {r["id"] for r in requirements.get("requirements", [])}

    actor_ids: set[str] = set()
    for actor in actors:
        scope = f"{where}#{actor.get('id', '?')}"
        actor_ids.add(actor.get("id", ""))
        problems += expect(str(actor.get("id", "")).startswith("external:"), "BOUNDARY_ACTOR", scope,
                           "external actor ids must be namespaced with 'external:'", "NN-01")
        for field in ("owns", "must_not"):
            problems += expect(isinstance(actor.get(field), list) and bool(actor.get(field)),
                               "BOUNDARY_ACTOR", scope,
                               f"actor must declare a non-empty '{field}' list", "NN-01")

    claimed: dict[str, str] = {}
    seen_caps: set[str] = set()
    for capability in capabilities:
        cid = capability.get("id", "?")
        scope = f"{where}#{cid}"
        problems += expect(cid not in seen_caps, "BOUNDARY_CAPABILITY", scope,
                           f"duplicate capability id '{cid}'", "NN-12")
        seen_caps.add(cid)
        owner = capability.get("owner_module")
        problems += expect(owner in known_modules, "BOUNDARY_CAPABILITY", scope,
                           f"owner_module '{owner}' is not in the module registry", "NN-12")
        for edge in ("inbound_from", "outbound_to"):
            for ref in capability.get(edge, []):
                ok = ref in known_modules or ref in AGGREGATES or ref in actor_ids
                problems += expect(ok, "BOUNDARY_EDGE", scope,
                                   f"{edge} references unknown '{ref}'", "NN-01")
        for rid in capability.get("requirements", []):
            if rid not in all_requirements:
                problems.append(Problem("BOUNDARY_REQ_MISSING", scope,
                                        f"capability references unknown requirement '{rid}'", "NN-12"))
                continue
            if rid in claimed:
                problems.append(Problem("BOUNDARY_REQ_DOUBLE_CLAIM", scope,
                                        f"requirement '{rid}' is already claimed by "
                                        f"'{claimed[rid]}'", "NN-12"))
            claimed[rid] = cid

    for rid in sorted(all_requirements - set(claimed)):
        problems.append(Problem("BOUNDARY_REQ_UNCLAIMED", where,
                                f"requirement '{rid}' belongs to no capability", "NN-12"))

    seen_flows: set[str] = set()
    for flow in forbidden:
        fid = flow.get("id", "?")
        scope = f"{where}#{fid}"
        problems += expect(fid not in seen_flows, "BOUNDARY_FLOW", scope,
                           f"duplicate forbidden flow id '{fid}'", "NN-12")
        seen_flows.add(fid)
        problems += expect(len(str(flow.get("description", "")).strip()) >= 8,
                           "BOUNDARY_FLOW", scope, "forbidden flow needs a description", "NN-12")
        refs = flow.get("enforced_by")
        problems += expect(isinstance(refs, list) and bool(refs), "BOUNDARY_FLOW", scope,
                           "forbidden flow must declare how it is enforced", "NN-12")
        for ref in refs or []:
            if ref in known_rules or ref in known_controls:
                continue
            if ref.startswith("test:"):
                module = root / TESTS_DIR / f"{ref.split(':', 1)[1]}.py"
                problems += expect(module.is_file(), "BOUNDARY_FLOW", scope,
                                   f"enforcement test '{ref}' does not exist", "NN-12")
            elif ref.startswith("batch:"):
                batch = ref.split(":", 1)[1]
                problems += expect(bool(BATCH_ID.match(batch)) and batch in known_batches,
                                   "BOUNDARY_FLOW", scope, f"unknown batch reference '{ref}'", "NN-12")
            else:
                problems.append(Problem("BOUNDARY_FLOW", scope,
                                        f"unrecognised enforcement reference '{ref}'", "NN-12"))
    return problems
