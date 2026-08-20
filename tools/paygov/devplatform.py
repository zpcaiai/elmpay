"""B04 — local development platform gate.

The batch document adds one hard rule to the global set: *the test environment
must never hold production credentials or real card data, and all test data must
be synthetic, masked, or supplied by an official sandbox*. That rule is only
real if a machine checks it, so this validator does.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import devgen
from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

PATH = Path("governance/dev-platform.json")
CATALOG = Path("governance/version-catalog.json")
PROJECT = Path("governance/project-config.json")

ALLOWED_ENVIRONMENTS = {"local", "integration"}
PRODUCTION_MARKERS = ("prod", "production", "live", "sk_live", "-----BEGIN", "AKIA")
ENV_REFERENCE = re.compile(r"^\$\{[A-Z][A-Z0-9_]*(?::[?-][^}]*)?\}$")
SECRETISH_KEY = re.compile(r"(?i)(password|secret|token|key|credential)")
REQUIRED_CLASSIFICATION = "synthetic"


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("dev-platform", "B04")

def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget().start()
    where = str(PATH)
    try:
        doc: Any = load_json(root / PATH, budget)
        catalog = {e["id"]: e for e in load_json(root / CATALOG, budget)["entries"]}
        project = load_json(root / PROJECT, budget)
    except BudgetExceeded:
        raise
    except Exception as exc:
        return [Problem("DEV_UNREADABLE", where, str(exc), "NN-12")]

    problems: list[Problem] = []
    problems += expect(bool(SEMVER.match(str(doc.get("schema_version", "")))),
                       "DEV_VERSION", where, "schema_version must be semantic version", "NN-12")

    environments = doc.get("environments")
    problems += expect(isinstance(environments, list) and bool(environments)
                       and set(environments) <= ALLOWED_ENVIRONMENTS,
                       "DEV_ENVIRONMENT", where,
                       f"the development platform may only target {sorted(ALLOWED_ENVIRONMENTS)}",
                       "NN-12")

    forbidden = doc.get("forbidden_in_environments")
    if not isinstance(forbidden, dict):
        problems.append(Problem("DEV_SHAPE", where,
                                "'forbidden_in_environments' must be an object", "NN-12"))
    else:
        for key in ("production_credentials", "real_card_data", "real_personal_data"):
            problems += expect(forbidden.get(key) is False, "DEV_FORBIDDEN", where,
                               f"'{key}' must be declared false for local/integration", "NN-02")

    services = doc.get("services")
    simulators = doc.get("simulators")
    if not isinstance(services, list) or not services or not isinstance(simulators, list):
        return problems + [Problem("DEV_SHAPE", where,
                                   "'services' and 'simulators' must be arrays", "NN-12")]

    declared_volumes = set(doc.get("volumes", []))
    secret_vars = set(doc.get("secret_env_vars", []))
    used_host_ports: dict[str, str] = {}
    service_ids: set[str] = set()

    for service in services:
        sid = service.get("id", "?")
        scope = f"{where}#{sid}"
        problems += expect(sid not in service_ids, "DEV_DUPLICATE", scope,
                           f"duplicate service '{sid}'", "NN-12")
        service_ids.add(sid)
        problems += expect(service.get("data_classification") == REQUIRED_CLASSIFICATION,
                           "DEV_DATA_CLASS", scope,
                           "every local service must be declared as holding synthetic data only",
                           "NN-02")
        problems += expect(len(str(service.get("healthcheck", "")).strip()) >= 4,
                           "DEV_HEALTHCHECK", scope,
                           "a service without a health check cannot be waited on deterministically",
                           "NN-12")
        image = service.get("image_ref")
        entry = catalog.get(image)
        if entry is None:
            problems.append(Problem("DEV_IMAGE", scope,
                                    f"image_ref '{image}' is not in the version catalogue", "NN-12"))
        else:
            problems += expect(entry.get("category") == "container", "DEV_IMAGE", scope,
                               f"'{image}' is not a container entry", "NN-12")
            problems += expect(entry.get("pin_type") == "digest", "DEV_IMAGE", scope,
                               f"'{image}' must be digest pinned", "NN-12")
        problems += _ports(service, scope, used_host_ports)
        problems += _environment(service, scope, secret_vars)
        for volume in service.get("volumes", []):
            name = str(volume).split(":", 1)[0]
            problems += expect(name in declared_volumes, "DEV_VOLUME", scope,
                               f"volume '{name}' is not declared", "NN-12")

    for required in doc.get("required_services", []):
        problems += expect(required in service_ids, "DEV_REQUIRED_SERVICE", where,
                           f"required service '{required}' is missing from the platform", "NN-12")

    enabled_providers = {name for name, cfg in project.get("providers", {}).items()
                         if isinstance(cfg, dict) and cfg.get("enabled")}
    simulated: set[str] = set()
    for simulator in simulators:
        sid = simulator.get("id", "?")
        scope = f"{where}#{sid}"
        simulated.add(simulator.get("provider"))
        problems += expect(sid not in service_ids, "DEV_DUPLICATE", scope,
                           f"'{sid}' collides with a service id", "NN-12")
        service_ids.add(sid)
        problems += expect(simulator.get("data_classification") == REQUIRED_CLASSIFICATION,
                           "DEV_DATA_CLASS", scope,
                           "simulators must serve synthetic data only", "NN-02")
        context = simulator.get("build_context", "")
        problems += expect(bool(context) and (root / context).is_dir(), "DEV_BUILD_CONTEXT", scope,
                           f"build context '{context}' does not exist", "NN-12")
        problems += _ports(simulator, scope, used_host_ports)

    for provider in sorted(enabled_providers - simulated):
        problems.append(Problem("DEV_SIMULATOR_MISSING", where,
                                f"provider '{provider}' is enabled but has no offline simulator; "
                                f"the platform would not be reproducible without network access",
                                "NN-12"))

    problems += _generated(root, budget)
    return problems


LOOPBACK = "127.0.0.1"


def _ports(service: dict, scope: str, used: dict[str, str]) -> list[Problem]:
    problems: list[Problem] = []
    for port in service.get("ports", []):
        host = str(port.get("host"))
        if host in used:
            problems.append(Problem("DEV_PORT_CONFLICT", scope,
                                    f"host port {host} is already used by '{used[host]}'", "NN-12"))
        used[host] = scope
        bind = str(port.get("bind", LOOPBACK))
        if bind != LOOPBACK:
            problems.append(Problem("DEV_PORT_EXPOSURE", scope,
                                    f"port {host} binds to '{bind}'; the local platform must not "
                                    f"be reachable beyond loopback", "NN-09"))
    return problems


def _environment(service: dict, scope: str, secret_vars: set[str]) -> list[Problem]:
    problems: list[Problem] = []
    for key, value in sorted(service.get("environment", {}).items()):
        text = str(value)
        lowered = text.lower()
        for marker in PRODUCTION_MARKERS:
            problems += expect(marker not in lowered, "DEV_PRODUCTION_VALUE", scope,
                               f"environment '{key}' looks like production material ('{marker}')",
                               "NN-07")
        if SECRETISH_KEY.search(key):
            problems += expect(bool(ENV_REFERENCE.match(text)), "DEV_INLINE_SECRET", scope,
                               f"'{key}' must be an ${{ENV_VAR}} reference, never an inline value",
                               "NN-07")
            if ENV_REFERENCE.match(text):
                name = text[2:].split(":", 1)[0].rstrip("}")
                problems += expect(name in secret_vars, "DEV_INLINE_SECRET", scope,
                                   f"'{name}' is not declared in secret_env_vars", "NN-07")
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    rendered = devgen.render_all(root)
    for rel, expected in sorted(rendered.items()):
        budget.check(rel)
        path = root / rel
        if not path.is_file():
            problems.append(Problem("DEV_MISSING", rel,
                                    "generated file is missing; run "
                                    "scripts/render-dev-platform.py", "NN-12"))
        elif path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("DEV_DRIFT", rel,
                                    "generated file differs from governance/dev-platform.json",
                                    "NN-12"))
    compose = rendered["platform/dev/compose.yaml"]
    for line in compose.splitlines():
        stripped = line.strip()
        if stripped.startswith("- \"") and ":" in stripped and "127.0.0.1" not in stripped \
                and "no-new-privileges" not in stripped:
            problems.append(Problem("DEV_PORT_EXPOSURE", "platform/dev/compose.yaml",
                                    f"port mapping must bind to 127.0.0.1: {stripped}", "NN-09"))
    for forbidden in ("network_mode: host", "privileged: true"):
        if forbidden in compose:
            problems.append(Problem("DEV_CONTAINER_PRIVILEGE", "platform/dev/compose.yaml",
                                    f"'{forbidden}' is not allowed in the local platform", "NN-09"))
    return problems
