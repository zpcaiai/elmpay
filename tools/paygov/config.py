"""B00 — project configuration validation (fail closed).

``governance/project-config.json`` is the single machine-readable statement of
what this deployment is allowed to do. Every rule below maps to a
non-negotiable; a violation is a build failure, never a warning.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import COUNTRY, SEMVER, expect, require_keys

CONFIG_PATH = Path("governance/project-config.json")

ALLOWED_SECRET_SCHEMES = ("kms://", "vault://")
REGULATED_FEATURES = ("stored_value", "fund_pool", "cross_merchant_clearing", "unlicensed_payouts")
KNOWN_PROVIDERS = ("wechat", "alipay", "stripe", "paypal", "apple_pay")
# Anything that looks like a literal credential rather than a reference.
LITERAL_SECRET_HINTS = ("sk_live", "sk_test", "-----BEGIN", "AKIA", "mch_key=", "apiv3")


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("project-config", "B00")

def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget().start()
    where = str(CONFIG_PATH)
    try:
        cfg: Any = load_json(root / CONFIG_PATH, budget)
    except BudgetExceeded:
        raise
    except Exception as exc:  # GovernanceError and JSON errors alike
        return [Problem("CONFIG_UNREADABLE", where, str(exc), "NN-12")]

    problems = require_keys(
        cfg,
        ("schema_version", "project", "providers", "security", "money", "regulated_features", "evidence"),
        where, "CONFIG_SHAPE", "NN-12",
    )
    if problems:
        return problems

    problems += expect(bool(SEMVER.match(str(cfg["schema_version"]))), "CONFIG_VERSION", where,
                       "schema_version must be semantic version x.y.z", "NN-12")
    problems += _project(cfg["project"], where)
    problems += _security(cfg["security"], where)
    problems += _money(cfg["money"], where)
    problems += _regulated(cfg["regulated_features"], where)
    problems += _providers(cfg["providers"], where)
    problems += _evidence(cfg["evidence"], where)
    return problems


def _project(project: Any, where: str) -> list[Problem]:
    problems = require_keys(project, ("name", "profile", "primary_region", "data_residency"),
                            where + "#project", "CONFIG_SHAPE", "NN-12")
    if problems:
        return problems
    residency = project["data_residency"]
    problems += expect(isinstance(residency, list) and len(residency) > 0,
                       "CONFIG_RESIDENCY", where + "#project.data_residency",
                       "data residency must list at least one jurisdiction", "NN-09")
    if isinstance(residency, list):
        for code in residency:
            problems += expect(isinstance(code, str) and bool(COUNTRY.match(code)),
                               "CONFIG_RESIDENCY", where + "#project.data_residency",
                               f"'{code}' is not an ISO-3166 alpha-2 country code", "NN-09")
    return problems


def _security(security: Any, where: str) -> list[Problem]:
    scope = where + "#security"
    problems = require_keys(security, ("admin_mfa", "raw_card_data", "high_risk_four_eyes",
                                       "service_identity", "secret_backends"),
                            scope, "CONFIG_SHAPE", "NN-12")
    if problems:
        return problems
    problems += expect(security["admin_mfa"] == "webauthn_required", "CONFIG_MFA", scope,
                       "admin_mfa must be 'webauthn_required'; weaker factors are phishable", "NN-11")
    problems += expect(security["raw_card_data"] == "prohibited", "CONFIG_CARD_DATA", scope,
                       "raw_card_data must be 'prohibited'; the platform never receives PAN/CVV", "NN-02")
    problems += expect(security["high_risk_four_eyes"] is True, "CONFIG_FOUR_EYES", scope,
                       "high_risk_four_eyes must be true", "NN-11")
    problems += expect(security["service_identity"] == "mtls", "CONFIG_SERVICE_IDENTITY", scope,
                       "service_identity must be 'mtls'", "NN-09")
    backends = security["secret_backends"]
    problems += expect(isinstance(backends, list) and set(backends) <= {"kms", "vault", "hsm"} and backends,
                       "CONFIG_SECRET_BACKEND", scope,
                       "secret_backends must be a non-empty subset of kms/vault/hsm", "NN-07")
    return problems


def _money(money: Any, where: str) -> list[Problem]:
    scope = where + "#money"
    problems = require_keys(money, ("representation", "forbidden_numeric_types",
                                    "currency_metadata_source", "rounding_policy"),
                            scope, "CONFIG_SHAPE", "NN-12")
    if problems:
        return problems
    problems += expect(money["representation"] == "integer_minor_unit", "CONFIG_MONEY", scope,
                       "money.representation must be 'integer_minor_unit'", "NN-05")
    forbidden = money["forbidden_numeric_types"]
    problems += expect(isinstance(forbidden, list) and {"float", "double"} <= set(forbidden),
                       "CONFIG_MONEY", scope,
                       "forbidden_numeric_types must contain at least 'float' and 'double'", "NN-05")
    return problems


def _regulated(features: Any, where: str) -> list[Problem]:
    scope = where + "#regulated_features"
    problems = require_keys(features, REGULATED_FEATURES, scope, "CONFIG_SHAPE", "NN-13")
    if problems:
        return problems
    for name in REGULATED_FEATURES:
        problems += expect(features[name] is False, "CONFIG_REGULATED", scope,
                           f"'{name}' must be false; enabling it requires a payment licence "
                           f"and a dedicated compliance batch", "NN-13")
    return problems


def _providers(providers: Any, where: str) -> list[Problem]:
    scope = where + "#providers"
    if not isinstance(providers, dict) or not providers:
        return [Problem("CONFIG_SHAPE", scope, "providers must be a non-empty object", "NN-12")]
    problems: list[Problem] = []
    enabled = 0
    for name, provider in sorted(providers.items()):
        pscope = f"{scope}.{name}"
        problems += expect(name in KNOWN_PROVIDERS, "CONFIG_PROVIDER", pscope,
                           f"unknown provider '{name}'", "NN-12")
        if not isinstance(provider, dict):
            problems.append(Problem("CONFIG_SHAPE", pscope, "provider must be an object", "NN-12"))
            continue
        if not provider.get("enabled"):
            continue
        enabled += 1
        credentials = provider.get("credentials")
        problems += expect(isinstance(credentials, str)
                           and credentials.startswith(ALLOWED_SECRET_SCHEMES),
                           "CONFIG_CREDENTIAL_REF", pscope,
                           "enabled provider credentials must be a kms:// or vault:// reference", "NN-07")
        if isinstance(credentials, str):
            lowered = credentials.lower()
            for hint in LITERAL_SECRET_HINTS:
                problems += expect(hint not in lowered, "CONFIG_LITERAL_SECRET", pscope,
                                   "credentials field looks like a literal secret", "NN-07")
    problems += expect(enabled > 0, "CONFIG_PROVIDER", scope,
                       "at least one payment provider must be enabled", "NN-12")

    stripe = providers.get("stripe")
    if isinstance(stripe, dict) and stripe.get("enabled"):
        problems += expect(stripe.get("card_data_mode") == "hosted_fields_only",
                           "CONFIG_CARD_DATA", scope + ".stripe",
                           "stripe.card_data_mode must be 'hosted_fields_only'", "NN-02")
    apple = providers.get("apple_pay")
    if isinstance(apple, dict) and apple.get("enabled"):
        problems += expect(apple.get("direct_token_decryption") is False,
                           "CONFIG_CARD_DATA", scope + ".apple_pay",
                           "direct Apple Pay token decryption expands PCI scope and is not allowed "
                           "in the default deployment", "NN-02")
    return problems


def _evidence(evidence: Any, where: str) -> list[Problem]:
    scope = where + "#evidence"
    problems = require_keys(evidence, ("executor", "reviewer", "environment"),
                            scope, "CONFIG_SHAPE", "NN-12")
    if problems:
        return problems
    executor = str(evidence["executor"]).strip()
    reviewer = str(evidence["reviewer"]).strip()
    problems += expect(len(executor) >= 2 and len(reviewer) >= 2, "CONFIG_EVIDENCE", scope,
                       "executor and reviewer must be named", "NN-11")
    problems += expect(executor != reviewer, "CONFIG_EVIDENCE", scope,
                       "executor and reviewer must be different principals (four-eyes)", "NN-11")
    problems += expect(evidence["environment"] != "production", "CONFIG_EVIDENCE", scope,
                       "batch evidence must not be produced against production", "NN-12")
    return problems
