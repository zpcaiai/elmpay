"""B09 — currency metadata and money model gate.

Zero-decimal currencies (JPY, KRW, VND) and three-decimal currencies (KWD, BHD,
TND) are where hard-coded "two decimal places" quietly becomes a 100x error.
The metadata is therefore versioned, and this validator makes the properties
that matter mechanical:

* every currency declares an ISO code, a numeric code and a minor-unit exponent
  in 0..4, with an explicit rounding mode;
* the metadata contains no floating-point value anywhere;
* the project configuration points at this file and nowhere else;
* the generated conformance vectors match the reference implementation, so any
  language implementation can be held to the same arithmetic.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

METADATA = Path("governance/currency-metadata.json")
PROJECT = Path("governance/project-config.json")
VECTORS = Path("contracts/money/vectors.json")

CODE = re.compile(r"^[A-Z]{3}$")
NUMERIC = re.compile(r"^\d{3}$")
MAX_EXPONENT = 4

# A deliberately small, independently-sourced pin. The metadata file is a source of
# truth for *our* platform, but the minor-unit exponent of a real currency is not ours
# to decide: getting JPY wrong by one digit multiplies every yen amount by 100. These
# entries are the ISO 4217 values for the currencies the platform actually settles in,
# so a typo or a well-meaning "fix" has to disagree with a second, separate record
# before it can reach production.
ISO_4217_EXPONENT = {
    "CNY": 2, "HKD": 2, "USD": 2, "EUR": 2, "GBP": 2, "AUD": 2, "CAD": 2, "SGD": 2,
    "CHF": 2, "NZD": 2, "THB": 2, "MYR": 2, "PHP": 2, "INR": 2, "ZAR": 2, "BRL": 2,
    "MXN": 2, "TRY": 2, "PLN": 2, "SEK": 2, "NOK": 2, "DKK": 2, "RUB": 2, "AED": 2,
    "SAR": 2, "ILS": 2, "CZK": 2, "TWD": 2, "IDR": 2, "MOP": 2, "ARS": 2,
    "JPY": 0, "KRW": 0, "VND": 0, "CLP": 0, "ISK": 0, "XOF": 0, "XAF": 0, "PYG": 0,
    "UGX": 0, "RWF": 0,
    "KWD": 3, "BHD": 3, "OMR": 3, "JOD": 3, "TND": 3, "IQD": 3, "LYD": 3,
}

ISO_4217_NUMERIC = {
    "CNY": "156", "HKD": "344", "USD": "840", "EUR": "978", "GBP": "826", "JPY": "392",
    "KRW": "410", "KWD": "414", "BHD": "048", "OMR": "512", "JOD": "400", "SGD": "702",
    "AUD": "036", "CAD": "124", "CHF": "756", "VND": "704", "TWD": "901",
}
REQUIRED_CODES = ("CNY", "USD", "EUR", "JPY", "KWD")
FLOAT_IN_JSON = re.compile(r":\s*-?\d+\.\d+")


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("money-model", "B09")

def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget(seconds=60).start()
    where = str(METADATA)
    try:
        doc: Any = load_json(root / METADATA, budget)
        project: Any = load_json(root / PROJECT, budget)
        raw = (root / METADATA).read_text(encoding="utf-8")
    except BudgetExceeded:
        raise
    except Exception as exc:
        return [Problem("MONEY_UNREADABLE", where, str(exc), "NN-12")]

    problems: list[Problem] = []
    problems += expect(bool(SEMVER.match(str(doc.get("schema_version", "")))),
                       "MONEY_VERSION", where, "schema_version must be semantic version", "NN-12")
    problems += expect(not FLOAT_IN_JSON.search(raw), "MONEY_FLOAT_LITERAL", where,
                       "currency metadata must not contain any floating-point literal (NN-05)",
                       "NN-05")

    allowed = set(doc.get("allowed_rounding", []))
    problems += expect(doc.get("default_rounding") in allowed, "MONEY_ROUNDING", where,
                       "default_rounding must be one of allowed_rounding", "NN-05")
    scale = doc.get("fx_rate_scale")
    problems += expect(isinstance(scale, int) and 0 < scale <= 12, "MONEY_FX_SCALE", where,
                       "fx_rate_scale must be a positive integer power of ten", "NN-05")

    currencies = doc.get("currencies")
    if not isinstance(currencies, list) or not currencies:
        return problems + [Problem("MONEY_SHAPE", where, "'currencies' must be a non-empty array",
                                   "NN-12")]

    seen_codes: set[str] = set()
    seen_numeric: set[str] = set()
    for entry in currencies:
        code = entry.get("code", "?")
        scope = f"{where}#{code}"
        problems += expect(bool(CODE.match(str(code))), "MONEY_CODE", scope,
                           "currency code must be three uppercase letters", "NN-05")
        problems += expect(code not in seen_codes, "MONEY_DUPLICATE", scope,
                           f"duplicate currency '{code}'", "NN-12")
        seen_codes.add(code)
        numeric = entry.get("numeric", "")
        problems += expect(bool(NUMERIC.match(str(numeric))), "MONEY_NUMERIC", scope,
                           "numeric code must be three digits", "NN-05")
        problems += expect(numeric not in seen_numeric, "MONEY_DUPLICATE", scope,
                           f"duplicate numeric code '{numeric}'", "NN-12")
        seen_numeric.add(numeric)
        exponent = entry.get("minor_unit_exponent")
        problems += expect(isinstance(exponent, int) and not isinstance(exponent, bool)
                           and 0 <= exponent <= MAX_EXPONENT, "MONEY_EXPONENT", scope,
                           f"minor_unit_exponent must be an integer in 0..{MAX_EXPONENT}", "NN-05")
        expected_exponent = ISO_4217_EXPONENT.get(code)
        if expected_exponent is not None:
            problems += expect(exponent == expected_exponent, "MONEY_EXPONENT", scope,
                               f"ISO 4217 defines {code} with {expected_exponent} minor digits, "
                               f"not {exponent}; changing this silently re-scales every stored "
                               f"amount in that currency", "NN-05")
        expected_numeric = ISO_4217_NUMERIC.get(code)
        if expected_numeric is not None:
            problems += expect(numeric == expected_numeric, "MONEY_NUMERIC", scope,
                               f"ISO 4217 numeric code for {code} is '{expected_numeric}', "
                               f"not '{numeric}'", "NN-12")
        problems += expect(entry.get("rounding") in allowed, "MONEY_ROUNDING", scope,
                           f"rounding must be one of {sorted(allowed)}", "NN-05")
        for field in ("name_en", "name_cn"):
            problems += expect(len(str(entry.get(field, "")).strip()) >= 2, "MONEY_NAME", scope,
                               f"'{field}' is required", "NN-12")
        cash = entry.get("cash_rounding_minor")
        if cash is not None:
            problems += expect(isinstance(cash, int) and cash > 0, "MONEY_CASH_ROUNDING", scope,
                               "cash_rounding_minor must be a positive integer of minor units",
                               "NN-05")

    for required in REQUIRED_CODES:
        problems += expect(required in seen_codes, "MONEY_COVERAGE", where,
                           f"'{required}' must be present: the metadata has to cover zero-, two- "
                           f"and three-decimal currencies", "NN-05")
    exponents = {e.get("minor_unit_exponent") for e in currencies}
    for needed in (0, 2, 3):
        problems += expect(needed in exponents, "MONEY_COVERAGE", where,
                           f"no currency with {needed} minor digits is modelled; the rounding "
                           f"rules would never be exercised for it", "NN-05")

    configured = project.get("money", {}).get("currency_metadata_source")
    problems += expect(configured == str(METADATA), "MONEY_SOURCE", str(PROJECT),
                       f"project config must point currency metadata at '{METADATA}', not "
                       f"'{configured}'", "NN-05")

    problems += _vectors(root, budget)
    return problems


def _vectors(root: Path, budget: Budget) -> list[Problem]:
    """Conformance vectors must match the reference implementation exactly."""
    path = root / VECTORS
    if not path.is_file():
        return [Problem("MONEY_VECTORS_MISSING", str(VECTORS),
                        "conformance vectors are missing; run scripts/render-money-vectors.py",
                        "NN-05")]
    try:
        from .moneygen import build_vectors
    except Exception as exc:  # pragma: no cover - import failure is a defect
        return [Problem("MONEY_VECTORS", str(VECTORS), f"cannot build vectors: {exc}", "NN-12")]
    budget.check(str(VECTORS))
    try:
        expected = build_vectors(root)
    except BudgetExceeded:
        raise
    except Exception as exc:
        # Fail closed: a gate must never turn a broken input into a crash. If the
        # metadata is malformed the reference implementation cannot be exercised,
        # so the vectors are unverifiable and the batch must not pass.
        return [Problem("MONEY_VECTORS", str(VECTORS),
                        f"conformance vectors cannot be derived from the reference "
                        f"implementation: {type(exc).__name__}: {exc}", "NN-05")]
    try:
        actual = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [Problem("MONEY_VECTORS", str(VECTORS),
                        f"conformance vectors are not readable JSON: {exc}", "NN-05")]
    if actual != expected:
        return [Problem("MONEY_VECTORS_DRIFT", str(VECTORS),
                        "conformance vectors differ from the reference implementation; "
                        "run scripts/render-money-vectors.py", "NN-05")]
    return []
