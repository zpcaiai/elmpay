"""B11 — API contract, error semantics and compatibility model.

This gate exists because most payment integration incidents are contract
incidents. The rules encode the failures that actually cost money:

* a write operation without an idempotency key is a duplicate charge whenever a
  client retries a timeout -- which clients do, always (NN-04);
* offset pagination over continuously-written payment data silently skips and
  duplicates rows, which shows up months later as an unexplainable
  reconciliation difference;
* an operation that lets a merchant drive a transition reserved for verified
  provider events turns the API into a way to declare yourself paid (NN-03);
* an error message that quotes the request back to the caller is how PANs end up
  in log aggregators (NN-14);
* a removed field or a narrowed enum inside a stable major version breaks every
  integrator at once, so compatibility is checked against a recorded baseline
  rather than against somebody's memory.

The contract is data (``governance/api-contract.json``); this file is the gate,
and ``tools/paygov/apigen.py`` turns the same data into OpenAPI and docs.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

CONTRACT = Path("governance/api-contract.json")
STATES = Path("governance/state-machines.json")
BASELINE = Path("contracts/api/openapi.baseline.json")

OPERATION_ID = re.compile(r"^[a-z][a-z0-9_]*$")
PATH = re.compile(r"^/v\d+(/[a-z0-9_]+|/\{[a-z0-9_]+\})*$")
ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]*$")
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ALLOWED_STATUS = {200, 201, 202, 204, 400, 401, 403, 404, 409, 422, 429, 500, 502, 503, 504}
RETRYABLE_STATUS = {429, 500, 502, 503, 504}
LEAKY = ("pan", "cvv", "cvc", "card_number", "卡号", "密钥", "secret", "password",
         "api_key", "private_key", "身份证")


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("api-contract", "B11")

def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    where = str(CONTRACT)
    budget.check(where)
    try:
        contract = load_json(root / CONTRACT)
    except Exception as exc:
        return [Problem("API_UNREADABLE", where, f"cannot read the API contract: {exc}", "NN-12")]

    problems += expect(SEMVER.match(str(contract.get("schema_version", ""))), "API_VERSION_FIELD",
                       where, "schema_version must be semver", "NN-12")

    operations = contract.get("operations")
    if not isinstance(operations, list) or not operations:
        return problems + [Problem("API_SHAPE", where, "'operations' must be a non-empty list",
                                   "NN-12")]
    catalogue = contract.get("errors")
    if not isinstance(catalogue, list) or not catalogue:
        return problems + [Problem("API_SHAPE", where, "'errors' must be a non-empty list",
                                   "NN-12")]

    problems += _versioning(contract, where)
    problems += _trace(contract, where)
    problems += _pagination_policy(contract, where)
    problems += _money_policy(contract, root, where)

    error_codes, problems_ = _errors(catalogue, where)
    problems += problems_

    transitions = _transitions(root)
    schemes = {s.get("id") for s in contract.get("auth_schemes") or []}
    problems += expect(schemes, "API_SHAPE", where, "'auth_schemes' must not be empty", "NN-12")

    seen_ids: set = set()
    seen_routes: set = set()
    used_errors: set = set()
    for index, operation in enumerate(operations):
        problems += _operation(operation, f"{where}#{index}", contract, error_codes, transitions,
                               schemes, seen_ids, seen_routes, used_errors, budget)

    for code in sorted(error_codes):
        problems += expect(code in used_errors, "API_ERROR_UNUSED", where,
                           f"error '{code}' is catalogued but no operation can return it; an "
                           f"error nobody raises is documentation debt", "NN-12")

    problems += _compatibility(root, contract, where, budget)
    problems += _generated(root, budget)
    return problems


def _versioning(contract: dict, where: str) -> list[Problem]:
    problems: list[Problem] = []
    versioning = contract.get("versioning") or {}
    problems += expect(versioning.get("scheme") == "path_major", "API_VERSIONING", where,
                       "the version must live in the path; header or query versioning makes a "
                       "request's contract invisible in access logs and CDN rules", "NN-12")
    problems += expect(isinstance(versioning.get("current_major"), int)
                       and versioning.get("current_major") >= 1, "API_VERSIONING", where,
                       "current_major must be a positive integer", "NN-12")
    problems += expect(int(versioning.get("minimum_parallel_support_months") or 0) >= 12,
                       "API_VERSIONING", where,
                       "a superseded major version must stay available for at least 12 months; "
                       "payment integrators cannot re-certify on a shorter notice", "NN-12")
    deprecation = versioning.get("deprecation") or {}
    problems += expect(int(deprecation.get("notice_days") or 0) >= 180, "API_DEPRECATION", where,
                       "deprecation notice must be at least 180 days", "NN-12")
    problems += expect(deprecation.get("header") == "Sunset", "API_DEPRECATION", where,
                       "deprecation must be announced with the standard 'Sunset' header", "NN-12")
    return problems


def _trace(contract: dict, where: str) -> list[Problem]:
    trace = contract.get("trace") or {}
    required = set(trace.get("required_headers") or [])
    problems = list(expect("traceparent" in required, "API_TRACE", where,
                           "'traceparent' (W3C Trace Context) must be a required header; without "
                           "it a payment cannot be followed across the provider boundary", "NN-12"))
    problems += expect(len(str(trace.get("policy") or "")) >= 10, "API_TRACE", where,
                       "the trace policy must state what may not appear in traces", "NN-14")
    return problems


def _pagination_policy(contract: dict, where: str) -> list[Problem]:
    pagination = contract.get("pagination") or {}
    problems = list(expect(pagination.get("style") == "cursor", "API_PAGINATION_POLICY", where,
                           "pagination must be cursor based", "NN-12"))
    forbidden = set(pagination.get("forbidden_params") or [])
    problems += expect({"offset", "page"} <= forbidden, "API_PAGINATION_POLICY", where,
                       "'offset' and 'page' must be explicitly forbidden, not merely unused",
                       "NN-12")
    problems += expect(0 < int(pagination.get("max_limit") or 0) <= 1000, "API_PAGINATION_POLICY",
                       where, "max_limit must be a sane positive bound", "NN-12")
    return problems


def _money_policy(contract: dict, root: Path, where: str) -> list[Problem]:
    shape = contract.get("money_shape") or {}
    problems = list(expect(shape.get("amount_type") == "int64", "API_MONEY_SHAPE", where,
                           "API money must be int64 minor units", "NN-05"))
    problems += expect(shape.get("amount_field", "").endswith("_minor"), "API_MONEY_SHAPE", where,
                       "the amount field name must say 'minor' so no integrator can mistake it "
                       "for a major-unit decimal", "NN-05")
    problems += expect(shape.get("currency_field") == "currency", "API_MONEY_SHAPE", where,
                       "every amount must be accompanied by a currency field", "NN-05")
    return problems


def _errors(catalogue: list, where: str) -> tuple[set, list[Problem]]:
    problems: list[Problem] = []
    codes: set = set()
    for entry in catalogue:
        if not isinstance(entry, dict):
            problems.append(Problem("API_SHAPE", where, "each error must be an object", "NN-12"))
            continue
        code = entry.get("code")
        scope = f"{where}#error:{code}"
        problems += expect(isinstance(code, str) and ERROR_CODE.match(code or ""),
                           "API_ERROR_CODE", scope,
                           f"error code '{code}' must be snake_case", "NN-12")
        problems += expect(code not in codes, "API_ERROR_DUPLICATE", scope,
                           f"duplicate error code '{code}'", "NN-12")
        codes.add(code)
        status = entry.get("http_status")
        problems += expect(status in ALLOWED_STATUS, "API_ERROR_STATUS", scope,
                           f"http_status {status} is not in the allowed set", "NN-12")
        retryable = entry.get("retryable")
        problems += expect(isinstance(retryable, bool), "API_ERROR_STATUS", scope,
                           "'retryable' must be declared as a boolean; leaving it unsaid is how "
                           "clients retry a hard decline forever", "NN-12")
        if retryable is True:
            problems += expect(status in RETRYABLE_STATUS, "API_ERROR_RETRYABLE", scope,
                               f"status {status} is declared retryable; telling a client to retry "
                               f"a deterministic rejection turns one failure into a storm",
                               "NN-04")
        message = str(entry.get("safe_message") or "")
        problems += expect(len(message) >= 6, "API_ERROR_MESSAGE", scope,
                           "every error needs a message that is safe to show a caller", "NN-12")
        for token in LEAKY:
            if token in message.lower():
                problems.append(Problem(
                    "API_ERROR_LEAK", scope,
                    f"the caller-visible message mentions '{token}'; error text reaches logs, "
                    f"aggregators and support tickets", "NN-14"))
        problems += expect(len(str(entry.get("remedy") or "")) >= 6, "API_ERROR_REMEDY", scope,
                           "every error must tell the caller what to do instead; an error without "
                           "a remedy becomes a support ticket", "NN-12")
    return codes, problems


def _transitions(root: Path) -> dict:
    try:
        model = load_json(root / STATES)
    except Exception:
        return {}
    # A list, not a single transition: the same event can be legal from more than
    # one state (a merchant may cancel an intent from 'created' *or* from
    # 'requires_action'). Keying by the last one seen would silently check only
    # half the contract.
    out: dict = {}
    for machine in model.get("machines", []):
        for tr in machine.get("transitions", []):
            out.setdefault((machine.get("name"), tr.get("event")), []).append(tr)
    return out


def _operation(operation: Any, scope: str, contract: dict, error_codes: set, transitions: dict,
               schemes: set, seen_ids: set, seen_routes: set, used_errors: set,
               budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    if not isinstance(operation, dict):
        return [Problem("API_SHAPE", scope, "each operation must be an object", "NN-12")]
    budget.check(scope)

    oid = operation.get("id")
    problems += expect(isinstance(oid, str) and OPERATION_ID.match(oid or ""), "API_OPERATION_ID",
                       scope, f"operation id '{oid}' must be snake_case", "NN-12")
    problems += expect(oid not in seen_ids, "API_OPERATION_DUPLICATE", scope,
                       f"duplicate operation id '{oid}'", "NN-12")
    seen_ids.add(oid)

    method = operation.get("method")
    path = operation.get("path")
    problems += expect(isinstance(path, str) and PATH.match(path or ""), "API_PATH", scope,
                       f"path '{path}' must start with the major version and use snake_case "
                       f"segments", "NN-12")
    route = (method, path)
    problems += expect(route not in seen_routes, "API_ROUTE_DUPLICATE", scope,
                       f"duplicate route {method} {path}", "NN-12")
    seen_routes.add(route)

    problems += expect(operation.get("auth") in schemes, "API_AUTH", scope,
                       f"auth scheme '{operation.get('auth')}' is not declared; an operation "
                       f"without an auth scheme is an anonymous payment API", "NN-12")
    problems += expect(len(str(operation.get("summary") or "")) >= 4, "API_SUMMARY", scope,
                       "every operation needs a summary", "NN-12")

    for code in operation.get("errors") or []:
        used_errors.add(code)
        problems += expect(code in error_codes, "API_ERROR_UNKNOWN", scope,
                           f"operation declares error '{code}', which is not in the catalogue",
                           "NN-12")

    idem = operation.get("idempotency")
    if method in WRITE_METHODS:
        problems += expect(isinstance(idem, dict) and idem.get("required") is True,
                           "API_MUTATION_NOT_IDEMPOTENT", scope,
                           f"{method} {path} changes state but does not require an idempotency "
                           f"key; every client retries a timeout, and a retry without a key is a "
                           f"second charge", "NN-04")
        if isinstance(idem, dict):
            problems += expect(int(idem.get("retention_hours") or 0)
                               >= int((contract.get("idempotency") or {})
                                      .get("min_retention_hours") or 0),
                               "API_IDEMPOTENCY_RETENTION", scope,
                               "the idempotency record must be kept at least as long as the "
                               "contract's minimum; a key that expires before the client stops "
                               "retrying is not idempotent", "NN-04")
            problems += expect(idem.get("conflict_error") in error_codes,
                               "API_IDEMPOTENCY_CONFLICT", scope,
                               "reusing a key with a different body must map to a catalogued "
                               "conflict error, not to a silent overwrite", "NN-04")
            used_errors.add(idem.get("conflict_error"))
    else:
        problems += expect(idem is None, "API_READ_IDEMPOTENCY", scope,
                           f"{method} {path} is a read but declares an idempotency key; that "
                           f"suggests it has side effects", "NN-04")

    transition = operation.get("drives_transition")
    if transition:
        key = (transition.get("machine"), transition.get("event"))
        declared = transitions.get(key) or []
        problems += expect(declared, "API_TRANSITION_UNKNOWN", scope,
                           f"operation drives '{key[1]}' on machine '{key[0]}', which is not a "
                           f"transition in the state model", "NN-12")
        for candidate in declared:
            problems += expect(candidate.get("idempotency") == (idem or {}).get("scope"),
                               "API_TRANSITION_KEY_MISMATCH", scope,
                               f"the operation's idempotency scope "
                               f"{(idem or {}).get('scope')!r} does not match the transition's "
                               f"declared key {candidate.get('idempotency')!r} "
                               f"(from '{candidate.get('from')}'); two different notions of 'the "
                               f"same request' is exactly one too many", "NN-04")
            problems += expect(candidate.get("actor") == operation.get("actor"),
                               "API_TRANSITION_ACTOR", scope,
                               f"the operation is exposed to '{operation.get('actor')}' but the "
                               f"transition from '{candidate.get('from')}' is driven by "
                               f"'{candidate.get('actor')}'; an API that lets a caller "
                               f"impersonate a verified provider event is a way to declare "
                               f"yourself paid", "NN-03")

    pagination = operation.get("pagination")
    if pagination:
        policy = contract.get("pagination") or {}
        problems += expect(pagination.get("style") == "cursor", "API_PAGINATION", scope,
                           "list operations must be cursor paginated", "NN-12")
        for forbidden in policy.get("forbidden_params") or []:
            problems += expect(forbidden not in pagination.values(), "API_PAGINATION", scope,
                               f"'{forbidden}' pagination is forbidden by the contract", "NN-12")
        problems += expect(0 < int(pagination.get("max_limit") or 0)
                           <= int(policy.get("max_limit") or 0), "API_PAGINATION", scope,
                           "the operation's max_limit exceeds the contract's bound", "NN-12")
        problems += expect(bool(pagination.get("stable_sort")), "API_PAGINATION", scope,
                           "cursor pagination needs a stable total order, otherwise pages overlap "
                           "or skip rows as new payments arrive", "NN-12")

    signature = operation.get("signature")
    if operation.get("auth") == "provider_signature":
        problems += expect(isinstance(signature, dict) and signature.get("required") is True,
                           "API_SIGNATURE", scope,
                           "an inbound provider callback must verify a signature before anything "
                           "else happens (NN-08)", "NN-08")
        if isinstance(signature, dict):
            problems += expect(0 < int(signature.get("tolerance_seconds") or 0) <= 600,
                               "API_SIGNATURE", scope,
                               "the timestamp tolerance must be positive and tight; an unbounded "
                               "window makes a captured callback replayable forever", "NN-08")
            problems += expect(str(signature.get("algorithm") or "").startswith(
                ("hmac-sha256", "ed25519", "rsa-sha256")), "API_SIGNATURE", scope,
                f"signature algorithm '{signature.get('algorithm')}' is not an accepted one",
                "NN-08")
            problems += expect(int(signature.get("replay_window_hours") or 0) >= 1,
                               "API_SIGNATURE", scope,
                               "a replay window must be declared so a re-sent event is recognised "
                               "rather than re-processed", "NN-04")
    else:
        problems += expect(signature is None, "API_SIGNATURE", scope,
                           "only provider callbacks carry a provider signature", "NN-08")

    deprecated = operation.get("deprecated")
    if deprecated:
        problems += expect(bool(deprecated.get("replacement")), "API_DEPRECATION", scope,
                           "a deprecated operation must name its replacement", "NN-12")
        problems += expect(bool(deprecated.get("sunset")), "API_DEPRECATION", scope,
                           "a deprecated operation must carry a sunset date", "NN-12")
    return problems


def _compatibility(root: Path, contract: dict, where: str, budget: Budget) -> list[Problem]:
    """Compare the contract with the recorded baseline for the current major."""
    path = root / BASELINE
    if not path.is_file():
        return [Problem("API_BASELINE_MISSING", str(BASELINE),
                        "no compatibility baseline is recorded; without one, 'we did not break "
                        "anything' is an opinion", "NN-12")]
    budget.check(str(BASELINE))
    try:
        baseline = load_json(path)
    except Exception as exc:
        return [Problem("API_BASELINE_UNREADABLE", str(BASELINE),
                        f"cannot read the baseline: {exc}", "NN-12")]

    problems: list[Problem] = []
    major = (contract.get("versioning") or {}).get("current_major")
    if baseline.get("major") != major:
        return [Problem("API_BASELINE_MAJOR", str(BASELINE),
                        f"the baseline records major {baseline.get('major')} but the contract is "
                        f"at major {major}; re-record the baseline when opening a new major",
                        "NN-12")]

    current = {op["id"]: op for op in contract["operations"] if isinstance(op, dict)}
    for oid, recorded in (baseline.get("operations") or {}).items():
        operation = current.get(oid)
        if operation is None:
            problems.append(Problem(
                "API_BREAKING_REMOVAL", str(BASELINE),
                f"operation '{oid}' existed in the baseline for major {major} and is gone; "
                f"removing an operation inside a stable major breaks every integrator at once",
                "NN-12"))
            continue
        if operation.get("path") != recorded.get("path") or \
                operation.get("method") != recorded.get("method"):
            problems.append(Problem(
                "API_BREAKING_ROUTE", str(BASELINE),
                f"operation '{oid}' moved from {recorded.get('method')} {recorded.get('path')} "
                f"to {operation.get('method')} {operation.get('path')} inside major {major}",
                "NN-12"))
        was_required = bool((recorded.get("idempotency") or {}).get("required"))
        now_required = bool((operation.get("idempotency") or {}).get("required"))
        if was_required and not now_required:
            problems.append(Problem(
                "API_BREAKING_IDEMPOTENCY", str(BASELINE),
                f"operation '{oid}' no longer requires an idempotency key; weakening a safety "
                f"guarantee is a breaking change even though it accepts more requests", "NN-04"))
        gone = set(recorded.get("errors") or []) - set(operation.get("errors") or [])
        if gone:
            problems.append(Problem(
                "API_BREAKING_ERRORS", str(BASELINE),
                f"operation '{oid}' no longer declares {sorted(gone)}; clients branch on error "
                f"codes, so silently dropping one changes their behaviour", "NN-12"))
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .apigen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        if not path.is_file():
            problems.append(Problem("API_GENERATED_MISSING", rel,
                                    "generated API artefact is missing; run "
                                    "scripts/render-api.py", "NN-12"))
            continue
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("API_GENERATED", rel,
                                    f"the artefact cannot be derived from the contract: "
                                    f"{type(exc).__name__}: {exc}", "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("API_GENERATED_DRIFT", rel,
                                    "the generated artefact differs from the contract; run "
                                    "scripts/render-api.py", "NN-12"))
    return problems
