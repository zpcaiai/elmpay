"""B27 — provider capability and regional policy matrix.

The batch asks the matrix to express payment methods, currencies, regions,
devices, authorisation/capture, refunds, subscriptions, disputes and
availability limits. One rule decides whether any of that is worth having:
``CAP_IMPLICIT_ALLOW``. A matrix that treats an undeclared combination as
"probably fine, let the provider decide" has not restricted anything. It has
moved the failure to the moment the payer has already entered their card
details, and the reason for it arrives as a third-party error code nobody in
the building can read.

The rest are the mistakes this area repeats:

* ``CAP_AUTH_NEVER_EXPIRES`` — an authorisation is not money set aside, it is
  the issuer agreeing to honour a charge for a bounded number of days. Capturing
  after that window often still returns success, and the cardholder still has
  the right to take it back;
* ``CAP_REFUND_PROMISED_BEYOND_WINDOW`` — offering a refund the provider will
  not accept. The button that does nothing is worse than no button, because
  support and the merchant both believe the money is moving;
* ``CAP_DISPUTE_AUTO_ACCEPT`` — conceding disputes automatically, which turns
  one convenience into a channel a fraudster can use repeatedly;
* ``CAP_SILENT_FALLBACK`` — quietly routing to another provider or method. The
  payer chose one thing and is billed by another, and the burden of explaining
  that in a dispute is ours.
"""
from __future__ import annotations

import re
from pathlib import Path

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

CAPS = Path("governance/provider-capabilities.json")
ACCOUNTS = Path("governance/provider-accounts.json")
MERCHANT = Path("governance/merchant-profile.json")
CURRENCY = Path("governance/currency-metadata.json")
AUDIT = Path("governance/audit-log.json")

CODE = re.compile(r"^[a-z][a-z0-9_]*$")
REGION = re.compile(r"^[A-Z]{2}$")
METHOD_KINDS = {"card", "wallet", "device_wallet", "bank_transfer"}
DEVICES = {"web", "ios", "android", "in_app_webview", "pos"}
DEGRADED = {"reject", "queue"}
# Card networks give the merchant a fixed number of days to answer a dispute.
# Anything longer than this in our model would be a promise we cannot keep.
MAX_DISPUTE_RESPONSE_DAYS = 45
MAX_AUTH_HOURS = 720
EVIDENCE_REQUIRED = {"order_record", "delivery_proof", "authorization_record"}


VALIDATOR = ("provider-capabilities", "B27")


def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    where = str(CAPS)
    budget.check(where)
    try:
        model = load_json(root / CAPS)
    except Exception as exc:
        return [Problem("CAP_UNREADABLE", where,
                        f"cannot read the capability matrix: {exc}", "NN-14")]
    if not isinstance(model, dict):
        return [Problem("CAP_SHAPE", where, "the model must be an object", "NN-12")]

    problems = list(expect(SEMVER.match(str(model.get("schema_version", ""))),
                           "CAP_VERSION_FIELD", where, "schema_version must be semver",
                           "NN-12"))
    problems += expect(len(str(model.get("principle") or "")) >= 20, "CAP_PRINCIPLE", where,
                       "say what an undeclared combination means", "NN-14")
    problems += _resolution(model, where)
    methods, problems_ = _methods(model, where, budget)
    problems += problems_
    problems += _devices(model, where)
    problems += _capabilities(model, root, where, methods, budget)
    problems += _authorization(model, where)
    problems += _refund(model, where)
    problems += _dispute(model, where)
    problems += _availability(model, root, where, budget)
    problems += _regions(model, root, where, methods, budget)
    problems += _audit_binding(model, root, where, budget)
    problems += _generated(root, budget)
    return problems


def _resolution(model: dict, where: str) -> list[Problem]:
    resolution = model.get("resolution")
    if not isinstance(resolution, dict):
        return [Problem("CAP_IMPLICIT_ALLOW", where,
                        "without a resolution policy the matrix has no default, and no default "
                        "means allow", "NN-14")]
    problems = list(expect(resolution.get("default") == "deny", "CAP_IMPLICIT_ALLOW", where,
                           "the matrix must deny by default", "NN-14"))
    problems += expect(resolution.get("unknown_combination") == "unsupported",
                       "CAP_IMPLICIT_ALLOW", where,
                       "an undeclared combination must be unsupported, not attempted; otherwise "
                       "the payer discovers the limit after entering their card details",
                       "NN-14")
    for field in ("silent_fallback_to_another_method", "silent_fallback_to_another_provider"):
        problems += expect(resolution.get(field) is False, "CAP_SILENT_FALLBACK", where,
                           f"{field} must be false: the payer chose one thing and would be "
                           f"billed by another, and explaining that in a dispute is our burden",
                           "NN-01")
    problems += expect(len(str(resolution.get("notes") or "")) >= 8, "CAP_RESOLUTION_NOTES",
                       where, "say in what order the matrix resolves", "NN-14")
    return problems


def _methods(model: dict, where: str, budget: Budget) -> tuple[dict, list[Problem]]:
    entries = model.get("payment_methods")
    if not isinstance(entries, list) or not entries:
        return {}, [Problem("CAP_SHAPE", where, "payment_methods must be a non-empty list",
                            "NN-14")]
    problems: list[Problem] = []
    methods: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("CAP_SHAPE", where, "each payment method must be an object",
                                    "NN-12"))
            continue
        mid = str(entry.get("id") or "")
        scope = f"{where}#{mid or '<anonymous>'}"
        budget.check(scope)
        problems += expect(bool(CODE.match(mid)), "CAP_METHOD_ID", scope,
                           f"payment method id '{mid}' must be snake_case", "NN-12")
        problems += expect(mid not in methods, "CAP_METHOD_DUPLICATE", scope,
                           f"payment method '{mid}' is declared twice", "NN-12")
        problems += expect(entry.get("kind") in METHOD_KINDS, "CAP_METHOD_KIND", scope,
                           f"kind must be one of {sorted(METHOD_KINDS)}", "NN-14")
        problems += expect(len(str(entry.get("notes") or "")) >= 4, "CAP_METHOD_NOTES", scope,
                           "say what is different about this method", "NN-14")
        if mid:
            methods[mid] = entry
    return methods, problems


def _devices(model: dict, where: str) -> list[Problem]:
    devices = model.get("device_kinds")
    if not isinstance(devices, list) or not devices:
        return [Problem("CAP_SHAPE", where, "device_kinds must be a non-empty list", "NN-14")]
    unknown = [d for d in devices if d not in DEVICES]
    return list(expect(not unknown, "CAP_DEVICE_UNKNOWN", where,
                       f"unknown device kinds {unknown}; the device is a hard limit for wallets, "
                       f"not a hint", "NN-12"))


def _capabilities(model: dict, root: Path, where: str, methods: dict,
                  budget: Budget) -> list[Problem]:
    entries = model.get("capabilities")
    if not isinstance(entries, list) or not entries:
        return [Problem("CAP_NO_MATRIX", where,
                        "an empty capability matrix denies everything, which is safe and also "
                        "useless; declare what is actually supported", "NN-14")]
    budget.check(str(ACCOUNTS))
    try:
        accounts = load_json(root / ACCOUNTS)
        providers = {str(p.get("id")): p for p in (accounts.get("providers") or [])
                     if isinstance(p, dict)}
    except Exception:
        providers = {}
    budget.check(str(MERCHANT))
    try:
        merchant = load_json(root / MERCHANT)
        regions = {str(r.get("code")) for r in (merchant.get("operating_regions") or [])
                   if isinstance(r, dict)}
    except Exception:
        regions = set()
    budget.check(str(CURRENCY))
    try:
        currency = load_json(root / CURRENCY)
        currencies = {str(c.get("code")) for c in (currency.get("currencies") or [])
                      if isinstance(c, dict)}
    except Exception:
        currencies = set()
    devices = set(model.get("device_kinds") or [])

    problems: list[Problem] = []
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("CAP_SHAPE", where, "each capability must be an object",
                                    "NN-12"))
            continue
        provider = str(entry.get("provider") or "")
        method = str(entry.get("method") or "")
        scope = f"{where}#{provider}/{method}"
        budget.check(scope)
        problems += expect(provider in providers, "CAP_PROVIDER_UNKNOWN", scope,
                           f"'{provider}' is not a provider the B26 binding model defines",
                           "NN-12")
        problems += expect(method in methods, "CAP_METHOD_UNKNOWN", scope,
                           f"'{method}' is not a declared payment method", "NN-12")
        problems += expect((provider, method) not in seen, "CAP_ROW_DUPLICATE", scope,
                           f"'{provider}/{method}' is declared twice; two rows for one pair "
                           f"means the resolution order decides which limit applies", "NN-12")
        seen.add((provider, method))

        row_regions = entry.get("regions")
        problems += expect(isinstance(row_regions, list) and bool(row_regions),
                           "CAP_ROW_NO_REGION", scope, f"'{provider}/{method}' supports no "
                           f"region", "NN-14")
        for code in row_regions or []:
            problems += expect(bool(REGION.match(str(code))) and code in regions,
                               "CAP_REGION_UNKNOWN", scope,
                               f"region '{code}' is not an operating region in B25", "NN-14")
        row_currencies = entry.get("currencies")
        problems += expect(isinstance(row_currencies, list) and bool(row_currencies),
                           "CAP_ROW_NO_CURRENCY", scope,
                           f"'{provider}/{method}' supports no currency", "NN-05")
        for code in row_currencies or []:
            problems += expect(code in currencies, "CAP_CURRENCY_UNKNOWN", scope,
                               f"currency '{code}' is not in the versioned currency metadata",
                               "NN-05")
        row_devices = entry.get("devices")
        problems += expect(isinstance(row_devices, list) and bool(row_devices),
                           "CAP_ROW_NO_DEVICE", scope,
                           f"'{provider}/{method}' supports no device", "NN-14")
        for device in row_devices or []:
            problems += expect(device in devices, "CAP_DEVICE_UNKNOWN", scope,
                               f"device '{device}' is not a declared device kind", "NN-12")
        provider_currencies = set((providers.get(provider) or {})
                                  .get("settlement_currencies") or [])
        if provider_currencies:
            extra = sorted(set(row_currencies or []) - provider_currencies)
            problems += expect(not extra, "CAP_CURRENCY_UNSETTLEABLE", scope,
                               f"{extra} can be charged but not settled: B26 does not list them "
                               f"as settlement currencies for '{provider}'", "NN-05")

        auth = entry.get("supports_authorization_capture")
        problems += expect(isinstance(auth, bool), "CAP_AUTH_UNSTATED", scope,
                           "say explicitly whether this pair supports authorise/capture",
                           "NN-14")
        hours = int(entry.get("authorization_valid_hours") or 0)
        if auth:
            problems += expect(0 < hours <= MAX_AUTH_HOURS, "CAP_AUTH_NEVER_EXPIRES", scope,
                               f"an authorisation must expire, got {hours}h; the issuer only "
                               f"agreed to honour the charge for a bounded time", "NN-01")
        else:
            problems += expect(hours == 0, "CAP_AUTH_WINDOW_WITHOUT_AUTH", scope,
                               f"'{provider}/{method}' has no authorise/capture step but "
                               f"declares a {hours}h authorisation window", "NN-12")
        percent = int(entry.get("capture_max_percent") or 0)
        problems += expect(percent == 100, "CAP_OVER_CAPTURE", scope,
                           f"capture is capped at the authorised amount, got {percent}%; some "
                           f"acquirers accept more and the cardholder may still take it back",
                           "NN-01")
        refund_days = int(entry.get("refund_window_days") or 0)
        problems += expect(0 < refund_days <= 730, "CAP_REFUND_NO_WINDOW", scope,
                           f"the refund window must be bounded and real, got {refund_days} days",
                           "NN-01")
        problems += expect(isinstance(entry.get("partial_refund"), bool), "CAP_REFUND_UNSTATED",
                           scope, "say explicitly whether partial refunds are supported",
                           "NN-14")
        problems += expect(entry.get("refund_to_original_instrument_only") is True,
                           "CAP_REFUND_ELSEWHERE", scope,
                           "a refund must go back to the instrument that paid; refunding "
                           "somewhere else is how a compromised account is cashed out", "NN-01")
        dispute_days = int(entry.get("dispute_window_days") or 0)
        problems += expect(dispute_days > 0, "CAP_DISPUTE_NO_WINDOW", scope,
                           f"'{provider}/{method}' declares no dispute window", "NN-01")
        response = int(entry.get("dispute_response_days") or 0)
        problems += expect(0 < response <= MAX_DISPUTE_RESPONSE_DAYS, "CAP_DISPUTE_NO_DEADLINE",
                           scope,
                           f"the dispute response deadline must be real and short, got "
                           f"{response} days", "NN-01")
        problems += expect(response < dispute_days, "CAP_DISPUTE_DEADLINE_INVERTED", scope,
                           f"the response deadline ({response}d) must fall inside the dispute "
                           f"window ({dispute_days}d)", "NN-12")
        problems += expect(isinstance(entry.get("supports_subscription"), bool),
                           "CAP_SUBSCRIPTION_UNSTATED", scope,
                           "say explicitly whether recurring charges are supported", "NN-14")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "CAP_ROW_NOTES", scope,
                           "say what this row's limits come from", "NN-14")
    return problems


def _authorization(model: dict, where: str) -> list[Problem]:
    authorization = model.get("authorization")
    if not isinstance(authorization, dict):
        return [Problem("CAP_SHAPE", where, "authorization must be an object", "NN-01")]
    hours = int(authorization.get("max_valid_hours") or 0)
    problems = list(expect(0 < hours <= MAX_AUTH_HOURS, "CAP_AUTH_NEVER_EXPIRES", where,
                           f"the global authorisation ceiling must be bounded, got {hours}h",
                           "NN-01"))
    problems += expect(authorization.get("capture_after_expiry_allowed") is False,
                       "CAP_CAPTURE_AFTER_EXPIRY", where,
                       "capturing an expired authorisation may still succeed and is still "
                       "reversible by the cardholder", "NN-01")
    problems += expect(authorization.get("reauthorization_required") is True,
                       "CAP_NO_REAUTHORIZATION", where,
                       "an expired authorisation must be re-taken, not reused", "NN-01")
    problems += expect(authorization.get("over_capture_allowed") is False, "CAP_OVER_CAPTURE",
                       where, "capturing more than was authorised must stay forbidden", "NN-01")
    problems += expect(len(str(authorization.get("notes") or "")) >= 8, "CAP_AUTH_NOTES", where,
                       "say what an authorisation actually is", "NN-14")
    return problems


def _refund(model: dict, where: str) -> list[Problem]:
    refund = model.get("refund")
    if not isinstance(refund, dict):
        return [Problem("CAP_SHAPE", where, "refund must be an object", "NN-01")]
    problems = list(expect(refund.get("promise_beyond_window") is False,
                           "CAP_REFUND_PROMISED_BEYOND_WINDOW", where,
                           "the product must not offer a refund the provider will refuse; a "
                           "button that does nothing is worse than no button", "NN-15"))
    problems += expect(refund.get("beyond_window_action") in {"manual_or_dispute", "manual",
                                                              "dispute"},
                       "CAP_REFUND_NO_FALLBACK", where,
                       "say what happens after the window closes", "NN-15")
    problems += expect(refund.get("refund_exceeding_capture_allowed") is False,
                       "CAP_OVER_REFUND", where,
                       "refunding more than was captured moves money the platform never took",
                       "NN-01")
    problems += expect(len(str(refund.get("notes") or "")) >= 8, "CAP_REFUND_NOTES", where,
                       "say why the window matters to the person clicking the button", "NN-14")
    return problems


def _dispute(model: dict, where: str) -> list[Problem]:
    dispute = model.get("dispute")
    if not isinstance(dispute, dict):
        return [Problem("CAP_SHAPE", where, "dispute must be an object", "NN-01")]
    problems = list(expect(dispute.get("deadline_is_external") is True,
                           "CAP_DISPUTE_DEADLINE_INTERNAL", where,
                           "the dispute deadline is set by the network, not by our SLA; "
                           "modelling it as internal invites someone to extend it", "NN-01"))
    problems += expect(dispute.get("missing_response_loses_by_default") is True,
                       "CAP_DISPUTE_NO_DEADLINE", where,
                       "say plainly that missing the deadline loses the case", "NN-01")
    problems += expect(dispute.get("auto_accept_allowed") is False, "CAP_DISPUTE_AUTO_ACCEPT",
                       where,
                       "automatic concession turns one convenience into a repeatable channel "
                       "for a fraudster", "NN-01")
    evidence = set(dispute.get("evidence_required") or [])
    problems += expect(EVIDENCE_REQUIRED <= evidence, "CAP_DISPUTE_NO_EVIDENCE", where,
                       f"the dispute pack is missing {sorted(EVIDENCE_REQUIRED - evidence)}",
                       "NN-13")
    problems += expect(len(str(dispute.get("notes") or "")) >= 8, "CAP_DISPUTE_NOTES", where,
                       "say who owns the clock", "NN-14")
    return problems


def _availability(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    entries = model.get("availability")
    if not isinstance(entries, list) or not entries:
        return [Problem("CAP_SHAPE", where, "availability must be a non-empty list", "NN-14")]
    budget.check(str(ACCOUNTS))
    try:
        accounts = load_json(root / ACCOUNTS)
        providers = {str(p.get("id")) for p in (accounts.get("providers") or [])
                     if isinstance(p, dict)}
    except Exception:
        providers = set()
    problems: list[Problem] = []
    covered: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("CAP_SHAPE", where, "each availability row must be an "
                                    "object", "NN-12"))
            continue
        provider = str(entry.get("provider") or "")
        scope = f"{where}#availability/{provider}"
        budget.check(scope)
        problems += expect(provider in providers, "CAP_PROVIDER_UNKNOWN", scope,
                           f"'{provider}' is not a provider the B26 binding model defines",
                           "NN-12")
        covered.add(provider)
        problems += expect(entry.get("degraded_behaviour") in DEGRADED,
                           "CAP_DEGRADED_UNDEFINED", scope,
                           f"degraded_behaviour must be one of {sorted(DEGRADED)}", "NN-14")
        problems += expect(entry.get("silent_fallback_allowed") is False, "CAP_SILENT_FALLBACK",
                           scope,
                           f"'{provider}' must not silently fall back to another provider "
                           f"while it is down", "NN-01")
        if entry.get("scheduled_maintenance") is True:
            problems += expect(bool(entry.get("maintenance_window_utc")),
                               "CAP_MAINTENANCE_UNDECLARED", scope,
                               f"'{provider}' has scheduled maintenance but no declared window; "
                               f"an undeclared window looks exactly like an outage", "NN-14")
        problems += expect(len(str(entry.get("notes") or "")) >= 4, "CAP_AVAILABILITY_NOTES",
                           scope, "say what happens to a payment during the window", "NN-14")
    for provider in sorted(providers - covered):
        problems.append(Problem("CAP_AVAILABILITY_MISSING", where,
                                f"'{provider}' has no availability row, so nothing says what "
                                f"happens to a payment when it is down", "NN-14"))
    return problems


def _regions(model: dict, root: Path, where: str, methods: dict,
             budget: Budget) -> list[Problem]:
    entries = model.get("region_policy")
    if not isinstance(entries, list) or not entries:
        return [Problem("CAP_SHAPE", where, "region_policy must be a non-empty list", "NN-14")]
    budget.check(str(MERCHANT))
    try:
        merchant = load_json(root / MERCHANT)
        regions = {str(r.get("code")) for r in (merchant.get("operating_regions") or [])
                   if isinstance(r, dict)}
    except Exception:
        regions = set()
    supported: dict[str, set[str]] = {}
    for row in model.get("capabilities") or []:
        if isinstance(row, dict):
            for code in row.get("regions") or []:
                supported.setdefault(str(code), set()).add(str(row.get("method")))

    problems: list[Problem] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("CAP_SHAPE", where, "each region policy must be an object",
                                    "NN-12"))
            continue
        code = str(entry.get("region") or "")
        scope = f"{where}#region/{code}"
        budget.check(scope)
        problems += expect(code in regions, "CAP_REGION_UNKNOWN", scope,
                           f"'{code}' is not an operating region in B25", "NN-14")
        problems += expect(code not in seen, "CAP_REGION_DUPLICATE", scope,
                           f"region '{code}' is declared twice", "NN-12")
        seen.add(code)
        allowed = entry.get("allowed_methods")
        problems += expect(isinstance(allowed, list) and bool(allowed), "CAP_REGION_NO_METHOD",
                           scope, f"'{code}' allows no payment method", "NN-14")
        for method in allowed or []:
            problems += expect(method in methods, "CAP_METHOD_UNKNOWN", scope,
                               f"'{code}' allows unknown method '{method}'", "NN-12")
            problems += expect(method in supported.get(code, set()),
                               "CAP_REGION_METHOD_UNSUPPORTED", scope,
                               f"'{code}' allows '{method}' but no capability row provides it "
                               f"there; the policy promises what the matrix cannot deliver",
                               "NN-14")
        problems += expect(isinstance(entry.get("requires_local_acquirer"), bool),
                           "CAP_REGION_ACQUIRER_UNSTATED", scope,
                           "say explicitly whether a local acquirer is required", "NN-14")
        problems += expect(isinstance(entry.get("strong_customer_authentication"), bool),
                           "CAP_SCA_UNSTATED", scope,
                           "say explicitly whether strong customer authentication applies",
                           "NN-14")
        if code == "EU":
            problems += expect(entry.get("strong_customer_authentication") is True,
                               "CAP_SCA_DISABLED", scope,
                               "strong customer authentication is a legal requirement in the "
                               "EU, not a configurable experience", "NN-15")
        problems += expect(len(str(entry.get("notes") or "")) >= 4, "CAP_REGION_NOTES", scope,
                           "say what is special about this region", "NN-14")
    return problems


def _audit_binding(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    event_class = str(model.get("audit_event_class") or "")
    budget.check(str(AUDIT))
    try:
        audit = load_json(root / AUDIT)
        classes = {str(c.get("id")) for c in (audit.get("event_classes") or [])
                   if isinstance(c, dict)}
    except Exception:
        classes = set()
    return list(expect(event_class in classes, "CAP_AUDIT_CLASS_UNKNOWN", where,
                       f"matrix changes are recorded as '{event_class}', which "
                       f"governance/audit-log.json does not define", "NN-13"))


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .capabilitiesgen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("CAP_GENERATED", rel, f"cannot generate {rel}: {exc}",
                                    "NN-12"))
            continue
        if not path.is_file():
            problems.append(Problem("CAP_GENERATED_MISSING", rel,
                                    f"{rel} is generated from "
                                    f"governance/provider-capabilities.json but does not exist; "
                                    f"run scripts/render-capabilities.py", "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("CAP_GENERATED_DRIFT", rel,
                                    f"{rel} differs from what the model generates", "NN-12"))
    return problems
