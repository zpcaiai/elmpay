"""B29 — fee, cost, commission and metering model.

The batch brief ends with the sentence this file is built around: the model
must **not substitute a book model for real settlement**. So the first rule is
``FEE_BOOK_IS_TRUTH``: whatever we compute is an estimate until the provider's
settlement report says what was actually taken, and a difference between the
two opens a reconciliation item. It must never overwrite the estimate, because
once it has, "what did we think we were charging" is a question with no answer
— and that question is the whole of a fee dispute.

The rest are the mistakes this area repeats:

* ``FEE_TAX_AS_REVENUE`` — netting tax into revenue. Tax is collected on behalf
  of an authority; counting it as income overstates the business and misstates
  what is owed;
* ``FEE_SPLIT_UNBALANCED`` / ``FEE_NO_REMAINDER_OWNER`` — a split whose parts do
  not add back to the total, or a rounding remainder with no declared owner. It
  is one minor unit a day, and a year later nobody can say where it went;
* ``FEE_IMPLICIT_CONVERSION`` — converting currency inside a fee calculation.
  The FX gain or loss then hides inside the fee, and the effective rate moves
  for reasons nobody can trace;
* ``FEE_ROUNDING_UNDECLARED`` — leaving the rounding mode to the implementation.
  Two services then disagree by one unit and both are "right".
"""
from __future__ import annotations

import re
from pathlib import Path

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

FEES = Path("governance/fee-model.json")
CAPS = Path("governance/provider-capabilities.json")
ACCOUNTS = Path("governance/provider-accounts.json")
CURRENCY = Path("governance/currency-metadata.json")
AUDIT = Path("governance/audit-log.json")

CODE = re.compile(r"^[a-z][a-z0-9_]*$")
CATEGORIES = {"provider_cost", "platform_service_fee", "tax", "internal_cost"}
ROUNDING_MODES = {"half_up", "half_even", "down"}
PARTIES = {"merchant", "platform", "provider", "authority"}
BASIS_KINDS = {"payment", "platform_service_fee"}
MAX_SETTLE_LAG_DAYS = 90
MAX_PERCENTAGE_BP = 10000
RATE_RECORD_FIELDS = {"rate", "quoted_at", "source"}


VALIDATOR = ("fee-model", "B29")


def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    where = str(FEES)
    budget.check(where)
    try:
        model = load_json(root / FEES)
    except Exception as exc:
        return [Problem("FEE_UNREADABLE", where, f"cannot read the fee model: {exc}", "NN-14")]
    if not isinstance(model, dict):
        return [Problem("FEE_SHAPE", where, "the model must be an object", "NN-12")]

    problems = list(expect(SEMVER.match(str(model.get("schema_version", ""))),
                           "FEE_VERSION_FIELD", where, "schema_version must be semver",
                           "NN-12"))
    problems += expect(len(str(model.get("principle") or "")) >= 20, "FEE_PRINCIPLE", where,
                       "say what the book value is and is not", "NN-14")
    categories, problems_ = _categories(model, where, budget)
    problems += problems_
    problems += _rounding(model, where)
    problems += _schedules(model, root, where, categories, budget)
    problems += _settlement(model, where)
    problems += _split(model, where)
    problems += _currency(model, where)
    problems += _metering(model, where)
    problems += _audit_binding(model, root, where, budget)
    problems += _generated(root, budget)
    return problems


def _categories(model: dict, where: str, budget: Budget) -> tuple[dict, list[Problem]]:
    entries = model.get("categories")
    if not isinstance(entries, list) or not entries:
        return {}, [Problem("FEE_SHAPE", where, "categories must be a non-empty list", "NN-14")]
    problems: list[Problem] = []
    categories: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("FEE_SHAPE", where, "each category must be an object",
                                    "NN-12"))
            continue
        cid = str(entry.get("id") or "")
        scope = f"{where}#{cid or '<anonymous>'}"
        budget.check(scope)
        problems += expect(cid in CATEGORIES, "FEE_CATEGORY_UNKNOWN", scope,
                           f"category must be one of {sorted(CATEGORIES)}", "NN-14")
        problems += expect(cid not in categories, "FEE_CATEGORY_DUPLICATE", scope,
                           f"category '{cid}' is declared twice", "NN-12")
        for field in ("is_revenue", "charged_to_merchant", "remitted_to_authority"):
            problems += expect(isinstance(entry.get(field), bool), "FEE_CATEGORY_UNSTATED",
                               scope, f"'{cid}' must answer '{field}' with a boolean", "NN-14")
        problems += expect(len(str(entry.get("notes") or "")) >= 4, "FEE_CATEGORY_NOTES", scope,
                           f"say what '{cid}' is", "NN-14")
        if cid:
            categories[cid] = entry

    tax = categories.get("tax") or {}
    if tax:
        problems += expect(tax.get("is_revenue") is False, "FEE_TAX_AS_REVENUE", where,
                           "tax is collected on behalf of an authority and must never count as "
                           "revenue", "NN-05")
        problems += expect(tax.get("remitted_to_authority") is True, "FEE_TAX_NOT_REMITTED",
                           where, "tax must be marked as remitted to an authority", "NN-05")
    cost = categories.get("provider_cost") or {}
    if cost:
        problems += expect(cost.get("is_revenue") is False, "FEE_COST_AS_REVENUE", where,
                           "the provider's cut is not our income", "NN-05")
    internal = categories.get("internal_cost") or {}
    if internal:
        problems += expect(internal.get("charged_to_merchant") is False,
                           "FEE_INTERNAL_COST_CHARGED", where,
                           "internal cost is a margin concept; charging it to the merchant "
                           "under another name is what makes a fee schedule unexplainable",
                           "NN-15")
    problems += expect(CATEGORIES <= set(categories), "FEE_CATEGORY_MISSING", where,
                       f"the model is missing {sorted(CATEGORIES - set(categories))}; a model "
                       f"that cannot separate them cannot report margin or tax correctly",
                       "NN-05")
    return categories, problems


def _rounding(model: dict, where: str) -> list[Problem]:
    rounding = model.get("rounding")
    if not isinstance(rounding, dict):
        return [Problem("FEE_ROUNDING_UNDECLARED", where,
                        "without a declared rounding rule, two services disagree by one minor "
                        "unit and both are right", "NN-05")]
    problems = list(expect(rounding.get("mode") in ROUNDING_MODES, "FEE_ROUNDING_UNDECLARED",
                           where, f"rounding mode must be one of {sorted(ROUNDING_MODES)}",
                           "NN-05"))
    problems += expect(rounding.get("unit") == "minor", "FEE_ROUNDING_UNIT", where,
                       "rounding happens in integer minor units; anything else reintroduces "
                       "floating point", "NN-05")
    problems += expect(rounding.get("declared") is True, "FEE_ROUNDING_UNDECLARED", where,
                       "the rounding rule must be part of the contract, not of an "
                       "implementation", "NN-05")
    problems += expect(rounding.get("sum_must_equal_total") is True, "FEE_SPLIT_UNBALANCED",
                       where, "the rounded parts must add back to the total", "NN-05")
    problems += expect(str(rounding.get("remainder_owner") or "") in PARTIES,
                       "FEE_NO_REMAINDER_OWNER", where,
                       f"the rounding remainder needs an owner from {sorted(PARTIES)}; leaving "
                       f"it to whoever computes first is one minor unit a day that nobody can "
                       f"trace a year later", "NN-05")
    problems += expect(len(str(rounding.get("notes") or "")) >= 8, "FEE_ROUNDING_NOTES", where,
                       "say who gets the remainder and why it matters", "NN-14")
    return problems


def _schedules(model: dict, root: Path, where: str, categories: dict,
               budget: Budget) -> list[Problem]:
    entries = model.get("schedules")
    if not isinstance(entries, list) or not entries:
        return [Problem("FEE_NO_SCHEDULES", where,
                        "a fee model with no schedules charges nothing and hides that behind "
                        "code", "NN-14")]
    budget.check(str(CAPS))
    try:
        caps = load_json(root / CAPS)
        capability_rows = [r for r in (caps.get("capabilities") or []) if isinstance(r, dict)]
    except Exception:
        capability_rows = []
    budget.check(str(ACCOUNTS))
    try:
        accounts = load_json(root / ACCOUNTS)
        providers = {str(p.get("id")) for p in (accounts.get("providers") or [])
                     if isinstance(p, dict)}
    except Exception:
        providers = set()
    budget.check(str(CURRENCY))
    try:
        currency = load_json(root / CURRENCY)
        currencies = {str(c.get("code")) for c in (currency.get("currencies") or [])
                      if isinstance(c, dict)}
    except Exception:
        currencies = set()

    problems: list[Problem] = []
    seen: set[str] = set()
    covered_costs: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("FEE_SHAPE", where, "each schedule must be an object",
                                    "NN-12"))
            continue
        sid = str(entry.get("id") or "")
        scope = f"{where}#{sid or '<anonymous>'}"
        budget.check(scope)
        problems += expect(bool(CODE.match(sid)), "FEE_SCHEDULE_ID", scope,
                           f"schedule id '{sid}' must be snake_case", "NN-12")
        problems += expect(sid not in seen, "FEE_SCHEDULE_DUPLICATE", scope,
                           f"schedule '{sid}' is declared twice", "NN-12")
        seen.add(sid)
        category = str(entry.get("category") or "")
        problems += expect(category in categories, "FEE_CATEGORY_UNKNOWN", scope,
                           f"'{sid}' uses undeclared category '{category}'", "NN-12")
        provider = str(entry.get("provider") or "")
        method = str(entry.get("method") or "")
        region = str(entry.get("region") or "")
        code = str(entry.get("currency") or "")
        problems += expect(provider in providers, "FEE_PROVIDER_UNKNOWN", scope,
                           f"'{sid}' prices provider '{provider}', which has no binding in B26",
                           "NN-12")
        problems += expect(code in currencies, "FEE_CURRENCY_UNKNOWN", scope,
                           f"currency '{code}' is not in the versioned currency metadata",
                           "NN-05")
        if capability_rows:
            served = any(r.get("provider") == provider and r.get("method") == method
                         and region in (r.get("regions") or [])
                         and code in (r.get("currencies") or [])
                         for r in capability_rows)
            problems += expect(served, "FEE_SCHEDULE_UNREACHABLE", scope,
                               f"'{sid}' prices {provider}/{method}/{region}/{code}, which the "
                               f"B27 matrix does not support; a price for a payment that "
                               f"cannot happen is a price nobody will ever check", "NN-14")
        basis = str(entry.get("basis") or "")
        problems += expect(basis in BASIS_KINDS, "FEE_BASIS_UNKNOWN", scope,
                           f"'{sid}' must say what it is a percentage of "
                           f"({sorted(BASIS_KINDS)}); a rate whose basis is implied is a rate "
                           f"two teams will compute differently", "NN-05")
        if category == "tax":
            problems += expect(basis == "platform_service_fee", "FEE_TAX_ON_PAYMENT", scope,
                               f"'{sid}' levies tax on the payment amount; VAT-style tax is "
                               f"levied on the service fee, and getting this wrong overstates "
                               f"the amount remitted by orders of magnitude", "NN-05")
        percentage = entry.get("percentage_bp")
        fixed = entry.get("fixed_minor")
        problems += expect(isinstance(percentage, int) and 0 <= percentage <= MAX_PERCENTAGE_BP,
                           "FEE_PERCENTAGE_RANGE", scope,
                           f"percentage_bp must be an integer 0-{MAX_PERCENTAGE_BP}", "NN-05")
        problems += expect(isinstance(fixed, int) and fixed >= 0, "FEE_FIXED_NOT_INTEGER",
                           scope, "fixed_minor must be a non-negative integer of minor units",
                           "NN-05")
        if isinstance(percentage, int) and isinstance(fixed, int):
            problems += expect(percentage > 0 or fixed > 0, "FEE_SCHEDULE_FREE", scope,
                               f"'{sid}' charges nothing; delete it rather than shipping a "
                               f"schedule that quietly does nothing", "NN-14")
        minimum = entry.get("min_minor")
        maximum = entry.get("max_minor")
        problems += expect(isinstance(minimum, int) and minimum >= 0, "FEE_BOUND_NOT_INTEGER",
                           scope, "min_minor must be a non-negative integer", "NN-05")
        problems += expect(isinstance(maximum, int) and maximum >= 0, "FEE_BOUND_NOT_INTEGER",
                           scope, "max_minor must be a non-negative integer", "NN-05")
        if isinstance(minimum, int) and isinstance(maximum, int) and maximum:
            problems += expect(maximum >= minimum, "FEE_BOUNDS_INVERTED", scope,
                               f"'{sid}' has a cap below its floor", "NN-05")
        if category == "platform_service_fee" and isinstance(percentage, int) and percentage:
            problems += expect(isinstance(maximum, int) and maximum > 0, "FEE_UNCAPPED_PERCENT",
                               scope,
                               f"'{sid}' is an uncapped percentage of the payment; on a large "
                               f"transfer that is a number nobody agreed to", "NN-15")
        problems += expect(len(str(entry.get("notes") or "")) >= 4, "FEE_SCHEDULE_NOTES", scope,
                           "say where this rate comes from", "NN-14")
        if category == "provider_cost" and provider:
            covered_costs.add(provider)
    for provider in sorted(providers - covered_costs):
        problems.append(Problem("FEE_PROVIDER_NO_COST", where,
                                f"'{provider}' has a binding but no provider_cost schedule, so "
                                f"every payment through it books an unknown cost", "NN-05"))
    return problems


def _settlement(model: dict, where: str) -> list[Problem]:
    settlement = model.get("settlement")
    if not isinstance(settlement, dict):
        return [Problem("FEE_BOOK_IS_TRUTH", where,
                        "without a settlement policy, the computed fee silently becomes the "
                        "truth", "NN-01")]
    problems = list(expect(settlement.get("book_value_is_estimate") is True,
                           "FEE_BOOK_IS_TRUTH", where,
                           "the computed fee is an estimate until the provider's settlement "
                           "report arrives", "NN-01"))
    problems += expect(str(settlement.get("authoritative_source") or "")
                       == "provider_settlement_report", "FEE_NO_AUTHORITATIVE_SOURCE", where,
                       "the settlement report is what actually happened; anything else is our "
                       "opinion of it", "NN-01")
    problems += expect(settlement.get("mismatch_opens_reconciliation") is True,
                       "FEE_MISMATCH_IGNORED", where,
                       "a difference between book and settlement must open a reconciliation "
                       "item", "NN-01")
    problems += expect(settlement.get("silent_overwrite_allowed") is False,
                       "FEE_SILENT_OVERWRITE", where,
                       "overwriting the estimate with the settled amount destroys the only "
                       "record of what we believed we were charging", "NN-13")
    tolerance = settlement.get("tolerance_minor")
    problems += expect(isinstance(tolerance, int) and tolerance == 0, "FEE_TOLERANCE_NONZERO",
                       where,
                       "amounts are integers, so any difference is a real difference; a "
                       "tolerance is a place for real breaks to hide", "NN-05")
    lag = int(settlement.get("max_settle_lag_days") or 0)
    problems += expect(0 < lag <= MAX_SETTLE_LAG_DAYS, "FEE_SETTLE_LAG_UNBOUNDED", where,
                       f"an estimate that is never settled must eventually be escalated, got "
                       f"{lag} days", "NN-13")
    problems += expect(len(str(settlement.get("notes") or "")) >= 8, "FEE_SETTLEMENT_NOTES",
                       where, "say what happens when the two disagree", "NN-14")
    return problems


def _split(model: dict, where: str) -> list[Problem]:
    split = model.get("split")
    if not isinstance(split, dict):
        return [Problem("FEE_SPLIT_UNBALANCED", where, "split must be an object", "NN-05")]
    parties = set(split.get("parties") or [])
    problems = list(expect(PARTIES <= parties, "FEE_SPLIT_PARTY_MISSING", where,
                           f"the split is missing {sorted(PARTIES - parties)}", "NN-05"))
    problems += expect(split.get("must_sum_to_total") is True, "FEE_SPLIT_UNBALANCED", where,
                       "the parts must add back to the total, exactly", "NN-05")
    problems += expect(str(split.get("residue_to") or "") in PARTIES, "FEE_NO_REMAINDER_OWNER",
                       where, "the residue needs a named owner", "NN-05")
    problems += expect(len(str(split.get("notes") or "")) >= 8, "FEE_SPLIT_NOTES", where,
                       "say who absorbs the residue", "NN-14")
    return problems


def _currency(model: dict, where: str) -> list[Problem]:
    currency = model.get("currency")
    if not isinstance(currency, dict):
        return [Problem("FEE_IMPLICIT_CONVERSION", where,
                        "without a currency policy, conversion happens wherever somebody needed "
                        "it", "NN-05")]
    problems = list(expect(currency.get("fee_currency_equals_payment_currency") is True,
                           "FEE_CURRENCY_MISMATCH", where,
                           "a fee must be denominated in the currency of the payment it came "
                           "from", "NN-05"))
    problems += expect(currency.get("implicit_conversion_allowed") is False,
                       "FEE_IMPLICIT_CONVERSION", where,
                       "implicit conversion buries the FX gain or loss inside the fee, so the "
                       "effective rate moves for reasons nobody can trace", "NN-05")
    problems += expect(currency.get("conversion_requires_rate_record") is True,
                       "FEE_NO_RATE_RECORD", where,
                       "a conversion must carry the rate that was used", "NN-05")
    fields = set(currency.get("rate_record_fields") or [])
    problems += expect(RATE_RECORD_FIELDS <= fields, "FEE_NO_RATE_RECORD", where,
                       f"the rate record is missing {sorted(RATE_RECORD_FIELDS - fields)}",
                       "NN-05")
    problems += expect(len(str(currency.get("notes") or "")) >= 8, "FEE_CURRENCY_NOTES", where,
                       "say what an implicit conversion would hide", "NN-14")
    return problems


def _metering(model: dict, where: str) -> list[Problem]:
    metering = model.get("metering")
    if not isinstance(metering, dict):
        return [Problem("FEE_SHAPE", where, "metering must be an object", "NN-03")]
    problems = list(expect(str(metering.get("event_key") or "") == "payment_id",
                           "FEE_METERING_KEY", where,
                           "metering must be keyed by the payment, which is the only identifier "
                           "stable across a retry", "NN-03"))
    problems += expect(metering.get("idempotent") is True, "FEE_METERING_NOT_IDEMPOTENT", where,
                       "providers resend, internal jobs re-run, and backfills replay; a "
                       "non-idempotent meter double-bills", "NN-03")
    problems += expect(metering.get("recomputable") is True, "FEE_METERING_UNRECOMPUTABLE",
                       where,
                       "any day's metering must be derivable again from the raw events; "
                       "otherwise the only record is a total nobody can check", "NN-13")
    days = int(metering.get("retention_days") or 0)
    problems += expect(days >= 365, "FEE_METERING_RETENTION_SHORT", where,
                       f"metering events must survive at least a year for disputes and audits, "
                       f"got {days}", "NN-13")
    problems += expect(len(str(metering.get("notes") or "")) >= 8, "FEE_METERING_NOTES", where,
                       "say why the meter must be idempotent", "NN-14")
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
    problems = list(expect(event_class in classes, "FEE_AUDIT_CLASS_UNKNOWN", where,
                           f"fee events are recorded as '{event_class}', which "
                           f"governance/audit-log.json does not define", "NN-13"))
    problems += expect(event_class == "money.movement", "FEE_AUDIT_CLASS_TOO_WEAK", where,
                       "a fee is a movement of money, not a configuration change; recording it "
                       "under a weaker class loses the retention and review that money events "
                       "get", "NN-13")
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .feesgen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("FEE_GENERATED", rel, f"cannot generate {rel}: {exc}",
                                    "NN-12"))
            continue
        if not path.is_file():
            problems.append(Problem("FEE_GENERATED_MISSING", rel,
                                    f"{rel} is generated from governance/fee-model.json but "
                                    f"does not exist; run scripts/render-fees.py", "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("FEE_GENERATED_DRIFT", rel,
                                    f"{rel} differs from what the model generates", "NN-12"))
    return problems
