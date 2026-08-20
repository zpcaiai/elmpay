"""B29 negative controls — the four ways a fee model stops matching the money."""
from __future__ import annotations

from . import EXIT_PROBLEMS

REL = "governance/fee-model.json"


def _schedule(d, sid):
    return next(s for s in d["schedules"] if s["id"] == sid)


def _category(d, cid):
    return next(c for c in d["categories"] if c["id"] == cid)


EXPECTED_CODES = {
    "B29 the book value becomes the truth": "FEE_BOOK_IS_TRUTH",
    "B29 a settlement mismatch is ignored": "FEE_MISMATCH_IGNORED",
    "B29 settlement silently overwrites the estimate": "FEE_SILENT_OVERWRITE",
    "B29 a tolerance is introduced for integer amounts": "FEE_TOLERANCE_NONZERO",
    "B29 tax is counted as revenue": "FEE_TAX_AS_REVENUE",
    "B29 tax stops being remitted to an authority": "FEE_TAX_NOT_REMITTED",
    "B29 tax is levied on the payment amount": "FEE_TAX_ON_PAYMENT",
    "B29 the provider's cut is counted as revenue": "FEE_COST_AS_REVENUE",
    "B29 internal cost is charged to the merchant": "FEE_INTERNAL_COST_CHARGED",
    "B29 a fee category disappears": "FEE_CATEGORY_MISSING",
    "B29 the rounding mode is left to the implementation": "FEE_ROUNDING_UNDECLARED",
    "B29 rounding moves out of minor units": "FEE_ROUNDING_UNIT",
    "B29 the rounded parts need not add up": "FEE_SPLIT_UNBALANCED",
    "B29 the rounding remainder has no owner": "FEE_NO_REMAINDER_OWNER",
    "B29 a schedule stops saying what it is a percentage of": "FEE_BASIS_UNKNOWN",
    "B29 a percentage service fee loses its cap": "FEE_UNCAPPED_PERCENT",
    "B29 a fixed fee becomes a decimal": "FEE_FIXED_NOT_INTEGER",
    "B29 a schedule prices a payment that cannot happen": "FEE_SCHEDULE_UNREACHABLE",
    "B29 a provider loses its cost schedule": "FEE_PROVIDER_NO_COST",
    "B29 a schedule prices a provider with no binding": "FEE_PROVIDER_UNKNOWN",
    "B29 the split loses a party": "FEE_SPLIT_PARTY_MISSING",
    "B29 currency is converted implicitly": "FEE_IMPLICIT_CONVERSION",
    "B29 conversion no longer needs a rate record": "FEE_NO_RATE_RECORD",
    "B29 the meter stops being idempotent": "FEE_METERING_NOT_IDEMPOTENT",
    "B29 the meter cannot be recomputed": "FEE_METERING_UNRECOMPUTABLE",
    "B29 fee events are recorded as configuration changes": "FEE_AUDIT_CLASS_TOO_WEAK",
    "B29 fee document hand-edited": "FEE_GENERATED_DRIFT",
}

SCENARIOS = [
    ("B29 the book value becomes the truth", REL,
     lambda d: d["settlement"].__setitem__("book_value_is_estimate", False), EXIT_PROBLEMS),
    ("B29 a settlement mismatch is ignored", REL,
     lambda d: d["settlement"].__setitem__("mismatch_opens_reconciliation", False),
     EXIT_PROBLEMS),
    ("B29 settlement silently overwrites the estimate", REL,
     lambda d: d["settlement"].__setitem__("silent_overwrite_allowed", True), EXIT_PROBLEMS),
    ("B29 a tolerance is introduced for integer amounts", REL,
     lambda d: d["settlement"].__setitem__("tolerance_minor", 5), EXIT_PROBLEMS),
    ("B29 tax is counted as revenue", REL,
     lambda d: _category(d, "tax").__setitem__("is_revenue", True), EXIT_PROBLEMS),
    ("B29 tax stops being remitted to an authority", REL,
     lambda d: _category(d, "tax").__setitem__("remitted_to_authority", False), EXIT_PROBLEMS),
    ("B29 tax is levied on the payment amount", REL,
     lambda d: _schedule(d, "tax_eu_vat").__setitem__("basis", "payment"), EXIT_PROBLEMS),
    ("B29 the provider's cut is counted as revenue", REL,
     lambda d: _category(d, "provider_cost").__setitem__("is_revenue", True), EXIT_PROBLEMS),
    ("B29 internal cost is charged to the merchant", REL,
     lambda d: _category(d, "internal_cost").__setitem__("charged_to_merchant", True),
     EXIT_PROBLEMS),
    ("B29 a fee category disappears", REL,
     lambda d: d.__setitem__("categories", [c for c in d["categories"]
                                            if c["id"] != "internal_cost"]), EXIT_PROBLEMS),
    ("B29 the rounding mode is left to the implementation", REL,
     lambda d: d["rounding"].__setitem__("declared", False), EXIT_PROBLEMS),
    ("B29 rounding moves out of minor units", REL,
     lambda d: d["rounding"].__setitem__("unit", "major"), EXIT_PROBLEMS),
    ("B29 the rounded parts need not add up", REL,
     lambda d: d["rounding"].__setitem__("sum_must_equal_total", False), EXIT_PROBLEMS),
    ("B29 the rounding remainder has no owner", REL,
     lambda d: d["rounding"].__setitem__("remainder_owner", "whoever"), EXIT_PROBLEMS),
    ("B29 a schedule stops saying what it is a percentage of", REL,
     lambda d: _schedule(d, "stripe_eu_cost").__setitem__("basis", ""), EXIT_PROBLEMS),
    ("B29 a percentage service fee loses its cap", REL,
     lambda d: _schedule(d, "platform_eu").__setitem__("max_minor", 0), EXIT_PROBLEMS),
    ("B29 a fixed fee becomes a decimal", REL,
     lambda d: _schedule(d, "stripe_eu_cost").__setitem__("fixed_minor", 0.25), EXIT_PROBLEMS),
    ("B29 a schedule prices a payment that cannot happen", REL,
     lambda d: _schedule(d, "stripe_eu_cost").__setitem__("region", "CN"), EXIT_PROBLEMS),
    ("B29 a provider loses its cost schedule", REL,
     lambda d: d.__setitem__("schedules", [s for s in d["schedules"]
                                           if s["provider"] != "paypal"]), EXIT_PROBLEMS),
    ("B29 a schedule prices a provider with no binding", REL,
     lambda d: _schedule(d, "stripe_eu_cost").__setitem__("provider", "klarna"),
     EXIT_PROBLEMS),
    ("B29 the split loses a party", REL,
     lambda d: d["split"].__setitem__("parties", ["merchant", "platform", "provider"]),
     EXIT_PROBLEMS),
    ("B29 currency is converted implicitly", REL,
     lambda d: d["currency"].__setitem__("implicit_conversion_allowed", True), EXIT_PROBLEMS),
    ("B29 conversion no longer needs a rate record", REL,
     lambda d: d["currency"].__setitem__("conversion_requires_rate_record", False),
     EXIT_PROBLEMS),
    ("B29 the meter stops being idempotent", REL,
     lambda d: d["metering"].__setitem__("idempotent", False), EXIT_PROBLEMS),
    ("B29 the meter cannot be recomputed", REL,
     lambda d: d["metering"].__setitem__("recomputable", False), EXIT_PROBLEMS),
    ("B29 fee events are recorded as configuration changes", REL,
     lambda d: d.__setitem__("audit_event_class", "config.change"), EXIT_PROBLEMS),
]

TEXT_SCENARIOS = [
    ("B29 fee document hand-edited",
     "docs/pricing/FEE_MODEL.md", "账面模型不是资金事实", "账面模型就是资金事实", EXIT_PROBLEMS),
]
