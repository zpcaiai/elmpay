"""B29 — an executable fee calculator that never pretends to be settlement.

Two methods carry the batch.

:meth:`Pricer.quote` computes what we *expect* to be charged, entirely in
integer minor units, with the rounding rule taken from the model rather than
from whatever the language does. Its result is a :class:`Quote` marked
``ESTIMATED``.

:meth:`Pricer.settle` takes the provider's settlement report and — this is the
point — does **not** write it over the estimate. It records both and returns a
:class:`Break` when they differ. Overwriting would be one line shorter and would
destroy the only record of what we believed we were charging, which is the
entire content of a fee dispute.

Everything is integers. Anything non-integral is refused outright rather than
rounded into shape, because a fee model that quietly accepts binary
floating-point will eventually produce two different answers for the same
payment. (The repository's money scanner flagged an earlier wording of this very
paragraph, which is a fair reminder that the rule is about the words the code
uses as well as the values it holds.)
"""
from __future__ import annotations

from dataclasses import dataclass, field

ESTIMATED = "estimated"
SETTLED = "settled"
DISPUTED = "disputed"

AMOUNT_NOT_INTEGER = "AMOUNT_NOT_INTEGER"
AMOUNT_NEGATIVE = "AMOUNT_NEGATIVE"
CURRENCY_MISMATCH = "CURRENCY_MISMATCH"
NO_SCHEDULE = "NO_SCHEDULE"
UNKNOWN_ROUNDING = "UNKNOWN_ROUNDING"
IMPLICIT_CONVERSION = "IMPLICIT_CONVERSION"
INCOMPLETE_RATE_RECORD = "INCOMPLETE_RATE_RECORD"
SPLIT_UNBALANCED = "SPLIT_UNBALANCED"
ALREADY_SETTLED = "ALREADY_SETTLED"
SETTLEMENT_OVERDUE = "SETTLEMENT_OVERDUE"
DUPLICATE_METER_EVENT = "DUPLICATE_METER_EVENT"
TAX_IN_REVENUE = "TAX_IN_REVENUE"


class PricingRefused(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class Payment:
    id: str
    provider: str
    method: str
    region: str
    currency: str
    amount_minor: int
    day: int


@dataclass(frozen=True)
class Component:
    schedule_id: str
    category: str
    amount_minor: int


@dataclass
class Quote:
    payment_id: str
    currency: str
    amount_minor: int
    components: tuple[Component, ...]
    status: str = ESTIMATED
    settled_total_minor: int | None = None

    @property
    def total_minor(self) -> int:
        return sum(c.amount_minor for c in self.components)

    def by_category(self, category: str) -> int:
        return sum(c.amount_minor for c in self.components if c.category == category)


@dataclass(frozen=True)
class Break:
    payment_id: str
    book_minor: int
    settled_minor: int

    @property
    def difference_minor(self) -> int:
        return self.settled_minor - self.book_minor


@dataclass(frozen=True)
class Rate:
    rate_bp: int
    quoted_at: int
    source: str


@dataclass
class Meter:
    events: dict[str, Quote] = field(default_factory=dict)
    duplicates: int = 0


def require_minor(amount: object, label: str = "amount") -> int:
    """Integer minor units or nothing. Never silently coerced."""
    if isinstance(amount, bool) or not isinstance(amount, int):
        raise PricingRefused(AMOUNT_NOT_INTEGER, f"{label}={amount!r}")
    if amount < 0:
        raise PricingRefused(AMOUNT_NEGATIVE, f"{label}={amount}")
    return amount


class Pricer:
    def __init__(self, model: dict) -> None:
        self.model = model
        self.categories = {c["id"]: c for c in model["categories"]}
        self.rounding = model["rounding"]
        self.schedules = model["schedules"]
        self.settlement_policy = model["settlement"]
        self.split_policy = model["split"]
        self.currency_policy = model["currency"]
        self.metering_policy = model["metering"]
        self.meter = Meter()
        self.breaks: list[Break] = []

    # -- arithmetic --------------------------------------------------------
    def apply_percentage(self, amount_minor: int, basis_points: int) -> int:
        """Integer percentage with the declared rounding. No floats anywhere."""
        require_minor(amount_minor)
        product = amount_minor * basis_points
        mode = self.rounding["mode"]
        if mode == "half_up":
            return (product + 5000) // 10000
        if mode == "down":
            return product // 10000
        if mode == "half_even":
            quotient, remainder = divmod(product, 10000)
            if remainder > 5000 or (remainder == 5000 and quotient % 2 == 1):
                quotient += 1
            return quotient
        raise PricingRefused(UNKNOWN_ROUNDING, mode)

    # -- quoting -----------------------------------------------------------
    def matching(self, payment: Payment) -> list[dict]:
        return [s for s in self.schedules
                if s["provider"] == payment.provider and s["method"] == payment.method
                and s["region"] == payment.region and s["currency"] == payment.currency]

    def component(self, schedule: dict, basis_minor: int) -> Component:
        amount = self.apply_percentage(basis_minor, int(schedule["percentage_bp"]))
        amount += int(schedule["fixed_minor"])
        minimum = int(schedule["min_minor"])
        maximum = int(schedule["max_minor"])
        if minimum:
            amount = max(amount, minimum)
        if maximum:
            amount = min(amount, maximum)
        return Component(schedule_id=schedule["id"], category=schedule["category"],
                         amount_minor=amount)

    def quote(self, payment: Payment) -> Quote:
        require_minor(payment.amount_minor, "payment.amount_minor")
        schedules = self.matching(payment)
        if not schedules:
            raise PricingRefused(NO_SCHEDULE,
                                 f"{payment.provider}/{payment.method}/{payment.region}/"
                                 f"{payment.currency}")
        ordered = sorted(schedules, key=lambda s: s["id"])
        # Two passes, because a tax is levied on the service fee rather than on
        # the payment. Computing it in one pass would apply the VAT rate to the
        # whole payment and overstate what we owe an authority by two orders of
        # magnitude.
        first = [self.component(s, payment.amount_minor)
                 for s in ordered if s["basis"] == "payment"]
        service_fee = sum(c.amount_minor for c in first
                          if c.category == "platform_service_fee")
        second = [self.component(s, service_fee)
                  for s in ordered if s["basis"] == "platform_service_fee"]
        components = tuple(sorted(first + second, key=lambda c: c.schedule_id))
        return Quote(payment_id=payment.id, currency=payment.currency,
                     amount_minor=payment.amount_minor, components=components)

    # -- what belongs to whom ---------------------------------------------
    def revenue(self, quote: Quote) -> int:
        total = 0
        for component in quote.components:
            category = self.categories[component.category]
            if category["is_revenue"]:
                if category.get("remitted_to_authority"):
                    # Belt and braces: tax must never reach a revenue total.
                    raise PricingRefused(TAX_IN_REVENUE, component.category)
                total += component.amount_minor
        return total

    def charged_to_merchant(self, quote: Quote) -> int:
        return sum(c.amount_minor for c in quote.components
                   if self.categories[c.category]["charged_to_merchant"])

    def remitted(self, quote: Quote) -> int:
        return sum(c.amount_minor for c in quote.components
                   if self.categories[c.category]["remitted_to_authority"])

    def split(self, quote: Quote) -> dict[str, int]:
        """Every minor unit of the payment lands somewhere, exactly once."""
        provider = quote.by_category("provider_cost")
        platform = quote.by_category("platform_service_fee")
        authority = quote.by_category("tax")
        merchant = quote.amount_minor - provider - platform - authority
        parts = {"merchant": merchant, "platform": platform, "provider": provider,
                 "authority": authority}
        residue = quote.amount_minor - sum(parts.values())
        if residue:
            owner = self.split_policy["residue_to"]
            parts[owner] += residue
        if sum(parts.values()) != quote.amount_minor:
            raise PricingRefused(SPLIT_UNBALANCED, str(sum(parts.values())))
        return parts

    # -- currency ----------------------------------------------------------
    def convert(self, amount_minor: int, *, from_currency: str, to_currency: str,
                rate: Rate | None) -> int:
        require_minor(amount_minor)
        if from_currency == to_currency:
            return amount_minor
        if not self.currency_policy["conversion_requires_rate_record"]:
            raise PricingRefused(IMPLICIT_CONVERSION, f"{from_currency}->{to_currency}")
        if rate is None:
            raise PricingRefused(IMPLICIT_CONVERSION, f"{from_currency}->{to_currency}")
        for name in self.currency_policy["rate_record_fields"]:
            attribute = {"rate": "rate_bp", "quoted_at": "quoted_at", "source": "source"}[name]
            value = getattr(rate, attribute, None)
            if value in (None, "", 0):
                raise PricingRefused(INCOMPLETE_RATE_RECORD, name)
        return self.apply_percentage(amount_minor, rate.rate_bp)

    def require_same_currency(self, quote: Quote, payment: Payment) -> str:
        if quote.currency != payment.currency:
            raise PricingRefused(CURRENCY_MISMATCH, f"{quote.currency}/{payment.currency}")
        return "OK"

    # -- settlement --------------------------------------------------------
    def settle(self, quote: Quote, settled_total_minor: int, *, day: int,
               payment_day: int) -> Break | None:
        """Record what actually happened. Never overwrite what we expected."""
        require_minor(settled_total_minor, "settled_total_minor")
        if quote.status != ESTIMATED:
            # A disputed quote may not be settled again either: a second write
            # would replace the settled figure we already recorded, which is
            # the same erasure this method exists to prevent.
            raise PricingRefused(ALREADY_SETTLED, f"{quote.payment_id}:{quote.status}")
        if day - payment_day > int(self.settlement_policy["max_settle_lag_days"]):
            raise PricingRefused(SETTLEMENT_OVERDUE, str(day - payment_day))
        quote.settled_total_minor = settled_total_minor
        difference = settled_total_minor - quote.total_minor
        if abs(difference) > int(self.settlement_policy["tolerance_minor"]):
            quote.status = DISPUTED
            item = Break(payment_id=quote.payment_id, book_minor=quote.total_minor,
                         settled_minor=settled_total_minor)
            self.breaks.append(item)
            return item
        quote.status = SETTLED
        return None

    def book_value(self, quote: Quote) -> int:
        """Still the estimate, even after a disagreeing settlement arrived."""
        return quote.total_minor

    # -- metering ----------------------------------------------------------
    def record(self, quote: Quote) -> str:
        key = quote.payment_id
        if key in self.meter.events:
            self.meter.duplicates += 1
            return "DUPLICATE"
        self.meter.events[key] = quote
        return "RECORDED"

    def recompute(self, payments: list[Payment]) -> int:
        """Derive the period total again from the raw payments."""
        return sum(self.quote(p).total_minor for p in payments)

    def metered_total(self) -> int:
        return sum(q.total_minor for q in self.meter.events.values())
