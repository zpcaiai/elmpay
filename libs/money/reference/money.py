"""Money: integer minor units, explicit currency, explicit rounding.

Design rules, each of which exists because its absence has caused real losses
in payment systems:

* an amount is an ``int`` count of minor units plus an ISO-4217 code — never a
  float, never a bare number (NN-05);
* arithmetic between different currencies raises, it does not coerce;
* every operation that cannot be exact takes an explicit rounding mode, and the
  default is banker's rounding (half-even), which does not drift upward over
  large populations;
* splitting money uses largest-remainder allocation, so the parts always sum
  back to the whole — no cent is created or lost;
* foreign exchange takes an integer rate scaled by a declared power of ten, so
  a rate is auditable and reproducible.

Standard library only.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

CURRENCY_CODE = re.compile(r"^[A-Z]{3}$")
ROUNDING_MODES = ("half_even", "half_up", "down", "up")
DEFAULT_METADATA = Path("governance/currency-metadata.json")


class MoneyError(ValueError):
    """Raised for any operation the money model refuses to guess about."""


class CurrencyMismatch(MoneyError):
    pass


@dataclass(frozen=True)
class Currency:
    code: str
    numeric: str
    minor_unit_exponent: int
    rounding: str
    cash_rounding_minor: int | None = None

    @property
    def minor_units_per_unit(self) -> int:
        return 10 ** self.minor_unit_exponent


class CurrencyRegistry:
    """Currency metadata loaded from the version-controlled source of truth."""

    def __init__(self, currencies: Iterable[Currency]) -> None:
        self._by_code = {c.code: c for c in currencies}
        if not self._by_code:
            raise MoneyError("currency registry is empty")

    @classmethod
    def from_file(cls, path: Path) -> "CurrencyRegistry":
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(Currency(code=c["code"], numeric=c["numeric"],
                            minor_unit_exponent=c["minor_unit_exponent"],
                            rounding=c["rounding"],
                            cash_rounding_minor=c.get("cash_rounding_minor"))
                   for c in doc["currencies"])

    def get(self, code: str) -> Currency:
        try:
            return self._by_code[code]
        except KeyError:
            raise MoneyError(
                f"unknown currency '{code}'; currencies come from the versioned metadata, "
                f"never from user input") from None

    def codes(self) -> list[str]:
        return sorted(self._by_code)


def divide_round(numerator: int, denominator: int, mode: str = "half_even") -> int:
    """Integer division with an explicit rounding mode. No floats involved."""
    if denominator == 0:
        raise MoneyError("division by zero")
    if mode not in ROUNDING_MODES:
        raise MoneyError(f"unknown rounding mode '{mode}'")
    negative = (numerator < 0) != (denominator < 0)
    n, d = abs(numerator), abs(denominator)
    quotient, remainder = divmod(n, d)
    if remainder:
        if mode == "up":
            quotient += 1
        elif mode == "down":
            pass
        elif mode == "half_up":
            if remainder * 2 >= d:
                quotient += 1
        else:  # half_even
            twice = remainder * 2
            if twice > d or (twice == d and quotient % 2 == 1):
                quotient += 1
    return -quotient if negative else quotient


@dataclass(frozen=True)
class Money:
    minor: int
    currency: str

    def __post_init__(self) -> None:
        if not isinstance(self.minor, int) or isinstance(self.minor, bool):
            raise MoneyError("amount must be an integer count of minor units (NN-05)")
        if not CURRENCY_CODE.match(self.currency):
            raise MoneyError(f"'{self.currency}' is not an ISO-4217 alphabetic code")

    # --- construction ---------------------------------------------------
    @classmethod
    def parse(cls, text: str, currency: str, registry: CurrencyRegistry) -> "Money":
        """Parse a decimal string exactly. Rejects anything it cannot represent."""
        meta = registry.get(currency)
        candidate = text.strip()
        if not re.fullmatch(r"-?\d+(\.\d+)?", candidate):
            raise MoneyError(f"'{text}' is not a plain decimal amount")
        negative = candidate.startswith("-")
        candidate = candidate.lstrip("-")
        whole, _, fraction = candidate.partition(".")
        if len(fraction) > meta.minor_unit_exponent:
            raise MoneyError(
                f"{currency} has {meta.minor_unit_exponent} minor digits; '{text}' would need "
                f"{len(fraction)} and cannot be represented exactly")
        fraction = fraction.ljust(meta.minor_unit_exponent, "0")
        minor = int(whole) * meta.minor_units_per_unit + (int(fraction) if fraction else 0)
        return cls(-minor if negative else minor, currency)

    def format(self, registry: CurrencyRegistry) -> str:
        meta = registry.get(self.currency)
        sign = "-" if self.minor < 0 else ""
        whole, fraction = divmod(abs(self.minor), meta.minor_units_per_unit)
        if meta.minor_unit_exponent == 0:
            return f"{sign}{whole}"
        return f"{sign}{whole}.{str(fraction).rjust(meta.minor_unit_exponent, '0')}"

    # --- arithmetic -----------------------------------------------------
    def _same(self, other: "Money") -> None:
        if self.currency != other.currency:
            raise CurrencyMismatch(
                f"cannot combine {self.currency} with {other.currency}; there is no implicit "
                f"conversion in the money model")

    def add(self, other: "Money") -> "Money":
        self._same(other)
        return Money(self.minor + other.minor, self.currency)

    def subtract(self, other: "Money") -> "Money":
        self._same(other)
        return Money(self.minor - other.minor, self.currency)

    def negate(self) -> "Money":
        return Money(-self.minor, self.currency)

    def multiply(self, factor: int) -> "Money":
        if not isinstance(factor, int) or isinstance(factor, bool):
            raise MoneyError("multiplying money by a non-integer requires an explicit rate")
        return Money(self.minor * factor, self.currency)

    def apply_rate(self, numerator: int, denominator: int, mode: str = "half_even") -> "Money":
        """Apply an exact rational rate (e.g. a fee of 29/1000) with explicit rounding."""
        return Money(divide_round(self.minor * numerator, denominator, mode), self.currency)

    def is_zero(self) -> bool:
        return self.minor == 0

    def compare(self, other: "Money") -> int:
        self._same(other)
        return (self.minor > other.minor) - (self.minor < other.minor)

    # --- splitting ------------------------------------------------------
    def allocate(self, weights: list[int]) -> list["Money"]:
        """Split by integer weights so the parts sum back to the whole exactly.

        Largest-remainder method: the unavoidable remainder is handed out one
        minor unit at a time to the largest fractional parts, so no minor unit
        is created or destroyed.
        """
        if not weights or any(w < 0 for w in weights) or sum(weights) == 0:
            raise MoneyError("allocation weights must be non-negative and not all zero")
        total_weight = sum(weights)
        sign = -1 if self.minor < 0 else 1
        amount = abs(self.minor)
        shares = [amount * w // total_weight for w in weights]
        remainder = amount - sum(shares)
        order = sorted(range(len(weights)),
                       key=lambda i: (-(amount * weights[i] % total_weight), i))
        for index in order[:remainder]:
            shares[index] += 1
        return [Money(sign * s, self.currency) for s in shares]

    def split(self, parts: int) -> list["Money"]:
        if parts <= 0:
            raise MoneyError("cannot split into fewer than one part")
        return self.allocate([1] * parts)

    # --- foreign exchange ------------------------------------------------
    def convert(self, target: str, rate_numerator: int, rate_scale: int,
                registry: CurrencyRegistry, mode: str = "half_even") -> "Money":
        """Convert using an integer rate scaled by ``10 ** rate_scale``.

        The exponent difference between the two currencies is applied in the
        same integer expression, so a JPY→KWD conversion does not silently lose
        or invent three decimal places.
        """
        if rate_numerator < 0 or rate_scale < 0:
            raise MoneyError("exchange rates are non-negative and integer-scaled")
        source = registry.get(self.currency)
        destination = registry.get(target)
        numerator = (self.minor * rate_numerator
                     * 10 ** destination.minor_unit_exponent)
        denominator = 10 ** (rate_scale + source.minor_unit_exponent)
        return Money(divide_round(numerator, denominator, mode), target)


def total(amounts: Iterable[Money]) -> Money:
    items = list(amounts)
    if not items:
        raise MoneyError("cannot total an empty collection without a declared currency")
    result = items[0]
    for item in items[1:]:
        result = result.add(item)
    return result
