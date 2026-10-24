package com.elmpay.money;

import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Non-negative money in integer minor units. */
public record Money(long amountMinor, CurrencyUnit currency) implements Comparable<Money> {
    public Money {
        Objects.requireNonNull(currency, "currency");
        if (amountMinor < 0) {
            throw new IllegalArgumentException("money cannot be negative");
        }
    }

    public static Money of(long amountMinor, String currency) {
        return new Money(amountMinor, CurrencyCatalog.require(currency));
    }

    public Money add(Money other) {
        requireSameCurrency(other);
        return new Money(Math.addExact(amountMinor, other.amountMinor), currency);
    }

    public Money subtract(Money other) {
        requireSameCurrency(other);
        if (other.amountMinor > amountMinor) {
            throw new IllegalArgumentException("money result would be negative");
        }
        return new Money(amountMinor - other.amountMinor, currency);
    }

    public Money multiplyRatio(long numerator, long denominator, RoundingMode roundingMode) {
        if (numerator < 0 || denominator <= 0) {
            throw new IllegalArgumentException("ratio must be non-negative with a positive denominator");
        }
        Objects.requireNonNull(roundingMode, "roundingMode");
        BigInteger product = BigInteger.valueOf(amountMinor).multiply(BigInteger.valueOf(numerator));
        BigInteger[] divided = product.divideAndRemainder(BigInteger.valueOf(denominator));
        BigInteger rounded = divided[0];
        if (divided[1].signum() != 0) {
            rounded = applyPositiveRounding(rounded, divided[1], BigInteger.valueOf(denominator), roundingMode);
        }
        return new Money(rounded.longValueExact(), currency);
    }

    public List<Money> allocate(List<Long> weights) {
        Objects.requireNonNull(weights, "weights");
        if (weights.isEmpty() || weights.stream().anyMatch(weight -> weight == null || weight <= 0)) {
            throw new IllegalArgumentException("allocation weights must be positive");
        }
        long totalWeight = weights.stream().reduce(0L, Math::addExact);
        List<Money> result = new ArrayList<>(weights.size());
        long allocated = 0;
        for (long weight : weights) {
            long share = BigInteger.valueOf(amountMinor).multiply(BigInteger.valueOf(weight))
                    .divide(BigInteger.valueOf(totalWeight)).longValueExact();
            result.add(new Money(share, currency));
            allocated = Math.addExact(allocated, share);
        }
        // Each division drops less than one unit, so the remainder is smaller
        // than the number of recipients. Check the index-width conversion.
        int remainder = Math.toIntExact(amountMinor - allocated);
        for (int index = 0; index < remainder; index++) {
            Money current = result.get(index % result.size());
            result.set(index % result.size(), new Money(current.amountMinor + 1, currency));
        }
        return List.copyOf(result);
    }

    @Override
    public int compareTo(Money other) {
        requireSameCurrency(other);
        return Long.compare(amountMinor, other.amountMinor);
    }

    private void requireSameCurrency(Money other) {
        Objects.requireNonNull(other, "other");
        if (!currency.code().equals(other.currency.code())
                || !currency.metadataVersion().equals(other.currency.metadataVersion())) {
            throw new IllegalArgumentException("currency metadata mismatch");
        }
    }

    private static BigInteger applyPositiveRounding(BigInteger quotient, BigInteger remainder,
            BigInteger denominator, RoundingMode mode) {
        return switch (mode) {
            case DOWN, FLOOR -> quotient;
            case UP, CEILING -> quotient.add(BigInteger.ONE);
            case HALF_UP -> remainder.shiftLeft(1).compareTo(denominator) >= 0
                    ? quotient.add(BigInteger.ONE) : quotient;
            case HALF_DOWN -> remainder.shiftLeft(1).compareTo(denominator) > 0
                    ? quotient.add(BigInteger.ONE) : quotient;
            case HALF_EVEN -> {
                int comparison = remainder.shiftLeft(1).compareTo(denominator);
                yield comparison > 0 || (comparison == 0 && quotient.testBit(0))
                        ? quotient.add(BigInteger.ONE) : quotient;
            }
            case UNNECESSARY -> throw new ArithmeticException("rounding required");
        };
    }
}
