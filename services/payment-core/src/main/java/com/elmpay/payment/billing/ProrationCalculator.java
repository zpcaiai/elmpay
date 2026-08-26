package com.elmpay.payment.billing;

import java.math.BigInteger;

/** Exact, half-even proration producing an explainable credit/debit adjustment. */
public final class ProrationCalculator {
    public record Adjustment(long oldUnusedCreditMinor, long newRemainingChargeMinor, long netDebitMinor,
                             long remainingSeconds, long periodSeconds) {}

    public Adjustment calculate(long oldPriceMinor, long newPriceMinor, long remainingSeconds, long periodSeconds) {
        if (oldPriceMinor < 0 || newPriceMinor < 0 || periodSeconds <= 0
                || remainingSeconds < 0 || remainingSeconds > periodSeconds) throw new IllegalArgumentException("invalid proration inputs");
        long credit = roundedRatio(oldPriceMinor, remainingSeconds, periodSeconds);
        long charge = roundedRatio(newPriceMinor, remainingSeconds, periodSeconds);
        return new Adjustment(credit, charge, Math.subtractExact(charge, credit), remainingSeconds, periodSeconds);
    }

    static long roundedRatio(long amount, long numerator, long denominator) {
        BigInteger product = BigInteger.valueOf(amount).multiply(BigInteger.valueOf(numerator));
        BigInteger[] qr = product.divideAndRemainder(BigInteger.valueOf(denominator));
        BigInteger twice = qr[1].abs().multiply(BigInteger.TWO);
        int comparison = twice.compareTo(BigInteger.valueOf(denominator).abs());
        boolean increment = comparison > 0 || (comparison == 0 && qr[0].testBit(0));
        BigInteger rounded = increment ? qr[0].add(BigInteger.ONE) : qr[0];
        return rounded.longValueExact();
    }
}
