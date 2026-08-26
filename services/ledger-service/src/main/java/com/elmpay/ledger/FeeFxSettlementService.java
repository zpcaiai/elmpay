package com.elmpay.ledger;

import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/** Exact fee, tax, FX and provider-direct settlement calculations. */
public final class FeeFxSettlementService {
    public enum Rounding { HALF_EVEN, DOWN, UP }
    public record FeeRule(long fixedMinor, long rateNumerator, long rateDenominator,
                          long taxNumerator, long taxDenominator, Rounding rounding, String version) {}
    public record FeeBreakdown(long grossMinor, long fixedMinor, long variableMinor, long taxMinor,
                               long totalFeeMinor, long netMinor, String currency, String ruleVersion) {}
    public record FxRate(String source, String baseCurrency, String quoteCurrency,
                         long numerator, long denominator, Instant observedAt, String version) {}
    public record Conversion(long sourceMinor, String sourceCurrency, long targetMinor,
                             String targetCurrency, FxRate rate, long roundingRemainderNumerator) {}
    public record SettlementView(String tenantId, String providerBatchId, String currency,
                                 long grossMinor, long feeMinor, long expectedBankMinor,
                                 Instant expectedArrival, String providerStatus) {}

    public FeeBreakdown quote(long grossMinor, String currency, FeeRule rule) {
        if (grossMinor < 0 || rule.fixedMinor() < 0 || rule.rateNumerator() < 0 || rule.rateDenominator() <= 0
                || rule.taxNumerator() < 0 || rule.taxDenominator() <= 0) throw new IllegalArgumentException("invalid fee inputs");
        long variable = ratio(grossMinor, rule.rateNumerator(), rule.rateDenominator(), rule.rounding());
        long feeBeforeTax = Math.addExact(rule.fixedMinor(), variable);
        long tax = ratio(feeBeforeTax, rule.taxNumerator(), rule.taxDenominator(), rule.rounding());
        long total = Math.addExact(feeBeforeTax, tax);
        if (total > grossMinor) throw new IllegalArgumentException("fees exceed gross amount");
        return new FeeBreakdown(grossMinor, rule.fixedMinor(), variable, tax, total,
                grossMinor - total, currency, rule.version());
    }

    public Conversion convert(long amountMinor, FxRate rate, Rounding rounding) {
        if (amountMinor < 0 || rate.numerator() <= 0 || rate.denominator() <= 0) throw new IllegalArgumentException("invalid FX inputs");
        BigInteger product = BigInteger.valueOf(amountMinor).multiply(BigInteger.valueOf(rate.numerator()));
        BigInteger denominator = BigInteger.valueOf(rate.denominator());
        long converted = divide(product, denominator, rounding).longValueExact();
        long remainder = product.subtract(BigInteger.valueOf(converted).multiply(denominator)).longValueExact();
        return new Conversion(amountMinor, rate.baseCurrency(), converted, rate.quoteCurrency(), rate, remainder);
    }

    public SettlementView settlement(String tenantId, String providerBatchId, FeeBreakdown breakdown,
                                     Instant expectedArrival, String providerStatus) {
        Objects.requireNonNull(expectedArrival); Objects.requireNonNull(providerStatus);
        return new SettlementView(tenantId, providerBatchId, breakdown.currency(), breakdown.grossMinor(),
                breakdown.totalFeeMinor(), breakdown.netMinor(), expectedArrival, providerStatus);
    }

    public void assertSettlementsTie(List<SettlementView> views, long ledgerNetMinor, String currency) {
        long total = views.stream().filter(view -> view.currency().equals(currency))
                .mapToLong(SettlementView::expectedBankMinor).reduce(0L, Math::addExact);
        if (total != ledgerNetMinor) throw new IllegalStateException("settlement view does not tie to ledger");
    }

    static long ratio(long amount, long numerator, long denominator, Rounding rounding) {
        return divide(BigInteger.valueOf(amount).multiply(BigInteger.valueOf(numerator)),
                BigInteger.valueOf(denominator), rounding).longValueExact();
    }
    private static BigInteger divide(BigInteger value, BigInteger denominator, Rounding rounding) {
        BigInteger[] qr = value.divideAndRemainder(denominator);
        if (qr[1].signum() == 0) return qr[0];
        return switch (rounding) {
            case DOWN -> qr[0];
            case UP -> qr[0].add(BigInteger.ONE);
            case HALF_EVEN -> {
                int comparison = qr[1].multiply(BigInteger.TWO).compareTo(denominator);
                yield comparison > 0 || (comparison == 0 && qr[0].testBit(0)) ? qr[0].add(BigInteger.ONE) : qr[0];
            }
        };
    }
}
