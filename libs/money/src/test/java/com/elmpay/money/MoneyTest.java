package com.elmpay.money;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.RoundingMode;
import java.util.List;
import org.junit.jupiter.api.Test;

final class MoneyTest {
    @Test
    void rejectsNegativeAndCrossCurrencyArithmetic() {
        assertThrows(IllegalArgumentException.class, () -> Money.of(-1, "CNY"));
        assertThrows(IllegalArgumentException.class, () -> Money.of(1, "CNY").add(Money.of(1, "USD")));
    }

    @Test
    void roundsRatiosWithoutFloatingPoint() {
        assertEquals(33, Money.of(100, "CNY").multiplyRatio(1, 3, RoundingMode.HALF_UP).amountMinor());
        assertEquals(34, Money.of(101, "CNY").multiplyRatio(1, 3, RoundingMode.HALF_UP).amountMinor());
        assertEquals(2, Money.of(3, "CNY").multiplyRatio(1, 2, RoundingMode.HALF_EVEN).amountMinor());
    }

    @Test
    void allocationConservesEveryMinorUnit() {
        List<Money> parts = Money.of(101, "CNY").allocate(List.of(1L, 1L, 1L));
        assertEquals(101, parts.stream().mapToLong(Money::amountMinor).sum());
        assertEquals(List.of(34L, 34L, 33L), parts.stream().map(Money::amountMinor).toList());
    }

    @Test
    void allocationBoundsRemainderEvenForMaximumAmount() {
        List<Money> parts = Money.of(Long.MAX_VALUE, "CNY").allocate(List.of(1L, 1L, 1L));
        assertEquals(Long.MAX_VALUE, parts.stream().mapToLong(Money::amountMinor).sum());
        assertEquals(List.of(3_074_457_345_618_258_603L, 3_074_457_345_618_258_602L,
                3_074_457_345_618_258_602L), parts.stream().map(Money::amountMinor).toList());
    }

    @Test
    void exactArithmeticComparisonAndOverflowPreserveMinorUnits() {
        Money ten = Money.of(10, "CNY");
        assertEquals(30L, ten.add(Money.of(20, "CNY")).amountMinor());
        assertEquals(5L, ten.subtract(Money.of(5, "CNY")).amountMinor());
        assertEquals(0L, ten.subtract(ten).amountMinor());
        assertEquals(-1, ten.compareTo(Money.of(11, "CNY")));
        assertEquals(1, ten.compareTo(Money.of(9, "CNY")));
        assertEquals(0, ten.compareTo(Money.of(10, "cny")));
        assertThrows(IllegalArgumentException.class, () -> ten.subtract(Money.of(11, "CNY")));
        assertThrows(IllegalArgumentException.class, () -> ten.subtract(Money.of(1, "USD")));
        assertThrows(IllegalArgumentException.class, () -> ten.compareTo(Money.of(10, "USD")));
        assertThrows(ArithmeticException.class,
                () -> Money.of(Long.MAX_VALUE, "CNY").add(Money.of(1, "CNY")));
        assertThrows(NullPointerException.class, () -> ten.add(null));
        assertThrows(NullPointerException.class, () -> ten.subtract(null));
        assertThrows(NullPointerException.class, () -> ten.compareTo(null));
        assertThrows(NullPointerException.class, () -> new Money(1, null));
    }

    @Test
    void currencyIdentityIncludesBothMetadataVersionAndMinorUnitScale() {
        Money canonical = Money.of(10, "CNY");
        Money equivalent = new Money(10, new CurrencyUnit("cny", 2, CurrencyCatalog.VERSION));
        assertEquals(20L, canonical.add(equivalent).amountMinor());
        assertEquals(0, canonical.compareTo(equivalent));
        for (CurrencyUnit different : List.of(
                new CurrencyUnit("CNY", 2, "other-metadata-version"),
                new CurrencyUnit("CNY", 3, CurrencyCatalog.VERSION))) {
            Money other = new Money(10, different);
            assertThrows(IllegalArgumentException.class, () -> canonical.add(other));
            assertThrows(IllegalArgumentException.class, () -> canonical.subtract(other));
            assertThrows(IllegalArgumentException.class, () -> canonical.compareTo(other));
        }
    }

    @Test
    void positiveRoundingModesFollowKnownFractionsAndTieParity() {
        for (RoundingMode mode : List.of(RoundingMode.DOWN, RoundingMode.FLOOR,
                RoundingMode.HALF_DOWN, RoundingMode.HALF_EVEN)) {
            assertEquals(0L, Money.of(1, "CNY").multiplyRatio(1, 2, mode).amountMinor());
        }
        for (RoundingMode mode : List.of(RoundingMode.UP, RoundingMode.CEILING, RoundingMode.HALF_UP)) {
            assertEquals(1L, Money.of(1, "CNY").multiplyRatio(1, 2, mode).amountMinor());
        }
        for (RoundingMode mode : List.of(RoundingMode.HALF_UP, RoundingMode.HALF_DOWN,
                RoundingMode.HALF_EVEN)) {
            assertEquals(2L, Money.of(7, "CNY").multiplyRatio(1, 3, mode).amountMinor());
            assertEquals(3L, Money.of(8, "CNY").multiplyRatio(1, 3, mode).amountMinor());
        }
        assertEquals(2L, Money.of(3, "CNY").multiplyRatio(1, 2, RoundingMode.HALF_EVEN).amountMinor());
        assertEquals(2L, Money.of(5, "CNY").multiplyRatio(1, 2, RoundingMode.HALF_EVEN).amountMinor());
        assertEquals(1L, Money.of(3, "CNY").multiplyRatio(1, 2, RoundingMode.HALF_DOWN).amountMinor());
        assertEquals(2L, Money.of(3, "CNY").multiplyRatio(1, 2, RoundingMode.HALF_UP).amountMinor());
        assertEquals(2L, Money.of(7, "CNY").multiplyRatio(1, 3, RoundingMode.FLOOR).amountMinor());
        assertEquals(3L, Money.of(7, "CNY").multiplyRatio(1, 3, RoundingMode.CEILING).amountMinor());
    }

    @Test
    void invalidRatiosAreDeniedAndLargeExactProductsDoNotUseFloatingPoint() {
        Money zero = Money.of(0, "CNY");
        assertThrows(IllegalArgumentException.class, () -> zero.multiplyRatio(-1, 1, RoundingMode.DOWN));
        assertThrows(IllegalArgumentException.class, () -> zero.multiplyRatio(1, -1, RoundingMode.DOWN));
        assertThrows(IllegalArgumentException.class, () -> zero.multiplyRatio(1, 0, RoundingMode.DOWN));
        assertThrows(NullPointerException.class, () -> Money.of(1, "CNY").multiplyRatio(1, 1, null));
        assertThrows(ArithmeticException.class,
                () -> Money.of(1, "CNY").multiplyRatio(1, 3, RoundingMode.UNNECESSARY));
        assertEquals(20L, Money.of(40, "CNY").multiplyRatio(1, 2, RoundingMode.UNNECESSARY).amountMinor());
        assertEquals(0L, Money.of(Long.MAX_VALUE, "CNY").multiplyRatio(0, 1,
                RoundingMode.UNNECESSARY).amountMinor());
        assertEquals(Long.MAX_VALUE, Money.of(Long.MAX_VALUE, "CNY").multiplyRatio(
                Long.MAX_VALUE, Long.MAX_VALUE, RoundingMode.UNNECESSARY).amountMinor());
        assertThrows(ArithmeticException.class, () -> Money.of(Long.MAX_VALUE, "CNY")
                .multiplyRatio(2, 1, RoundingMode.UNNECESSARY));
    }

    @Test
    void allocationRejectsInvalidWeightsAndKeepsImmutableExactShares() {
        Money zero = Money.of(0, "CNY");
        assertThrows(NullPointerException.class, () -> zero.allocate(null));
        assertThrows(IllegalArgumentException.class, () -> zero.allocate(List.of()));
        assertThrows(IllegalArgumentException.class, () -> zero.allocate(List.of(0L)));
        assertThrows(IllegalArgumentException.class, () -> zero.allocate(List.of(-1L)));
        assertThrows(IllegalArgumentException.class,
                () -> zero.allocate(java.util.Arrays.asList(1L, null)));
        assertThrows(ArithmeticException.class,
                () -> zero.allocate(List.of(Long.MAX_VALUE, 1L)));
        assertEquals(List.of(0L, 0L, 0L), zero.allocate(List.of(1L, 2L, 3L))
                .stream().map(Money::amountMinor).toList());
        assertEquals(List.of(1L, 0L, 0L), Money.of(1, "CNY").allocate(List.of(1L, 1L, 1L))
                .stream().map(Money::amountMinor).toList());
        List<Money> parts = Money.of(10, "CNY").allocate(List.of(1L, 2L, 1L));
        assertEquals(List.of(3L, 5L, 2L), parts.stream().map(Money::amountMinor).toList());
        assertEquals(10L, parts.stream().mapToLong(Money::amountMinor).sum());
        assertTrue(parts.stream().allMatch(value -> value.currency().equals(CurrencyCatalog.require("CNY"))));
        assertThrows(UnsupportedOperationException.class, () -> parts.add(Money.of(1, "CNY")));
        assertEquals(Long.MAX_VALUE, Money.of(Long.MAX_VALUE, "CNY").allocate(List.of(Long.MAX_VALUE))
                .getFirst().amountMinor());
    }

    @Test
    void controlledCurrencyMetadataIsNormalizedAndValidated() {
        assertTrue(CurrencyCatalog.isEnabled("cny"));
        assertFalse(CurrencyCatalog.isEnabled(null));
        assertFalse(CurrencyCatalog.isEnabled("ZZZ"));
        assertEquals(0, CurrencyCatalog.require("JPY").fractionDigits());
        assertEquals(2, CurrencyCatalog.require("CNY").fractionDigits());
        assertThrows(NullPointerException.class, () -> CurrencyCatalog.require(null));
        assertThrows(IllegalArgumentException.class, () -> CurrencyCatalog.require("ZZZ"));
        assertThrows(NullPointerException.class, () -> new CurrencyUnit(null, 2, "version"));
        assertThrows(NullPointerException.class, () -> new CurrencyUnit("CNY", 2, null));
        assertThrows(IllegalArgumentException.class, () -> new CurrencyUnit("CN", 2, "version"));
        assertThrows(IllegalArgumentException.class, () -> new CurrencyUnit("CN1", 2, "version"));
        assertThrows(IllegalArgumentException.class, () -> new CurrencyUnit("CNY", -1, "version"));
        assertThrows(IllegalArgumentException.class, () -> new CurrencyUnit("CNY", 5, "version"));
        assertThrows(IllegalArgumentException.class, () -> new CurrencyUnit("CNY", 2, " "));
    }
}
