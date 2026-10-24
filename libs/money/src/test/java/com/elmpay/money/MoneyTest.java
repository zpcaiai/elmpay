package com.elmpay.money;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
}
