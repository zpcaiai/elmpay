package com.elmpay.provider;

import static org.junit.jupiter.api.Assertions.assertThrows;

import com.elmpay.money.Money;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class ProviderContractsTest {
    @Test
    void unknownCanNeverBeMarkedFinal() {
        assertThrows(IllegalArgumentException.class,
                () -> new ProviderPayment("req", "pay", ProviderOutcome.UNKNOWN,
                        Money.of(1, "CNY"), Money.of(0, "CNY"), true, Map.of()));
    }
}
