package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import org.junit.jupiter.api.Test;

final class JsonTest {
    @Test
    void roundTripsIntegerObjectsWithoutFloatingPoint() {
        Map<String, Object> value = Json.object("{\"amount_minor\":123,\"currency\":\"USD\"}");
        assertEquals(123L, value.get("amount_minor"));
        assertEquals("{\"amount_minor\":123,\"currency\":\"USD\"}", Json.stringify(value));
    }

    @Test
    void rejectsDuplicateKeysAndDecimalMoney() {
        assertThrows(IllegalArgumentException.class, () -> Json.parse("{\"a\":1,\"a\":2}"));
        assertThrows(IllegalArgumentException.class, () -> Json.parse("{\"amount\":1.5}"));
    }
}
