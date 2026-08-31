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

    @Test
    void acceptsUnicodeScalarPairsAndRejectsUnpairedSurrogates() {
        assertEquals("\uD83D\uDE03", Json.object("{\"value\":\"\\uD83D\\uDE03\"}").get("value"));
        assertThrows(IllegalArgumentException.class,
                () -> Json.parse("{\"value\":\"\\uD83D\"}"));
        assertThrows(IllegalArgumentException.class,
                () -> Json.parse("{\"value\":\"\\uDE03\"}"));
        assertThrows(IllegalArgumentException.class,
                () -> Json.stringify(Map.of("value", "\uD83D")));
        assertThrows(IllegalArgumentException.class,
                () -> Json.parse("{\"value\":1}\u2003"));
    }
}
