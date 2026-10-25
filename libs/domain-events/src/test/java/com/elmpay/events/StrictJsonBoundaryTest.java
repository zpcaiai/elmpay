package com.elmpay.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class StrictJsonBoundaryTest {
    @Test
    void arraysPreserveNullAtEveryPositionAndRemainImmutable() {
        List<?> values = (List<?>) StrictJson.parse("[null,1,null,[null],{\"n\":null},null]");
        assertEquals(6, values.size());
        assertNull(values.get(0));
        assertEquals(1L, values.get(1));
        assertNull(values.get(2));
        assertEquals(Arrays.asList((Object) null), values.get(3));
        assertNull(((Map<?, ?>) values.get(4)).get("n"));
        assertNull(values.get(5));
        assertThrows(UnsupportedOperationException.class, values::clear);
        assertThrows(UnsupportedOperationException.class, ((List<?>) values.get(3))::clear);
        assertEquals("[null,1,null,[null],{\"n\":null},null]", StrictJson.canonical(values));
    }

    @Test
    void canonicalObjectsSortKeysWithoutLosingNullOrIntegerIdentity() {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("z", Arrays.asList(true, false, null, (byte) 1, (short) 2, 3, 4L));
        value.put("a", null);
        String encoded = "{\"a\":null,\"z\":[true,false,null,1,2,3,4]}";
        assertEquals(encoded, StrictJson.canonical(value));
        assertEquals(encoded, StrictJson.canonical(StrictJson.parse(encoded)));
        assertEquals("{}", StrictJson.canonical(Map.of()));
        assertEquals("[]", StrictJson.canonical(List.of()));
        UUID id = UUID.fromString("8a9a6a21-249a-4717-8f6f-09d89e6e836e");
        assertEquals("[\"8a9a6a21-249a-4717-8f6f-09d89e6e836e\",\"2026-01-01T00:00:00Z\"]",
                StrictJson.canonical(List.of(id, Instant.parse("2026-01-01T00:00:00Z"))));
    }

    @Test
    void signedInt64BoundsAndOnlyJsonWhitespaceAreAccepted() {
        assertEquals(Long.MIN_VALUE, StrictJson.parse("-9223372036854775808"));
        assertEquals(Long.MAX_VALUE, StrictJson.parse("9223372036854775807"));
        assertEquals(0L, StrictJson.parse(" \r\n\t-0 \t\r\n"));
        assertEquals(-100L, StrictJson.parse("-100"));
        assertEquals(Map.of("a", 2L), StrictJson.object(" \t{\"a\" : 2 }\r\n"));
        assertEquals(List.of(), StrictJson.parse("[ \n\r\t ]"));
        assertThrows(IllegalArgumentException.class, () -> StrictJson.parse("\u00a01"));
    }

    @Test
    void decimalDigitsMustBeAsciiEvenWhenJavaCanParseOtherScripts() {
        for (String invalid : List.of("٢", "-٢", "١٠", "１２", "1٢", "-1２")) {
            assertThrows(IllegalArgumentException.class, () -> StrictJson.parse(invalid), invalid);
        }
    }

    @Test
    void unicodeEscapesRequireFourAsciiHexDigitsWithoutSigns() {
        String prefix = "\"\\u";
        for (String invalid : List.of("+041", "-001", "ＦＦＦＦ", "０000", " 041", "00g0")) {
            assertThrows(IllegalArgumentException.class,
                    () -> StrictJson.parse(prefix + invalid + "\""), invalid);
        }
        assertEquals("Aé", StrictJson.parse("\"\\u0041\\u00e9\""));
        assertEquals("\uffff", StrictJson.parse("\"\\uFFFF\""));
    }

    @Test
    void stringEscapesAndAllControlCharactersRoundTripExactly() {
        String text = "\"\\/\b\f\n\r\t" + (char) 0 + (char) 31 + "支付";
        String encoded = "\"\\\"\\\\/\\b\\f\\n\\r\\t\\u0000\\u001f支付\"";
        assertEquals(encoded, StrictJson.canonical(text));
        assertEquals(text, StrictJson.parse(encoded));
        assertEquals("/", StrictJson.parse("\"\\/\""));
        for (int control = 0; control < 32; control++) {
            String value = String.valueOf((char) control);
            assertEquals(value, StrictJson.parse(StrictJson.canonical(value)));
            assertThrows(IllegalArgumentException.class, () -> StrictJson.parse('"' + value + '"'));
        }
    }

    @Test
    void supplementaryUnicodeWorksButEveryLoneSurrogateIsRejected() {
        String pair = new String(Character.toChars(0x1f642));
        assertEquals(pair, StrictJson.parse("\"\\ud83d\\ude42\""));
        assertEquals('"' + pair + '"', StrictJson.canonical(pair));
        for (String invalid : List.of(String.valueOf((char) 0xd800),
                String.valueOf((char) 0xdc00), String.valueOf((char) 0xd800) + "a")) {
            assertThrows(IllegalArgumentException.class, () -> StrictJson.canonical(invalid));
            assertThrows(IllegalArgumentException.class, () -> StrictJson.parse('"' + invalid + '"'));
            assertThrows(IllegalArgumentException.class, () -> StrictJson.canonical(Map.of(invalid, 1)));
        }
        for (String invalid : List.of("\"\\ud800\"", "\"\\udc00\"", "\"\\ud800a\"")) {
            assertThrows(IllegalArgumentException.class, () -> StrictJson.parse(invalid));
        }
    }

    @Test
    void malformedStringsNumbersCollectionsAndLiteralsAreRejected() {
        for (String invalid : List.of("", " \n", "-", "+1", "00", "01", "-01", "1.0", "1e2",
                "1E2", "9223372036854775808", "-9223372036854775809", "tru", "fals", "nul",
                "truex", "false null", "[1,]", "[", "[1", "{", "{1:2}", "{\"a\" 1}",
                "{\"a\":1,}", "{}[]", "\"unfinished", "\"\\", "\"\\q\"", "\"\\u0\"")) {
            assertThrows(IllegalArgumentException.class, () -> StrictJson.parse(invalid), invalid);
        }
        assertThrows(NullPointerException.class, () -> StrictJson.parse(null));
    }

    @Test
    void duplicateKeysAreRejectedEvenIfTheFirstValueWasNullOrEscaped() {
        for (String invalid : List.of("{\"a\":null,\"a\":1}", "{\"a\":1,\"\\u0061\":2}",
                "{\"outer\":{\"a\":true,\"a\":false}}")) {
            assertThrows(IllegalArgumentException.class, () -> StrictJson.parse(invalid));
        }
        Map<String, Object> parsed = StrictJson.object("{\"a\":null}");
        assertEquals(1, parsed.size());
        assertNull(parsed.get("a"));
        assertThrows(UnsupportedOperationException.class, parsed::clear);
    }

    @Test
    void objectEntryPointRejectsEveryOtherJsonShape() {
        for (String invalid : List.of("[]", "null", "true", "false", "1", "\"a\"")) {
            assertThrows(IllegalArgumentException.class, () -> StrictJson.object(invalid));
        }
        assertEquals(true, StrictJson.parse("true"));
        assertEquals(false, StrictJson.parse("false"));
        assertNull(StrictJson.parse("null"));
    }

    @Test
    void canonicalCodecRejectsUnsupportedNumbersAndNonStringMapKeys() {
        for (Object invalid : List.of(1.5, Float.valueOf("1.5"), new BigDecimal("1.00"),
                BigInteger.ONE, new Object(), new int[] {1, 2}, Map.of(1, "a"))) {
            assertThrows(IllegalArgumentException.class, () -> StrictJson.canonical(invalid));
        }
        Map<Object, Object> invalidKey = new LinkedHashMap<>();
        invalidKey.put(null, "a");
        assertThrows(IllegalArgumentException.class, () -> StrictJson.canonical(invalidKey));
    }
}
