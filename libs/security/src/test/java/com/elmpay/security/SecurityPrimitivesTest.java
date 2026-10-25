package com.elmpay.security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

final class SecurityPrimitivesTest {
    private enum Outcome { UNKNOWN }

    private static String canonical(Object value) {
        return new String(CanonicalPayload.encode(value), StandardCharsets.UTF_8);
    }

    @Test
    void canonicalBytesAndDigestMatchKnownSortedObject() {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("b", 2);
        value.put("a", 1);
        assertArrayEquals("{\"a\":1,\"b\":2}".getBytes(StandardCharsets.UTF_8),
                CanonicalPayload.encode(value));
        assertEquals("43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
                CanonicalPayload.sha256Hex(value));
        assertEquals("{}", canonical(Map.of()));
        assertEquals("[]", canonical(List.of()));
    }

    @Test
    void canonicalIntegersAndDomainValuesKeepTheirExactRepresentation() {
        UUID tenant = UUID.fromString("8148b213-ab2b-4004-ae81-7b4ed4332849");
        Instant at = Instant.parse("2026-01-01T00:00:00Z");
        assertEquals("[null,true,false,-1,2,3,9223372036854775807,123456789012345678901234567890]",
                canonical(Arrays.asList(null, true, false, (byte) -1, (short) 2, 3,
                        Long.MAX_VALUE, new BigInteger("123456789012345678901234567890"))));
        assertEquals("[\"UNKNOWN\",\"8148b213-ab2b-4004-ae81-7b4ed4332849\",\"2026-01-01T00:00:00Z\"]",
                canonical(List.of(Outcome.UNKNOWN, tenant, at)));
        Map<String, Object> nullable = new LinkedHashMap<>();
        nullable.put("n", null);
        assertEquals("{\"n\":null}", canonical(nullable));
    }

    @Test
    void canonicalStringsEscapeControlsAndPreserveValidUnicode() {
        assertEquals("\"\\\"\\\\\\b\\f\\n\\r\\t\\u0000\\u001f/\"",
                canonical("\"\\\b\f\n\r\t" + (char) 0 + (char) 31 + "/"));
        String text = "支付-é-" + new String(Character.toChars(0x1f642));
        assertArrayEquals(('"' + text + '"').getBytes(StandardCharsets.UTF_8),
                CanonicalPayload.encode(text));
        assertNotEquals(CanonicalPayload.sha256Hex("é"),
                CanonicalPayload.sha256Hex("e" + (char) 0x0301));
        assertEquals("{\"a\":1,\"é\":2}", canonical(Map.of("é", 2, "a", 1)));
    }

    @Test
    void canonicalRejectsLoneSurrogatesInValuesAndPropertyNames() {
        String high = String.valueOf((char) 0xd800);
        String low = String.valueOf((char) 0xdc00);
        for (String invalid : List.of(high, low, high + "x", "x" + low,
                high + high + low, high + low + low)) {
            assertThrows(IllegalArgumentException.class, () -> CanonicalPayload.encode(invalid));
            assertThrows(IllegalArgumentException.class,
                    () -> CanonicalPayload.sha256Hex(Map.of("nested", List.of(invalid))));
            assertThrows(IllegalArgumentException.class,
                    () -> CanonicalPayload.encode(Map.of(invalid, "value")));
        }
        assertEquals("\"?\"", canonical("?"));
        for (String valid : List.of(high + low, high + low + "a", "a" + high + low + "b",
                high + low + high + low)) {
            assertArrayEquals(('"' + valid + '"').getBytes(StandardCharsets.UTF_8),
                    CanonicalPayload.encode(valid));
        }
    }

    @Test
    void canonicalRejectsAmbiguousNumbersAndUnsupportedShapes() {
        for (Object invalid : List.of(Double.valueOf("NaN"), Float.valueOf("1.5"),
                new BigDecimal("1.00"), new Object(), new int[] {1, 2})) {
            assertThrows(IllegalArgumentException.class, () -> CanonicalPayload.encode(invalid));
        }
        assertThrows(IllegalArgumentException.class, () -> CanonicalPayload.encode(Map.of(1, "value")));
        Map<Object, Object> nullKey = new LinkedHashMap<>();
        nullKey.put(null, "value");
        assertThrows(IllegalArgumentException.class, () -> CanonicalPayload.encode(nullKey));
    }

    @Test
    void hmacMatchesRfc4231KnownAnswerAndRejectsTampering() {
        byte[] key = new byte[20];
        Arrays.fill(key, (byte) 0x0b);
        HmacSigner signer = new HmacSigner("test-rfc4231", new SecretKeySpec(key, "HmacSHA256"));
        byte[] expected = HexFormat.of().parseHex(
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(expected);
        assertEquals("test-rfc4231", signer.keyId());
        assertEquals(signature, signer.sign("Hi There"));
        assertEquals(signature, signer.sign("Hi There".getBytes(StandardCharsets.UTF_8)));
        assertTrue(signer.verify("Hi There".getBytes(StandardCharsets.UTF_8), signature));
        assertFalse(signer.verify("Hi There!".getBytes(StandardCharsets.UTF_8), signature));
        assertFalse(signer.verify("Hi There".getBytes(StandardCharsets.UTF_8), "invalid:base64"));
        assertFalse(signer.verify("Hi There".getBytes(StandardCharsets.UTF_8), ""));
        expected[0] ^= 1;
        assertFalse(signer.verify("Hi There".getBytes(StandardCharsets.UTF_8),
                Base64.getUrlEncoder().withoutPadding().encodeToString(expected)));
    }

    @Test
    void hmacRequiresAnExplicitKeyAndKeyIdentity() {
        SecretKeySpec key = new SecretKeySpec(new byte[32], "HmacSHA256");
        assertThrows(NullPointerException.class, () -> new HmacSigner(null, key));
        assertThrows(NullPointerException.class, () -> new HmacSigner("test", null));
        assertThrows(IllegalArgumentException.class, () -> new HmacSigner(" \t", key));
    }

    @Test
    void sensitiveCatalogNormalizesEveryGovernedDeniedField() {
        for (String field : SensitiveFieldCatalog.DENIED_KEYS) {
            assertTrue(SensitiveFieldCatalog.denied(field));
            assertTrue(SensitiveFieldCatalog.denied(field.toUpperCase(java.util.Locale.ROOT)));
            assertThrows(IllegalArgumentException.class,
                    () -> SensitiveDataGuard.assertSafe(Map.of("event", List.of(Map.of(field, "demo")))));
        }
        assertEquals("cardpan", SensitiveFieldCatalog.normalize(" CARD-_ .Pan "));
        assertEquals("", SensitiveFieldCatalog.normalize(null));
        assertFalse(SensitiveFieldCatalog.denied(null));
        assertFalse(SensitiveFieldCatalog.denied("provider"));
    }

    @Test
    void cardDetectionChecksLengthLuhnAndNestedCollections() {
        for (String card : List.of("4111111111111111", "4111 1111 1111 1111",
                "4111-1111-1111-1111", "4222222222222", "4000000000000000006")) {
            assertThrows(IllegalArgumentException.class,
                    () -> SensitiveDataGuard.assertSafe(Map.of("note", "before " + card + " after")));
        }
        assertThrows(IllegalArgumentException.class, () -> SensitiveDataGuard.assertSafe(
                Map.of("items", List.of(Map.of("note", "4111111111111112 then 4111111111111111")))));
        SensitiveDataGuard.assertSafe(Map.of("note", "4111111111111112", "order", "12345678901234567890",
                "short", "123456789012", "amount_minor", 1000, "approved", true));
        SensitiveDataGuard.assertSafe(Map.of("items", Arrays.asList(null, false, 3, "reference")));
    }

    @Test
    void redactionMinimizesNestedDataAndReturnsImmutableCopies() {
        Map<String, Object> inner = new LinkedHashMap<>();
        inner.put("Authorization.Header", "demo-only-value");
        inner.put("note", "4111-1111-1111-1111");
        inner.put("provider", "local-sandbox");
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("items", List.of(inner));
        input.put("status", "UNKNOWN");
        input.put("count", 2);
        input.put("optional", null);
        Map<String, Object> output = SensitiveDataGuard.redact(input);
        inner.put("provider", "changed");
        assertEquals(List.of(Map.of("Authorization.Header", "[REDACTED]",
                "note", "[REDACTED]", "provider", "local-sandbox")), output.get("items"));
        assertEquals("UNKNOWN", output.get("status"));
        assertEquals(2, output.get("count"));
        assertTrue(output.containsKey("optional"));
        assertEquals(null, output.get("optional"));
        assertThrows(UnsupportedOperationException.class, () -> output.put("status", "SUCCEEDED"));
        List<?> items = (List<?>) output.get("items");
        assertThrows(UnsupportedOperationException.class, items::clear);
        Map<?, ?> nested = (Map<?, ?>) items.getFirst();
        assertThrows(UnsupportedOperationException.class, nested::clear);
    }

    @Test
    void callbackAllowlistNormalizesOnlyRegisteredHostsAndPaths() {
        UrlAllowlist allowlist = new UrlAllowlist(Set.of("PAY.EXAMPLE.COM.", "BÜCHER.example", "192.0.2.10"));
        assertEquals(URI.create("https://pay.example.com/complete?order=demo"),
                allowlist.requireAllowed("https://pay.example.com/a/../complete?order=demo"));
        assertEquals("xn--bcher-kva.example",
                allowlist.requireAllowed("https://xn--bcher-kva.example/return").getHost());
        assertEquals("192.0.2.10", allowlist.requireAllowed("https://192.0.2.10/return").getHost());
        for (String invalid : List.of("http://pay.example.com/return", "/return",
                "https://user@pay.example.com/return", "https://pay.example.com/return#result",
                "https://pay.example.com.evil.test/return", "https://child.pay.example.com/return")) {
            assertThrows(IllegalArgumentException.class, () -> allowlist.requireAllowed(invalid));
        }
        assertThrows(IllegalArgumentException.class, () -> new UrlAllowlist(Set.of()));
        assertThrows(NullPointerException.class, () -> new UrlAllowlist(null));
    }

    @Test
    void callbackAllowlistRejectsEvenRegisteredPrivateAndInvalidIpLiterals() {
        Set<String> denied = Set.of("0.0.0.0", "127.0.0.1", "10.1.2.3", "172.16.0.1",
                "192.168.1.1", "169.254.1.1", "224.0.0.1", "999.999.999.999");
        UrlAllowlist allowlist = new UrlAllowlist(denied);
        for (String host : denied) {
            assertThrows(IllegalArgumentException.class,
                    () -> allowlist.requireAllowed("https://" + host + "/return"));
        }
    }

    @Test
    void secretReferencesAcceptOnlyExternalManagedSecretSchemes() {
        assertEquals(URI.create("kms://tenant/payment/key-v1"),
                SecretReference.parse("kms://tenant/payment/key-v1").uri());
        assertEquals(URI.create("vault://tenant/payment/key-v2"),
                SecretReference.parse("vault://tenant/payment/key-v2").uri());
        for (String invalid : List.of("https://tenant/payment/key", "file:///tmp/key", "literal-value", "kms:")) {
            assertThrows(IllegalArgumentException.class, () -> SecretReference.parse(invalid));
        }
        assertThrows(NullPointerException.class, () -> new SecretReference(null));
        assertThrows(NullPointerException.class, () -> SecretReference.parse(null));
    }
}
