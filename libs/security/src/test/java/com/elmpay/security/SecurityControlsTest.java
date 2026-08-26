package com.elmpay.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

final class SecurityControlsTest {
    @Test
    void canonicalEncodingRejectsFloatingPointAndSortsKeys() {
        assertEquals("{\"a\":1,\"b\":2}",
                new String(CanonicalPayload.encode(Map.of("b", 2, "a", 1)), StandardCharsets.UTF_8));
        assertThrows(IllegalArgumentException.class,
                () -> CanonicalPayload.encode(Map.of("amount", 0.1d)));
    }

    @Test
    void guardRejectsCardAndCredentialFields() {
        assertThrows(IllegalArgumentException.class,
                () -> SensitiveDataGuard.assertSafe(Map.of("pan", "not-even-a-number")));
        assertThrows(IllegalArgumentException.class,
                () -> SensitiveDataGuard.assertSafe(Map.of("note", "4111 1111 1111 1111")));
    }

    @Test
    void hmacVerificationIsFailClosed() {
        HmacSigner signer = new HmacSigner("v1",
                new SecretKeySpec("01234567890123456789012345678901".getBytes(StandardCharsets.UTF_8),
                        "HmacSHA256"));
        byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);
        assertTrue(signer.verify(payload, signer.sign(payload)));
        assertFalse(signer.verify(payload, "invalid"));
    }

    @Test
    void callbackRequiresExactRegisteredHttpsHost() {
        UrlAllowlist allowlist = new UrlAllowlist(Set.of("pay.example.com"));
        assertEquals("pay.example.com", allowlist.requireAllowed("https://pay.example.com/return").getHost());
        assertThrows(IllegalArgumentException.class,
                () -> allowlist.requireAllowed("https://pay.example.com.evil.test/return"));
        assertThrows(IllegalArgumentException.class,
                () -> allowlist.requireAllowed("http://pay.example.com/return"));
    }
}
