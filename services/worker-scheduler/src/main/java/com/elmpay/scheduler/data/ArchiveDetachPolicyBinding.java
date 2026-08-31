package com.elmpay.scheduler.data;

import com.elmpay.events.StrictJson;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Immutable, mounted governance binding for the destructive detach capability. */
record ArchiveDetachPolicyBinding(String policyDigest, Instant validFrom, Instant validUntil) {
    private static final int MAXIMUM_BYTES = 16_384;

    ArchiveDetachPolicyBinding {
        if (policyDigest == null || !policyDigest.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("archive detach policy digest is invalid");
        }
        Objects.requireNonNull(validFrom, "validFrom");
        Objects.requireNonNull(validUntil, "validUntil");
        if (!validFrom.isBefore(validUntil)) {
            throw new IllegalArgumentException("archive detach policy validity is invalid");
        }
    }

    static ArchiveDetachPolicyBinding load(Path path) {
        Map<String, Object> document = StrictJson.object(
                ArchiveReceiptVerifier.readBounded(path, MAXIMUM_BYTES));
        if (!document.keySet().equals(Set.of(
                "schemaVersion", "policyDigest", "validFrom", "validUntil"))
                || !Long.valueOf(1).equals(document.get("schemaVersion"))) {
            throw new IllegalArgumentException("archive detach policy schema is not exact");
        }
        String digest = exactText(document, "policyDigest");
        if (!digest.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("archive detach policy digest is invalid");
        }
        Instant from = instant(document, "validFrom");
        Instant until = instant(document, "validUntil");
        return new ArchiveDetachPolicyBinding(digest, from, until);
    }

    boolean authorizes(String suppliedDigest, Instant issuedAt, Instant expiresAt, Instant now) {
        byte[] expected = policyDigest.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] supplied = suppliedDigest.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        try {
            return MessageDigest.isEqual(expected, supplied)
                    && !now.isBefore(validFrom) && now.isBefore(validUntil)
                    && !issuedAt.isBefore(validFrom) && !expiresAt.isAfter(validUntil);
        } finally {
            java.util.Arrays.fill(expected, (byte) 0);
            java.util.Arrays.fill(supplied, (byte) 0);
        }
    }

    private static String exactText(Map<String, Object> document, String field) {
        Object raw = document.get(field);
        if (!(raw instanceof String text) || text.isBlank() || !text.equals(text.trim())
                || text.length() > 128 || text.chars().anyMatch(character -> character < 0x20)) {
            throw new IllegalArgumentException(field + " is invalid");
        }
        return text;
    }

    private static Instant instant(Map<String, Object> document, String field) {
        try {
            String value = exactText(document, field);
            Instant parsed = Instant.parse(value);
            if (!parsed.toString().equals(value)) {
                throw new IllegalArgumentException(field + " is not canonical UTC");
            }
            return parsed;
        } catch (RuntimeException failure) {
            throw new IllegalArgumentException(field + " is not a canonical instant", failure);
        }
    }
}
