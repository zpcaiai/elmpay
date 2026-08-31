package com.elmpay.gateway;

import com.elmpay.payment.commerce.JdbcProviderEvidenceReplayGuard;
import com.elmpay.provider.ProviderEvidenceVerifier;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.sql.DataSource;

/** Builds the commerce provider-evidence verifier from a bounded read-only trust document. */
final class ProviderEvidenceRuntimeFactory {
    private static final int MAX_TRUST_BYTES = 65_536;
    private static final Set<String> TYPES = Set.of(
            "PROVIDER_DISPUTE_EVENT", "PROVIDER_DISPUTE_RESULT",
            "PROVIDER_RENEWAL_RESULT", "PROVIDER_DUNNING_RESULT");
    private static final Set<String> PROVIDERS = Set.of(
            "wechat", "alipay", "stripe", "paypal", "apple_pay");

    private ProviderEvidenceRuntimeFactory() {
    }

    static ProviderEvidenceVerifier create(Map<String, String> environment,
            DataSource dataSource, Clock clock) {
        Path path = Path.of(required(environment, "ELMPAY_PROVIDER_EVIDENCE_TRUST_FILE"));
        Map<String, Object> document = Json.object(readBounded(path));
        if (!Set.of("schemaVersion", "keys").equals(document.keySet())
                || !Long.valueOf(1L).equals(document.get("schemaVersion"))
                || !(document.get("keys") instanceof List<?> rawKeys) || rawKeys.isEmpty()) {
            throw new IllegalStateException("provider evidence trust document is invalid");
        }
        Map<String, ProviderEvidenceVerifier.TrustKey> keys = new HashMap<>();
        for (Object rawKey : rawKeys) {
            Map<String, Object> key = object(rawKey, "provider evidence key");
            if (!Set.of("keyId", "algorithm", "publicKeyPem", "identity", "provider",
                    "evidenceTypes", "notBefore", "notAfter", "revoked")
                    .equals(key.keySet()) || !"Ed25519".equals(key.get("algorithm"))) {
                throw new IllegalStateException("provider evidence trust key is invalid");
            }
            String keyId = text(key.get("keyId"), "provider evidence keyId");
            String provider = text(key.get("provider"), "provider evidence provider");
            Set<String> evidenceTypes = strings(key.get("evidenceTypes"));
            if (!keyId.matches("[A-Za-z0-9._:-]{1,128}") || !PROVIDERS.contains(provider)
                    || evidenceTypes.isEmpty() || !TYPES.containsAll(evidenceTypes)
                    || !(key.get("revoked") instanceof Boolean revoked)) {
                throw new IllegalStateException("provider evidence trust key policy is invalid");
            }
            ProviderEvidenceVerifier.TrustKey trustKey = new ProviderEvidenceVerifier.TrustKey(
                    publicKey(text(key.get("publicKeyPem"), "provider evidence public key")),
                    text(key.get("identity"), "provider evidence identity"), provider,
                    evidenceTypes, Instant.parse(text(key.get("notBefore"), "notBefore")),
                    Instant.parse(text(key.get("notAfter"), "notAfter")), revoked);
            if (keys.putIfAbsent(keyId, trustKey) != null) {
                throw new IllegalStateException("provider evidence trust contains duplicate keyId");
            }
        }
        long maximumSeconds = number(environment.get("ELMPAY_PROVIDER_EVIDENCE_MAX_SECONDS"),
                300L, 30L, 600L, "ELMPAY_PROVIDER_EVIDENCE_MAX_SECONDS");
        long skewSeconds = number(environment.get("ELMPAY_PROVIDER_EVIDENCE_SKEW_SECONDS"),
                30L, 0L, 120L, "ELMPAY_PROVIDER_EVIDENCE_SKEW_SECONDS");
        return new ProviderEvidenceVerifier(keys,
                new JdbcProviderEvidenceReplayGuard(dataSource),
                Duration.ofSeconds(maximumSeconds), Duration.ofSeconds(skewSeconds));
    }

    private static PublicKey publicKey(String pem) {
        String normalized = pem.trim();
        if (!normalized.startsWith("-----BEGIN PUBLIC KEY-----")
                || !normalized.endsWith("-----END PUBLIC KEY-----")) {
            throw new IllegalStateException("provider evidence public key PEM is invalid");
        }
        String encoded = normalized.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "").replaceAll("\\s", "");
        try {
            byte[] der = Base64.getDecoder().decode(encoded);
            PublicKey key = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(der));
            if (!"EdDSA".equals(key.getAlgorithm()) && !"Ed25519".equals(key.getAlgorithm())) {
                throw new IllegalStateException("provider evidence key is not Ed25519");
            }
            return key;
        } catch (IllegalArgumentException | GeneralSecurityException invalid) {
            throw new IllegalStateException("provider evidence public key is invalid", invalid);
        }
    }

    private static Set<String> strings(Object value) {
        if (!(value instanceof List<?> list) || list.size() > TYPES.size()
                || !list.stream().allMatch(String.class::isInstance)) {
            throw new IllegalStateException("provider evidence types are invalid");
        }
        Set<String> result = new HashSet<>();
        for (Object item : list) {
            if (!result.add((String) item)) {
                throw new IllegalStateException("provider evidence types contain duplicates");
            }
        }
        return Set.copyOf(result);
    }

    private static Map<String, Object> object(Object value, String field) {
        if (!(value instanceof Map<?, ?> raw)) {
            throw new IllegalStateException(field + " is invalid");
        }
        Map<String, Object> result = new HashMap<>();
        for (Map.Entry<?, ?> entry : raw.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw new IllegalStateException(field + " key is invalid");
            }
            result.put(key, entry.getValue());
        }
        return Map.copyOf(result);
    }

    private static String text(Object value, String field) {
        if (!(value instanceof String text) || text.isBlank() || text.length() > 8_192) {
            throw new IllegalStateException(field + " is required and bounded");
        }
        return text;
    }

    private static String required(Map<String, String> environment, String name) {
        String value = environment.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required for provider evidence");
        }
        return value;
    }

    private static long number(String value, long fallback, long minimum, long maximum,
            String field) {
        try {
            long parsed = value == null || value.isBlank() ? fallback : Long.parseLong(value);
            if (parsed < minimum || parsed > maximum) {
                throw new IllegalStateException(field + " is outside the allowed range");
            }
            return parsed;
        } catch (NumberFormatException invalid) {
            throw new IllegalStateException(field + " is invalid", invalid);
        }
    }

    private static String readBounded(Path path) {
        if (!Files.isRegularFile(path)) {
            throw new IllegalStateException("provider evidence trust file is missing");
        }
        try (InputStream input = Files.newInputStream(path)) {
            byte[] content = input.readNBytes(MAX_TRUST_BYTES + 1);
            if (content.length > MAX_TRUST_BYTES) {
                throw new IllegalStateException("provider evidence trust file is too large");
            }
            try {
                return StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(content)).toString();
            } catch (CharacterCodingException invalid) {
                throw new IllegalStateException("provider evidence trust is not UTF-8", invalid);
            }
        } catch (IOException invalid) {
            throw new IllegalStateException("provider evidence trust file could not be read",
                    invalid);
        }
    }
}
