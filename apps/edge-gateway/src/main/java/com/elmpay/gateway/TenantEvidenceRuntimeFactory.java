package com.elmpay.gateway;

import com.elmpay.merchant.JdbcTenantEvidenceReplayGuard;
import com.elmpay.tenant.TenantEvidenceType;
import com.elmpay.tenant.TenantEvidenceVerifier;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
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

/** Builds tenant authority verification only from a bounded read-only trust mount. */
final class TenantEvidenceRuntimeFactory {
    private static final int MAX_TRUST_BYTES = 65_536;
    private static final Set<TenantEvidenceType> TYPES = Set.of(
            TenantEvidenceType.KYB_VERIFIED, TenantEvidenceType.CONTRACT_SIGNED,
            TenantEvidenceType.SETTLEMENT_COMPLETE,
            TenantEvidenceType.RETENTION_PERIOD_STARTED, TenantEvidenceType.KEK_DESTROYED);

    private TenantEvidenceRuntimeFactory() {
    }

    static TenantEvidenceVerifier create(Map<String, String> environment,
            DataSource dataSource, Clock clock) {
        Path path = Path.of(required(environment, "ELMPAY_TENANT_EVIDENCE_TRUST_FILE"));
        Map<String, Object> document = Json.object(readBoundedReadOnly(path));
        if (!Set.of("schemaVersion", "keys").equals(document.keySet())
                || !Long.valueOf(1L).equals(document.get("schemaVersion"))
                || !(document.get("keys") instanceof List<?> rawKeys) || rawKeys.isEmpty()
                || rawKeys.size() > 64) {
            throw new IllegalStateException("tenant evidence trust document is invalid");
        }
        Map<String, TenantEvidenceVerifier.TrustKey> keys = new HashMap<>();
        for (Object rawKey : rawKeys) {
            Map<String, Object> key = object(rawKey, "tenant evidence key");
            if (!Set.of("keyId", "algorithm", "publicKeyPem", "signerIdentity",
                    "authority", "evidenceTypes", "notBefore", "notAfter", "revoked")
                    .equals(key.keySet()) || !"Ed25519".equals(key.get("algorithm"))) {
                throw new IllegalStateException("tenant evidence trust key is invalid");
            }
            String keyId = text(key.get("keyId"), "tenant evidence keyId");
            Set<TenantEvidenceType> evidenceTypes = evidenceTypes(key.get("evidenceTypes"));
            if (!keyId.matches("[A-Za-z0-9._:-]{1,128}") || evidenceTypes.isEmpty()
                    || !(key.get("revoked") instanceof Boolean revoked)) {
                throw new IllegalStateException("tenant evidence trust key policy is invalid");
            }
            TenantEvidenceVerifier.TrustKey trustKey =
                    new TenantEvidenceVerifier.TrustKey(
                            publicKey(text(key.get("publicKeyPem"),
                                    "tenant evidence public key")),
                            text(key.get("signerIdentity"), "tenant evidence signer identity"),
                            text(key.get("authority"), "tenant evidence authority"),
                            evidenceTypes,
                            Instant.parse(text(key.get("notBefore"), "notBefore")),
                            Instant.parse(text(key.get("notAfter"), "notAfter")), revoked);
            if (keys.putIfAbsent(keyId, trustKey) != null) {
                throw new IllegalStateException("tenant evidence trust contains duplicate keyId");
            }
        }
        Instant now = clock.instant();
        Set<TenantEvidenceType> activeTypes = new HashSet<>();
        keys.values().stream().filter(key -> !key.revoked()
                        && !now.isBefore(key.notBefore()) && now.isBefore(key.notAfter()))
                .forEach(key -> activeTypes.addAll(key.evidenceTypes()));
        if (!activeTypes.containsAll(TYPES)) {
            throw new IllegalStateException(
                    "tenant evidence trust lacks a currently active key for every type");
        }
        long maximumSeconds = number(environment.get("ELMPAY_TENANT_EVIDENCE_MAX_SECONDS"),
                300L, 30L, 600L, "ELMPAY_TENANT_EVIDENCE_MAX_SECONDS");
        long skewSeconds = number(environment.get("ELMPAY_TENANT_EVIDENCE_SKEW_SECONDS"),
                30L, 0L, 120L, "ELMPAY_TENANT_EVIDENCE_SKEW_SECONDS");
        return new TenantEvidenceVerifier(keys, new JdbcTenantEvidenceReplayGuard(dataSource),
                Duration.ofSeconds(maximumSeconds), Duration.ofSeconds(skewSeconds));
    }

    private static Set<TenantEvidenceType> evidenceTypes(Object value) {
        if (!(value instanceof List<?> list) || list.isEmpty() || list.size() > TYPES.size()
                || !list.stream().allMatch(String.class::isInstance)) {
            throw new IllegalStateException("tenant evidence types are invalid");
        }
        Set<TenantEvidenceType> result = new HashSet<>();
        for (Object item : list) {
            TenantEvidenceType type;
            try {
                type = TenantEvidenceType.valueOf((String) item);
            } catch (IllegalArgumentException unknown) {
                throw new IllegalStateException("tenant evidence type is unknown", unknown);
            }
            if (!TYPES.contains(type) || !result.add(type)) {
                throw new IllegalStateException("tenant evidence types are invalid");
            }
        }
        return Set.copyOf(result);
    }

    private static PublicKey publicKey(String pem) {
        String normalized = pem.trim();
        if (!normalized.startsWith("-----BEGIN PUBLIC KEY-----")
                || !normalized.endsWith("-----END PUBLIC KEY-----")) {
            throw new IllegalStateException("tenant evidence public key PEM is invalid");
        }
        String encoded = normalized.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "").replaceAll("\\s", "");
        try {
            byte[] der = Base64.getDecoder().decode(encoded);
            PublicKey key = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(der));
            if (!"EdDSA".equals(key.getAlgorithm()) && !"Ed25519".equals(key.getAlgorithm())) {
                throw new IllegalStateException("tenant evidence key is not Ed25519");
            }
            return key;
        } catch (IllegalArgumentException | GeneralSecurityException invalid) {
            throw new IllegalStateException("tenant evidence public key is invalid", invalid);
        }
    }

    private static String readBoundedReadOnly(Path path) {
        try {
            Path real = path.toRealPath();
            if (!Files.isRegularFile(real, LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalStateException("tenant evidence trust file is missing");
            }
            requireReadOnly(real);
            try (InputStream input = Files.newInputStream(real)) {
                byte[] content = input.readNBytes(MAX_TRUST_BYTES + 1);
                if (content.length > MAX_TRUST_BYTES) {
                    throw new IllegalStateException("tenant evidence trust file is too large");
                }
                try {
                    return StandardCharsets.UTF_8.newDecoder()
                            .onMalformedInput(CodingErrorAction.REPORT)
                            .onUnmappableCharacter(CodingErrorAction.REPORT)
                            .decode(ByteBuffer.wrap(content)).toString();
                } catch (CharacterCodingException invalid) {
                    throw new IllegalStateException("tenant evidence trust is not UTF-8",
                            invalid);
                }
            }
        } catch (IOException invalid) {
            throw new IllegalStateException("tenant evidence trust file could not be read",
                    invalid);
        }
    }

    private static void requireReadOnly(Path path) throws IOException {
        FileStore store = Files.getFileStore(path);
        if (store.isReadOnly()) {
            return;
        }
        requireNonWritable(path, "file");
        Path parent = path.getParent();
        if (parent == null) {
            throw new IllegalStateException("tenant evidence trust mount is invalid");
        }
        requireNonWritable(parent, "mount");
    }

    private static void requireNonWritable(Path path, String kind) throws IOException {
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path,
                    LinkOption.NOFOLLOW_LINKS);
            if (permissions.contains(PosixFilePermission.OWNER_WRITE)
                    || permissions.contains(PosixFilePermission.GROUP_WRITE)
                    || permissions.contains(PosixFilePermission.OTHERS_WRITE)
                    || Files.isWritable(path)) {
                throw new IllegalStateException(
                        "tenant evidence trust " + kind + " must be read-only");
            }
        } catch (UnsupportedOperationException unsupported) {
            if (Files.isWritable(path)) {
                throw new IllegalStateException(
                        "tenant evidence trust " + kind + " must be read-only", unsupported);
            }
        }
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
            throw new IllegalStateException(name + " is required for tenant evidence");
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
}
