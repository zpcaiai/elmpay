package com.elmpay.scheduler.data;

import com.elmpay.events.StrictJson;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/** Verifies independently signed all-tenant archive receipts before any database write. */
public final class ArchiveReceiptVerifier {
    private static final int MAX_TRUST_BYTES = 1_048_576;
    private static final int MAX_BUNDLE_BYTES = 8_388_608;
    private static final int MAX_TENANTS = 10_000;
    private static final Duration CLOCK_SKEW = Duration.ofMinutes(1);
    private static final Duration MAX_VALIDITY = Duration.ofDays(30);
    private static final Duration MAX_DETACH_VALIDITY = Duration.ofMinutes(15);
    private static final Set<PosixFilePermission> WRITABLE = Set.of(
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.GROUP_WRITE,
            PosixFilePermission.OTHERS_WRITE);

    public record VerifiedTenantReceipt(UUID tenantId, String partitionName, String objectUri,
            String manifestDigest, String objectDigest, String canonicalReceiptDigest,
            String keyId, String nonce, byte[] signature, Instant issuedAt, Instant expiresAt) {
        public VerifiedTenantReceipt {
            Objects.requireNonNull(tenantId, "tenantId");
            signature = signature.clone();
        }

        @Override
        public byte[] signature() {
            return signature.clone();
        }
    }

    public record VerifiedPartitionRelease(UUID releaseId, String partitionName, int tenantCount,
            String receiptSetBinding, String receiptSetDigest, String aggregateManifestBinding,
            String aggregateManifestDigest, String canonicalReceiptDigest, String keyId,
            String nonce, byte[] signature, Instant issuedAt, Instant expiresAt) {
        public VerifiedPartitionRelease {
            Objects.requireNonNull(releaseId, "releaseId");
            signature = signature.clone();
        }

        @Override
        public byte[] signature() {
            return signature.clone();
        }
    }

    public record VerifiedDetachAuthorization(UUID releaseId, String partitionName,
            String actorId, String approverId, String reason, String ticketId,
            String policyDigest, String canonicalAuthorizationDigest,
            String partitionReleaseKeyId, String actorKeyId, String actorNonce,
            byte[] actorSignature, String approverKeyId, String approverNonce,
            byte[] approverSignature, Instant issuedAt, Instant expiresAt) {
        public VerifiedDetachAuthorization {
            Objects.requireNonNull(releaseId, "releaseId");
            actorSignature = actorSignature.clone();
            approverSignature = approverSignature.clone();
        }

        @Override
        public byte[] actorSignature() {
            return actorSignature.clone();
        }

        @Override
        public byte[] approverSignature() {
            return approverSignature.clone();
        }
    }

    public record VerifiedBundle(List<VerifiedTenantReceipt> tenantReceipts,
            VerifiedPartitionRelease release) {
        public VerifiedBundle {
            tenantReceipts = List.copyOf(tenantReceipts);
            Objects.requireNonNull(release, "release");
        }
    }

    private record TrustKey(String keyId, PublicKey key, Instant notBefore, Instant notAfter,
            String status, String role, String subjectId) { }

    private final Map<String, TrustKey> keys;
    private final Clock clock;

    private ArchiveReceiptVerifier(Map<String, TrustKey> keys, Clock clock) {
        this.keys = Map.copyOf(keys);
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public static ArchiveReceiptVerifier load(Path trustFile, Clock clock) {
        Map<String, Object> document = StrictJson.object(readBounded(trustFile, MAX_TRUST_BYTES));
        exactKeys(document, "archive trust", "schemaVersion", "keys");
        if (!Long.valueOf(1).equals(document.get("schemaVersion"))) {
            throw new IllegalArgumentException("archive trust schemaVersion must be one");
        }
        List<Object> rawKeys = list(document.get("keys"), "archive trust keys");
        if (rawKeys.isEmpty() || rawKeys.size() > 128) {
            throw new IllegalArgumentException("archive trust requires 1..128 keys");
        }
        Map<String, TrustKey> keys = new LinkedHashMap<>();
        Set<String> keyFingerprints = new java.util.HashSet<>();
        int activeKeys = 0;
        for (Object raw : rawKeys) {
            Map<String, Object> value = object(raw, "archive trust key");
            exactKeys(value, "archive trust key", "keyId", "algorithm", "publicKeyDerBase64",
                    "notBefore", "notAfter", "status", "role", "subjectId");
            String keyId = identifier(value, "keyId");
            String status = text(value, "status");
            String role = text(value, "role");
            String subjectId = identifier(value, "subjectId");
            if (!"Ed25519".equals(text(value, "algorithm"))
                    || !("ACTIVE".equals(status) || "REVOKED".equals(status))
                    || !Set.of("TENANT_EXPORT_ATTESTOR", "PARTITION_RELEASE_APPROVER",
                            "DETACH_ACTOR", "DETACH_APPROVER").contains(role)) {
                throw new IllegalArgumentException("archive trust key status or algorithm is invalid");
            }
            Instant notBefore = instant(value, "notBefore");
            Instant notAfter = instant(value, "notAfter");
            if (!notBefore.isBefore(notAfter)) {
                throw new IllegalArgumentException("archive trust key validity is invalid");
            }
            PublicKey key = publicKey(text(value, "publicKeyDerBase64"));
            byte[] encodedKey = key.getEncoded();
            try {
                if (!keyFingerprints.add(sha256(encodedKey))) {
                    throw new IllegalArgumentException(
                            "archive trust cannot alias one key under multiple identities");
                }
            } finally {
                Arrays.fill(encodedKey, (byte) 0);
            }
            if (keys.putIfAbsent(keyId,
                    new TrustKey(keyId, key, notBefore, notAfter, status, role,
                            subjectId)) != null) {
                throw new IllegalArgumentException("duplicate archive trust key id");
            }
            if ("ACTIVE".equals(status)) {
                activeKeys++;
            }
        }
        if (activeKeys == 0) {
            throw new IllegalArgumentException("archive trust requires an active key");
        }
        return new ArchiveReceiptVerifier(keys, clock);
    }

    public VerifiedBundle verify(Path bundleFile) {
        Map<String, Object> bundle = StrictJson.object(readBounded(bundleFile, MAX_BUNDLE_BYTES));
        exactKeys(bundle, "archive receipt bundle", "schemaVersion", "tenantReceipts",
                "partitionRelease");
        if (!Long.valueOf(1).equals(bundle.get("schemaVersion"))) {
            throw new IllegalArgumentException("archive receipt bundle schemaVersion must be one");
        }
        List<Object> rawReceipts = list(bundle.get("tenantReceipts"), "tenant receipts");
        if (rawReceipts.isEmpty() || rawReceipts.size() > MAX_TENANTS) {
            throw new IllegalArgumentException("archive receipt bundle tenant count is invalid");
        }
        List<VerifiedTenantReceipt> receipts = new ArrayList<>(rawReceipts.size());
        for (Object raw : rawReceipts) {
            receipts.add(verifyTenant(object(raw, "tenant archive receipt")));
        }
        receipts.sort(Comparator.comparing(receipt -> receipt.tenantId().toString()));
        if (receipts.stream().map(VerifiedTenantReceipt::tenantId).distinct().count()
                != receipts.size()) {
            throw new IllegalArgumentException("archive bundle contains a duplicate tenant");
        }
        VerifiedPartitionRelease release = verifyRelease(
                object(bundle.get("partitionRelease"), "archive partition release"), receipts);
        if (receipts.stream().anyMatch(receipt ->
                !receipt.partitionName().equals(release.partitionName()))) {
            throw new IllegalArgumentException("tenant receipt belongs to another partition");
        }
        return new VerifiedBundle(receipts, release);
    }

    private VerifiedTenantReceipt verifyTenant(Map<String, Object> value) {
        exactKeys(value, "tenant archive receipt", "type", "tenantId", "partitionName",
                "objectUri", "manifestDigest", "objectDigest", "keyId", "nonce",
                "issuedAt", "expiresAt", "algorithm", "signature");
        if (!"TENANT_ARCHIVE_EXPORT_V1".equals(text(value, "type"))) {
            throw new IllegalArgumentException("unsupported tenant archive receipt type");
        }
        UUID tenantId = uuid(value, "tenantId");
        String partition = partition(value, "partitionName");
        String objectUri = objectUri(value, "objectUri");
        String manifest = digest(value, "manifestDigest");
        String object = digest(value, "objectDigest");
        String keyId = identifier(value, "keyId");
        String nonce = nonce(value, "nonce");
        Instant issued = instant(value, "issuedAt");
        Instant expires = instant(value, "expiresAt");
        requireValidity(keyId, issued, expires, MAX_VALIDITY,
                "TENANT_EXPORT_ATTESTOR", null);
        if (!"Ed25519".equals(text(value, "algorithm"))) {
            throw new IllegalArgumentException("archive receipt algorithm must be Ed25519");
        }
        byte[] signature = signature(value, "signature");
        Map<String, Object> canonical = withoutSignature(value);
        byte[] bytes = StrictJson.canonical(canonical).getBytes(StandardCharsets.UTF_8);
        String canonicalDigest = sha256(bytes);
        try {
            verifySignature(keyId, bytes, signature);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
        return new VerifiedTenantReceipt(tenantId, partition, objectUri, manifest, object,
                canonicalDigest, keyId, nonce, signature, issued, expires);
    }

    private VerifiedPartitionRelease verifyRelease(Map<String, Object> value,
            List<VerifiedTenantReceipt> receipts) {
        exactKeys(value, "archive partition release", "type", "releaseId", "partitionName",
                "tenantCount", "receiptSetBinding", "receiptSetDigest",
                "aggregateManifestBinding", "aggregateManifestDigest", "keyId", "nonce",
                "issuedAt", "expiresAt", "algorithm", "signature");
        if (!"ARCHIVE_PARTITION_RELEASE_V1".equals(text(value, "type"))) {
            throw new IllegalArgumentException("unsupported archive partition release type");
        }
        int count = integer(value, "tenantCount");
        if (count != receipts.size()) {
            throw new IllegalArgumentException("release tenant count is not the verified set");
        }
        String binding = receipts.stream().map(VerifiedTenantReceipt::canonicalReceiptDigest)
                .collect(Collectors.joining(","));
        if (!MessageDigest.isEqual(binding.getBytes(StandardCharsets.US_ASCII),
                asciiBinding(value, "receiptSetBinding", 1_048_576)
                        .getBytes(StandardCharsets.US_ASCII))
                || !constantEquals(sha256(binding.getBytes(StandardCharsets.US_ASCII)),
                        digest(value, "receiptSetDigest"))) {
            throw new IllegalArgumentException("release receipt set binding is forged");
        }
        String manifestBinding = receipts.stream()
                .map(receipt -> receipt.tenantId() + ":" + receipt.manifestDigest())
                .collect(Collectors.joining(","));
        if (!MessageDigest.isEqual(manifestBinding.getBytes(StandardCharsets.US_ASCII),
                asciiBinding(value, "aggregateManifestBinding", 2_097_152)
                        .getBytes(StandardCharsets.US_ASCII))
                || !constantEquals(sha256(manifestBinding.getBytes(StandardCharsets.US_ASCII)),
                        digest(value, "aggregateManifestDigest"))) {
            throw new IllegalArgumentException("release aggregate manifest binding is forged");
        }
        String keyId = identifier(value, "keyId");
        Instant issued = instant(value, "issuedAt");
        Instant expires = instant(value, "expiresAt");
        requireValidity(keyId, issued, expires, MAX_VALIDITY,
                "PARTITION_RELEASE_APPROVER", null);
        if (receipts.stream().anyMatch(receipt -> receipt.keyId().equals(keyId))) {
            throw new SecurityException(
                    "partition release signer must be independent from tenant attestations");
        }
        if (!"Ed25519".equals(text(value, "algorithm"))) {
            throw new IllegalArgumentException("archive release algorithm must be Ed25519");
        }
        byte[] signature = signature(value, "signature");
        byte[] bytes = StrictJson.canonical(withoutSignature(value))
                .getBytes(StandardCharsets.UTF_8);
        String canonicalDigest = sha256(bytes);
        try {
            verifySignature(keyId, bytes, signature);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
        return new VerifiedPartitionRelease(uuid(value, "releaseId"),
                partition(value, "partitionName"), count, binding,
                digest(value, "receiptSetDigest"), manifestBinding,
                digest(value, "aggregateManifestDigest"), canonicalDigest, keyId,
                nonce(value, "nonce"), signature, issued, expires);
    }

    public VerifiedDetachAuthorization verifyDetachAuthorization(Path authorizationFile,
            ArchiveDetachPolicyBinding policy) {
        Objects.requireNonNull(policy, "policy");
        Map<String, Object> value = StrictJson.object(readBounded(
                authorizationFile, MAX_TRUST_BYTES));
        exactKeys(value, "archive detach authorization", "type", "releaseId",
                "partitionName", "actorId", "approverId", "reason", "ticketId",
                "policyDigest", "partitionReleaseKeyId", "actorKeyId", "actorNonce",
                "actorSignature", "approverKeyId", "approverNonce", "approverSignature",
                "issuedAt", "expiresAt", "algorithm");
        if (!"ARCHIVE_PARTITION_DETACH_AUTHORIZATION_V1".equals(text(value, "type"))) {
            throw new IllegalArgumentException("unsupported archive detach authorization type");
        }
        String actor = identifier(value, "actorId");
        String approver = identifier(value, "approverId");
        if (actor.equals(approver)) {
            throw new SecurityException("archive detach requires separation of duties");
        }
        String reason = text(value, "reason");
        if (reason.length() < 8 || reason.length() > 512) {
            throw new IllegalArgumentException("archive detach reason is invalid");
        }
        String partitionReleaseKeyId = identifier(value, "partitionReleaseKeyId");
        String actorKeyId = identifier(value, "actorKeyId");
        String approverKeyId = identifier(value, "approverKeyId");
        requireCurrentlyTrusted(partitionReleaseKeyId, "PARTITION_RELEASE_APPROVER");
        if (actorKeyId.equals(approverKeyId)
                || partitionReleaseKeyId.equals(actorKeyId)
                || partitionReleaseKeyId.equals(approverKeyId)) {
            throw new SecurityException("archive detach requires three independent trust keys");
        }
        Instant issued = instant(value, "issuedAt");
        Instant expires = instant(value, "expiresAt");
        if (!policy.authorizes(digest(value, "policyDigest"), issued, expires,
                clock.instant())) {
            throw new SecurityException("archive detach policy binding is not active");
        }
        requireValidity(actorKeyId, issued, expires, MAX_DETACH_VALIDITY,
                "DETACH_ACTOR", actor);
        requireValidity(approverKeyId, issued, expires, MAX_DETACH_VALIDITY,
                "DETACH_APPROVER", approver);
        if (!"Ed25519".equals(text(value, "algorithm"))) {
            throw new IllegalArgumentException("archive detach algorithm must be Ed25519");
        }
        byte[] actorSignature = signature(value, "actorSignature");
        byte[] approverSignature = signature(value, "approverSignature");
        byte[] canonical = StrictJson.canonical(withoutDetachSignatures(value))
                .getBytes(StandardCharsets.UTF_8);
        String canonicalDigest = sha256(canonical);
        try {
            verifySignature(actorKeyId, canonical, actorSignature);
            verifySignature(approverKeyId, canonical, approverSignature);
        } finally {
            Arrays.fill(canonical, (byte) 0);
        }
        return new VerifiedDetachAuthorization(uuid(value, "releaseId"),
                partition(value, "partitionName"), actor, approver, reason,
                identifier(value, "ticketId"), digest(value, "policyDigest"),
                canonicalDigest, partitionReleaseKeyId, actorKeyId,
                nonce(value, "actorNonce"), actorSignature, approverKeyId,
                nonce(value, "approverNonce"), approverSignature, issued, expires);
    }

    private void requireValidity(String keyId, Instant issued, Instant expires,
            Duration maximumValidity, String requiredRole, String requiredSubject) {
        TrustKey trust = keys.get(keyId);
        Instant now = clock.instant();
        if (trust == null || !"ACTIVE".equals(trust.status())
                || !requiredRole.equals(trust.role())
                || (requiredSubject != null && !requiredSubject.equals(trust.subjectId()))
                || issued.isBefore(trust.notBefore()) || expires.isAfter(trust.notAfter())
                || issued.isAfter(now.plus(CLOCK_SKEW)) || !expires.isAfter(now)
                || !issued.isBefore(expires) || Duration.between(issued, expires).compareTo(
                        maximumValidity) > 0) {
            throw new SecurityException("archive receipt key or validity is not trusted");
        }
    }

    private void requireCurrentlyTrusted(String keyId, String requiredRole) {
        TrustKey trust = keys.get(keyId);
        Instant now = clock.instant();
        if (trust == null || !"ACTIVE".equals(trust.status())
                || !requiredRole.equals(trust.role()) || now.isBefore(trust.notBefore())
                || !now.isBefore(trust.notAfter())) {
            throw new SecurityException("archive trust key is not currently active for its role");
        }
    }

    private void verifySignature(String keyId, byte[] canonical, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(keys.get(keyId).key());
            verifier.update(canonical);
            if (!verifier.verify(signature)) {
                throw new SecurityException("archive receipt signature is invalid");
            }
        } catch (java.security.GeneralSecurityException failure) {
            throw new SecurityException("archive receipt signature cannot be verified", failure);
        }
    }

    private static PublicKey publicKey(String encoded) {
        byte[] der = null;
        try {
            if (encoded.length() % 4 != 0
                    || !encoded.matches("[A-Za-z0-9+/]+={0,2}")) {
                throw new IllegalArgumentException(
                        "archive trust public key is not canonical standard Base64");
            }
            der = Base64.getDecoder().decode(encoded);
            String canonical = Base64.getEncoder().encodeToString(der);
            if (!MessageDigest.isEqual(canonical.getBytes(StandardCharsets.US_ASCII),
                    encoded.getBytes(StandardCharsets.US_ASCII))) {
                throw new IllegalArgumentException(
                        "archive trust public key encoding is not canonical");
            }
            PublicKey key = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(der));
            if (!"EdDSA".equals(key.getAlgorithm()) && !"Ed25519".equals(key.getAlgorithm())) {
                throw new IllegalArgumentException("archive trust key is not Ed25519");
            }
            return key;
        } catch (IllegalArgumentException | java.security.GeneralSecurityException failure) {
            throw new IllegalArgumentException("archive trust public key is invalid", failure);
        } finally {
            if (der != null) {
                Arrays.fill(der, (byte) 0);
            }
        }
    }

    private static byte[] signature(Map<String, Object> value, String field) {
        try {
            String encoded = text(value, field);
            if (!encoded.matches("[A-Za-z0-9_-]{86}")) {
                throw new IllegalArgumentException(
                        "archive Ed25519 signature must be canonical unpadded Base64URL");
            }
            byte[] signature = Base64.getUrlDecoder().decode(encoded);
            if (signature.length != 64) {
                Arrays.fill(signature, (byte) 0);
                throw new IllegalArgumentException("archive Ed25519 signature must be 64 bytes");
            }
            if (!Base64.getUrlEncoder().withoutPadding().encodeToString(signature)
                    .equals(encoded)) {
                Arrays.fill(signature, (byte) 0);
                throw new IllegalArgumentException(
                        "archive signature encoding is not canonical");
            }
            return signature;
        } catch (IllegalArgumentException failure) {
            throw new IllegalArgumentException("archive signature is invalid base64url", failure);
        }
    }

    private static Map<String, Object> withoutSignature(Map<String, Object> value) {
        Map<String, Object> canonical = new LinkedHashMap<>(value);
        canonical.remove("signature");
        return Map.copyOf(canonical);
    }

    private static Map<String, Object> withoutDetachSignatures(Map<String, Object> value) {
        Map<String, Object> canonical = new LinkedHashMap<>(value);
        canonical.remove("actorSignature");
        canonical.remove("approverSignature");
        return Map.copyOf(canonical);
    }

    static String readBounded(Path path, int maximum) {
        Objects.requireNonNull(path, "path");
        byte[] bytes = null;
        try {
            Path normalized = path.normalize();
            if (!normalized.isAbsolute() || normalized.getParent() == null) {
                throw new IllegalArgumentException("archive input must be an absolute mount");
            }
            Path configuredParent = normalized.getParent();
            if (Files.isSymbolicLink(configuredParent)
                    || !Files.isDirectory(configuredParent, LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalArgumentException("archive input mount parent is not controlled");
            }
            Path parent = configuredParent.toRealPath(LinkOption.NOFOLLOW_LINKS);
            if (Files.isWritable(parent)) {
                throw new IllegalArgumentException(
                        "archive input mount parent is writable by the workload");
            }
            Path real = normalized.toRealPath();
            if (!real.startsWith(parent) || !Files.isRegularFile(real, LinkOption.NOFOLLOW_LINKS)
                    || Files.getPosixFilePermissions(real, LinkOption.NOFOLLOW_LINKS).stream()
                            .anyMatch(WRITABLE::contains)) {
                throw new IllegalArgumentException("archive input escapes or is writable");
            }
            long size = Files.size(real);
            if (size < 2 || size > maximum) {
                throw new IllegalArgumentException("archive input size is invalid");
            }
            bytes = Files.readAllBytes(real);
            if (bytes.length != size) {
                throw new IllegalArgumentException("archive input changed while it was read");
            }
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException failure) {
            throw new IllegalArgumentException("archive input is not strict UTF-8", failure);
        } catch (IOException | UnsupportedOperationException failure) {
            throw new IllegalArgumentException("archive input cannot be proven read-only", failure);
        } finally {
            if (bytes != null) {
                Arrays.fill(bytes, (byte) 0);
            }
        }
    }

    private static Map<String, Object> object(Object value, String field) {
        if (!(value instanceof Map<?, ?> map)) {
            throw new IllegalArgumentException(field + " must be an object");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw new IllegalArgumentException(field + " has a non-string key");
            }
            result.put(key, entry.getValue());
        }
        return Map.copyOf(result);
    }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object value, String field) {
        if (!(value instanceof List<?> list)) {
            throw new IllegalArgumentException(field + " must be an array");
        }
        return (List<Object>) list;
    }

    private static void exactKeys(Map<String, Object> value, String field, String... keys) {
        if (!value.keySet().equals(Set.of(keys))) {
            throw new IllegalArgumentException(field + " fields are not exact");
        }
    }

    private static String text(Map<String, Object> value, String field) {
        Object raw = value.get(field);
        if (!(raw instanceof String text) || text.isBlank() || text.length() > 2_048
                || text.chars().anyMatch(character -> character < 0x20)) {
            throw new IllegalArgumentException(field + " is invalid");
        }
        return text;
    }

    private static String asciiBinding(Map<String, Object> value, String field, int maximum) {
        Object raw = value.get(field);
        if (!(raw instanceof String text) || text.isEmpty() || text.length() > maximum
                || !StandardCharsets.US_ASCII.newEncoder().canEncode(text)
                || text.chars().anyMatch(character -> character < 0x20)) {
            throw new IllegalArgumentException(field + " is not a bounded ASCII binding");
        }
        return text;
    }

    private static String identifier(Map<String, Object> value, String field) {
        String text = text(value, field);
        if (!text.matches("[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")) {
            throw new IllegalArgumentException(field + " is not an identifier");
        }
        return text;
    }

    private static String nonce(Map<String, Object> value, String field) {
        String text = text(value, field);
        if (!text.matches("[A-Za-z0-9_-]{16,128}")) {
            throw new IllegalArgumentException(field + " is not a nonce");
        }
        return text;
    }

    private static String digest(Map<String, Object> value, String field) {
        String text = text(value, field);
        if (!text.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(field + " is not a SHA-256 digest");
        }
        return text;
    }

    private static UUID uuid(Map<String, Object> value, String field) {
        try {
            UUID parsed = UUID.fromString(text(value, field));
            if (!parsed.toString().equals(text(value, field))) {
                throw new IllegalArgumentException(field + " UUID is not canonical");
            }
            return parsed;
        } catch (IllegalArgumentException failure) {
            throw new IllegalArgumentException(field + " is not a canonical UUID", failure);
        }
    }

    private static int integer(Map<String, Object> value, String field) {
        Object raw = value.get(field);
        if (!(raw instanceof Long number) || number < 1 || number > MAX_TENANTS) {
            throw new IllegalArgumentException(field + " is not a bounded integer");
        }
        return number.intValue();
    }

    private static Instant instant(Map<String, Object> value, String field) {
        try {
            Instant instant = Instant.parse(text(value, field));
            if (!instant.toString().equals(text(value, field))) {
                throw new IllegalArgumentException(field + " is not canonical UTC");
            }
            return instant;
        } catch (RuntimeException failure) {
            throw new IllegalArgumentException(field + " is not a canonical instant", failure);
        }
    }

    private static String partition(Map<String, Object> value, String field) {
        String partition = text(value, field);
        if (!partition.matches("tenant_archive_fact_[0-9]{6}")) {
            throw new IllegalArgumentException(field + " is invalid");
        }
        return partition;
    }

    private static String objectUri(Map<String, Object> value, String field) {
        String valueText = text(value, field);
        final URI uri;
        try {
            uri = new URI(valueText);
        } catch (URISyntaxException failure) {
            throw new IllegalArgumentException(field + " is not a URI", failure);
        }
        String bucket = uri.getHost();
        String path = uri.getRawPath();
        if (!"object-storage".equals(uri.getScheme()) || uri.getRawUserInfo() != null
                || uri.getPort() != -1 || uri.getRawQuery() != null
                || uri.getRawFragment() != null || bucket == null
                || !bucket.matches("[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?")
                || path == null || path.length() < 2 || path.length() > 1_900
                || path.contains("//") || path.contains("%")
                || !path.matches("/[A-Za-z0-9._~/-]+")
                || Arrays.stream(path.substring(1).split("/"))
                        .anyMatch(segment -> segment.isEmpty()
                                || ".".equals(segment) || "..".equals(segment))
                || !uri.toASCIIString().equals(valueText)) {
            throw new IllegalArgumentException(field + " is invalid");
        }
        return valueText;
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static boolean constantEquals(String left, String right) {
        return MessageDigest.isEqual(left.getBytes(StandardCharsets.US_ASCII),
                right.getBytes(StandardCharsets.US_ASCII));
    }
}
