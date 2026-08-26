package com.elmpay.gateway;

import com.sun.net.httpserver.Headers;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/** API keys are configured and compared as SHA-256 digests; plaintext keys are never retained. */
public final class ApiKeyAuthenticator {
    private final List<Entry> entries;

    public ApiKeyAuthenticator(List<Entry> entries) {
        if (entries == null || entries.isEmpty()) {
            throw new IllegalArgumentException("at least one hashed API principal is required");
        }
        this.entries = List.copyOf(entries);
    }

    /** Production entries must include an explicit sixth, '+'-separated scope field. */
    public static ApiKeyAuthenticator parse(String configuration) {
        return parse(configuration, false);
    }

    /** Five-field entries are accepted only by the explicitly enabled local sandbox. */
    public static ApiKeyAuthenticator parse(String configuration, boolean allowLocalLegacyScopes) {
        if (configuration == null || configuration.isBlank()) {
            throw new IllegalArgumentException("ELMPAY_API_PRINCIPALS is required");
        }
        List<Entry> result = new ArrayList<>();
        for (String item : configuration.split(",")) {
            String[] fields = item.trim().split("\\|", -1);
            if ((fields.length != 6 && !(allowLocalLegacyScopes && fields.length == 5))
                    || !fields[0].matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("invalid hashed API principal configuration");
            }
            Set<String> scopes = fields.length == 5 ? ApiPrincipal.SUPPORTED_SCOPES
                    : parseScopes(fields[5]);
            result.add(new Entry(HexFormat.of().parseHex(fields[0]), new ApiPrincipal(fields[1],
                    UUID.fromString(fields[2]), UUID.fromString(fields[3]), UUID.fromString(fields[4]),
                    scopes)));
        }
        return new ApiKeyAuthenticator(result);
    }

    public Optional<ApiPrincipal> authenticate(Headers headers) {
        List<String> values = headers.get("Authorization");
        if (values == null || values.size() != 1) {
            return Optional.empty();
        }
        String authorization = values.getFirst();
        if (authorization == null || !authorization.startsWith("Bearer ")
                || authorization.length() <= 7) {
            return Optional.empty();
        }
        byte[] presented = sha256(authorization.substring(7));
        ApiPrincipal match = null;
        for (Entry entry : entries) {
            if (MessageDigest.isEqual(presented, entry.digest())) {
                match = entry.principal();
            }
        }
        return Optional.ofNullable(match);
    }

    public static String digestForProvisioning(String plaintext) {
        return HexFormat.of().formatHex(sha256(plaintext));
    }

    private static Set<String> parseScopes(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("API principal scopes are required");
        }
        Set<String> scopes = Set.of(value.split("\\+", -1));
        if (scopes.isEmpty() || scopes.stream().anyMatch(String::isBlank)
                || !ApiPrincipal.SUPPORTED_SCOPES.containsAll(scopes)) {
            throw new IllegalArgumentException("invalid API principal scopes");
        }
        return scopes;
    }

    private static byte[] sha256(String plaintext) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(plaintext.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("JDK is missing SHA-256", exception);
        }
    }

    public record Entry(byte[] digest, ApiPrincipal principal) {
        public Entry {
            if (digest == null || digest.length != 32 || principal == null) {
                throw new IllegalArgumentException("invalid API principal entry");
            }
            digest = digest.clone();
        }

        @Override
        public byte[] digest() {
            return digest.clone();
        }
    }
}
