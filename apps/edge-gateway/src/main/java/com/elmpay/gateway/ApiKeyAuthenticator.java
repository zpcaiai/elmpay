package com.elmpay.gateway;

import com.sun.net.httpserver.HttpExchange;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/** Local API credentials use versioned verifiers; plaintext keys are never retained. */
public final class ApiKeyAuthenticator implements ApiAuthenticator {
    private static final int PBKDF2_ITERATIONS = 600_000;
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
            if (fields.length != 6 && !(allowLocalLegacyScopes && fields.length == 5)) {
                throw new IllegalArgumentException("invalid hashed API principal configuration");
            }
            String digest = fields[0];
            byte[] salt = null;
            int iterations = 0;
            if (!digest.matches("[0-9a-f]{64}")) {
                String[] verifier = digest.split(":", -1);
                if (verifier.length != 4 || !verifier[0].equals("pbkdf2-sha256")
                        || !verifier[1].equals(Integer.toString(PBKDF2_ITERATIONS))
                        || !verifier[2].matches("[0-9a-f]{32}")
                        || !verifier[3].matches("[0-9a-f]{64}")) {
                    throw new IllegalArgumentException("invalid versioned API credential verifier");
                }
                salt = HexFormat.of().parseHex(verifier[2]);
                iterations = PBKDF2_ITERATIONS;
                digest = verifier[3];
            }
            Set<String> scopes = fields.length == 5 ? ApiPrincipal.SUPPORTED_SCOPES
                    : parseScopes(fields[5]);
            result.add(new Entry(HexFormat.of().parseHex(digest), new ApiPrincipal(fields[1],
                    UUID.fromString(fields[2]), UUID.fromString(fields[3]), UUID.fromString(fields[4]),
                    scopes), salt, iterations));
        }
        return new ApiKeyAuthenticator(result);
    }

    @Override
    public Optional<ApiPrincipal> authenticate(HttpExchange exchange) {
        var headers = java.util.Objects.requireNonNull(exchange, "exchange").getRequestHeaders();
        List<String> values = headers.get("Authorization");
        if (values == null || values.size() != 1) {
            return Optional.empty();
        }
        String authorization = values.getFirst();
        if (authorization == null || !authorization.startsWith("Bearer ")
                || authorization.length() <= 7 || authorization.length() > 512) {
            return Optional.empty();
        }
        String credential = authorization.substring(7);
        byte[] presented = sha256(credential);
        ApiPrincipal match = null;
        try {
            for (Entry entry : entries) {
                byte[] candidate = entry.iterations() == 0 ? presented
                        : derive(credential, entry.salt(), entry.iterations());
                try {
                    if (MessageDigest.isEqual(candidate, entry.digest())) {
                        match = entry.principal();
                    }
                } finally {
                    if (candidate != presented) Arrays.fill(candidate, (byte) 0);
                }
            }
            return Optional.ofNullable(match);
        } finally {
            Arrays.fill(presented, (byte) 0);
        }
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

    private static byte[] derive(String credential, byte[] salt, int iterations) {
        char[] characters = credential.toCharArray();
        PBEKeySpec specification = new PBEKeySpec(characters, salt, iterations, 256);
        Arrays.fill(characters, '\0');
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(specification).getEncoded();
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("JDK PBKDF2 support is unavailable", exception);
        } finally {
            specification.clearPassword();
        }
    }

    public record Entry(byte[] digest, ApiPrincipal principal, byte[] salt, int iterations) {
        public Entry(byte[] digest, ApiPrincipal principal) {
            this(digest, principal, null, 0);
        }

        public Entry {
            if (digest == null || digest.length != 32 || principal == null
                    || (salt == null && iterations != 0)
                    || (salt != null && (salt.length != 16 || iterations != PBKDF2_ITERATIONS))) {
                throw new IllegalArgumentException("invalid API principal entry");
            }
            digest = digest.clone();
            salt = salt == null ? null : salt.clone();
        }

        @Override
        public byte[] digest() {
            return digest.clone();
        }

        @Override
        public byte[] salt() {
            return salt == null ? null : salt.clone();
        }
    }
}
