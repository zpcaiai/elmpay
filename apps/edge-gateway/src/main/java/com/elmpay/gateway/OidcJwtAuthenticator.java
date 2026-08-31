package com.elmpay.gateway;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsExchange;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPublicKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Strict RS256 OAuth2 access-token verifier for the production gateway.
 *
 * <p>Keys are loaded from a reviewed, locally mounted JWKS document. Tokens are short lived and
 * must be bound to the authenticated TLS peer certificate. The thumbprint is derived from the
 * {@link javax.net.ssl.SSLSession}; no request header is accepted as transport identity.</p>
 */
public final class OidcJwtAuthenticator implements ApiAuthenticator {
    static final String FORBIDDEN_CLIENT_CERTIFICATE_HEADER =
            "X-ELMPAY-Client-Certificate-SHA256";
    private static final int MAX_TOKEN_BYTES = 8_192;
    private static final int MAX_JWKS_BYTES = 65_536;
    private static final int MAX_REVOCATION_BYTES = 262_144;
    private static final int MAX_REVOCATION_ENTRIES = 10_000;
    private static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9._:-]{1,128}");
    private static final Pattern TOKEN_ID = Pattern.compile("[A-Za-z0-9._:-]{16,160}");
    private static final Set<String> HEADER_FIELDS = Set.of("alg", "kid", "typ");

    private final String issuer;
    private final String audience;
    private final Map<String, PublicKey> keys;
    private final Duration maximumLifetime;
    private final Duration clockSkew;
    private final Path revocationFile;
    private final Duration maximumRevocationAge;
    private final Clock clock;

    public OidcJwtAuthenticator(String issuer, String audience, Map<String, PublicKey> keys,
            Duration maximumLifetime, Duration clockSkew, Path revocationFile,
            Duration maximumRevocationAge, Clock clock) {
        this.issuer = required(issuer, "OIDC issuer");
        this.audience = required(audience, "OIDC audience");
        URI issuerUri = URI.create(this.issuer);
        if (!"https".equalsIgnoreCase(issuerUri.getScheme()) || issuerUri.getHost() == null
                || issuerUri.getUserInfo() != null || issuerUri.getFragment() != null) {
            throw new IllegalArgumentException("OIDC issuer must be an HTTPS origin or path");
        }
        if (!this.audience.matches("[A-Za-z0-9._:/-]{3,160}")) {
            throw new IllegalArgumentException("OIDC audience is invalid");
        }
        if (keys == null || keys.isEmpty()) {
            throw new IllegalArgumentException("at least one OIDC verification key is required");
        }
        this.keys = Map.copyOf(keys);
        this.maximumLifetime = positive(maximumLifetime, "maximum token lifetime");
        if (clockSkew == null || clockSkew.isNegative() || clockSkew.compareTo(
                Duration.ofMinutes(2)) > 0) {
            throw new IllegalArgumentException("OIDC clock skew is invalid");
        }
        this.clockSkew = clockSkew;
        this.revocationFile = java.util.Objects.requireNonNull(revocationFile,
                "revocationFile");
        if (maximumRevocationAge == null || maximumRevocationAge.isZero()
                || maximumRevocationAge.isNegative()
                || maximumRevocationAge.compareTo(Duration.ofSeconds(60)) > 0) {
            throw new IllegalArgumentException("OIDC revocation age is invalid");
        }
        this.maximumRevocationAge = maximumRevocationAge;
        this.clock = java.util.Objects.requireNonNull(clock, "clock");
    }

    public static OidcJwtAuthenticator fromEnvironment(Map<String, String> environment,
            Clock clock) {
        java.util.Objects.requireNonNull(environment, "environment");
        String issuer = required(environment.get("ELMPAY_OIDC_ISSUER"), "ELMPAY_OIDC_ISSUER");
        String audience = required(environment.get("ELMPAY_OIDC_AUDIENCE"),
                "ELMPAY_OIDC_AUDIENCE");
        String path = required(environment.get("ELMPAY_OIDC_JWKS_FILE"),
                "ELMPAY_OIDC_JWKS_FILE");
        String revocationPath = required(environment.get("ELMPAY_OIDC_REVOCATION_FILE"),
                "ELMPAY_OIDC_REVOCATION_FILE");
        long maximumSeconds = boundedLong(environment.get("ELMPAY_OIDC_MAX_TOKEN_SECONDS"),
                300L, 30L, 900L, "ELMPAY_OIDC_MAX_TOKEN_SECONDS");
        long skewSeconds = boundedLong(environment.get("ELMPAY_OIDC_CLOCK_SKEW_SECONDS"),
                30L, 0L, 120L, "ELMPAY_OIDC_CLOCK_SKEW_SECONDS");
        long revocationSeconds = boundedLong(
                environment.get("ELMPAY_OIDC_MAX_REVOCATION_AGE_SECONDS"),
                60L, 1L, 60L, "ELMPAY_OIDC_MAX_REVOCATION_AGE_SECONDS");
        return new OidcJwtAuthenticator(issuer, audience, readJwks(Path.of(path)),
                Duration.ofSeconds(maximumSeconds), Duration.ofSeconds(skewSeconds),
                Path.of(revocationPath), Duration.ofSeconds(revocationSeconds), clock);
    }

    @Override
    public Optional<ApiPrincipal> authenticate(HttpExchange exchange) {
        try {
            if (!(java.util.Objects.requireNonNull(exchange, "exchange")
                    instanceof HttpsExchange secureExchange)
                    || exchange.getRequestHeaders().containsKey(
                    FORBIDDEN_CLIENT_CERTIFICATE_HEADER)) {
                return Optional.empty();
            }
            Headers headers = exchange.getRequestHeaders();
            String token = singleBearer(headers);
            String certificateThumbprint = peerCertificateThumbprint(secureExchange);
            if (token == null || certificateThumbprint == null) {
                return Optional.empty();
            }
            return Optional.of(verify(token, certificateThumbprint));
        } catch (RuntimeException | GeneralSecurityException invalid) {
            return Optional.empty();
        }
    }

    private static String peerCertificateThumbprint(HttpsExchange exchange)
            throws GeneralSecurityException {
        Certificate[] chain;
        try {
            chain = exchange.getSSLSession().getPeerCertificates();
        } catch (javax.net.ssl.SSLPeerUnverifiedException missingPeer) {
            throw new GeneralSecurityException(
                    "mTLS peer certificate is unavailable", missingPeer);
        }
        if (chain.length == 0 || !(chain[0] instanceof X509Certificate leaf)) {
            throw new GeneralSecurityException("mTLS peer did not present an X.509 certificate");
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(leaf.getEncoded()));
    }

    private ApiPrincipal verify(String token, String certificateThumbprint)
            throws GeneralSecurityException {
        if (token.length() > MAX_TOKEN_BYTES) {
            throw new IllegalArgumentException("access token is too large");
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty()
                || parts[2].isEmpty()) {
            throw new IllegalArgumentException("access token is malformed");
        }
        Map<String, Object> header = Json.object(utf8(canonicalBase64Url(parts[0])));
        if (!HEADER_FIELDS.containsAll(header.keySet()) || !"RS256".equals(header.get("alg"))
                || !"at+jwt".equals(header.get("typ"))) {
            throw new IllegalArgumentException("access token header is not allowed");
        }
        String keyId = string(header.get("kid"), "token kid");
        if (!KEY_ID.matcher(keyId).matches() || !keys.containsKey(keyId)) {
            throw new IllegalArgumentException("access token key is not trusted");
        }
        byte[] signatureBytes = canonicalBase64Url(parts[2]);
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(keys.get(keyId));
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        if (!verifier.verify(signatureBytes)) {
            throw new IllegalArgumentException("access token signature is invalid");
        }

        Map<String, Object> claims = Json.object(utf8(canonicalBase64Url(parts[1])));
        Instant now = clock.instant();
        Instant issuedAt = Instant.ofEpochSecond(integer(claims.get("iat"), "token iat"));
        Instant expiresAt = Instant.ofEpochSecond(integer(claims.get("exp"), "token exp"));
        Object notBeforeClaim = claims.get("nbf");
        Instant notBefore = notBeforeClaim == null ? issuedAt
                : Instant.ofEpochSecond(integer(notBeforeClaim, "token nbf"));
        if (!issuer.equals(claims.get("iss")) || !hasAudience(claims.get("aud"), audience)
                || !"access".equals(claims.get("token_use"))) {
            throw new IllegalArgumentException("access token authority is invalid");
        }
        if (issuedAt.isAfter(now.plus(clockSkew)) || notBefore.isAfter(now.plus(clockSkew))
                || !expiresAt.isAfter(now.minus(clockSkew)) || !expiresAt.isAfter(issuedAt)
                || Duration.between(issuedAt, expiresAt).compareTo(maximumLifetime) > 0) {
            throw new IllegalArgumentException("access token time window is invalid");
        }
        String subject = string(claims.get("sub"), "token subject");
        String tokenId = string(claims.get("jti"), "token jti");
        if (!subject.equals(string(claims.get("client_id"), "token client_id"))
                || !TOKEN_ID.matcher(tokenId).matches()) {
            throw new IllegalArgumentException("access token identity is invalid");
        }
        verifyNotRevoked(subject, tokenId, issuedAt, now);
        verifyCertificateBinding(claims.get("cnf"), certificateThumbprint);
        Set<String> scopes = scopes(claims.get("scope"));
        return new ApiPrincipal(subject,
                UUID.fromString(string(claims.get("tenant_id"), "token tenant_id")),
                UUID.fromString(string(claims.get("project_id"), "token project_id")),
                UUID.fromString(string(claims.get("merchant_id"), "token merchant_id")), scopes);
    }

    private static Map<String, PublicKey> readJwks(Path path) {
        try {
            Map<String, Object> document = Json.object(readBounded(path, MAX_JWKS_BYTES,
                    "OIDC JWKS"));
            if (!Set.of("keys").equals(document.keySet())
                    || !(document.get("keys") instanceof List<?> rawKeys) || rawKeys.isEmpty()) {
                throw new IllegalArgumentException("OIDC JWKS document is invalid");
            }
            Map<String, PublicKey> result = new HashMap<>();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            for (Object value : rawKeys) {
                if (!(value instanceof Map<?, ?> raw)) {
                    throw new IllegalArgumentException("OIDC JWKS key is invalid");
                }
                Map<String, Object> key = stringMap(raw);
                String keyId = string(key.get("kid"), "JWKS kid");
                if (!KEY_ID.matcher(keyId).matches() || !"RSA".equals(key.get("kty"))
                        || !"RS256".equals(key.get("alg")) || !"sig".equals(key.get("use"))) {
                    throw new IllegalArgumentException("OIDC JWKS key policy is invalid");
                }
                BigInteger modulus = unsigned(canonicalBase64Url(string(key.get("n"),
                        "JWKS modulus")));
                BigInteger exponent = unsigned(canonicalBase64Url(string(key.get("e"),
                        "JWKS exponent")));
                if (modulus.bitLength() < 2_048 || exponent.bitLength() > 32
                        || exponent.compareTo(BigInteger.valueOf(3L)) < 0) {
                    throw new IllegalArgumentException("OIDC JWKS RSA key strength is invalid");
                }
                PublicKey prior = result.putIfAbsent(keyId,
                        keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent)));
                if (prior != null) {
                    throw new IllegalArgumentException("OIDC JWKS contains duplicate kid");
                }
            }
            return Map.copyOf(result);
        } catch (IOException | GeneralSecurityException exception) {
            throw new IllegalArgumentException("OIDC JWKS could not be loaded", exception);
        }
    }

    private void verifyNotRevoked(String subject, String tokenId, Instant issuedAt, Instant now) {
        try {
            Map<String, Object> snapshot = Json.object(readBounded(revocationFile,
                    MAX_REVOCATION_BYTES, "OIDC revocation snapshot"));
            if (!Set.of("schemaVersion", "generatedAt", "expiresAt", "revokedBefore",
                    "revokedJtis", "revokedSubjects", "keyId", "signature")
                    .equals(snapshot.keySet())
                    || !Long.valueOf(1L).equals(snapshot.get("schemaVersion"))) {
                throw new IllegalArgumentException("OIDC revocation snapshot is invalid");
            }
            String signerKeyId = string(snapshot.get("keyId"), "revocation keyId");
            if (!KEY_ID.matcher(signerKeyId).matches() || !keys.containsKey(signerKeyId)) {
                throw new IllegalArgumentException("OIDC revocation signer is not trusted");
            }
            Map<String, Object> signedFields = new LinkedHashMap<>();
            for (String field : List.of("schemaVersion", "generatedAt", "expiresAt",
                    "revokedBefore", "revokedJtis", "revokedSubjects")) {
                signedFields.put(field, snapshot.get(field));
            }
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(keys.get(signerKeyId));
            verifier.update(Json.stringify(signedFields).getBytes(StandardCharsets.UTF_8));
            if (!verifier.verify(canonicalBase64Url(string(snapshot.get("signature"),
                    "revocation signature")))) {
                throw new IllegalArgumentException("OIDC revocation signature is invalid");
            }
            Instant generatedAt = Instant.ofEpochSecond(integer(snapshot.get("generatedAt"),
                    "revocation generatedAt"));
            Instant expiresAt = Instant.ofEpochSecond(integer(snapshot.get("expiresAt"),
                    "revocation expiresAt"));
            Instant revokedBefore = Instant.ofEpochSecond(integer(snapshot.get("revokedBefore"),
                    "revocation revokedBefore"));
            if (generatedAt.isAfter(now.plus(clockSkew))
                    || generatedAt.plus(maximumRevocationAge).isBefore(now)
                    || !expiresAt.isAfter(now) || !expiresAt.isAfter(generatedAt)) {
                throw new IllegalArgumentException("OIDC revocation snapshot is stale");
            }
            Set<String> revokedTokenIds = stringSet(snapshot.get("revokedJtis"),
                    "revokedJtis");
            Set<String> revokedSubjects = stringSet(snapshot.get("revokedSubjects"),
                    "revokedSubjects");
            if (!issuedAt.isAfter(revokedBefore) || revokedTokenIds.contains(tokenId)
                    || revokedSubjects.contains(subject)) {
                throw new IllegalArgumentException("access token is revoked");
            }
        } catch (IOException | GeneralSecurityException invalid) {
            throw new IllegalArgumentException("OIDC revocation snapshot could not be read",
                    invalid);
        }
    }

    private static void verifyCertificateBinding(Object rawConfirmation, String presented) {
        if (!(rawConfirmation instanceof Map<?, ?> raw)) {
            throw new IllegalArgumentException("access token is not certificate bound");
        }
        Map<String, Object> confirmation = stringMap(raw);
        if (!Set.of("x5t#S256").equals(confirmation.keySet())) {
            throw new IllegalArgumentException("access token certificate binding is invalid");
        }
        byte[] expected = canonicalBase64Url(string(confirmation.get("x5t#S256"),
                "token certificate thumbprint"));
        byte[] actual = canonicalBase64Url(presented);
        if (expected.length != 32 || actual.length != 32
                || !MessageDigest.isEqual(expected, actual)) {
            throw new IllegalArgumentException("access token certificate binding mismatch");
        }
    }

    private static Set<String> scopes(Object rawScope) {
        String value = string(rawScope, "token scope");
        String[] parts = value.split(" ", -1);
        Set<String> result = new HashSet<>(List.of(parts));
        if (result.size() != parts.length || result.isEmpty() || result.contains("")
                || !ApiPrincipal.SUPPORTED_SCOPES.containsAll(result)) {
            throw new IllegalArgumentException("access token scopes are invalid");
        }
        return Set.copyOf(result);
    }

    private static Set<String> stringSet(Object rawValues, String field) {
        if (!(rawValues instanceof List<?> values) || values.size() > MAX_REVOCATION_ENTRIES
                || !values.stream().allMatch(String.class::isInstance)) {
            throw new IllegalArgumentException(field + " is invalid");
        }
        Set<String> result = new HashSet<>();
        for (Object value : values) {
            String text = string(value, field + " item");
            if (text.length() > 160 || !result.add(text)) {
                throw new IllegalArgumentException(field + " is invalid");
            }
        }
        return Set.copyOf(result);
    }

    private static boolean hasAudience(Object rawAudience, String expected) {
        if (rawAudience instanceof String value) {
            return expected.equals(value);
        }
        if (rawAudience instanceof List<?> values) {
            return values.stream().allMatch(String.class::isInstance)
                    && values.stream().filter(expected::equals).count() == 1L;
        }
        return false;
    }

    private static String singleBearer(Headers headers) {
        String authorization = singleHeader(headers, "Authorization");
        if (authorization == null || !authorization.startsWith("Bearer ")
                || authorization.length() <= 7) {
            return null;
        }
        return authorization.substring(7);
    }

    private static String singleHeader(Headers headers, String name) {
        if (headers == null) {
            return null;
        }
        List<String> values = headers.get(name);
        return values == null || values.size() != 1 ? null : values.getFirst();
    }

    private static byte[] canonicalBase64Url(String value) {
        if (value == null || value.isEmpty() || value.indexOf('=') >= 0) {
            throw new IllegalArgumentException("non-canonical base64url");
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(value);
            if (!Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(value)) {
                throw new IllegalArgumentException("non-canonical base64url");
            }
            return decoded;
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("non-canonical base64url", invalid);
        }
    }

    private static String utf8(byte[] value) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value)).toString();
        } catch (CharacterCodingException invalid) {
            throw new IllegalArgumentException("token JSON is not valid UTF-8", invalid);
        }
    }

    private static String readBounded(Path path, int maximumBytes, String field)
            throws IOException {
        if (!Files.isRegularFile(path)) {
            throw new IllegalArgumentException(field + " file is missing");
        }
        try (InputStream input = Files.newInputStream(path)) {
            byte[] content = input.readNBytes(maximumBytes + 1);
            if (content.length > maximumBytes) {
                throw new IllegalArgumentException(field + " file is too large");
            }
            return utf8(content);
        }
    }

    private static long integer(Object value, String field) {
        if (!(value instanceof Long number)) {
            throw new IllegalArgumentException(field + " must be an integer");
        }
        return number;
    }

    private static String string(Object value, String field) {
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return text;
    }

    private static String required(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value;
    }

    private static Duration positive(Duration value, String field) {
        if (value == null || value.isZero() || value.isNegative()
                || value.compareTo(Duration.ofMinutes(15)) > 0) {
            throw new IllegalArgumentException(field + " is invalid");
        }
        return value;
    }

    private static long boundedLong(String value, long fallback, long minimum, long maximum,
            String field) {
        try {
            long parsed = value == null || value.isBlank() ? fallback : Long.parseLong(value);
            if (parsed < minimum || parsed > maximum) {
                throw new IllegalArgumentException(field + " is outside the allowed range");
            }
            return parsed;
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException(field + " is invalid", invalid);
        }
    }

    private static BigInteger unsigned(byte[] value) {
        if (value.length == 0) {
            throw new IllegalArgumentException("RSA integer is empty");
        }
        return new BigInteger(1, value);
    }

    private static Map<String, Object> stringMap(Map<?, ?> raw) {
        Map<String, Object> result = new HashMap<>();
        for (Map.Entry<?, ?> entry : raw.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw new IllegalArgumentException("JSON object key must be a string");
            }
            result.put(key, entry.getValue());
        }
        return Map.copyOf(result);
    }
}
