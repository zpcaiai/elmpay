package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.Headers;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class OidcJwtAuthenticatorTest {
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");
    private static final String ISSUER = "https://identity.elmpay.test";
    private static final String AUDIENCE = "elmpay-api";
    private static final String KEY_ID = "oidc-signing-key-1";
    private static final UUID TENANT = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID PROJECT = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final UUID MERCHANT = UUID.fromString("33333333-3333-4333-8333-333333333333");

    @TempDir
    Path temporary;
    private KeyPair keyPair;
    private byte[] certificateDer;
    private String certificateThumbprint;
    private Path revocations;
    private OidcJwtAuthenticator authenticator;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2_048);
        keyPair = generator.generateKeyPair();
        certificateDer = new byte[32];
        certificateThumbprint = base64Url(MessageDigest.getInstance("SHA-256")
                .digest(certificateDer));
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        Path jwks = temporary.resolve("trusted-jwks.json");
        Files.writeString(jwks, Json.stringify(Map.of("keys", java.util.List.of(Map.of(
                "kid", KEY_ID,
                "kty", "RSA",
                "alg", "RS256",
                "use", "sig",
                "n", base64Url(unsigned(publicKey.getModulus())),
                "e", base64Url(unsigned(publicKey.getPublicExponent()))
        )))), StandardCharsets.UTF_8);
        revocations = temporary.resolve("revocations.json");
        writeRevocations(NOW, java.util.List.of(), java.util.List.of());
        authenticator = OidcJwtAuthenticator.fromEnvironment(Map.of(
                "ELMPAY_OIDC_ISSUER", ISSUER,
                "ELMPAY_OIDC_AUDIENCE", AUDIENCE,
                "ELMPAY_OIDC_JWKS_FILE", jwks.toString(),
                "ELMPAY_OIDC_REVOCATION_FILE", revocations.toString(),
                "ELMPAY_OIDC_MAX_TOKEN_SECONDS", "300",
                "ELMPAY_OIDC_CLOCK_SKEW_SECONDS", "0"
        ), Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void verifiesShortLivedCertificateBoundTenantPrincipal() throws Exception {
        Optional<ApiPrincipal> result = authenticate(token(claims()));

        assertTrue(result.isPresent());
        ApiPrincipal principal = result.orElseThrow();
        assertEquals("service-client-0001", principal.id());
        assertEquals(TENANT, principal.tenantId());
        assertEquals(PROJECT, principal.projectId());
        assertEquals(MERCHANT, principal.merchantId());
        assertEquals(java.util.Set.of("payments.read", "payments.write"), principal.scopes());
    }

    @Test
    void rejectsAuthorityLifetimeScopeAndCertificateBindingMutations() throws Exception {
        Map<String, Object> wrongIssuer = claims();
        wrongIssuer.put("iss", "https://attacker.invalid");
        assertTrue(authenticate(token(wrongIssuer)).isEmpty());

        Map<String, Object> excessiveLifetime = claims();
        excessiveLifetime.put("exp", NOW.plusSeconds(301).getEpochSecond());
        assertTrue(authenticate(token(excessiveLifetime)).isEmpty());

        Map<String, Object> unknownScope = claims();
        unknownScope.put("scope", "payments.write platform.root");
        assertTrue(authenticate(token(unknownScope)).isEmpty());

        assertTrue(authenticate(token(claims()), new byte[] {
                    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                }).isEmpty());
    }

    @Test
    void rejectsSignatureAndHeaderConfusionAndDuplicateCredentials() throws Exception {
        String valid = token(claims());
        String[] parts = valid.split("\\.");
        Map<String, Object> confusedHeader = new LinkedHashMap<>();
        confusedHeader.put("alg", "RS256");
        confusedHeader.put("kid", KEY_ID);
        confusedHeader.put("typ", "at+jwt");
        confusedHeader.put("jku", "https://attacker.invalid/jwks.json");
        String confused = sign(confusedHeader, claims(), keyPair.getPrivate());
        assertTrue(authenticate(confused).isEmpty());

        String genericJwt = sign(Map.of("alg", "RS256", "kid", KEY_ID, "typ", "JWT"),
                claims(), keyPair.getPrivate());
        assertTrue(authenticate(genericJwt).isEmpty());

        char replacement = parts[2].charAt(parts[2].length() - 1) == 'A' ? 'B' : 'A';
        String tampered = parts[0] + "." + parts[1] + "."
                + parts[2].substring(0, parts[2].length() - 1) + replacement;
        assertTrue(authenticate(tampered).isEmpty());

        Headers duplicate = headers(valid);
        duplicate.add("Authorization", "Bearer " + valid);
        assertTrue(authenticator.authenticate(new TestHttpsExchange(duplicate,
                certificateDer)).isEmpty());

        Headers forged = headers(valid);
        forged.set(OidcJwtAuthenticator.FORBIDDEN_CLIENT_CERTIFICATE_HEADER,
                certificateThumbprint);
        assertTrue(authenticator.authenticate(new TestHttpsExchange(forged,
                certificateDer)).isEmpty());
    }

    @Test
    void checksFreshRevocationStateOnEveryRequest() throws Exception {
        String valid = token(claims());
        assertTrue(authenticate(valid).isPresent());

        writeRevocations(NOW, java.util.List.of("access-token-jti-0001"),
                java.util.List.of());
        assertTrue(authenticate(valid).isEmpty());

        writeRevocations(NOW.minusSeconds(61), java.util.List.of(), java.util.List.of());
        assertTrue(authenticate(valid).isEmpty());
    }

    @Test
    void startupFailsClosedForMissingOrWeakJwks() throws Exception {
        assertThrows(IllegalArgumentException.class, () ->
                OidcJwtAuthenticator.fromEnvironment(Map.of(), Clock.systemUTC()));

        // Only public JWKS input is needed for this rejection test. Never
        // generate a usable private signing key with an insecure key size.
        RSAPublicKey strongKey = (RSAPublicKey) keyPair.getPublic();
        BigInteger undersizedModulus = strongKey.getModulus().shiftRight(1_024).setBit(0);
        assertEquals(1_024, undersizedModulus.bitLength());
        Path weakJwks = temporary.resolve("weak-jwks.json");
        Files.writeString(weakJwks, Json.stringify(Map.of("keys", java.util.List.of(Map.of(
                "kid", "weak-key", "kty", "RSA", "alg", "RS256", "use", "sig",
                "n", base64Url(unsigned(undersizedModulus)),
                "e", base64Url(unsigned(strongKey.getPublicExponent()))
        )))), StandardCharsets.UTF_8);
        assertThrows(IllegalArgumentException.class, () ->
                OidcJwtAuthenticator.fromEnvironment(Map.of(
                        "ELMPAY_OIDC_ISSUER", ISSUER,
                        "ELMPAY_OIDC_AUDIENCE", AUDIENCE,
                        "ELMPAY_OIDC_JWKS_FILE", weakJwks.toString(),
                        "ELMPAY_OIDC_REVOCATION_FILE", revocations.toString()
                ), Clock.systemUTC()));
    }

    private Map<String, Object> claims() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", ISSUER);
        claims.put("aud", AUDIENCE);
        claims.put("sub", "service-client-0001");
        claims.put("client_id", "service-client-0001");
        claims.put("jti", "access-token-jti-0001");
        claims.put("token_use", "access");
        claims.put("iat", NOW.getEpochSecond());
        claims.put("nbf", NOW.getEpochSecond());
        claims.put("exp", NOW.plusSeconds(300).getEpochSecond());
        claims.put("tenant_id", TENANT.toString());
        claims.put("project_id", PROJECT.toString());
        claims.put("merchant_id", MERCHANT.toString());
        claims.put("scope", "payments.read payments.write");
        claims.put("cnf", Map.of("x5t#S256", certificateThumbprint));
        return claims;
    }

    private String token(Map<String, Object> claims) throws Exception {
        return sign(Map.of("alg", "RS256", "kid", KEY_ID, "typ", "at+jwt"), claims,
                keyPair.getPrivate());
    }

    private static String sign(Map<String, Object> header, Map<String, Object> claims,
            PrivateKey privateKey) throws Exception {
        String encodedHeader = base64Url(Json.stringify(header).getBytes(StandardCharsets.UTF_8));
        String encodedClaims = base64Url(Json.stringify(claims).getBytes(StandardCharsets.UTF_8));
        String signingInput = encodedHeader + "." + encodedClaims;
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + base64Url(signer.sign());
    }

    private Optional<ApiPrincipal> authenticate(String token) {
        return authenticate(token, certificateDer);
    }

    private Optional<ApiPrincipal> authenticate(String token, byte[] peerCertificateDer) {
        return authenticator.authenticate(new TestHttpsExchange(headers(token),
                peerCertificateDer));
    }

    private static Headers headers(String token) {
        Headers headers = new Headers();
        headers.set("Authorization", "Bearer " + token);
        return headers;
    }

    private static byte[] unsigned(BigInteger value) {
        byte[] signed = value.toByteArray();
        if (signed.length > 1 && signed[0] == 0) {
            return java.util.Arrays.copyOfRange(signed, 1, signed.length);
        }
        return signed;
    }

    private static String base64Url(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private void writeRevocations(Instant generatedAt, java.util.List<String> revokedJtis,
            java.util.List<String> revokedSubjects) throws Exception {
        Map<String, Object> snapshot = new LinkedHashMap<>();
        snapshot.put("schemaVersion", 1L);
        snapshot.put("generatedAt", generatedAt.getEpochSecond());
        snapshot.put("expiresAt", generatedAt.plusSeconds(120).getEpochSecond());
        snapshot.put("revokedBefore", NOW.minusSeconds(86_400).getEpochSecond());
        snapshot.put("revokedJtis", revokedJtis);
        snapshot.put("revokedSubjects", revokedSubjects);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(Json.stringify(snapshot).getBytes(StandardCharsets.UTF_8));
        snapshot.put("keyId", KEY_ID);
        snapshot.put("signature", base64Url(signer.sign()));
        Files.writeString(revocations, Json.stringify(snapshot), StandardCharsets.UTF_8);
    }
}
