package com.elmpay.payment.provider;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class MutualTlsContextsTest {
    @TempDir
    Path temporary;

    @Test
    void legacyBooleanIsDetectedOnlyToFailClosed() {
        Map<String, String> environment = Map.of(
                "ELMPAY_PROVIDER_CREDENTIAL_MTLS", "true");
        assertTrue(MutualTlsContexts.anyConfiguration(environment,
                "ELMPAY_PROVIDER_CREDENTIAL"));
        assertThrows(IllegalStateException.class, () -> MutualTlsContexts.fromEnvironment(
                environment, "ELMPAY_PROVIDER_CREDENTIAL", Clock.systemUTC()));
    }

    @Test
    void allThreeExplicitMaterialPathsAreMandatory() throws Exception {
        Path certificate = temporary.resolve("client.pem");
        Files.writeString(certificate, "not-a-certificate");
        Map<String, String> environment = new LinkedHashMap<>();
        environment.put("ELMPAY_PROVIDER_CREDENTIAL_MTLS_CLIENT_CERT_FILE",
                certificate.toString());
        assertTrue(MutualTlsContexts.anyConfiguration(environment,
                "ELMPAY_PROVIDER_CREDENTIAL"));
        assertThrows(IllegalStateException.class, () -> MutualTlsContexts.fromEnvironment(
                environment, "ELMPAY_PROVIDER_CREDENTIAL", Clock.systemUTC()));

        environment.put("ELMPAY_PROVIDER_CREDENTIAL_MTLS_CLIENT_KEY_FILE",
                certificate.toString());
        environment.put("ELMPAY_PROVIDER_CREDENTIAL_MTLS_TRUST_BUNDLE_FILE",
                certificate.toString());
        assertThrows(IllegalStateException.class, () -> MutualTlsContexts.fromEnvironment(
                environment, "ELMPAY_PROVIDER_CREDENTIAL", Clock.systemUTC()));
    }

    @Test
    void cryptographicallyBindsPrivateKeyToCertificatePublicKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var matching = generator.generateKeyPair();
        var different = generator.generateKeyPair();
        assertDoesNotThrow(() -> MutualTlsContexts.verifyKeyPair(
                matching.getPrivate(), matching.getPublic()));
        assertThrows(SecurityException.class, () -> MutualTlsContexts.verifyKeyPair(
                matching.getPrivate(), different.getPublic()));
    }
}
