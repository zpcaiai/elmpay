package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;

final class GatewayTlsConfigurationTest {
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");
    private static final String SERVER_NAME = "edge-gateway.elmpay.svc.cluster.local";

    @Test
    void serverCertificatePurposeValiditySanAndKeyMatchFailClosed() throws Exception {
        KeyPair valid = rsa();
        PolicyCertificate leaf = certificate(valid.getPublic(), -1,
                List.of("1.3.6.1.5.5.7.3.1"), usage(true, false), SERVER_NAME,
                NOW.minusSeconds(60), NOW.plusSeconds(600));
        assertDoesNotThrow(() -> GatewayTlsConfiguration.validateServerChain(List.of(leaf),
                SERVER_NAME, Clock.fixed(NOW, ZoneOffset.UTC)));
        assertDoesNotThrow(() -> GatewayTlsConfiguration.validateKeyMatch(leaf,
                valid.getPrivate()));

        assertThrows(Exception.class, () -> GatewayTlsConfiguration.validateServerChain(List.of(
                certificate(valid.getPublic(), -1, List.of("1.3.6.1.5.5.7.3.1"),
                        usage(true, false), "attacker.example", NOW.minusSeconds(60),
                        NOW.plusSeconds(600))), SERVER_NAME, Clock.fixed(NOW, ZoneOffset.UTC)));
        assertThrows(Exception.class, () -> GatewayTlsConfiguration.validateServerChain(List.of(
                certificate(valid.getPublic(), 1, List.of("1.3.6.1.5.5.7.3.1"),
                        usage(true, true), SERVER_NAME, NOW.minusSeconds(60),
                        NOW.plusSeconds(600))), SERVER_NAME, Clock.fixed(NOW, ZoneOffset.UTC)));
        assertThrows(Exception.class, () -> GatewayTlsConfiguration.validateServerChain(List.of(
                certificate(valid.getPublic(), -1, List.of("1.3.6.1.5.5.7.3.2"),
                        usage(true, false), SERVER_NAME, NOW.minusSeconds(60),
                        NOW.plusSeconds(600))), SERVER_NAME, Clock.fixed(NOW, ZoneOffset.UTC)));
        assertThrows(Exception.class, () -> GatewayTlsConfiguration.validateServerChain(List.of(
                certificate(valid.getPublic(), -1, List.of("1.3.6.1.5.5.7.3.1"),
                        usage(true, false), SERVER_NAME, NOW.minusSeconds(600),
                        NOW.minusSeconds(1))), SERVER_NAME, Clock.fixed(NOW, ZoneOffset.UTC)));
        PrivateKey mismatched = rsa().getPrivate();
        assertThrows(Exception.class, () -> GatewayTlsConfiguration.validateKeyMatch(leaf,
                mismatched));
    }

    @Test
    void clientTrustBundleAcceptsOnlyCurrentlyValidCertificateAuthorities() throws Exception {
        PublicKey key = rsa().getPublic();
        PolicyCertificate authority = certificate(key, 1, List.of(), usage(false, true),
                "client-ca.example", NOW.minusSeconds(60), NOW.plusSeconds(600));
        assertDoesNotThrow(() -> GatewayTlsConfiguration.validateAuthorities(List.of(authority),
                Clock.fixed(NOW, ZoneOffset.UTC)));
        assertThrows(Exception.class, () -> GatewayTlsConfiguration.validateAuthorities(List.of(
                certificate(key, -1, List.of(), usage(true, false), "client.example",
                        NOW.minusSeconds(60), NOW.plusSeconds(600))),
                Clock.fixed(NOW, ZoneOffset.UTC)));
    }

    @Test
    void productionRejectsStaticBearerConfigurationBeforeStartup() {
        assertThrows(IllegalStateException.class, () -> RuntimeFactory.create(Map.of(
                "ELMPAY_RUNTIME_MODE", "postgres", "ELMPAY_API_PRINCIPALS", "forbidden")));
        assertThrows(IllegalStateException.class, () -> GatewayTlsConfiguration.fromEnvironment(
                Map.of(), Clock.systemUTC()));
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2_048);
        return generator.generateKeyPair();
    }

    private static boolean[] usage(boolean digitalSignature, boolean certificateSigning) {
        boolean[] value = new boolean[9];
        value[0] = digitalSignature;
        value[5] = certificateSigning;
        return value;
    }

    private static PolicyCertificate certificate(PublicKey key, int basicConstraints,
            List<String> extendedUsage, boolean[] keyUsage, String dns, Instant notBefore,
            Instant notAfter) {
        return new PolicyCertificate(key, basicConstraints, extendedUsage, keyUsage, dns,
                Date.from(notBefore), Date.from(notAfter));
    }

    @SuppressWarnings("deprecation")
    private static final class PolicyCertificate extends X509Certificate {
        private static final long serialVersionUID = 1L;
        private final PublicKey key;
        private final int basicConstraints;
        private final transient List<String> extendedUsage;
        private final boolean[] keyUsage;
        private final String dns;
        private final Date notBefore;
        private final Date notAfter;

        private PolicyCertificate(PublicKey key, int basicConstraints, List<String> extendedUsage,
                boolean[] keyUsage, String dns, Date notBefore, Date notAfter) {
            this.key = key;
            this.basicConstraints = basicConstraints;
            this.extendedUsage = List.copyOf(extendedUsage);
            this.keyUsage = keyUsage.clone();
            this.dns = dns;
            this.notBefore = new Date(notBefore.getTime());
            this.notAfter = new Date(notAfter.getTime());
        }

        @Override public void checkValidity() throws CertificateExpiredException,
                CertificateNotYetValidException { checkValidity(new Date()); }
        @Override public void checkValidity(Date date) throws CertificateExpiredException,
                CertificateNotYetValidException {
            if (date.before(notBefore)) throw new CertificateNotYetValidException();
            if (date.after(notAfter)) throw new CertificateExpiredException();
        }
        @Override public int getVersion() { return 3; }
        @Override public BigInteger getSerialNumber() { return BigInteger.ONE; }
        @Override public Principal getIssuerDN() { return getIssuerX500Principal(); }
        @Override public Principal getSubjectDN() { return getSubjectX500Principal(); }
        @Override public X500Principal getIssuerX500Principal() { return new X500Principal("CN=test-ca"); }
        @Override public X500Principal getSubjectX500Principal() { return new X500Principal("CN=test"); }
        @Override public Date getNotBefore() { return new Date(notBefore.getTime()); }
        @Override public Date getNotAfter() { return new Date(notAfter.getTime()); }
        @Override public byte[] getTBSCertificate() { return key.getEncoded(); }
        @Override public byte[] getSignature() { return new byte[0]; }
        @Override public String getSigAlgName() { return "NONE"; }
        @Override public String getSigAlgOID() { return "0.0"; }
        @Override public byte[] getSigAlgParams() { return null; }
        @Override public boolean[] getIssuerUniqueID() { return null; }
        @Override public boolean[] getSubjectUniqueID() { return null; }
        @Override public boolean[] getKeyUsage() { return keyUsage.clone(); }
        @Override public List<String> getExtendedKeyUsage() { return extendedUsage; }
        @Override public int getBasicConstraints() { return basicConstraints; }
        @Override public Collection<List<?>> getSubjectAlternativeNames() {
            return List.of(List.of(Integer.valueOf(2), dns));
        }
        @Override public byte[] getEncoded() { return key.getEncoded(); }
        @Override public void verify(PublicKey publicKey) { }
        @Override public void verify(PublicKey publicKey, String provider) { }
        @Override public String toString() { return "policy certificate"; }
        @Override public PublicKey getPublicKey() { return key; }
        @Override public Set<String> getCriticalExtensionOIDs() { return Set.of(); }
        @Override public Set<String> getNonCriticalExtensionOIDs() { return Set.of(); }
        @Override public byte[] getExtensionValue(String oid) { return null; }
        @Override public boolean hasUnsupportedCriticalExtension() { return false; }
    }
}
