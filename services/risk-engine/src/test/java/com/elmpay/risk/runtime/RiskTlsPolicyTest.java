package com.elmpay.risk.runtime;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.Principal;
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
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;

final class RiskTlsPolicyTest {
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");
    private static final String SPIFFE = "spiffe://elmpay.example/edge-gateway";
    private static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
    private static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

    @Test
    void peerIdentityRequiresTls13DigitalSignatureAndOneCanonicalSpiffe() {
        PolicyCertificate valid = certificate("CN=client", "CN=ca", -1,
                List.of(CLIENT_AUTH), usage(true, false), List.of(SPIFFE));
        assertEquals(SPIFFE, RiskHttpApi.spiffe(valid, "TLSv1.3", NOW));
        assertThrows(SecurityException.class,
                () -> RiskHttpApi.spiffe(valid, "TLSv1.2", NOW));
        assertThrows(SecurityException.class, () -> RiskHttpApi.spiffe(certificate("CN=client",
                "CN=ca", -1, List.of(CLIENT_AUTH), usage(false, false), List.of(SPIFFE)),
                "TLSv1.3", NOW));
        assertThrows(SecurityException.class, () -> RiskHttpApi.spiffe(certificate("CN=client",
                "CN=ca", -1, List.of(CLIENT_AUTH), null, List.of(SPIFFE)), "TLSv1.3", NOW));
        assertThrows(SecurityException.class, () -> RiskHttpApi.spiffe(certificate("CN=client",
                "CN=ca", -1, List.of(CLIENT_AUTH), usage(true, false),
                List.of(SPIFFE, SPIFFE)), "TLSv1.3", NOW));
        for (String invalid : List.of("spiffe://a..b/workload",
                "spiffe://-bad.example/workload", "spiffe://bad-.example/workload",
                "spiffe://" + "a".repeat(64) + ".example/workload",
                "spiffe://" + ("a".repeat(63) + ".").repeat(4) + "a/workload")) {
            assertThrows(SecurityException.class, () -> RiskHttpApi.spiffe(certificate(
                    "CN=client", "CN=ca", -1, List.of(CLIENT_AUTH), usage(true, false),
                    List.of(invalid)), "TLSv1.3", NOW));
        }
    }

    @Test
    void workloadChainsAndTrustAnchorsRequireCaAndKeyCertSignUsage() {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        PolicyCertificate leaf = certificate("CN=risk", "CN=ca", -1,
                List.of(SERVER_AUTH), usage(true, false), List.of());
        PolicyCertificate authority = certificate("CN=ca", "CN=ca", 1,
                List.of(), usage(false, true), List.of());
        assertDoesNotThrow(() -> RiskTlsContexts.validateChain(List.of(leaf, authority),
                SERVER_AUTH, clock));
        assertDoesNotThrow(() -> RiskTlsContexts.validateAuthorities(List.of(authority), clock));

        PolicyCertificate noSigningUsage = certificate("CN=ca", "CN=ca", 1,
                List.of(), usage(false, false), List.of());
        assertThrows(Exception.class, () -> RiskTlsContexts.validateChain(
                List.of(leaf, noSigningUsage), SERVER_AUTH, clock));
        assertThrows(Exception.class,
                () -> RiskTlsContexts.validateAuthorities(List.of(noSigningUsage), clock));
        assertThrows(Exception.class, () -> RiskTlsContexts.validateChain(List.of(certificate(
                "CN=risk", "CN=ca", -1, List.of(SERVER_AUTH), usage(false, false),
                List.of()), authority), SERVER_AUTH, clock));
    }

    private static boolean[] usage(boolean digitalSignature, boolean certificateSigning) {
        boolean[] usage = new boolean[9];
        usage[0] = digitalSignature;
        usage[5] = certificateSigning;
        return usage;
    }

    private static PolicyCertificate certificate(String subject, String issuer,
            int basicConstraints, List<String> extendedUsage, boolean[] keyUsage,
            List<String> uriSans) {
        return new PolicyCertificate(new X500Principal(subject), new X500Principal(issuer),
                basicConstraints, extendedUsage, keyUsage, uriSans,
                Date.from(NOW.minusSeconds(60)), Date.from(NOW.plusSeconds(600)));
    }

    @SuppressWarnings("deprecation")
    private static final class PolicyCertificate extends X509Certificate {
        private static final long serialVersionUID = 1L;
        private final X500Principal subject;
        private final X500Principal issuer;
        private final int basicConstraints;
        private final transient List<String> extendedUsage;
        private final boolean[] keyUsage;
        private final transient List<String> uriSans;
        private final Date notBefore;
        private final Date notAfter;

        private PolicyCertificate(X500Principal subject, X500Principal issuer,
                int basicConstraints, List<String> extendedUsage, boolean[] keyUsage,
                List<String> uriSans, Date notBefore, Date notAfter) {
            this.subject = subject;
            this.issuer = issuer;
            this.basicConstraints = basicConstraints;
            this.extendedUsage = List.copyOf(extendedUsage);
            this.keyUsage = keyUsage == null ? null : keyUsage.clone();
            this.uriSans = List.copyOf(uriSans);
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
        @Override public Principal getIssuerDN() { return issuer; }
        @Override public Principal getSubjectDN() { return subject; }
        @Override public X500Principal getIssuerX500Principal() { return issuer; }
        @Override public X500Principal getSubjectX500Principal() { return subject; }
        @Override public Date getNotBefore() { return new Date(notBefore.getTime()); }
        @Override public Date getNotAfter() { return new Date(notAfter.getTime()); }
        @Override public byte[] getTBSCertificate() { return new byte[] {1}; }
        @Override public byte[] getSignature() { return new byte[] {1}; }
        @Override public String getSigAlgName() { return "NONE"; }
        @Override public String getSigAlgOID() { return "0.0"; }
        @Override public byte[] getSigAlgParams() { return null; }
        @Override public boolean[] getIssuerUniqueID() { return null; }
        @Override public boolean[] getSubjectUniqueID() { return null; }
        @Override public boolean[] getKeyUsage() {
            return keyUsage == null ? null : keyUsage.clone();
        }
        @Override public List<String> getExtendedKeyUsage() { return extendedUsage; }
        @Override public int getBasicConstraints() { return basicConstraints; }
        @Override public Collection<List<?>> getSubjectAlternativeNames() {
            return uriSans.stream().<List<?>>map(
                    value -> List.of(Integer.valueOf(6), value)).toList();
        }
        @Override public byte[] getEncoded() { return new byte[] {1, 2, 3}; }
        @Override public void verify(PublicKey key) { }
        @Override public void verify(PublicKey key, String provider) { }
        @Override public String toString() { return "risk policy certificate"; }
        @Override public PublicKey getPublicKey() { return null; }
        @Override public Set<String> getCriticalExtensionOIDs() { return Set.of(); }
        @Override public Set<String> getNonCriticalExtensionOIDs() { return Set.of(); }
        @Override public byte[] getExtensionValue(String oid) { return null; }
        @Override public boolean hasUnsupportedCriticalExtension() { return false; }
    }
}
