package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sun.net.httpserver.Headers;
import java.math.BigInteger;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

final class AdminActionPeerVerifierTest {
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");
    private static final String SPIFFE = "spiffe://elmpay.example/admin-web";

    @Test
    void exactTlsSessionSpiffeClientIdentityIsAccepted() {
        AdminActionPeerVerifier verifier = new AdminActionPeerVerifier(SPIFFE,
                Clock.fixed(NOW, ZoneOffset.UTC));
        assertDoesNotThrow(() -> verifier.verify(new TestHttpsExchange(new Headers(),
                certificate(SPIFFE, true, true))));
    }

    @Test
    void forgedHeaderWrongSpiffeAndMissingClientPurposeFailClosed() {
        AdminActionPeerVerifier verifier = new AdminActionPeerVerifier(SPIFFE,
                Clock.fixed(NOW, ZoneOffset.UTC));
        Headers forged = new Headers();
        forged.set("X-Forwarded-Client-Cert", "spiffe=" + SPIFFE);
        assertThrows(AdminActionException.class, () -> verifier.verify(
                new TestHttpsExchange(forged, certificate(SPIFFE, true, true))));
        assertThrows(AdminActionException.class, () -> verifier.verify(
                new TestHttpsExchange(new Headers(),
                        certificate("spiffe://elmpay.example/other", true, true))));
        assertThrows(AdminActionException.class, () -> verifier.verify(
                new TestHttpsExchange(new Headers(), certificate(SPIFFE, false, true))));
        assertThrows(AdminActionException.class, () -> verifier.verify(
                new TestHttpsExchange(new Headers(), certificate(SPIFFE, true, false))));
        assertThrows(AdminActionException.class, () -> verifier.verify(
                new TestHttpsExchange(new Headers(), certificate(
                        List.of(SPIFFE, SPIFFE), true, true))));
    }

    @Test
    void configuredSpiffeIdentityMustBeCanonical() {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        for (String invalid : List.of("spiffe://elmpay.example/admin-web/",
                "spiffe://elmpay.example/admin/../admin-web",
                "spiffe://ELMPAY.example/admin-web",
                "spiffe://elmpay.example/admin//web",
                "spiffe://elmpay..example/admin-web",
                "spiffe://-elmpay.example/admin-web",
                "spiffe://elmpay-.example/admin-web",
                "spiffe://user@elmpay.example/admin-web?role=admin")) {
            assertThrows(IllegalArgumentException.class,
                    () -> new AdminActionPeerVerifier(invalid, clock));
        }
    }

    @SuppressWarnings("deprecation")
    private static X509Certificate certificate(String spiffe, boolean clientPurpose,
            boolean digitalSignature) {
        return certificate(List.of(spiffe), clientPurpose, digitalSignature);
    }

    @SuppressWarnings("deprecation")
    private static X509Certificate certificate(List<String> spiffe, boolean clientPurpose,
            boolean digitalSignature) {
        return new X509Certificate() {
            @Override public void checkValidity() throws CertificateExpiredException {
                checkValidity(Date.from(NOW));
            }
            @Override public void checkValidity(Date date) throws CertificateExpiredException {
                if (date.before(getNotBefore()) || date.after(getNotAfter())) {
                    throw new CertificateExpiredException("expired");
                }
            }
            @Override public int getVersion() { return 3; }
            @Override public BigInteger getSerialNumber() { return BigInteger.ONE; }
            @Override public Principal getIssuerDN() { return () -> "CN=admin-ca"; }
            @Override public Principal getSubjectDN() { return () -> "CN=admin-web"; }
            @Override public Date getNotBefore() { return Date.from(NOW.minusSeconds(60)); }
            @Override public Date getNotAfter() { return Date.from(NOW.plusSeconds(60)); }
            @Override public byte[] getTBSCertificate() { return new byte[] {1}; }
            @Override public byte[] getSignature() { return new byte[] {1}; }
            @Override public String getSigAlgName() { return "SHA256withECDSA"; }
            @Override public String getSigAlgOID() { return "1.2.840.10045.4.3.2"; }
            @Override public byte[] getSigAlgParams() { return null; }
            @Override public boolean[] getIssuerUniqueID() { return null; }
            @Override public boolean[] getSubjectUniqueID() { return null; }
            @Override public boolean[] getKeyUsage() {
                return new boolean[] {digitalSignature, false, false, false, false, false,
                        false, false, false};
            }
            @Override public int getBasicConstraints() { return -1; }
            @Override public byte[] getEncoded() throws CertificateEncodingException {
                return new byte[] {1, 2, 3};
            }
            @Override public void verify(PublicKey key) { }
            @Override public void verify(PublicKey key, String provider) { }
            @Override public String toString() { return "admin-web test certificate"; }
            @Override public PublicKey getPublicKey() { return null; }
            @Override public Set<String> getCriticalExtensionOIDs() { return Set.of(); }
            @Override public Set<String> getNonCriticalExtensionOIDs() { return Set.of(); }
            @Override public byte[] getExtensionValue(String oid) { return null; }
            @Override public boolean hasUnsupportedCriticalExtension() { return false; }
            @Override public List<String> getExtendedKeyUsage() {
                return clientPurpose ? List.of("1.3.6.1.5.5.7.3.2")
                        : List.of("1.3.6.1.5.5.7.3.1");
            }
            @Override public Collection<List<?>> getSubjectAlternativeNames() {
                return spiffe.stream().<List<?>>map(
                        value -> List.of(Integer.valueOf(6), value)).toList();
            }
        };
    }
}
