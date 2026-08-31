package com.elmpay.gateway;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsExchange;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.net.ssl.SSLPeerUnverifiedException;

/** Authorizes the admin-web workload only from the TLS session, never proxy headers. */
public final class AdminActionPeerVerifier {
    private static final String CLIENT_AUTH_EKU = "1.3.6.1.5.5.7.3.2";
    private static final Set<String> FORBIDDEN_HEADERS = Set.of("forwarded",
            "x-forwarded-client-cert", "x-forwarded-for", "x-forwarded-host",
            "x-forwarded-proto", "x-forwarded-port", "x-real-ip", "x-client-cert",
            "x-elmpay-client-certificate", "x-envoy-external-address",
            "x-original-forwarded-for", "x-proxy-user");

    private final String expectedSpiffeId;
    private final Clock clock;

    public AdminActionPeerVerifier(String expectedSpiffeId, Clock clock) {
        this.expectedSpiffeId = requireSpiffeId(expectedSpiffeId);
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public static AdminActionPeerVerifier fromEnvironment(Map<String, String> environment,
            Clock clock) {
        Objects.requireNonNull(environment, "environment");
        String identity = environment.get("ELMPAY_ADMIN_ACTION_EXPECTED_SPIFFE_ID");
        if (identity == null || identity.isBlank()) {
            throw new IllegalStateException(
                    "ELMPAY_ADMIN_ACTION_EXPECTED_SPIFFE_ID is required");
        }
        return new AdminActionPeerVerifier(identity, clock);
    }

    public void verify(HttpExchange exchange) {
        Objects.requireNonNull(exchange, "exchange");
        if (!(exchange instanceof HttpsExchange secure)) {
            throw new AdminActionException("ADMIN_PEER_UNAUTHENTICATED",
                    "admin action API requires mutual TLS");
        }
        for (String header : exchange.getRequestHeaders().keySet()) {
            String canonical = header.toLowerCase(Locale.ROOT);
            if (FORBIDDEN_HEADERS.contains(canonical) || canonical.startsWith("ssl-client-")
                    || canonical.startsWith("x-forwarded-user")) {
                throw new AdminActionException("ADMIN_PEER_UNAUTHENTICATED",
                        "client identity forwarding headers are forbidden");
            }
        }
        try {
            if (!"TLSv1.3".equals(secure.getSSLSession().getProtocol())) {
                throw new GeneralSecurityException("TLS protocol is not TLS 1.3");
            }
            Certificate[] chain = secure.getSSLSession().getPeerCertificates();
            if (chain.length < 1 || !(chain[0] instanceof X509Certificate leaf)) {
                throw new GeneralSecurityException("peer certificate is unavailable");
            }
            leaf.checkValidity(Date.from(clock.instant()));
            if (leaf.getBasicConstraints() >= 0) {
                throw new GeneralSecurityException("peer leaf is a certificate authority");
            }
            boolean[] keyUsage = leaf.getKeyUsage();
            if (keyUsage == null || keyUsage.length == 0 || !keyUsage[0]) {
                throw new GeneralSecurityException("peer certificate cannot sign TLS handshakes");
            }
            List<String> extended = leaf.getExtendedKeyUsage();
            if (extended == null || !extended.contains(CLIENT_AUTH_EKU)) {
                throw new GeneralSecurityException("peer certificate is not a TLS client");
            }
            if (!uriSans(leaf).equals(List.of(expectedSpiffeId))) {
                throw new GeneralSecurityException("peer SPIFFE identity is not authorized");
            }
        } catch (SSLPeerUnverifiedException | GeneralSecurityException failure) {
            throw new AdminActionException("ADMIN_PEER_UNAUTHENTICATED",
                    "admin action peer authentication failed", failure);
        }
    }

    private static List<String> uriSans(X509Certificate certificate)
            throws CertificateParsingException {
        Collection<List<?>> alternatives = certificate.getSubjectAlternativeNames();
        if (alternatives == null) {
            return List.of();
        }
        List<String> uris = new ArrayList<>();
        for (List<?> alternative : alternatives) {
            if (alternative.size() == 2 && Integer.valueOf(6).equals(alternative.get(0))
                    && alternative.get(1) instanceof String uri && !uri.isBlank()) {
                uris.add(uri);
            }
        }
        return List.copyOf(uris);
    }

    private static String requireSpiffeId(String value) {
        Objects.requireNonNull(value, "expectedSpiffeId");
        URI identity;
        try {
            identity = URI.create(value);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("expected admin SPIFFE identity is invalid",
                    invalid);
        }
        String path = identity.getRawPath();
        String host = identity.getHost();
        if (!"spiffe".equals(identity.getScheme()) || identity.getRawUserInfo() != null
                || identity.getPort() != -1 || identity.getRawQuery() != null
                || identity.getRawFragment() != null || host == null
                || !validTrustDomain(host)
                || !host.equals(host.toLowerCase(Locale.ROOT))
                || !host.equals(identity.getRawAuthority()) || path == null
                || !path.startsWith("/") || path.length() < 2 || path.endsWith("/")
                || path.indexOf('%') >= 0 || !path.equals(identity.getPath())
                || !identity.equals(identity.normalize())) {
            throw new IllegalArgumentException("expected admin SPIFFE identity is invalid");
        }
        for (String segment : path.substring(1).split("/", -1)) {
            if (segment.isEmpty() || ".".equals(segment) || "..".equals(segment)
                    || !segment.matches("[A-Za-z0-9._-]{1,128}")) {
                throw new IllegalArgumentException("expected admin SPIFFE identity is invalid");
            }
        }
        return value;
    }

    private static boolean validTrustDomain(String host) {
        if (host.length() > 253 || host.startsWith(".") || host.endsWith(".")) {
            return false;
        }
        String[] labels = host.split("\\.", -1);
        if (labels.length == 0) {
            return false;
        }
        for (String label : labels) {
            if (label.length() < 1 || label.length() > 63
                    || !asciiAlphanumeric(label.charAt(0))
                    || !asciiAlphanumeric(label.charAt(label.length() - 1))) {
                return false;
            }
            for (int index = 0; index < label.length(); index++) {
                char character = label.charAt(index);
                if (!(asciiAlphanumeric(character) || character == '-')) {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean asciiAlphanumeric(char character) {
        return (character >= 'a' && character <= 'z')
                || (character >= '0' && character <= '9');
    }
}
