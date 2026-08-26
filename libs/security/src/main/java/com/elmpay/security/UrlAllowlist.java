package com.elmpay.security;

import java.net.IDN;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/** Exact-host HTTPS allowlist with SSRF and open-redirect protections. */
public final class UrlAllowlist {
    private final Set<String> allowedHosts;

    public UrlAllowlist(Set<String> allowedHosts) {
        Objects.requireNonNull(allowedHosts, "allowedHosts");
        this.allowedHosts = allowedHosts.stream().map(UrlAllowlist::normalizeHost)
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        if (this.allowedHosts.isEmpty()) {
            throw new IllegalArgumentException("at least one callback host is required");
        }
    }

    public URI requireAllowed(String value) {
        URI uri = URI.create(value).normalize();
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                || uri.getUserInfo() != null || uri.getFragment() != null) {
            throw new IllegalArgumentException("callback must be a normalized HTTPS URI");
        }
        String host = normalizeHost(uri.getHost());
        if (!allowedHosts.contains(host) || isForbiddenLiteral(host)) {
            throw new IllegalArgumentException("callback host is not registered");
        }
        return uri;
    }

    private static String normalizeHost(String host) {
        String value = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
        return value.endsWith(".") ? value.substring(0, value.length() - 1) : value;
    }

    private static boolean isForbiddenLiteral(String host) {
        if (!host.matches("[0-9a-fA-F:.]+")) {
            return false;
        }
        try {
            InetAddress address = InetAddress.getByName(host);
            return address.isAnyLocalAddress() || address.isLoopbackAddress()
                    || address.isLinkLocalAddress() || address.isSiteLocalAddress()
                    || address.isMulticastAddress();
        } catch (UnknownHostException exception) {
            return true;
        }
    }
}
