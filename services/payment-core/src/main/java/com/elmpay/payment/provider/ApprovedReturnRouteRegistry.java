package com.elmpay.payment.provider;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** Immutable allowlist mapping opaque return-route IDs to HTTPS merchant routes. */
public final class ApprovedReturnRouteRegistry {
    private final Map<String, URI> routes;

    public ApprovedReturnRouteRegistry(Map<String, URI> routes) {
        Objects.requireNonNull(routes, "routes");
        Map<String, URI> copy = new LinkedHashMap<>();
        for (Map.Entry<String, URI> entry : routes.entrySet()) {
            String id = entry.getKey();
            URI uri = entry.getValue();
            if (id == null || !id.matches("[a-z0-9][a-z0-9._-]{0,63}")) {
                throw new IllegalArgumentException("approved return-route id is invalid");
            }
            requireHttps(uri);
            if (copy.putIfAbsent(id, uri) != null) {
                throw new IllegalArgumentException("approved return-route id is duplicated");
            }
        }
        if (copy.isEmpty()) {
            throw new IllegalArgumentException("approved return-route registry is empty");
        }
        this.routes = Map.copyOf(copy);
    }

    public URI resolve(String routeId) {
        URI result = routes.get(routeId);
        if (result == null) {
            throw new SecurityException("return route is not registered");
        }
        return result;
    }

    public java.util.Set<String> hosts() {
        return routes.values().stream().map(URI::getHost).collect(
                java.util.stream.Collectors.toUnmodifiableSet());
    }

    private static void requireHttps(URI value) {
        Objects.requireNonNull(value, "return route URI");
        if (!"https".equalsIgnoreCase(value.getScheme()) || value.getHost() == null
                || value.getUserInfo() != null || value.getFragment() != null) {
            throw new IllegalArgumentException("approved return route must be HTTPS");
        }
    }
}
