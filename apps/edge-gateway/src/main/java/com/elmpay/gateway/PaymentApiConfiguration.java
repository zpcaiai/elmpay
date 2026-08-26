package com.elmpay.gateway;

import java.time.Duration;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/** Server-authoritative Payment Intent defaults and allowlists. */
public record PaymentApiConfiguration(String region, Duration intentTtl,
        Set<String> defaultAllowedMethods, Set<String> returnRouteIds) {
    private static final Set<String> CONTRACT_METHODS = Set.of(
            "wechat_jsapi", "wechat_native", "wechat_h5", "wechat_app",
            "alipay_web", "alipay_wap", "alipay_app", "alipay_qr",
            "stripe_card", "paypal", "apple_pay");

    public PaymentApiConfiguration {
        region = normalizeRegion(region);
        if (intentTtl == null || intentTtl.compareTo(Duration.ofMinutes(1)) < 0
                || intentTtl.compareTo(Duration.ofHours(24)) > 0) {
            throw new IllegalArgumentException("payment intent TTL must be between 1 minute and 24 hours");
        }
        defaultAllowedMethods = normalizeMethods(defaultAllowedMethods);
        if (returnRouteIds == null || returnRouteIds.isEmpty()) {
            throw new IllegalArgumentException("at least one payment return route is required");
        }
        returnRouteIds = returnRouteIds.stream().map(PaymentApiConfiguration::normalizeRoute)
                .collect(Collectors.toUnmodifiableSet());
    }

    static PaymentApiConfiguration from(Map<String, String> environment, boolean local) {
        String region = environment.get("ELMPAY_PAYMENT_REGION");
        String ttl = environment.get("ELMPAY_PAYMENT_INTENT_TTL_MINUTES");
        String methods = environment.get("ELMPAY_PAYMENT_DEFAULT_METHODS");
        String routes = environment.get("ELMPAY_PAYMENT_RETURN_ROUTE_IDS");
        if (local) {
            region = defaultIfBlank(region, "US");
            ttl = defaultIfBlank(ttl, "60");
            methods = defaultIfBlank(methods, "stripe_card");
            routes = defaultIfBlank(routes, "checkout-complete");
        } else if (blank(region) || blank(ttl) || blank(methods) || blank(routes)) {
            throw new IllegalStateException("PostgreSQL mode requires ELMPAY_PAYMENT_REGION, "
                    + "ELMPAY_PAYMENT_INTENT_TTL_MINUTES, ELMPAY_PAYMENT_DEFAULT_METHODS, and "
                    + "ELMPAY_PAYMENT_RETURN_ROUTE_IDS");
        }
        long minutes;
        try {
            minutes = Long.parseLong(ttl);
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("ELMPAY_PAYMENT_INTENT_TTL_MINUTES must be an integer",
                    exception);
        }
        return new PaymentApiConfiguration(region, Duration.ofMinutes(minutes), csv(methods),
                csv(routes));
    }

    public Set<String> allowedMethods(Set<String> requested) {
        if (requested == null) {
            return defaultAllowedMethods;
        }
        Set<String> normalized = normalizeMethods(requested);
        if (!defaultAllowedMethods.containsAll(normalized)) {
            throw new IllegalArgumentException(
                    "requested payment method is outside the server-configured allowlist");
        }
        return normalized;
    }

    public String approvedReturnRoute(String routeId) {
        if (routeId == null) {
            return null;
        }
        String normalized = normalizeRoute(routeId);
        if (!returnRouteIds.contains(normalized)) {
            throw new IllegalArgumentException("return_url_token is not a registered route");
        }
        return normalized;
    }

    private static Set<String> normalizeMethods(Set<String> values) {
        if (values == null || values.isEmpty()) {
            throw new IllegalArgumentException("at least one allowed payment method is required");
        }
        Set<String> normalized = values.stream().map(value -> value == null ? ""
                        : value.toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
        if (normalized.size() != values.size() || !CONTRACT_METHODS.containsAll(normalized)) {
            throw new IllegalArgumentException("allowed payment methods do not satisfy the contract");
        }
        return normalized;
    }

    private static String normalizeRegion(String value) {
        if (value == null || !value.matches("[A-Za-z]{2,8}")) {
            throw new IllegalArgumentException("payment region is invalid");
        }
        return value.toUpperCase(Locale.ROOT);
    }

    private static String normalizeRoute(String value) {
        if (value == null || !value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) {
            throw new IllegalArgumentException("payment return route identifier is invalid");
        }
        return value;
    }

    private static Set<String> csv(String value) {
        return Arrays.stream(value.split(",", -1)).map(String::trim)
                .collect(Collectors.toUnmodifiableSet());
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static String defaultIfBlank(String value, String fallback) {
        return blank(value) ? fallback : value;
    }
}
