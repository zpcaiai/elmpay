package com.elmpay.payment.provider;

import com.elmpay.security.MountedHttpsClient;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import javax.net.ssl.SSLContext;
import javax.sql.DataSource;

/** Creates the five built-in production provider factories from fail-closed configuration. */
public final class ProductionProviderAccountFactories {
    private ProductionProviderAccountFactories() {
    }

    public static List<ProviderAccountAdapterFactory> create(DataSource dataSource,
            Map<String, String> environment, Clock clock) {
        SSLContext mutualTls = MountedHttpsClient.mutualTlsContextFromEnvironment(environment,
                "ELMPAY_APPLE_PAY_PSP", "apple-pay-psp-client", clock);
        return create(dataSource, environment, clock, mutualTls);
    }

    static List<ProviderAccountAdapterFactory> create(DataSource dataSource,
            Map<String, String> environment, Clock clock, SSLContext applePspMutualTls) {
        ProviderRuntimeLookup lookup = new JdbcProviderRuntimeLookup(dataSource);
        Duration timeout = Duration.ofMillis(number(environment,
                "ELMPAY_PROVIDER_TIMEOUT_MILLISECONDS", 2_000, 1, 10_000));
        Duration tolerance = Duration.ofSeconds(number(environment,
                "ELMPAY_PROVIDER_WEBHOOK_TOLERANCE_SECONDS", 300, 30, 3_600));
        int attempts = Math.toIntExact(number(environment,
                "ELMPAY_PROVIDER_MAX_ATTEMPTS", 2, 1, 3));
        ApprovedReturnRouteRegistry routes = new ApprovedReturnRouteRegistry(
                routes(required(environment, "ELMPAY_CHECKOUT_RETURN_ROUTES")));
        return List.of(
                new WechatAccountAdapterFactory(lookup,
                        uri(environment, "ELMPAY_WECHAT_NOTIFY_URI"), timeout, tolerance,
                        attempts, clock),
                new AlipayAccountAdapterFactory(lookup, routes,
                        uri(environment, "ELMPAY_ALIPAY_NOTIFY_URI"), timeout, attempts, clock),
                new StripeAccountAdapterFactory(lookup,
                        directoryUri(environment, "ELMPAY_STRIPE_RETURN_BASE"), timeout,
                        tolerance, attempts, clock),
                new PayPalAccountAdapterFactory(lookup,
                        directoryUri(environment, "ELMPAY_PAYPAL_CHECKOUT_BASE"),
                        csv(environment, "ELMPAY_PAYPAL_CERTIFICATE_HOSTS"), timeout, attempts,
                        clock),
                new ApplePayAccountAdapterFactory(dataSource,
                        uri(environment, "ELMPAY_APPLE_PAY_PSP_FORWARD_ENDPOINT"),
                        java.util.Objects.requireNonNull(applePspMutualTls,
                                "applePspMutualTls"),
                        timeout, clock));
    }

    static Map<String, URI> routes(String configured) {
        Map<String, URI> routes = new LinkedHashMap<>();
        for (String item : configured.split(",", -1)) {
            String[] fields = item.strip().split("=", 2);
            if (fields.length != 2 || fields[0].isBlank() || fields[1].isBlank()) {
                throw new IllegalStateException("ELMPAY_CHECKOUT_RETURN_ROUTES is invalid");
            }
            URI value = requireHttps(URI.create(fields[1]));
            if (routes.putIfAbsent(fields[0], value) != null) {
                throw new IllegalStateException("checkout return route is duplicated");
            }
        }
        if (routes.isEmpty()) {
            throw new IllegalStateException("checkout return routes are required");
        }
        return Map.copyOf(routes);
    }

    private static Set<String> csv(Map<String, String> environment, String key) {
        Set<String> values = Arrays.stream(required(environment, key).split(",", -1))
                .map(String::strip).filter(value -> !value.isBlank())
                .collect(Collectors.toUnmodifiableSet());
        if (values.isEmpty()) {
            throw new IllegalStateException(key + " is empty");
        }
        return values;
    }

    private static URI uri(Map<String, String> environment, String key) {
        return requireHttps(URI.create(required(environment, key)));
    }

    private static URI directoryUri(Map<String, String> environment, String key) {
        URI value = uri(environment, key);
        if (!value.getPath().endsWith("/") || value.getQuery() != null) {
            throw new IllegalStateException(key + " must be an HTTPS directory URI");
        }
        return value;
    }

    private static URI requireHttps(URI value) {
        if (!"https".equalsIgnoreCase(value.getScheme()) || value.getHost() == null
                || value.getUserInfo() != null || value.getFragment() != null) {
            throw new IllegalStateException("provider runtime endpoint must be HTTPS");
        }
        return value;
    }

    private static long number(Map<String, String> environment, String key, long fallback,
            long minimum, long maximum) {
        String configured = environment.get(key);
        long value = fallback;
        if (configured != null && !configured.isBlank()) {
            try {
                value = Long.parseLong(configured);
            } catch (NumberFormatException exception) {
                throw new IllegalStateException(key + " is invalid", exception);
            }
        }
        if (value < minimum || value > maximum) {
            throw new IllegalStateException(key + " is outside its safe bound");
        }
        return value;
    }

    private static String required(Map<String, String> environment, String key) {
        String value = environment.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(key + " is required");
        }
        return value;
    }
}
