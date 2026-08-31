package com.elmpay.gateway;

import com.elmpay.payment.PaymentService;
import com.elmpay.payment.checkout.CheckoutCapabilitySource;
import com.elmpay.payment.checkout.CheckoutLocalization;
import com.elmpay.payment.checkout.CheckoutSessionRepository;
import com.elmpay.payment.checkout.CheckoutTokenSigner;
import com.elmpay.payment.checkout.ConfiguredCheckoutCapabilitySource;
import com.elmpay.payment.checkout.CheckoutProviderSdkSource;
import com.elmpay.payment.checkout.HostedCheckoutService;
import com.elmpay.payment.checkout.InMemoryCheckoutSessionRepository;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/** Builds checkout signing configuration without allowing production defaults. */
public final class CheckoutRuntimeFactory {
    public record Runtime(HostedCheckoutService checkout,
            CheckoutProviderSdkRuntime providerSdk) {
    }

    private CheckoutRuntimeFactory() {
    }

    public static HostedCheckoutService create(PaymentService payments, String runtimeMode,
            Map<String, String> environment) {
        return createRuntime(payments, runtimeMode, environment).checkout();
    }

    public static Runtime createRuntime(PaymentService payments, String runtimeMode,
            Map<String, String> environment) {
        return switch (runtimeMode) {
            case "local" -> localRuntime(payments, environment);
            case "postgres" -> productionRuntime(payments, environment);
            default -> throw new IllegalStateException("checkout runtime mode is unsupported");
        };
    }

    static HostedCheckoutService local(PaymentService payments) {
        return local(payments, Map.of());
    }

    private static HostedCheckoutService local(PaymentService payments,
            Map<String, String> environment) {
        return localRuntime(payments, environment).checkout();
    }

    private static Runtime localRuntime(PaymentService payments,
            Map<String, String> environment) {
        Map<String, URI> routes = Map.of("checkout-complete",
                URI.create("https://merchant.example/checkout/complete"));
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, (byte) 0x4c);
        URI publicBase = URI.create(environment.getOrDefault("ELMPAY_CHECKOUT_PUBLIC_BASE_URL",
                "http://127.0.0.1:8081/"));
        HostedCheckoutService checkout = service(payments, Map.of("local-v1", key), "local-v1", routes,
                "checkout-complete", Set.of("card"), publicBase, Duration.ofMinutes(10), "US",
                true, new InMemoryCheckoutSessionRepository(),
                new ConfiguredCheckoutCapabilitySource(Set.of("card")),
                CheckoutProviderSdkSource.disabled());
        return new Runtime(checkout, new CheckoutProviderSdkRuntime(checkout,
                CheckoutProviderSdkRegistry.fromClasspath(environment), ignored -> {
                }, Clock.systemUTC()));
    }

    private static Runtime productionRuntime(PaymentService payments,
            Map<String, String> environment) {
        if (environment.containsKey("ELMPAY_CHECKOUT_SIGNING_KEY_B64")) {
            throw new IllegalStateException(
                    "ELMPAY_CHECKOUT_SIGNING_KEY_B64 is forbidden; use the read-only key mount");
        }
        String keyId = required(environment, "ELMPAY_CHECKOUT_SIGNING_KEY_ID");
        if (!keyId.matches("[A-Za-z0-9._-]{1,64}")) {
            throw new IllegalStateException("ELMPAY_CHECKOUT_SIGNING_KEY_ID is invalid");
        }
        byte[] key = decodeKey(MountedSecretFiles.readUtf8(required(environment,
                "ELMPAY_CHECKOUT_SIGNING_KEY_FILE"), "checkout signing key", 8_192));
        Map<String, URI> routes = parseRoutes(required(environment,
                "ELMPAY_CHECKOUT_RETURN_ROUTES"));
        String defaultRoute = required(environment, "ELMPAY_CHECKOUT_DEFAULT_RETURN_ROUTE_ID");
        Set<String> methods = java.util.Arrays.stream(required(environment,
                        "ELMPAY_CHECKOUT_ALLOWED_METHODS").split(","))
                .map(String::trim).filter(value -> !value.isEmpty()).collect(Collectors.toSet());
        URI publicBase = URI.create(required(environment, "ELMPAY_CHECKOUT_PUBLIC_BASE_URL"));
        if (!"https".equalsIgnoreCase(publicBase.getScheme())) {
            throw new IllegalStateException(
                    "production ELMPAY_CHECKOUT_PUBLIC_BASE_URL must use HTTPS");
        }
        long ttlSeconds;
        try {
            ttlSeconds = Long.parseLong(environment.getOrDefault(
                    "ELMPAY_CHECKOUT_SESSION_TTL_SECONDS", "600"));
        } catch (NumberFormatException invalid) {
            throw new IllegalStateException("ELMPAY_CHECKOUT_SESSION_TTL_SECONDS is invalid",
                    invalid);
        }
        var dataSource = DriverManagerDataSource.fromEnvironment(environment,
                "elmpay-edge-checkout");
        HostedCheckoutService checkout;
        try {
            checkout = service(payments, Map.of(keyId, key), keyId, routes,
                    defaultRoute, methods,
                    publicBase, Duration.ofSeconds(ttlSeconds),
                    required(environment, "ELMPAY_CHECKOUT_REGION"), false,
                    new JdbcCheckoutSessionRepository(dataSource),
                    new JdbcCheckoutCapabilitySource(dataSource),
                    new JdbcCheckoutProviderSdkSource(dataSource));
        } finally {
            java.util.Arrays.fill(key, (byte) 0);
        }
        return new Runtime(checkout, new CheckoutProviderSdkRuntime(checkout,
                CheckoutProviderSdkRegistry.fromClasspath(environment),
                new JdbcCheckoutProviderSdkAudit(dataSource), Clock.systemUTC()));
    }

    private static HostedCheckoutService service(PaymentService payments, Map<String, byte[]> keys,
            String activeKeyId, Map<String, URI> routes, String defaultRoute, Set<String> methods,
            URI publicBase, Duration ttl, String region, CheckoutSessionRepository repository,
            CheckoutCapabilitySource capabilitySource) {
        return service(payments, keys, activeKeyId, routes, defaultRoute, methods, publicBase, ttl,
                region, true, repository, capabilitySource, CheckoutProviderSdkSource.disabled());
    }

    private static HostedCheckoutService service(PaymentService payments, Map<String, byte[]> keys,
            String activeKeyId, Map<String, URI> routes, String defaultRoute, Set<String> methods,
            URI publicBase, Duration ttl, String region, boolean allowSyntheticPaymentReference,
            CheckoutSessionRepository repository, CheckoutCapabilitySource capabilitySource,
            CheckoutProviderSdkSource providerSdkSource) {
        Clock clock = Clock.systemUTC();
        return new HostedCheckoutService(payments, repository,
                new CheckoutTokenSigner(keys, activeKeyId), routes, defaultRoute, methods,
                publicBase, ttl, region, allowSyntheticPaymentReference, clock,
                capabilitySource, CheckoutLocalization.defaultCatalog(), providerSdkSource);
    }

    private static Map<String, URI> parseRoutes(String configuration) {
        Map<String, URI> routes = new LinkedHashMap<>();
        for (String item : configuration.split(",")) {
            String[] fields = item.trim().split("=", 2);
            if (fields.length != 2 || !fields[0].matches("[a-z0-9][a-z0-9._-]{0,63}")) {
                throw new IllegalStateException("ELMPAY_CHECKOUT_RETURN_ROUTES is invalid");
            }
            URI uri = URI.create(fields[1]);
            if (routes.putIfAbsent(fields[0], uri) != null) {
                throw new IllegalStateException("checkout return route is duplicated");
            }
        }
        if (routes.isEmpty()) {
            throw new IllegalStateException("checkout return routes are required");
        }
        return Map.copyOf(routes);
    }

    private static byte[] decodeKey(String encoded) {
        byte[] key;
        try {
            key = Base64.getUrlDecoder().decode(encoded);
        } catch (IllegalArgumentException failure) {
            throw new IllegalStateException("ELMPAY_CHECKOUT_SIGNING_KEY_FILE is invalid",
                    failure);
        }
        if (key.length < 32 || !Base64.getUrlEncoder().withoutPadding()
                .encodeToString(key).equals(encoded)) {
            java.util.Arrays.fill(key, (byte) 0);
            throw new IllegalStateException(
                    "checkout signing key must be canonical base64url with at least 256 bits");
        }
        return key;
    }

    private static String required(Map<String, String> environment, String key) {
        String value = environment.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(key + " is required");
        }
        return value;
    }
}
