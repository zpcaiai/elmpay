package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

final class PaymentApiConfigurationTest {
    @Test
    void localModeUsesSafeDefaultsWhenValuesAreMissingOrBlank() {
        PaymentApiConfiguration defaults = PaymentApiConfiguration.from(Map.of(), true);
        PaymentApiConfiguration blankValues = PaymentApiConfiguration.from(Map.of(
                "ELMPAY_PAYMENT_REGION", " ",
                "ELMPAY_PAYMENT_INTENT_TTL_MINUTES", "",
                "ELMPAY_PAYMENT_DEFAULT_METHODS", " ",
                "ELMPAY_PAYMENT_RETURN_ROUTE_IDS", "\t"), true);

        assertEquals("US", defaults.region());
        assertEquals(Duration.ofMinutes(60), defaults.intentTtl());
        assertEquals(Set.of("stripe_card"), defaults.defaultAllowedMethods());
        assertEquals(Set.of("checkout-complete"), defaults.returnRouteIds());
        assertEquals(defaults, blankValues);
    }

    @Test
    void productionModeRequiresEveryServerOwnedValue() {
        assertThrows(IllegalStateException.class,
                () -> PaymentApiConfiguration.from(Map.of(), false));
        assertThrows(IllegalStateException.class, () -> PaymentApiConfiguration.from(Map.of(
                "ELMPAY_PAYMENT_REGION", "US",
                "ELMPAY_PAYMENT_INTENT_TTL_MINUTES", "60",
                "ELMPAY_PAYMENT_DEFAULT_METHODS", "stripe_card"), false));
    }

    @Test
    void environmentParsingTrimsCsvAndCanonicalizesRegionAndMethods() {
        PaymentApiConfiguration config = PaymentApiConfiguration.from(Map.of(
                "ELMPAY_PAYMENT_REGION", "uswest",
                "ELMPAY_PAYMENT_INTENT_TTL_MINUTES", "90",
                "ELMPAY_PAYMENT_DEFAULT_METHODS", " Stripe_Card, WeChat_Native ",
                "ELMPAY_PAYMENT_RETURN_ROUTE_IDS", " checkout.done,route:cancel-1 "), false);

        assertEquals("USWEST", config.region());
        assertEquals(Duration.ofMinutes(90), config.intentTtl());
        assertEquals(Set.of("stripe_card", "wechat_native"), config.defaultAllowedMethods());
        assertEquals(Set.of("checkout.done", "route:cancel-1"), config.returnRouteIds());
    }

    @Test
    void ttlMustBeAnIntegerWithinInclusiveContractBounds() {
        assertThrows(IllegalArgumentException.class, () -> PaymentApiConfiguration.from(Map.of(
                "ELMPAY_PAYMENT_REGION", "US",
                "ELMPAY_PAYMENT_INTENT_TTL_MINUTES", "one hour",
                "ELMPAY_PAYMENT_DEFAULT_METHODS", "stripe_card",
                "ELMPAY_PAYMENT_RETURN_ROUTE_IDS", "checkout.done"), false));
        assertThrows(IllegalArgumentException.class, () -> config(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> config(Duration.ofSeconds(59)));
        assertEquals(Duration.ofMinutes(1), config(Duration.ofMinutes(1)).intentTtl());
        assertEquals(Duration.ofHours(24), config(Duration.ofHours(24)).intentTtl());
        assertThrows(IllegalArgumentException.class,
                () -> config(Duration.ofHours(24).plusMinutes(1)));
    }

    @Test
    void constructorRejectsInvalidRegionsMethodsAndReturnRoutes() {
        assertThrows(IllegalArgumentException.class, () -> new PaymentApiConfiguration(null,
                Duration.ofMinutes(10), Set.of("stripe_card"), Set.of("checkout.done")));
        assertThrows(IllegalArgumentException.class, () -> new PaymentApiConfiguration("U1",
                Duration.ofMinutes(10), Set.of("stripe_card"), Set.of("checkout.done")));
        assertThrows(IllegalArgumentException.class, () -> new PaymentApiConfiguration("US",
                Duration.ofMinutes(10), null, Set.of("checkout.done")));
        assertThrows(IllegalArgumentException.class, () -> new PaymentApiConfiguration("US",
                Duration.ofMinutes(10), Set.of(), Set.of("checkout.done")));
        assertThrows(IllegalArgumentException.class, () -> new PaymentApiConfiguration("US",
                Duration.ofMinutes(10), Set.of("unknown_method"), Set.of("checkout.done")));
        assertThrows(IllegalArgumentException.class, () -> new PaymentApiConfiguration("US",
                Duration.ofMinutes(10), Set.of("stripe_card", "STRIPE_CARD"),
                Set.of("checkout.done")));
        assertThrows(IllegalArgumentException.class, () -> new PaymentApiConfiguration("US",
                Duration.ofMinutes(10), Set.of("stripe_card"), null));
        assertThrows(IllegalArgumentException.class, () -> new PaymentApiConfiguration("US",
                Duration.ofMinutes(10), Set.of("stripe_card"), Set.of()));
        assertThrows(IllegalArgumentException.class, () -> new PaymentApiConfiguration("US",
                Duration.ofMinutes(10), Set.of("stripe_card"), Set.of("../checkout")));
    }

    @Test
    void requestedMethodsMustStayInsideImmutableServerAllowlist() {
        PaymentApiConfiguration config = new PaymentApiConfiguration("US", Duration.ofMinutes(10),
                Set.of("stripe_card", "paypal"), Set.of("checkout.done"));

        assertEquals(Set.of("paypal"), config.allowedMethods(Set.of("PAYPAL")));
        assertEquals(config.defaultAllowedMethods(), config.allowedMethods(null));
        assertThrows(IllegalArgumentException.class,
                () -> config.allowedMethods(Set.of("wechat_native")));
        assertThrows(IllegalArgumentException.class, () -> config.allowedMethods(Set.of()));
        assertThrows(UnsupportedOperationException.class,
                () -> config.defaultAllowedMethods().add("wechat_native"));
        assertThrows(UnsupportedOperationException.class,
                () -> config.returnRouteIds().add("external.route"));
    }

    @Test
    void returnRouteIsAcceptedOnlyWhenRegisteredAndCanonical() {
        PaymentApiConfiguration config = new PaymentApiConfiguration("US", Duration.ofMinutes(10),
                Set.of("stripe_card"), Set.of("checkout.done", "route:cancel-1"));

        assertEquals("checkout.done", config.approvedReturnRoute("checkout.done"));
        assertEquals("route:cancel-1", config.approvedReturnRoute("route:cancel-1"));
        assertNull(config.approvedReturnRoute(null));
        assertThrows(IllegalArgumentException.class,
                () -> config.approvedReturnRoute("attacker.example"));
        assertThrows(IllegalArgumentException.class,
                () -> config.approvedReturnRoute("bad route"));
    }

    private static PaymentApiConfiguration config(Duration ttl) {
        return new PaymentApiConfiguration("US", ttl, Set.of("stripe_card"),
                Set.of("checkout.done"));
    }
}
