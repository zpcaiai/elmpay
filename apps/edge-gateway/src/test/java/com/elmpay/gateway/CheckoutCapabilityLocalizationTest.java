package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.payment.checkout.CapabilityResolver;
import com.elmpay.payment.checkout.CheckoutCapabilitySource;
import com.elmpay.payment.checkout.CheckoutLocalization;
import com.elmpay.payment.checkout.CheckoutTokenSigner;
import com.elmpay.payment.checkout.HostedCheckoutService;
import com.elmpay.payment.checkout.InMemoryCheckoutSessionRepository;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

final class CheckoutCapabilityLocalizationTest {
    private static final UUID TENANT = UUID.fromString(
            "62000000-0000-4000-8000-000000000001");
    private static final UUID PROJECT = UUID.fromString(
            "62000000-0000-4000-8000-000000000002");
    private static final UUID MERCHANT = UUID.fromString(
            "62000000-0000-4000-8000-000000000003");

    @Test
    void checkoutUsesTenantScopedRuntimeCapabilityAndVersionedLocale() {
        AtomicReference<CheckoutCapabilitySource.Request> observed = new AtomicReference<>();
        CheckoutCapabilitySource capabilities = request -> {
            observed.set(request);
            boolean web = "WEB".equals(request.deviceClass());
            return List.of(new CapabilityResolver.Decision("card", web,
                    web ? List.of() : List.of("DEVICE_UNSUPPORTED")));
        };
        HostedCheckoutService checkout = checkout(capabilities);
        HostedCheckoutService.Created created = checkout.create(
                new HostedCheckoutService.CreateCommand(TENANT, PROJECT, MERCHANT, "order-62",
                        1_234, "USD", "complete", "device-context-0000000062",
                        "checkout-capability-create-0001"));

        HostedCheckoutService.View chinese = checkout.getForPrincipal(TENANT, PROJECT,
                created.checkoutSessionId(), Locale.forLanguageTag("zh-CN"), "WEB");
        assertEquals("zh-CN", chinese.locale());
        assertEquals("银行卡", chinese.methods().getFirst().label());
        assertTrue(chinese.methods().getFirst().eligible());
        assertEquals("checkout-catalog-2026-08-v1", chinese.catalogVersion());
        assertEquals(TENANT, observed.get().tenantId());
        assertEquals(PROJECT, observed.get().projectId());
        assertEquals(MERCHANT, observed.get().merchantId());

        HostedCheckoutService.View arabic = checkout.getForPrincipal(TENANT, PROJECT,
                created.checkoutSessionId(), Locale.forLanguageTag("ar-SA"), "IOS");
        assertEquals("ar", arabic.locale());
        assertEquals("rtl", arabic.direction());
        assertFalse(arabic.methods().getFirst().eligible());
        assertEquals("DEVICE_UNSUPPORTED", arabic.methods().getFirst().reason());
        assertThrows(IllegalArgumentException.class, () -> checkout.confirmForPrincipal(TENANT,
                PROJECT, created.checkoutSessionId(), new HostedCheckoutService.ConfirmCommand(
                        "card", "psp://stripe/pm_62", "fp_62", Map.of(),
                        "checkout-capability-confirm-0001", "correlation-62"), Locale.ENGLISH,
                "IOS"));
    }

    private static HostedCheckoutService checkout(CheckoutCapabilitySource capabilities) {
        RuntimeComponents runtime = RuntimeFactory.create(Map.of(
                "ELMPAY_RUNTIME_MODE", "local", "ELMPAY_ENABLE_LOCAL_SANDBOX", "true",
                "ELMPAY_LOCAL_RISK_POLICY", "approve-sandbox", "ELMPAY_API_PRINCIPALS",
                ApiKeyAuthenticator.digestForProvisioning("checkout-capability-placeholder")
                        + "|test|" + TENANT + "|" + PROJECT + "|" + MERCHANT));
        byte[] signingKey = new byte[32];
        java.util.Arrays.fill(signingKey, (byte) 0x62);
        return new HostedCheckoutService(runtime.payments(),
                new InMemoryCheckoutSessionRepository(),
                new CheckoutTokenSigner(Map.of("checkout-capability-v1", signingKey),
                        "checkout-capability-v1"),
                Map.of("complete", URI.create("https://merchant.example/checkout/complete")),
                "complete", Set.of("card"), URI.create("http://127.0.0.1/checkout"),
                Duration.ofMinutes(10), "US", true, Clock.systemUTC(), capabilities,
                CheckoutLocalization.defaultCatalog());
    }
}
