package com.elmpay.connectors.applepay;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.money.Money;
import com.elmpay.provider.CreatePaymentCommand;
import com.elmpay.provider.ProviderException;
import com.elmpay.provider.ProviderOutcome;
import com.elmpay.provider.ProviderRequestContext;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

final class ApplePayAdapterTest {
    private static final Instant NOW = Instant.parse("2026-08-26T00:00:00Z");

    @Test
    void forwardsOpaqueTokenToPspThenZeroizesEveryInternalCopy() {
        AtomicReference<ApplePayAdapter.PspRequest> retained = new AtomicReference<>();
        ApplePayAdapter adapter = new ApplePayAdapter(
                (tenant, merchant, domain, token, at) -> new ApplePayAdapter.Authorization(
                        ApplePayAdapter.Capability.AVAILABLE, "cert-v2"),
                (psp, request) -> {
                    retained.set(request);
                    assertEquals(ApplePayAdapter.Psp.STRIPE, psp);
                    assertTrue(new String(request.opaquePaymentToken(), StandardCharsets.UTF_8)
                            .contains("\"signature\""));
                    return new ApplePayAdapter.Result("pi_fixture123", "PROCESSING", false);
                });
        ApplePayAdapter.Request request = request(validToken());

        ApplePayAdapter.Result result = adapter.forward(request);

        assertEquals("pi_fixture123", result.providerPaymentId());
        assertTrue(allZero(retained.get().opaquePaymentToken()));
        assertTrue(allZero(request.opaquePaymentToken()));
    }

    @Test
    void rejectsRawPanAndDoesNotInvokePsp() {
        AtomicInteger calls = new AtomicInteger();
        ApplePayAdapter adapter = new ApplePayAdapter(
                (tenant, merchant, domain, token, at) -> new ApplePayAdapter.Authorization(
                        ApplePayAdapter.Capability.AVAILABLE, "cert-v2"),
                (psp, request) -> {
                    calls.incrementAndGet();
                    return new ApplePayAdapter.Result("pi_fixture123", "PROCESSING", false);
                });
        byte[] forbidden = "{\"data\":\"x\",\"signature\":\"s\",\"header\":{},"
                .concat("\"cardNumber\":\"4242424242424242\"}").getBytes(StandardCharsets.UTF_8);
        assertThrows(IllegalArgumentException.class, () -> adapter.forward(request(forbidden)));
        assertEquals(0, calls.get());
    }

    @Test
    void failsClosedForUnverifiedDomainAndSupportsNoWalletFallbackSignal() {
        ApplePayAdapter adapter = new ApplePayAdapter(
                (tenant, merchant, domain, token, at) -> new ApplePayAdapter.Authorization(
                        ApplePayAdapter.Capability.DOMAIN_NOT_VERIFIED, ""),
                (psp, request) -> new ApplePayAdapter.Result("never", "never", true));
        assertEquals(ApplePayAdapter.Capability.NO_WALLET,
                adapter.capability("tenant-001", "merchant-001", "pay.example.test", false, null, NOW));
        assertThrows(IllegalStateException.class, () -> adapter.forward(request(validToken())));
    }

    @Test
    void commonBridgeRunsCapabilityPreflightAndMissingConfigFailsClosed() {
        ApplePayAdapter adapter = new ApplePayAdapter(
                (tenant, merchant, domain, token, at) -> new ApplePayAdapter.Authorization(
                        ApplePayAdapter.Capability.AVAILABLE, "cert-v2"),
                (psp, request) -> new ApplePayAdapter.Result("pi_fixture123", "PROCESSING", false));
        ApplePayProviderBridge bridge = new ApplePayProviderBridge(new ApplePayProviderBridge.Runtime(
                adapter, Clock.fixed(NOW, ZoneOffset.UTC)));
        assertTrue(bridge.configured());
        assertEquals(ProviderOutcome.REQUIRES_ACTION, bridge.createPayment(command()).outcome());

        String previous = System.getProperty("elmpay.applePay.adapterFactory");
        System.clearProperty("elmpay.applePay.adapterFactory");
        try {
            ApplePayProviderBridge missing = new ApplePayProviderBridge();
            assertFalse(missing.configured());
            assertThrows(ProviderException.class, () -> missing.createPayment(command()));
        } finally {
            restore("elmpay.applePay.adapterFactory", previous);
        }
    }

    private static CreatePaymentCommand command() {
        ProviderRequestContext context = new ProviderRequestContext(
                UUID.fromString("50000000-0000-0000-0000-000000000001"),
                UUID.fromString("50000000-0000-0000-0000-000000000002"),
                UUID.fromString("50000000-0000-0000-0000-000000000003"),
                "idem-applepay-00000001", "corr-applepay", "cred-v1");
        return new CreatePaymentCommand(context,
                UUID.fromString("50000000-0000-0000-0000-000000000004"), "order_123456",
                Money.of(1250, "USD"), "apple_pay", null,
                Map.of("domain", "pay.example.test", "device_has_wallet", "true", "psp", "stripe"));
    }

    private static void restore(String name, String value) {
        if (value == null) System.clearProperty(name); else System.setProperty(name, value);
    }

    private static ApplePayAdapter.Request request(byte[] token) {
        return new ApplePayAdapter.Request("tenant-001", "merchant-001", "pay.example.test", 1250,
                "USD", token, ApplePayAdapter.Psp.STRIPE, null, "idem-applepay-00000001", NOW);
    }

    private static byte[] validToken() {
        return "{\"data\":\"opaque-encrypted-data\",\"signature\":\"opaque-signature\","
                .concat("\"header\":{\"ephemeralPublicKey\":\"opaque\"}}")
                .getBytes(StandardCharsets.UTF_8);
    }

    private static boolean allZero(byte[] value) {
        for (byte item : value) {
            if (item != 0) {
                return false;
            }
        }
        return true;
    }
}
