package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.money.Money;
import com.elmpay.provider.CreatePaymentCommand;
import com.elmpay.provider.ProviderAdapter;
import com.elmpay.provider.ProviderPayment;
import com.elmpay.provider.ProviderRefund;
import com.elmpay.provider.ProviderRequestContext;
import com.elmpay.provider.RefundCommand;
import com.elmpay.provider.VerifiedProviderEvent;
import com.elmpay.provider.WebhookRequest;
import java.util.List;
import org.junit.jupiter.api.Test;

final class RuntimeFactoryTest {
    @Test
    void postgresReadinessRequiresAtLeastOneConfiguredProvider() {
        assertFalse(RuntimeFactory.providersReady(List.of(new StubAdapter("wechat", false),
                new StubAdapter("stripe", false))));
        assertTrue(RuntimeFactory.providersReady(List.of(new StubAdapter("wechat", false),
                new StubAdapter("stripe", true))));
    }

    private record StubAdapter(String provider, boolean configured) implements ProviderAdapter {
        @Override public ProviderPayment createPayment(CreatePaymentCommand command) { return null; }
        @Override public ProviderPayment queryPayment(ProviderRequestContext context, String id, String order) {
            return null;
        }
        @Override public ProviderPayment capture(ProviderRequestContext context, String id, Money amount) {
            return null;
        }
        @Override public ProviderPayment cancel(ProviderRequestContext context, String id, String reason) {
            return null;
        }
        @Override public ProviderRefund refund(RefundCommand command) { return null; }
        @Override public ProviderRefund queryRefund(ProviderRequestContext context, String id, String reference) {
            return null;
        }
        @Override public VerifiedProviderEvent verifyWebhook(WebhookRequest request) { return null; }
    }
}
