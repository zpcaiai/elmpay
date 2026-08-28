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
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class RuntimeFactoryTest {
    @Test
    void postgresReadinessRequiresAtLeastOneConfiguredProvider() {
        assertFalse(RuntimeFactory.providersReady(List.of(new StubAdapter("wechat", false),
                new StubAdapter("stripe", false))));
        assertFalse(RuntimeFactory.providersReady(List.of(new StubAdapter("wechat", false),
                new StubAdapter("stripe", true))));
        assertTrue(RuntimeFactory.providersReady(List.of(new StubAdapter("stripe", true))));
        assertFalse(RuntimeFactory.providersReady(List.of()));
    }

    @Test
    void readinessAccountConfigurationIsExplicitAndStrict() {
        UUID tenant = UUID.randomUUID();
        UUID project = UUID.randomUUID();
        UUID account = UUID.randomUUID();
        var values = RuntimeFactory.readinessBindings(
                "stripe|" + tenant + "|" + project + "|" + account);
        assertTrue(values.size() == 1 && values.getFirst().tenantId().equals(tenant)
                && values.getFirst().providerAccountId().equals(account));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                () -> RuntimeFactory.readinessBindings("stripe|missing-fields"));
    }

    @Test
    void localSandboxRequiresAnExplicitRiskPolicy() {
        String principals = ApiKeyAuthenticator.digestForProvisioning("test-key")
                + "|test|10000000-0000-0000-0000-000000000001"
                + "|10000000-0000-0000-0000-000000000002"
                + "|10000000-0000-0000-0000-000000000003";
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                () -> RuntimeFactory.create(Map.of(
                        "ELMPAY_RUNTIME_MODE", "local",
                        "ELMPAY_ENABLE_LOCAL_SANDBOX", "true",
                        "ELMPAY_API_PRINCIPALS", principals)));
        assertTrue(RuntimeFactory.create(Map.of(
                "ELMPAY_RUNTIME_MODE", "local",
                "ELMPAY_ENABLE_LOCAL_SANDBOX", "true",
                "ELMPAY_LOCAL_RISK_POLICY", "review-all",
                "ELMPAY_API_PRINCIPALS", principals)).mode().equals("local"));
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
