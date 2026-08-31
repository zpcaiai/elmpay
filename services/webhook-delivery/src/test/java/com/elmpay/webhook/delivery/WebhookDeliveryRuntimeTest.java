package com.elmpay.webhook.delivery;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Proxy;
import java.time.Clock;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

final class WebhookDeliveryRuntimeTest {
    @Test
    void tenantWithoutWebhookConfigurationIsIdleWithoutResolvingSecretsOrOpeningJdbc() {
        AtomicInteger resolutions = new AtomicInteger();
        WebhookDeliveryRuntime runtime = new WebhookDeliveryRuntime(unusableDataSource(),
                (tenant, now) -> new WebhookDeliveryRuntime.Configuration(Set.of(), List.of()),
                (tenant, descriptor, maximumLifetime) -> {
                    resolutions.incrementAndGet();
                    throw new AssertionError("secret resolver must not run");
                }, WebhookDeliveryRuntime.Settings.productionDefaults(), Clock.systemUTC());

        assertEquals(WebhookDeliveryService.Outcome.IDLE, runtime.runOnce("tenant_001"));
        assertEquals(0, resolutions.get());
    }

    @Test
    void partialWebhookConfigurationFailsClosed() {
        assertThrows(IllegalArgumentException.class,
                () -> new WebhookDeliveryRuntime.Configuration(Set.of("hooks.example.test"),
                        List.of()));
    }

    private static DataSource unusableDataSource() {
        return (DataSource) Proxy.newProxyInstance(
                WebhookDeliveryRuntimeTest.class.getClassLoader(),
                new Class<?>[] {DataSource.class}, (proxy, method, arguments) -> {
                    if (method.getName().equals("toString")) {
                        return "unusable-test-data-source";
                    }
                    throw new AssertionError("JDBC must not be used for an idle tenant");
                });
    }
}
