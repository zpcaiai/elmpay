package com.elmpay.scheduler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.elmpay.payment.commerce.CommerceService;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class BillingLifecycleJobTest {
    @Test
    void jobDrainsBoundedDurableRenewalAndDunningQueues() {
        AtomicInteger renewalCalls = new AtomicInteger();
        AtomicInteger dunningCalls = new AtomicInteger();
        UUID tenant = UUID.randomUUID();
        UUID project = UUID.randomUUID();
        CommerceService commerce = (CommerceService) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[] {CommerceService.class},
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "enqueueDueRenewal" -> renewalCalls.getAndIncrement() < 2
                            ? Optional.of(new CommerceService.BillingCycle(UUID.randomUUID(), tenant,
                                    project, UUID.randomUUID(), Instant.EPOCH,
                                    Instant.EPOCH.plusSeconds(1), 1, "USD", "queued"))
                            : Optional.empty();
                    case "enqueueDueDunning" -> dunningCalls.getAndIncrement() < 1
                            ? Optional.of(new CommerceService.DunningCase(UUID.randomUUID(), tenant,
                                    project, UUID.randomUUID(), UUID.randomUUID(),
                                    CommerceService.DunningState.WAITING_PROVIDER_QUERY, 1, 4,
                                    null, Instant.EPOCH.plusSeconds(100), 2))
                            : Optional.empty();
                    default -> throw new AssertionError(method.getName());
                });
        BillingLifecycleJob.Result result = new BillingLifecycleJob(commerce, 10)
                .run(tenant, "worker-1", Instant.EPOCH);
        assertEquals(2, result.renewalEvents());
        assertEquals(1, result.dunningEvents());
    }

    @Test
    void itemLimitMustBeExplicitlyBounded() {
        CommerceService commerce = (CommerceService) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[] {CommerceService.class},
                (proxy, method, arguments) -> Optional.empty());
        assertThrows(IllegalArgumentException.class, () -> new BillingLifecycleJob(commerce, 0));
        assertThrows(IllegalArgumentException.class,
                () -> new BillingLifecycleJob(commerce, 10_001));
    }
}
