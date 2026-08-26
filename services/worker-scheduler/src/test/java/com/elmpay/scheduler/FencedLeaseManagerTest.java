package com.elmpay.scheduler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

class FencedLeaseManagerTest {
    private static final Instant NOW = Instant.parse("2026-08-26T00:00:00Z");

    @Test
    void onlyOneHolderAcquiresActiveLease() {
        FencedLeaseManager manager = new FencedLeaseManager(Clock.fixed(NOW, ZoneOffset.UTC));
        FencedLeaseManager.JobKey key = new FencedLeaseManager.JobKey("tenant-a", "retention");
        FencedLeaseManager.Lease lease = manager.tryAcquire(key, "worker-a", Duration.ofMinutes(1)).orElseThrow();

        assertTrue(manager.tryAcquire(key, "worker-b", Duration.ofMinutes(1)).isEmpty());
        assertEquals(1L, lease.fencingToken());
    }

    @Test
    void releasedLeaseGetsHigherTokenAndFencesOldWorker() {
        FencedLeaseManager manager = new FencedLeaseManager(Clock.fixed(NOW, ZoneOffset.UTC));
        FencedLeaseManager.JobKey key = new FencedLeaseManager.JobKey("tenant-a", "retention");
        FencedLeaseManager.Lease first = manager.tryAcquire(key, "worker-a", Duration.ofMinutes(1)).orElseThrow();
        manager.release(first);
        FencedLeaseManager.Lease second = manager.tryAcquire(key, "worker-b", Duration.ofMinutes(1)).orElseThrow();

        assertEquals(2L, second.fencingToken());
        assertThrows(FencedLeaseManager.StaleFencingTokenException.class,
                () -> manager.assertCurrent(first));
    }

    @Test
    void concurrentContendersProduceExactlyOneLease() throws Exception {
        FencedLeaseManager manager = new FencedLeaseManager(Clock.fixed(NOW, ZoneOffset.UTC));
        FencedLeaseManager.JobKey key = new FencedLeaseManager.JobKey("tenant-a", "retention");
        var executor = Executors.newFixedThreadPool(8);
        try {
            var tasks = new ArrayList<Callable<Boolean>>();
            for (int index = 0; index < 32; index++) {
                String holder = "worker-" + index;
                tasks.add(() -> manager.tryAcquire(key, holder, Duration.ofMinutes(1)).isPresent());
            }
            long winners = executor.invokeAll(tasks).stream().filter(future -> {
                try {
                    return future.get();
                } catch (Exception exception) {
                    throw new IllegalStateException(exception);
                }
            }).count();
            assertEquals(1L, winners);
        } finally {
            executor.shutdownNow();
        }
    }
}
