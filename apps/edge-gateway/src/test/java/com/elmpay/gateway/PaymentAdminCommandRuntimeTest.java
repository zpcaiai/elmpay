package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.payment.admin.PaymentAdminDomainCommandConsumer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

final class PaymentAdminCommandRuntimeTest {
    @Test
    void readinessRequiresSuccessfulPollingAndCurrentGovernanceBinding() throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-30T00:00:00Z"));
        PaymentAdminCommandRuntime runtime = new PaymentAdminCommandRuntime(
                () -> PaymentAdminDomainCommandConsumer.Outcome.IDLE, clock,
                Duration.ofMillis(100), Duration.ofMillis(300),
                clock.instant().plusSeconds(600), 5);
        try {
            assertFalse(runtime.ready());
            runtime.start();
            for (int attempt = 0; attempt < 100 && !runtime.ready(); attempt++) {
                Thread.sleep(10);
            }
            assertTrue(runtime.ready());
            clock.advance(Duration.ofSeconds(601));
            assertFalse(runtime.ready());
        } finally {
            runtime.close();
        }
    }

    @Test
    void consumerFailureNeverClaimsReadiness() throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-30T00:00:00Z"));
        PaymentAdminCommandRuntime runtime = new PaymentAdminCommandRuntime(
                () -> { throw new IllegalStateException("sensitive database detail"); }, clock,
                Duration.ofMillis(100), Duration.ofMillis(300),
                clock.instant().plusSeconds(600), 5);
        try {
            runtime.start();
            Thread.sleep(150);
            assertFalse(runtime.ready());
        } finally {
            runtime.close();
        }
    }

    @Test
    void startupSchemaOrPrivilegeFailureKeepsMainGatewayReadinessClosed() {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-30T00:00:00Z"));
        PaymentAdminCommandRuntime runtime = new PaymentAdminCommandRuntime(
                () -> PaymentAdminDomainCommandConsumer.Outcome.IDLE, clock,
                Duration.ofMillis(100), Duration.ofMillis(300),
                clock.instant().plusSeconds(600), 5,
                () -> { throw new IllegalStateException("BYPASSRLS"); });
        try {
            assertThrows(IllegalStateException.class, runtime::start);
            assertFalse(runtime.ready());
        } finally {
            runtime.close();
        }
    }

    private static final class MutableClock extends Clock {
        private final AtomicReference<Instant> value;

        private MutableClock(Instant value) {
            this.value = new AtomicReference<>(value);
        }

        void advance(Duration duration) {
            value.updateAndGet(current -> current.plus(duration));
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            if (!ZoneOffset.UTC.equals(zone)) {
                throw new IllegalArgumentException("only UTC is supported");
            }
            return this;
        }

        @Override
        public Instant instant() {
            return value.get();
        }
    }
}
