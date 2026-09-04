package com.elmpay.gateway;

import com.elmpay.admin.AdminActionPolicyBinding;
import com.elmpay.payment.admin.PaymentAdminDomainCommandConsumer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.sql.DataSource;

/** Physical edge lifecycle for the payment-core-owned refund approval command consumer. */
public final class PaymentAdminCommandRuntime implements AutoCloseable {
    @FunctionalInterface
    interface Work {
        PaymentAdminDomainCommandConsumer.Outcome run();
    }

    private final Work work;
    private final Clock clock;
    private final Duration pollInterval;
    private final Duration readinessStaleness;
    private final Instant policyValidUntil;
    private final int maximumPerCycle;
    private final Runnable schemaVerifier;
    private final boolean readinessRequired;
    private final ScheduledExecutorService executor;
    private final AtomicBoolean started = new AtomicBoolean();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean running = new AtomicBoolean();
    private final AtomicReference<Instant> lastSuccessfulCycle = new AtomicReference<>();
    private final AtomicBoolean schemaVerified = new AtomicBoolean();

    static PaymentAdminCommandRuntime production(DataSource dataSource,
            Map<String, String> environment, Clock clock) {
        AdminActionPolicyBinding policy = AdminActionPolicyBinding.load(java.nio.file.Path.of(
                required(environment, "ELMPAY_ADMIN_ACTION_POLICY_BINDING_FILE")));
        String workerId = required(environment, "ELMPAY_PAYMENT_ADMIN_WORKER_ID");
        Duration lease = duration(environment, "ELMPAY_PAYMENT_ADMIN_COMMAND_LEASE_TTL");
        Duration poll = duration(environment, "ELMPAY_PAYMENT_ADMIN_COMMAND_POLL_INTERVAL");
        Duration staleness = duration(environment,
                "ELMPAY_PAYMENT_ADMIN_READINESS_MAX_STALENESS");
        int maximum = integer(environment, "ELMPAY_PAYMENT_ADMIN_COMMAND_MAX_PER_CYCLE", 1, 100);
        PaymentAdminDomainCommandConsumer consumer = new PaymentAdminDomainCommandConsumer(
                dataSource, workerId, lease, policy);
        return new PaymentAdminCommandRuntime(consumer::runOnce, clock, poll, staleness,
                policy.validUntil(), maximum,
                new PaymentAdminCommandSchemaVerifier(dataSource)::verify);
    }

    static PaymentAdminCommandRuntime disabled(Clock clock) {
        PaymentAdminCommandRuntime runtime = new PaymentAdminCommandRuntime(
                () -> PaymentAdminDomainCommandConsumer.Outcome.IDLE, clock,
                Duration.ofSeconds(1), Duration.ofMinutes(1), Instant.MAX, 1, () -> { }, false);
        runtime.started.set(true);
        runtime.running.set(true);
        runtime.schemaVerified.set(true);
        runtime.lastSuccessfulCycle.set(clock.instant());
        return runtime;
    }

    PaymentAdminCommandRuntime(Work work, Clock clock, Duration pollInterval,
            Duration readinessStaleness, Instant policyValidUntil, int maximumPerCycle) {
        this(work, clock, pollInterval, readinessStaleness, policyValidUntil, maximumPerCycle,
                () -> { }, true);
    }

    PaymentAdminCommandRuntime(Work work, Clock clock, Duration pollInterval,
            Duration readinessStaleness, Instant policyValidUntil, int maximumPerCycle,
            Runnable schemaVerifier) {
        this(work, clock, pollInterval, readinessStaleness, policyValidUntil, maximumPerCycle,
                schemaVerifier, true);
    }

    private PaymentAdminCommandRuntime(Work work, Clock clock, Duration pollInterval,
            Duration readinessStaleness, Instant policyValidUntil, int maximumPerCycle,
            Runnable schemaVerifier, boolean readinessRequired) {
        this.work = Objects.requireNonNull(work, "work");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.pollInterval = bounded(pollInterval, Duration.ofMillis(100),
                Duration.ofSeconds(5), "pollInterval");
        this.readinessStaleness = bounded(readinessStaleness,
                pollInterval.multipliedBy(3), Duration.ofMinutes(1), "readinessStaleness");
        this.policyValidUntil = Objects.requireNonNull(policyValidUntil, "policyValidUntil");
        if (maximumPerCycle < 1 || maximumPerCycle > 100) {
            throw new IllegalArgumentException("maximumPerCycle is outside 1..100");
        }
        this.maximumPerCycle = maximumPerCycle;
        this.schemaVerifier = Objects.requireNonNull(schemaVerifier, "schemaVerifier");
        this.readinessRequired = readinessRequired;
        this.executor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "edge-payment-admin-command-consumer");
            thread.setDaemon(false);
            thread.setUncaughtExceptionHandler((ignored, failure) -> {
                lastSuccessfulCycle.set(null);
                running.set(false);
            });
            return thread;
        });
    }

    public void start() {
        if (closed.get() || !started.compareAndSet(false, true)) {
            throw new IllegalStateException("payment admin command runtime cannot start");
        }
        try {
            schemaVerifier.run();
            schemaVerified.set(true);
        } catch (RuntimeException failure) {
            started.set(false);
            throw failure;
        }
        running.set(true);
        try {
            executor.scheduleWithFixedDelay(this::runCycle, 0, pollInterval.toMillis(),
                    TimeUnit.MILLISECONDS);
        } catch (RuntimeException failure) {
            running.set(false);
            started.set(false);
            throw failure;
        }
    }

    void runCycle() {
        if (!running.get()) {
            return;
        }
        try {
            for (int index = 0; index < maximumPerCycle; index++) {
                if (work.run() == PaymentAdminDomainCommandConsumer.Outcome.IDLE) {
                    break;
                }
            }
            lastSuccessfulCycle.set(clock.instant());
        } catch (RuntimeException ignored) {
            // Never log JDBC messages, tenant identity, target ids, approvals, or credentials.
            lastSuccessfulCycle.set(null);
        } catch (Error fatal) {
            lastSuccessfulCycle.set(null);
            running.set(false);
            throw fatal;
        }
    }

    public boolean ready() {
        if (!readinessRequired) {
            return !closed.get();
        }
        Instant success = lastSuccessfulCycle.get();
        Instant now = clock.instant();
        return running.get() && schemaVerified.get() && success != null && !closed.get()
                && !success.plus(readinessStaleness).isBefore(now)
                && policyValidUntil.isAfter(now);
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        running.set(false);
        executor.shutdown();
        try {
            if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException interrupted) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    private static Duration duration(Map<String, String> environment, String key) {
        try {
            return Duration.parse(required(environment, key));
        } catch (RuntimeException invalid) {
            throw new IllegalStateException(key + " is invalid", invalid);
        }
    }

    private static int integer(Map<String, String> environment, String key, int minimum,
            int maximum) {
        int value;
        try {
            value = Integer.parseInt(required(environment, key));
        } catch (NumberFormatException invalid) {
            throw new IllegalStateException(key + " is invalid", invalid);
        }
        if (value < minimum || value > maximum) {
            throw new IllegalStateException(key + " is outside the governed range");
        }
        return value;
    }

    private static String required(Map<String, String> environment, String key) {
        String value = environment.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(key + " is required");
        }
        return value;
    }

    private static Duration bounded(Duration value, Duration minimum, Duration maximum,
            String field) {
        Objects.requireNonNull(value, field);
        if (value.compareTo(minimum) < 0 || value.compareTo(maximum) > 0) {
            throw new IllegalArgumentException(field + " is outside the governed range");
        }
        return value;
    }
}
