package com.elmpay.scheduler.events;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.kafka.common.errors.WakeupException;

/** Dedicated bounded Kafka polling thread and readiness signal. */
public final class KafkaLedgerConsumerRunner implements AutoCloseable {
    private final KafkaLedgerConsumer consumer;
    private final Clock clock;
    private final Duration maximumStaleness;
    private final AtomicBoolean started = new AtomicBoolean();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicReference<Instant> lastSuccessfulPoll = new AtomicReference<>();
    private Thread thread;

    public KafkaLedgerConsumerRunner(KafkaLedgerConsumer consumer, Clock clock,
            Duration maximumStaleness) {
        this.consumer = Objects.requireNonNull(consumer, "consumer");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.maximumStaleness = Objects.requireNonNull(maximumStaleness, "maximumStaleness");
    }

    public synchronized void start() {
        if (!started.compareAndSet(false, true) || closed.get()) {
            throw new IllegalStateException("Kafka ledger consumer cannot be started");
        }
        thread = new Thread(this::run, "elmpay-ledger-kafka-consumer");
        thread.setDaemon(false);
        thread.start();
    }

    public boolean live() {
        Thread current = thread;
        return started.get() && !closed.get() && current != null && current.isAlive();
    }

    public boolean ready() {
        Instant success = lastSuccessfulPoll.get();
        return live() && consumer.assigned() && success != null
                && !success.plus(maximumStaleness).isBefore(clock.instant());
    }

    private void run() {
        try {
            while (!closed.get()) {
                try {
                    consumer.pollOnce();
                    lastSuccessfulPoll.set(clock.instant());
                } catch (WakeupException failure) {
                    if (!closed.get()) {
                        recordFailure(failure);
                    }
                } catch (RuntimeException failure) {
                    recordFailure(failure);
                    java.util.concurrent.locks.LockSupport.parkNanos(Duration.ofMillis(250).toNanos());
                }
            }
        } finally {
            consumer.close();
        }
    }

    @Override
    public synchronized void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        consumer.wakeup();
        Thread current = thread;
        if (current != null) {
            try {
                current.join(Duration.ofSeconds(15).toMillis());
                if (current.isAlive()) {
                    throw new IllegalStateException("Kafka ledger consumer did not stop");
                }
            } catch (InterruptedException failure) {
                Thread.currentThread().interrupt();
            }
        } else {
            consumer.close();
        }
    }

    private static void recordFailure(Throwable failure) {
        System.err.println("elmpay_worker_failure stage=ledger_consumer code="
                + failure.getClass().getSimpleName());
    }
}
