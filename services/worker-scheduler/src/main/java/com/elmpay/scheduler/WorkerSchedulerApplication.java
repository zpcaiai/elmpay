package com.elmpay.scheduler;

import com.elmpay.ledger.LedgerService;
import com.elmpay.scheduler.events.EventDeliverySettings;
import com.elmpay.scheduler.events.JdbcEventDeliveryStore;
import com.elmpay.scheduler.events.KafkaLedgerConsumer;
import com.elmpay.scheduler.events.KafkaLedgerConsumerRunner;
import com.elmpay.scheduler.events.KafkaOutboxPublisher;
import com.elmpay.scheduler.events.OutboxRelay;
import com.elmpay.scheduler.events.WebhookFanoutPublisher;
import java.io.IOException;
import java.time.Clock;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

/** Production worker process entrypoint. */
public final class WorkerSchedulerApplication {
    private WorkerSchedulerApplication() {
    }

    public static void main(String[] arguments) throws IOException, InterruptedException {
        Map<String, String> environment = System.getenv();
        WorkerSchedulerSettings settings = WorkerSchedulerSettings.from(environment);
        EventDeliverySettings delivery = EventDeliverySettings.from(environment);
        PaymentTimelineProjectionSettings projection =
                PaymentTimelineProjectionSettings.from(environment);
        FileBackedPostgresDataSource dataSource = new FileBackedPostgresDataSource(
                settings.databaseUrl(), settings.databaseUsername(),
                settings.databasePasswordFile(), settings.databaseCaFile(),
                settings.databaseClientCertificateFile(),
                settings.databaseClientPrivateKeyFile());
        Clock clock = Clock.systemUTC();
        KafkaOutboxPublisher kafkaPublisher = new KafkaOutboxPublisher(settings);
        OutboxRelay.Publisher publisher = new WebhookFanoutPublisher(
                dataSource, kafkaPublisher, clock);
        JdbcEventDeliveryStore eventStore = new JdbcEventDeliveryStore(dataSource);
        LedgerPostingConsumer posting = new LedgerPostingConsumer(eventStore,
                new LedgerService(dataSource, clock), new JdbcPostingPolicyResolver(),
                delivery.inboxLeaseTtl(), delivery.inboxRetryDelay());
        KafkaLedgerConsumerRunner ledgerConsumer = new KafkaLedgerConsumerRunner(
                new KafkaLedgerConsumer(settings, posting, clock), clock,
                settings.readinessMaximumStaleness());
        WorkerSchedulerRuntime runtime = WorkerSchedulerRuntime.production(settings, delivery,
                dataSource, publisher, projection, clock, ledgerConsumer::ready, environment);
        WorkerHealthServer health = new WorkerHealthServer(runtime, settings.healthHost(),
                settings.healthPort());
        CountDownLatch stopped = new CountDownLatch(1);
        AtomicBoolean cleaned = new AtomicBoolean();
        Runnable cleanup = () -> {
            if (cleaned.compareAndSet(false, true)) {
                health.close();
                ledgerConsumer.close();
                runtime.close();
                kafkaPublisher.close();
            }
        };
        Thread shutdown = new Thread(() -> {
            cleanup.run();
            stopped.countDown();
        }, "elmpay-worker-shutdown");
        Runtime.getRuntime().addShutdownHook(shutdown);
        try {
            runtime.start();
            ledgerConsumer.start();
            health.start();
            stopped.await();
        } finally {
            removeHook(shutdown);
            cleanup.run();
        }
    }

    private static void removeHook(Thread hook) {
        try {
            Runtime.getRuntime().removeShutdownHook(hook);
        } catch (IllegalStateException ignored) {
            // The JVM has already started shutdown; the hook owns cleanup.
        }
    }
}
