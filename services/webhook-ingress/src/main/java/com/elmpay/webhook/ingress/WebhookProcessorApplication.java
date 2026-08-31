package com.elmpay.webhook.ingress;

import com.elmpay.payment.ProviderWebhookEffectService;
import java.io.IOException;
import java.time.Clock;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

/** Production entrypoint for durable asynchronous verified-provider-effect processing. */
public final class WebhookProcessorApplication {
    private WebhookProcessorApplication() {
    }

    public static void main(String[] arguments) throws IOException, InterruptedException {
        Map<String, String> environment = System.getenv();
        WebhookProcessorSettings settings = WebhookProcessorSettings.from(environment);
        FileBackedWebhookPostgresDataSource dataSource =
                new FileBackedWebhookPostgresDataSource(settings.databaseUrl(),
                        settings.databaseUsername(), settings.databasePasswordFile(),
                        settings.databaseCaFile(), settings.databaseClientCertificateFile(),
                        settings.databaseClientPrivateKeyFile());
        Clock clock = Clock.systemUTC();
        PaymentCoreWebhookEffectAdapter adapter = new PaymentCoreWebhookEffectAdapter(
                new ProviderWebhookEffectService(clock));
        WebhookProcessorRuntime runtime = new WebhookProcessorRuntime(settings, dataSource,
                adapter, clock);
        WebhookProcessorHealthServer health = new WebhookProcessorHealthServer(runtime,
                settings.healthHost(), settings.healthPort());
        CountDownLatch stopped = new CountDownLatch(1);
        AtomicBoolean cleaned = new AtomicBoolean();
        Runnable cleanup = () -> {
            if (cleaned.compareAndSet(false, true)) {
                health.close();
                runtime.close();
            }
        };
        Thread shutdown = new Thread(() -> {
            cleanup.run();
            stopped.countDown();
        }, "elmpay-webhook-processor-shutdown");
        Runtime.getRuntime().addShutdownHook(shutdown);
        try {
            runtime.start();
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
            // JVM shutdown is already in progress; the hook owns cleanup.
        }
    }
}
