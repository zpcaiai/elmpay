package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.elmpay.payment.readmodel.JdbcPaymentTimeline;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

final class PaymentTimelineHttpTest {
    private static final String KEY_A = "timeline-tenant-a-secret";
    private static final String KEY_B = "timeline-tenant-b-secret";
    private static final UUID TENANT_A = UUID.randomUUID();
    private static final UUID PROJECT_A = UUID.randomUUID();
    private static final UUID MERCHANT_A = UUID.randomUUID();
    private static final UUID TENANT_B = UUID.randomUUID();
    private static final UUID PROJECT_B = UUID.randomUUID();
    private static final UUID MERCHANT_B = UUID.randomUUID();
    private static final UUID INTENT = UUID.randomUUID();
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    @Test
    void timelineIsReadScopedTenantIsolatedAndPayloadMinimized() throws Exception {
        String principals = principal(KEY_A, "tenant-a", TENANT_A, PROJECT_A, MERCHANT_A) + ","
                + principal(KEY_B, "tenant-b", TENANT_B, PROJECT_B, MERCHANT_B);
        RuntimeComponents base = RuntimeFactory.create(Map.of(
                "ELMPAY_RUNTIME_MODE", "local",
                "ELMPAY_ENABLE_LOCAL_SANDBOX", "true",
                "ELMPAY_LOCAL_RISK_POLICY", "approve-sandbox",
                "ELMPAY_API_PRINCIPALS", principals));
        RuntimeComponents runtime = new RuntimeComponents(base.payments(), base.authenticator(),
                base.refunds(), base.metadata(), base.webhookIngress(), new FakeTimeline(), true,
                "local");
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", new PaymentHttpHandler(runtime));
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.start();
        try {
            URI baseUri = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
            HttpClient client = HttpClient.newHttpClient();
            HttpResponse<String> status = client.send(request(baseUri.resolve(
                    "/v1/payment_intents/" + INTENT + "/status"), KEY_A, PROJECT_A),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, status.statusCode(), status.body());
            assertEquals("APPROVED", Json.object(status.body()).get("risk_outcome"));

            HttpResponse<String> timeline = client.send(request(baseUri.resolve(
                    "/v1/payment-intents/" + INTENT
                            + "/timeline?after_sequence=0&limit=25"), KEY_A, PROJECT_A),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, timeline.statusCode(), timeline.body());
            assertFalse(timeline.body().contains("never-return"), timeline.body());
            assertEquals(7L, Json.object(timeline.body()).get("next_after_sequence"));

            HttpResponse<String> crossTenant = client.send(request(baseUri.resolve(
                    "/v1/payment_intents/" + INTENT + "/status"), KEY_B, PROJECT_B),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(404, crossTenant.statusCode(), crossTenant.body());

            HttpResponse<String> invalidQuery = client.send(request(baseUri.resolve(
                    "/v1/payment_intents/" + INTENT + "/timeline?limit=101"), KEY_A, PROJECT_A),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(400, invalidQuery.statusCode(), invalidQuery.body());
        } finally {
            server.stop(0);
        }
    }

    private static String principal(String key, String id, UUID tenant, UUID project,
            UUID merchant) {
        return ApiKeyAuthenticator.digestForProvisioning(key) + "|" + id + "|" + tenant + "|"
                + project + "|" + merchant + "|payments.read";
    }

    private static HttpRequest request(URI uri, String key, UUID project) {
        return HttpRequest.newBuilder(uri)
                .header("Authorization", "Bearer " + key)
                .header("X-Project-Id", project.toString())
                .header("X-Request-Id", "timeline-request-0001")
                .header("traceparent",
                        "00-11111111111111111111111111111111-2222222222222222-01")
                .GET().build();
    }

    private static final class FakeTimeline implements PaymentTimelineRuntime {
        @Override
        public Optional<JdbcPaymentTimeline.PaymentStatus> status(UUID tenantId, UUID projectId,
                UUID paymentIntentId) {
            return inScope(tenantId, projectId, paymentIntentId)
                    ? Optional.of(statusValue()) : Optional.empty();
        }

        @Override
        public Optional<TimelinePage> timeline(UUID tenantId, UUID projectId,
                UUID paymentIntentId, long afterSequence, int limit) {
            if (!inScope(tenantId, projectId, paymentIntentId)) {
                return Optional.empty();
            }
            JdbcPaymentTimeline.TimelineEntry entry = new JdbcPaymentTimeline.TimelineEntry(7,
                    UUID.randomUUID(), "payment.attempt.resolved.v1", 1, "stripe", "pi_1",
                    "APPROVED", "correlation-1", "{\"sensitive\":\"never-return\"}",
                    "a".repeat(64), NOW);
            return Optional.of(new TimelinePage(statusValue(), List.of(entry)));
        }

        private static boolean inScope(UUID tenantId, UUID projectId, UUID paymentIntentId) {
            return TENANT_A.equals(tenantId) && PROJECT_A.equals(projectId)
                    && INTENT.equals(paymentIntentId);
        }

        private static JdbcPaymentTimeline.PaymentStatus statusValue() {
            return new JdbcPaymentTimeline.PaymentStatus(TENANT_A, PROJECT_A, INTENT, "captured",
                    1_000, "USD", 1_000, 0, "stripe", "pi_1", "SUCCEEDED", "APPROVED",
                    7, 1, NOW);
        }
    }
}
