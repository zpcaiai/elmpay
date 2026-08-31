package com.elmpay.webhook.ingress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

final class WebhookIngressServiceTest {
    private static final Instant NOW = Instant.parse("2026-08-26T00:00:00Z");

    @Test
    void verifiesBeforeDurableWriteAndAcknowledgesDuplicates() {
        AtomicInteger verificationCalls = new AtomicInteger();
        Set<String> inbox = new HashSet<>();
        WebhookIngressService service = new WebhookIngressService(Map.of("stripe",
                (context, headers, body, receivedAt) -> {
                    verificationCalls.incrementAndGet();
                    if (!"valid".equals(headers.get("signature"))) {
                        throw new SecurityException("bad signature");
                    }
                    return event("evt-001", receivedAt);
                }), (context, event, digest) -> inbox.add(event.providerEventId()));

        WebhookIngressService.Receipt first = service.ingest(context(), Map.of("signature", "valid"),
                "{\"safe\":true}".getBytes(StandardCharsets.UTF_8));
        WebhookIngressService.Receipt duplicate = service.ingest(context(), Map.of("signature", "valid"),
                "{\"safe\":true}".getBytes(StandardCharsets.UTF_8));

        assertEquals(WebhookIngressService.Outcome.ACCEPTED, first.outcome());
        assertEquals(WebhookIngressService.Outcome.DUPLICATE, duplicate.outcome());
        assertEquals(2, verificationCalls.get());
        assertEquals(1, inbox.size());
    }

    @Test
    void badSignatureCannotReachInbox() {
        AtomicInteger writes = new AtomicInteger();
        WebhookIngressService service = new WebhookIngressService(Map.of("stripe",
                (context, headers, body, receivedAt) -> {
                    throw new SecurityException("bad signature");
                }), (context, event, digest) -> {
                    writes.incrementAndGet();
                    return true;
                });
        assertThrows(SecurityException.class, () -> service.ingest(context(), Map.of(),
                "{}".getBytes(StandardCharsets.UTF_8)));
        assertEquals(0, writes.get());
    }

    @Test
    void preservesOutOfOrderVerifiedFactsForAsynchronousStateMachine() {
        Set<String> stored = new HashSet<>();
        WebhookIngressService service = new WebhookIngressService(Map.of("stripe",
                (context, headers, body, receivedAt) -> event(headers.get("event"),
                        Instant.parse(headers.get("occurred")))),
                (context, event, digest) -> stored.add(event.providerEventId()));
        WebhookIngressService.Receipt recent = service.ingest(context(),
                Map.of("event", "evt-recent", "occurred", "2026-08-26T00:00:10Z"),
                "{\"safe\":true}".getBytes(StandardCharsets.UTF_8));
        WebhookIngressService.Receipt older = service.ingest(context(),
                Map.of("event", "evt-older", "occurred", "2026-08-26T00:00:05Z"),
                "{\"safe\":true}".getBytes(StandardCharsets.UTF_8));
        assertEquals(WebhookIngressService.Outcome.ACCEPTED, recent.outcome());
        assertEquals(WebhookIngressService.Outcome.ACCEPTED, older.outcome());
        assertEquals(Set.of("evt-recent", "evt-older"), stored);
    }

    @Test
    void rejectsCardFieldsBeforeVerificationOrPersistence() {
        AtomicInteger verifierCalls = new AtomicInteger();
        WebhookIngressService service = new WebhookIngressService(Map.of("stripe",
                (context, headers, body, receivedAt) -> {
                    verifierCalls.incrementAndGet();
                    return event("evt-001", receivedAt);
                }), (context, event, digest) -> true);
        assertThrows(SecurityException.class, () -> service.ingest(context(), Map.of(),
                "{\"card_number\":\"4242424242424242\"}".getBytes(StandardCharsets.UTF_8)));
        assertEquals(0, verifierCalls.get());
    }

    @Test
    void publicEndpointTokenResolvesServerOwnedTenantBeforeProviderVerification() {
        AtomicReference<WebhookIngressService.Context> storedContext = new AtomicReference<>();
        AtomicReference<String> verifiedMerchant = new AtomicReference<>();
        WebhookIngressService service = new WebhookIngressService(Map.of("stripe",
                (context, headers, body, receivedAt) -> {
                    verifiedMerchant.set(context.merchantAccountId());
                    return event("evt-bound", receivedAt);
                }), (context, event, digest) -> {
                    storedContext.set(context);
                    return true;
                });
        WebhookIngressRuntime runtime = new WebhookIngressRuntime(token -> Optional.of(
                new WebhookIngressRuntime.EndpointBinding("tenant-owned", "project-owned",
                        "stripe", "merchant-owned")), service);

        runtime.ingest("a".repeat(32), Map.of("x-tenant-id", "tenant-attacker"),
                "{\"safe\":true}".getBytes(StandardCharsets.UTF_8), NOW);

        assertEquals("merchant-owned", verifiedMerchant.get());
        assertEquals("tenant-owned", storedContext.get().tenantId());
        assertEquals("project-owned", storedContext.get().projectId());
    }

    @Test
    void unknownPublicEndpointCannotReachVerifierOrInbox() {
        AtomicInteger calls = new AtomicInteger();
        WebhookIngressService service = new WebhookIngressService(Map.of("stripe",
                (context, headers, body, receivedAt) -> {
                    calls.incrementAndGet();
                    return event("evt", receivedAt);
                }), (context, event, digest) -> {
                    calls.incrementAndGet();
                    return true;
                });
        WebhookIngressRuntime runtime = new WebhookIngressRuntime(token -> Optional.empty(), service);
        assertThrows(SecurityException.class, () -> runtime.ingest("a".repeat(32), Map.of(),
                "{}".getBytes(StandardCharsets.UTF_8), NOW));
        assertEquals(0, calls.get());
    }

    @Test
    void canonicalHttpRouteIsReachableAndUsesOnlyServerOwnedScope() throws Exception {
        AtomicReference<WebhookIngressService.Context> stored = new AtomicReference<>();
        WebhookIngressService service = new WebhookIngressService(Map.of("stripe",
                (context, headers, body, receivedAt) -> event("evt-http", receivedAt)),
                (context, event, digest) -> {
                    stored.set(context);
                    return true;
                });
        WebhookIngressRuntime runtime = new WebhookIngressRuntime(token -> Optional.of(
                new WebhookIngressRuntime.EndpointBinding("tenant-owned", "project-owned",
                        "stripe", "merchant-owned")), service);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(WebhookIngressHttpHandler.PATH_PREFIX,
                new WebhookIngressHttpHandler(runtime, Clock.fixed(NOW, ZoneOffset.UTC)));
        server.start();
        try {
            URI endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort()
                    + WebhookIngressHttpHandler.PATH_PREFIX + "a".repeat(32));
            HttpRequest request = HttpRequest.newBuilder(endpoint)
                    .header("X-Tenant-Id", "tenant-attacker")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"safe\":true}"))
                    .build();
            HttpResponse<Void> response = HttpClient.newHttpClient().send(request,
                    HttpResponse.BodyHandlers.discarding());
            assertEquals(202, response.statusCode());
            assertEquals("tenant-owned", stored.get().tenantId());
            assertEquals("project-owned", stored.get().projectId());
        } finally {
            server.stop(0);
        }
    }

    private static WebhookIngressService.Context context() {
        return new WebhookIngressService.Context("tenant-001", "project-001", "stripe",
                "merchant-001", NOW);
    }

    private static WebhookIngressService.VerifiedEvent event(String id, Instant occurredAt) {
        return new WebhookIngressService.VerifiedEvent(id, "payment.succeeded", "pi-001",
                "order-001", occurredAt, "key-001", "{\"verified\":true}".getBytes(StandardCharsets.UTF_8));
    }
}
