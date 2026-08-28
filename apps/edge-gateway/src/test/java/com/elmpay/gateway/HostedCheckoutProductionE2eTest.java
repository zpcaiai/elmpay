package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.elmpay.payment.checkout.CheckoutTokenSigner;
import com.elmpay.payment.checkout.HostedCheckoutService;
import com.elmpay.payment.checkout.InMemoryCheckoutSessionRepository;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

final class HostedCheckoutProductionE2eTest {
    private static final String TEST_PRINCIPAL_PLACEHOLDER =
            "placeholder-only-for-local-auth-test";
    private static final UUID TENANT = UUID.fromString("21000000-0000-0000-0000-000000000001");
    private static final UUID PROJECT = UUID.fromString("21000000-0000-0000-0000-000000000002");
    private static final UUID MERCHANT = UUID.fromString("21000000-0000-0000-0000-000000000003");

    @Test
    void browserConfirmationCarriesOnlyAnOfficialReferenceAndRejectsPan() throws Exception {
        String principals = ApiKeyAuthenticator.digestForProvisioning(TEST_PRINCIPAL_PLACEHOLDER)
                + "|test|" + TENANT + "|" + PROJECT + "|" + MERCHANT;
        RuntimeComponents runtime = RuntimeFactory.create(Map.of(
                "ELMPAY_RUNTIME_MODE", "local",
                "ELMPAY_ENABLE_LOCAL_SANDBOX", "true",
                "ELMPAY_LOCAL_RISK_POLICY", "approve-sandbox",
                "ELMPAY_API_PRINCIPALS", principals));
        byte[] signingKey = new byte[32];
        Arrays.fill(signingKey, (byte) 0x37);
        HostedCheckoutService checkout = new HostedCheckoutService(runtime.payments(),
                new InMemoryCheckoutSessionRepository(),
                new CheckoutTokenSigner(Map.of("production-test-v1", signingKey),
                        "production-test-v1"),
                Map.of("complete", URI.create("https://merchant.example/checkout/complete")),
                "complete", Set.of("card"), URI.create("http://127.0.0.1/checkout"),
                Duration.ofMinutes(10), "US", false, Clock.systemUTC());

        HttpServer server = HttpServer.create(new InetSocketAddress(0), 16);
        server.createContext("/", new PaymentHttpHandler(runtime, checkout));
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.start();
        try {
            URI base = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
            HttpClient client = HttpClient.newHttpClient();
            HostedCheckoutService.Created safe = checkout.create(create("official-reference",
                    "checkout-production-create-0001"));
            Map<String, String> safeClaims = fragment(safe.checkoutUrl().getRawFragment());
            HttpResponse<String> confirmed = client.send(confirmRequest(base,
                    safeClaims.get("session"), safeClaims.get("token"),
                    "checkout-production-confirm-0001", """
                    {"method":"card","payment_method_reference":"psp://stripe/pm_test_123",
                     "fingerprint":"fp_provider_123"}
                    """), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, confirmed.statusCode(), confirmed.body());
            assertEquals("SUCCEEDED", Json.object(confirmed.body()).get("status"));

            HostedCheckoutService.Created unsafe = checkout.create(create("pan-reference",
                    "checkout-production-create-0002"));
            Map<String, String> unsafeClaims = fragment(unsafe.checkoutUrl().getRawFragment());
            HttpResponse<String> rejected = client.send(confirmRequest(base,
                    unsafeClaims.get("session"), unsafeClaims.get("token"),
                    "checkout-production-confirm-0002", """
                    {"method":"card","payment_method_reference":"psp://unsafe/4111111111111111",
                     "fingerprint":"fp_unsafe"}
                    """), HttpResponse.BodyHandlers.ofString());
            assertEquals(400, rejected.statusCode(), rejected.body());
            assertEquals("invalid_request", Json.object(rejected.body()).get("code"));
        } finally {
            server.stop(0);
        }
    }

    private static HostedCheckoutService.CreateCommand create(String order, String key) {
        return new HostedCheckoutService.CreateCommand(TENANT, PROJECT, MERCHANT, order, 1_250,
                "USD", "complete", "device-context-digest-00000001", key);
    }

    private static HttpRequest confirmRequest(URI base, String sessionId, String token,
            String idempotencyKey, String body) {
        return HttpRequest.newBuilder(base.resolve("/api/checkout/sessions/" + sessionId
                        + "/confirm"))
                .header("Authorization", "CheckoutSession " + token)
                .header("Content-Type", "application/json")
                .header("Idempotency-Key", idempotencyKey)
                .header("X-Request-Id", "request-production-checkout-0001")
                .header("traceparent",
                        "00-77777777777777777777777777777777-8888888888888888-01")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
    }

    private static Map<String, String> fragment(String raw) {
        Map<String, String> values = new LinkedHashMap<>();
        for (String pair : raw.split("&")) {
            String[] fields = pair.split("=", 2);
            values.put(URLDecoder.decode(fields[0], StandardCharsets.UTF_8),
                    URLDecoder.decode(fields[1], StandardCharsets.UTF_8));
        }
        return values;
    }
}
