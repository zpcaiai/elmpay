package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.payment.checkout.CheckoutLocalization;
import com.elmpay.payment.checkout.CheckoutProviderSdkSource;
import com.elmpay.payment.checkout.CheckoutTokenSigner;
import com.elmpay.payment.checkout.ConfiguredCheckoutCapabilitySource;
import com.elmpay.payment.checkout.HostedCheckoutService;
import com.elmpay.payment.checkout.InMemoryCheckoutSessionRepository;
import java.net.URI;
import java.net.URLDecoder;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

final class CheckoutProviderSdkRuntimeTest {
    private static final UUID TENANT = UUID.fromString("56000000-0000-4000-8000-000000000001");
    private static final UUID PROJECT = UUID.fromString("56000000-0000-4000-8000-000000000002");
    private static final UUID MERCHANT = UUID.fromString("56000000-0000-4000-8000-000000000003");
    private static final UUID ACCOUNT = UUID.fromString("56000000-0000-4000-8000-000000000004");
    private static final String CHANNEL = "channel_56000000000000000000";

    @Test
    void sessionAuthorizationBindsAuthoritativeSnapshotAccountConfigurationAndAudit() {
        Fixture fixture = fixture();

        CheckoutProviderSdkRuntime.Configuration result = fixture.runtime().authorizeBrowser(
                fixture.created().checkoutSessionId(), fixture.token(), "card", CHANNEL,
                "request-provider-sdk-56000001");

        assertEquals("stripe", result.provider());
        assertEquals("stripe-js-v3", result.sdkVersion());
        assertEquals(Map.of("publishableKey", "pk_live_server_owned"),
                result.publicParameters());
        assertEquals(1, fixture.audit().size());
        CheckoutProviderSdkAudit.Receipt receipt = fixture.audit().getFirst();
        assertEquals(TENANT, receipt.tenantId());
        assertEquals(PROJECT, receipt.projectId());
        assertEquals(MERCHANT, receipt.merchantId());
        assertEquals(ACCOUNT, receipt.providerAccountId());
        assertTrue(receipt.configurationDigest().matches("[0-9a-f]{64}"));
        assertTrue(receipt.channelDigest().matches("[0-9a-f]{64}"));
    }

    @Test
    void concurrentReadsRemainDeterministicAndEveryDisclosureIsAudited() throws Exception {
        Fixture fixture = fixture();
        try (var executor = Executors.newFixedThreadPool(8)) {
            List<Callable<CheckoutProviderSdkRuntime.Configuration>> calls =
                    java.util.stream.IntStream.range(0, 24).mapToObj(index ->
                            (Callable<CheckoutProviderSdkRuntime.Configuration>) () -> fixture.runtime()
                                    .authorizeBrowser(fixture.created().checkoutSessionId(),
                                            fixture.token(), "card", CHANNEL,
                                            "request-provider-sdk-" + (5_600_100 + index)))
                            .toList();
            Set<CheckoutProviderSdkRuntime.Configuration> results = executor.invokeAll(calls).stream()
                    .map(future -> {
                        try {
                            return future.get();
                        } catch (Exception failure) {
                            throw new AssertionError(failure);
                        }
                    }).collect(java.util.stream.Collectors.toSet());
            assertEquals(1, results.size());
            assertEquals(24, fixture.audit().size());
        }
    }

    @Test
    void tamperExpiryConsumptionAndCrossTenantAccessFailClosed() {
        Fixture tamper = fixture();
        String token = tamper.token();
        String modified = token.substring(0, token.length() - 1)
                + (token.endsWith("A") ? "B" : "A");
        assertThrows(SecurityException.class, () -> tamper.runtime().authorizeBrowser(
                tamper.created().checkoutSessionId(), modified, "card", CHANNEL,
                "request-provider-sdk-56000201"));

        ApiPrincipal otherTenant = new ApiPrincipal("other-client",
                UUID.fromString("56000000-0000-4000-8000-000000000099"), PROJECT, MERCHANT,
                Set.of(ApiPrincipal.PAYMENTS_READ));
        assertThrows(SecurityException.class, () -> tamper.runtime().authorizePrincipal(otherTenant,
                tamper.created().checkoutSessionId(), "card", CHANNEL,
                "request-provider-sdk-56000202"));

        Fixture expired = fixture();
        expired.clock().advance(Duration.ofMinutes(11));
        assertThrows(IllegalArgumentException.class, () -> expired.runtime().authorizeBrowser(
                expired.created().checkoutSessionId(), expired.token(), "card", CHANNEL,
                "request-provider-sdk-56000203"));

        Fixture consumed = fixture();
        consumed.checkout().confirmForBrowser(consumed.created().checkoutSessionId(), consumed.token(),
                new HostedCheckoutService.ConfirmCommand("card", "psp://stripe/pm_56", "fp_56",
                        Map.of(), "checkout-provider-confirm-56000001", "correlation-56000001"));
        assertThrows(IllegalArgumentException.class, () -> consumed.runtime().authorizeBrowser(
                consumed.created().checkoutSessionId(), consumed.token(), "card", CHANNEL,
                "request-provider-sdk-56000204"));
    }

    @Test
    void unknownAndDisabledRegistryEntriesCannotBeEnabledByRuntimeParameters() {
        CheckoutProviderSdkRegistry registry = new CheckoutProviderSdkRegistry("policy-v1", List.of(
                new CheckoutProviderSdkRegistry.Entry("stripe", Set.of("card"), "stripe-js-v3",
                        false, Map.of("publishableKey", "ELMPAY_PROVIDER_PUBLIC_STRIPE_KEY"))),
                Map.of("ELMPAY_PROVIDER_PUBLIC_STRIPE_KEY", "pk_attacker_override"));
        assertTrue(registry.resolve("stripe", "card").isEmpty());
        assertTrue(registry.resolve("unknown", "card").isEmpty());
    }

    @Test
    void browserHttpRouteAcceptsOnlyBodylessExactQueryAndReturnsMinimalConfiguration()
            throws Exception {
        Fixture fixture = fixture();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 8);
        server.createContext("/", new PaymentHttpHandler(fixture.components(), fixture.checkout(),
                fixture.runtime()));
        server.start();
        try {
            URI endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort()
                    + "/api/checkout/sessions/" + fixture.created().checkoutSessionId()
                    + "/provider-sdk-config?method=card&channel=" + CHANNEL);
            HttpRequest.Builder request = HttpRequest.newBuilder(endpoint)
                    .header("Authorization", "CheckoutSession " + fixture.token())
                    .header("X-Request-Id", "request-provider-sdk-http-560001")
                    .header("traceparent",
                            "00-56565656565656565656565656565656-5656565656565656-01");
            HttpResponse<String> response = HttpClient.newHttpClient().send(request.GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode(), response.body());
            assertEquals(Set.of("method", "provider", "sdkVersion", "publicParameters"),
                    Json.object(response.body()).keySet());

            HttpResponse<String> injected = HttpClient.newHttpClient().send(HttpRequest.newBuilder(
                            URI.create(endpoint + "&scriptUrl=https://attacker.example/sdk.js"))
                    .header("Authorization", "CheckoutSession " + fixture.token())
                    .header("X-Request-Id", "request-provider-sdk-http-560002")
                    .header("traceparent",
                            "00-56565656565656565656565656565657-5656565656565657-01")
                    .GET().build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(400, injected.statusCode());

            HttpResponse<String> bodyAttempt = HttpClient.newHttpClient().send(request
                    .header("Content-Type", "application/json")
                    .method("GET", HttpRequest.BodyPublishers.ofString("{}"))
                    .build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(400, bodyAttempt.statusCode());
        } finally {
            server.stop(0);
        }
    }

    private static Fixture fixture() {
        RuntimeComponents payments = RuntimeFactory.create(Map.of(
                "ELMPAY_RUNTIME_MODE", "local", "ELMPAY_ENABLE_LOCAL_SANDBOX", "true",
                "ELMPAY_LOCAL_RISK_POLICY", "approve-sandbox", "ELMPAY_API_PRINCIPALS",
                ApiKeyAuthenticator.digestForProvisioning("checkout-provider-sdk-placeholder")
                        + "|test|" + TENANT + "|" + PROJECT + "|" + MERCHANT));
        MutableClock clock = new MutableClock(Clock.systemUTC().instant());
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, (byte) 0x56);
        CheckoutProviderSdkSource sdkSource = request -> java.util.Optional.of(
                new CheckoutProviderSdkSource.Selection(ACCOUNT, "stripe", request.method(),
                        "sha256:" + "a".repeat(64)));
        HostedCheckoutService checkout = new HostedCheckoutService(payments.payments(),
                new InMemoryCheckoutSessionRepository(),
                new CheckoutTokenSigner(Map.of("checkout-provider-v1", key),
                        "checkout-provider-v1"),
                Map.of("complete", URI.create("https://merchant.example/checkout/complete")),
                "complete", Set.of("card"), URI.create("http://127.0.0.1/checkout"),
                Duration.ofMinutes(10), "US", true, clock,
                new ConfiguredCheckoutCapabilitySource(Set.of("card")),
                CheckoutLocalization.defaultCatalog(), sdkSource);
        List<CheckoutProviderSdkAudit.Receipt> audit = java.util.Collections.synchronizedList(
                new ArrayList<>());
        CheckoutProviderSdkRegistry registry = new CheckoutProviderSdkRegistry("policy-v1", List.of(
                new CheckoutProviderSdkRegistry.Entry("stripe", Set.of("card"), "stripe-js-v3",
                        true, Map.of("publishableKey", "ELMPAY_PROVIDER_PUBLIC_STRIPE_KEY"))),
                Map.of("ELMPAY_PROVIDER_PUBLIC_STRIPE_KEY", "pk_live_server_owned"));
        CheckoutProviderSdkRuntime runtime = new CheckoutProviderSdkRuntime(checkout, registry,
                audit::add, clock);
        HostedCheckoutService.Created created = checkout.create(
                new HostedCheckoutService.CreateCommand(TENANT, PROJECT, MERCHANT, "order-56",
                        5_600, "USD", "complete", "device-context-5600000001",
                        "checkout-provider-create-56000001"));
        return new Fixture(payments, checkout, runtime, created,
                fragment(created.checkoutUrl(), "token"), audit, clock);
    }

    private static String fragment(URI uri, String name) {
        for (String item : uri.getRawFragment().split("&")) {
            String[] fields = item.split("=", 2);
            if (name.equals(URLDecoder.decode(fields[0], StandardCharsets.UTF_8))) {
                return URLDecoder.decode(fields[1], StandardCharsets.UTF_8);
            }
        }
        throw new AssertionError("fragment claim is missing");
    }

    private record Fixture(RuntimeComponents components, HostedCheckoutService checkout,
            CheckoutProviderSdkRuntime runtime,
            HostedCheckoutService.Created created, String token,
            List<CheckoutProviderSdkAudit.Receipt> audit, MutableClock clock) {
    }

    private static final class MutableClock extends Clock {
        private Instant now;
        private MutableClock(Instant now) { this.now = now; }
        private void advance(Duration duration) { now = now.plus(duration); }
        @Override public ZoneId getZone() { return ZoneId.of("UTC"); }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
