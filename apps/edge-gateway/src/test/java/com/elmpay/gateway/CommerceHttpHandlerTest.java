package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.payment.commerce.CommerceService;
import com.sun.net.httpserver.HttpServer;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

final class CommerceHttpHandlerTest {
    @Test
    void authenticatedPlanApiUsesPrincipalTenantAndIdempotency() throws Exception {
        String authorizationPlaceholder = "placeholder-only-for-commerce-http-test";
        UUID tenant = UUID.randomUUID();
        UUID project = UUID.randomUUID();
        UUID merchant = UUID.randomUUID();
        ApiKeyAuthenticator authenticator = ApiKeyAuthenticator.parse(
                ApiKeyAuthenticator.digestForProvisioning(authorizationPlaceholder)
                        + "|actor|" + tenant + "|" + project + "|" + merchant
                        + "|payments.read+payments.write");
        UUID planId = UUID.randomUUID();
        CommerceService service = (CommerceService) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[] {CommerceService.class},
                (proxy, method, arguments) -> {
                    if (!"createPlan".equals(method.getName())) {
                        throw new AssertionError(method.getName());
                    }
                    CommerceService.Context context = (CommerceService.Context) arguments[0];
                    assertEquals(tenant, context.tenantId());
                    assertEquals(project, context.projectId());
                    assertEquals("idem-1", arguments[2]);
                    return new CommerceService.Plan(planId, tenant, project, "pro", 1_000,
                            "USD", 2_592_000, 0, false, 3);
                });
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/billing", new CommerceHttpHandler(authenticator,
                Optional.of(service)));
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.start();
        try (HttpClient client = HttpClient.newHttpClient()) {
            URI uri = URI.create("http://127.0.0.1:" + server.getAddress().getPort()
                    + "/v1/billing/plans");
            HttpRequest request = HttpRequest.newBuilder(uri)
                    .header("Authorization", "Bearer " + authorizationPlaceholder)
                    .header("X-Project-Id", project.toString())
                    .header("X-Request-Id", UUID.randomUUID().toString())
                    .header("traceparent", "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
                    .header("Idempotency-Key", "idem-1")
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("""
                            {"code":"pro","amount_minor":1000,"currency":"USD",
                             "billing_period_seconds":2592000,"trial_period_seconds":0,
                             "metered":false,"version":3}
                            """))
                    .build();
            HttpResponse<String> response = client.send(request,
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(201, response.statusCode());
            assertTrue(response.body().contains(planId.toString()));
            assertTrue(response.body().contains("\"version\":3"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void productionFinancialRuntimeRequiresKmsSigner() {
        assertTrue(FinancialRuntimeFactory.create(java.util.Map.of(
                "ELMPAY_RUNTIME_MODE", "local")).isEmpty());
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                () -> FinancialRuntimeFactory.create(java.util.Map.of(
                        "ELMPAY_RUNTIME_MODE", "postgres")));
    }
}
