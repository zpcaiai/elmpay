package com.elmpay.sdk;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Dependency-free Java client with bounded idempotent retries and webhook verification. */
public final class ElmpayClient {
    public record CheckoutRequest(String businessOrderNo, long amount, String currency,
            String returnRouteId) {}
    public record ConfirmRequest(String paymentMethodType, String paymentMethodReference,
            String fingerprint) {}
    public record ApiResponse(int statusCode, String body, String requestId) {}
    public record SdkRequest(String method, URI uri, Map<String, String> headers, String body) {
        public SdkRequest { headers = Map.copyOf(headers); }
    }
    @FunctionalInterface
    public interface Transport {
        ApiResponse execute(SdkRequest request, Duration timeout)
                throws IOException, InterruptedException;
    }

    private final URI baseUri;
    private final String bearerToken;
    private final String projectId;
    private final Transport transport;
    private final Duration timeout;
    private final int maximumAttempts;

    public ElmpayClient(URI baseUri, String bearerToken, String projectId, Duration timeout,
            int maximumAttempts) {
        this(baseUri, bearerToken, projectId, timeout, maximumAttempts,
                new JdkTransport(timeout));
    }

    public ElmpayClient(URI baseUri, String bearerToken, String projectId, Duration timeout,
            int maximumAttempts, Transport transport) {
        if (!"https".equalsIgnoreCase(baseUri.getScheme())) throw new IllegalArgumentException("base URI must be HTTPS");
        if (bearerToken == null || bearerToken.isBlank()) throw new IllegalArgumentException("bearer token required");
        if (projectId == null || projectId.isBlank() || projectId.length() > 64) throw new IllegalArgumentException("project ID required");
        if (maximumAttempts < 1 || maximumAttempts > 5) throw new IllegalArgumentException("maximumAttempts must be 1..5");
        this.baseUri = baseUri; this.bearerToken = bearerToken; this.projectId = projectId;
        this.timeout = Objects.requireNonNull(timeout); this.maximumAttempts = maximumAttempts;
        this.transport = Objects.requireNonNull(transport);
    }

    public ApiResponse createCheckoutSession(CheckoutRequest value, String idempotencyKey)
            throws IOException, InterruptedException {
        if (value.amount() <= 0 || value.businessOrderNo() == null
                || value.businessOrderNo().isBlank() || value.currency() == null
                || value.currency().isBlank() || idempotencyKey == null || idempotencyKey.isBlank())
            throw new IllegalArgumentException("positive amount and idempotency key required");
        String body = "{\"business_order_no\":\"" + json(value.businessOrderNo())
                + "\",\"amount\":" + value.amount() + ",\"currency\":\""
                + json(value.currency()) + "\"" + (value.returnRouteId() == null ? ""
                : ",\"return_route_id\":\"" + json(value.returnRouteId()) + "\"") + "}";
        return send("POST", "/v1/checkout-sessions", body, idempotencyKey);
    }

    public ApiResponse getCheckoutSession(String sessionId) throws IOException, InterruptedException {
        return send("GET", "/v1/checkout-sessions/" + encodePath(sessionId), null, null);
    }

    public ApiResponse confirmCheckoutSession(String sessionId, ConfirmRequest value,
            String idempotencyKey) throws IOException, InterruptedException {
        if (value.paymentMethodType() == null || value.paymentMethodType().isBlank()
                || idempotencyKey == null || idempotencyKey.isBlank()) {
            throw new IllegalArgumentException("payment method and idempotency key required");
        }
        String body = "{\"payment_method_type\":\"" + json(value.paymentMethodType()) + "\""
                + (value.paymentMethodReference() == null ? "" : ",\"payment_method_reference\":\""
                + json(value.paymentMethodReference()) + "\"")
                + (value.fingerprint() == null ? "" : ",\"fingerprint\":\""
                + json(value.fingerprint()) + "\"") + "}";
        return send("POST", "/v1/checkout-sessions/" + encodePath(sessionId) + "/confirm",
                body, idempotencyKey);
    }

    private ApiResponse send(String method, String path, String body, String idempotencyKey)
            throws IOException, InterruptedException {
        IOException lastTransport = null;
        boolean retrySafe = idempotencyKey != null || method.equals("GET");
        for (int attempt = 1; attempt <= maximumAttempts; attempt++) {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("accept", "application/json");
            headers.put("authorization", "Bearer " + bearerToken);
            headers.put("user-agent", "elmpay-java/0.1");
            headers.put("x-project-id", projectId);
            if (idempotencyKey != null) headers.put("idempotency-key", idempotencyKey);
            if (body != null) headers.put("content-type", "application/json");
            try {
                ApiResponse response = transport.execute(new SdkRequest(method,
                        baseUri.resolve(path), headers, body), timeout);
                if (!retryable(response.statusCode()) || attempt == maximumAttempts || !retrySafe)
                    return response;
            } catch (IOException failure) {
                lastTransport = failure;
                if (!retrySafe || attempt == maximumAttempts) throw failure;
            }
            Thread.sleep(Math.min(1000L, 100L << (attempt - 1)));
        }
        throw Objects.requireNonNull(lastTransport);
    }

    public static boolean verifyWebhook(byte[] secret, byte[] rawBody, String signatureHeader,
                                        Clock clock, Duration tolerance) {
        if (secret == null || secret.length < 32 || signatureHeader == null) return false;
        long timestamp = -1; String signature = null;
        for (String part : signatureHeader.split(",")) {
            String[] pair = part.trim().split("=", 2);
            if (pair.length == 2 && pair[0].equals("t")) try { timestamp = Long.parseLong(pair[1]); } catch (NumberFormatException ignored) { return false; }
            if (pair.length == 2 && pair[0].equals("v1")) signature = pair[1];
        }
        if (timestamp < 0 || signature == null || Duration.between(Instant.ofEpochSecond(timestamp), clock.instant()).abs().compareTo(tolerance) > 0) return false;
        try {
            Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            mac.update(Long.toString(timestamp).getBytes(StandardCharsets.US_ASCII)); mac.update((byte) '.'); mac.update(rawBody);
            return MessageDigest.isEqual(mac.doFinal(), Base64.getUrlDecoder().decode(signature));
        } catch (GeneralSecurityException | IllegalArgumentException invalid) { return false; }
    }

    public static String newIdempotencyKey() { return UUID.randomUUID().toString(); }
    private static boolean retryable(int status) { return status == 408 || status == 429 || status >= 500; }
    private static String encodePath(String value) { return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20"); }
    private static String json(String value) { return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r"); }

    private static final class JdkTransport implements Transport {
        private final HttpClient http;
        private JdkTransport(Duration timeout) {
            http = HttpClient.newBuilder().connectTimeout(timeout)
                    .followRedirects(HttpClient.Redirect.NEVER).build();
        }
        @Override
        public ApiResponse execute(SdkRequest value, Duration timeout)
                throws IOException, InterruptedException {
            HttpRequest.Builder builder = HttpRequest.newBuilder(value.uri()).timeout(timeout);
            value.headers().forEach(builder::header);
            builder.method(value.method(), value.body() == null
                    ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofString(value.body(), StandardCharsets.UTF_8));
            HttpResponse<String> response = http.send(builder.build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return new ApiResponse(response.statusCode(), response.body(),
                    response.headers().firstValue("x-request-id").orElse(""));
        }
    }
}
