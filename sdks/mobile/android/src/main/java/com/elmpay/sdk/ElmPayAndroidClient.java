package com.elmpay.sdk;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Android-callable client core; platform HTTP/attestation/provider launch are injected boundaries. */
public final class ElmPayAndroidClient {
    public interface Transport { Response execute(Request request) throws Exception; }
    public interface DeviceAttestation { String attest(byte[] challenge) throws Exception; }
    public interface ProviderLauncher { void launch(String method, URI launchUri) throws Exception; }
    public record Request(String method, URI uri, Map<String, String> headers, byte[] body, Duration timeout) {}
    public record Response(int status, byte[] body) {}
    public record CheckoutRequest(String businessOrderNo, long amount, String currency,
            String returnRouteId) {}
    public record ConfirmRequest(String paymentMethodType, String paymentMethodReference,
            String fingerprint) {}

    private final URI baseUri; private final String bearerToken; private final String projectId;
    private final Transport transport;
    private final int maximumAttempts; private final Duration timeout;
    public ElmPayAndroidClient(URI baseUri, String bearerToken, String projectId,
            Transport transport, int maximumAttempts, Duration timeout) {
        if (!"https".equalsIgnoreCase(baseUri.getScheme()) || bearerToken == null || bearerToken.isBlank()
                || projectId == null || projectId.isBlank() || maximumAttempts < 1
                || maximumAttempts > 5) throw new IllegalArgumentException("secure SDK configuration required");
        this.baseUri = baseUri; this.bearerToken = bearerToken; this.projectId = projectId;
        this.transport = Objects.requireNonNull(transport);
        this.maximumAttempts = maximumAttempts; this.timeout = Objects.requireNonNull(timeout);
    }

    public Response createSession(CheckoutRequest value, DeviceAttestation attestation) throws Exception {
        if (value.amount() <= 0 || value.businessOrderNo() == null
                || value.businessOrderNo().isBlank() || value.currency() == null
                || value.currency().isBlank()) throw new IllegalArgumentException("invalid checkout request");
        String assertion = attestation.attest(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        if (assertion == null || assertion.isBlank()) throw new SecurityException("device assertion missing");
        String body = "{\"business_order_no\":\"" + json(value.businessOrderNo())
                + "\",\"amount\":" + value.amount() + ",\"currency\":\""
                + json(value.currency()) + "\"" + (value.returnRouteId() == null ? ""
                : ",\"return_route_id\":\"" + json(value.returnRouteId()) + "\"") + "}";
        return send("POST", "/v1/checkout-sessions", body.getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString(), assertion);
    }
    public Response retrieveSession(String id) throws Exception { return send("GET", "/v1/checkout-sessions/" + encode(id), null, null, null); }
    public Response confirmSession(String id, ConfirmRequest value) throws Exception {
        if (value.paymentMethodType() == null || value.paymentMethodType().isBlank())
            throw new IllegalArgumentException("payment method type required");
        String body = "{\"payment_method_type\":\"" + json(value.paymentMethodType()) + "\""
                + (value.paymentMethodReference() == null ? "" : ",\"payment_method_reference\":\""
                + json(value.paymentMethodReference()) + "\"")
                + (value.fingerprint() == null ? "" : ",\"fingerprint\":\""
                + json(value.fingerprint()) + "\"") + "}";
        return send("POST", "/v1/checkout-sessions/" + encode(id) + "/confirm",
                body.getBytes(StandardCharsets.UTF_8), UUID.randomUUID().toString(), null);
    }

    public void launchPaymentMethod(String method, URI launchUri, ProviderLauncher launcher)
            throws Exception {
        if (method == null || !method.matches("[a-z0-9][a-z0-9._-]{0,63}")) {
            throw new IllegalArgumentException("payment method is invalid");
        }
        requireProviderLaunchUri(launchUri);
        Objects.requireNonNull(launcher, "launcher").launch(method, launchUri);
    }

    public String validateDeepLink(URI uri, String expectedScheme, String expectedHost, String expectedState) {
        Map<String, String> parameters = new HashMap<>();
        for (String item : Objects.requireNonNullElse(uri.getRawQuery(), "").split("&")) {
            String[] pair = item.split("=", 2); if (pair.length == 2) parameters.put(pair[0], URLDecoder.decode(pair[1], StandardCharsets.UTF_8));
        }
        boolean valid = Objects.equals(uri.getScheme(), expectedScheme) && Objects.equals(uri.getHost(), expectedHost)
                && MessageDigest.isEqual(bytes(parameters.getOrDefault("state", "")), bytes(expectedState));
        String session = parameters.get("session");
        if (!valid || session == null || session.isBlank()) throw new SecurityException("untrusted deep link");
        return session; // retrieve server state; never infer payment success from the deep link
    }

    private Response send(String method, String path, byte[] body, String idempotencyKey, String attestation) throws Exception {
        Exception last = null;
        boolean retrySafe = idempotencyKey != null || method.equals("GET");
        for (int attempt = 0; attempt < maximumAttempts; attempt++) {
            Map<String, String> headers = new HashMap<>(); headers.put("authorization", "Bearer " + bearerToken); headers.put("accept", "application/json"); headers.put("x-project-id", projectId); headers.put("x-elmpay-device-class", "ANDROID");
            if (body != null) headers.put("content-type", "application/json");
            if (idempotencyKey != null) headers.put("idempotency-key", idempotencyKey);
            if (attestation != null) headers.put("x-device-attestation", attestation);
            try {
                Response response = transport.execute(new Request(method, baseUri.resolve(path), Map.copyOf(headers), body, timeout));
                if (!retrySafe || attempt + 1 == maximumAttempts || !retryable(response.status())) return response;
            } catch (Exception failure) {
                last = failure; if (!retrySafe || attempt + 1 == maximumAttempts) throw failure;
            }
            Thread.sleep(Math.min(1000L, 100L << attempt));
        }
        throw Objects.requireNonNull(last);
    }
    private static boolean retryable(int status) { return status == 408 || status == 429 || status >= 500; }
    private static void requireProviderLaunchUri(URI value) {
        if (value == null || value.getScheme() == null || value.getUserInfo() != null
                || value.getFragment() != null || !("https".equalsIgnoreCase(value.getScheme())
                || Set.of("weixin", "alipay", "paypal").contains(
                        value.getScheme().toLowerCase(java.util.Locale.ROOT)))) {
            throw new SecurityException("provider launch URI is not trusted");
        }
    }
    private static String encode(String value) { return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20"); }
    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static String json(String value) { return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r"); }
}
