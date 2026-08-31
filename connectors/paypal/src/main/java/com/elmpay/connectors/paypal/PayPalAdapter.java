package com.elmpay.connectors.paypal;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;
import javax.net.ssl.SSLParameters;

import com.elmpay.events.StrictJson;
import com.elmpay.security.BoundedHttpTransport;

/** PayPal Orders v2 adapter with OAuth, stable request IDs and official webhook verification. */
public final class PayPalAdapter implements AutoCloseable {
    private static final int MAX_BODY_BYTES = 1_048_576;
    private static final Pattern IDEMPOTENCY_KEY = Pattern.compile("[A-Za-z0-9._:-]{16,128}");
    private static final Pattern PROVIDER_ID = Pattern.compile("[A-Za-z0-9_-]{6,128}");

    public enum State { CREATED, APPROVAL_REQUIRED, AUTHORIZED, PROCESSING, SUCCEEDED, FAILED, VOIDED, UNKNOWN }

    public record ClientCredentials(String clientId, String clientSecret) {
        public ClientCredentials {
            requireText(clientId, "clientId");
            requireText(clientSecret, "clientSecret");
        }
    }

    @FunctionalInterface
    public interface CredentialProvider {
        ClientCredentials current();
    }

    public record Config(URI apiBase, URI approvedCheckoutBase, String webhookId,
            Set<String> certificateHosts, CredentialProvider credentialProvider,
            Duration requestTimeout, int maxAttempts, Clock clock) {
        public Config {
            requireHttps(apiBase, "apiBase");
            requireHttps(approvedCheckoutBase, "approvedCheckoutBase");
            if (!approvedCheckoutBase.getPath().endsWith("/") || approvedCheckoutBase.getQuery() != null) {
                throw new IllegalArgumentException("approvedCheckoutBase must end in a path separator");
            }
            requireText(webhookId, "webhookId");
            certificateHosts = certificateHosts.stream().map(host -> host.toLowerCase(Locale.ROOT))
                    .collect(java.util.stream.Collectors.toUnmodifiableSet());
            if (certificateHosts.isEmpty()) {
                throw new IllegalArgumentException("certificateHosts is empty");
            }
            Objects.requireNonNull(credentialProvider, "credentialProvider");
            positive(requestTimeout, "requestTimeout");
            if (maxAttempts < 1 || maxAttempts > 3) {
                throw new IllegalArgumentException("maxAttempts must be between 1 and 3");
            }
            Objects.requireNonNull(clock, "clock");
        }
    }

    public record OrderRequest(String merchantReference, long amountMinor, String currency,
            int currencyExponent, boolean authorizeOnly, String approvedReturnRouteToken,
            String approvedCancelRouteToken, String idempotencyKey) {
        public OrderRequest {
            requireText(merchantReference, "merchantReference");
            positiveAmount(amountMinor);
            requireCurrency(currency);
            requireExponent(currencyExponent);
            requireRouteToken(approvedReturnRouteToken, "approvedReturnRouteToken");
            requireRouteToken(approvedCancelRouteToken, "approvedCancelRouteToken");
            requireIdempotency(idempotencyKey);
        }
    }

    public record ExpectedWebhook(String providerObjectId, String merchantId,
            long amountMinor, String currency, int currencyExponent, String businessOrderNo) {
        public ExpectedWebhook {
            requireProviderId(providerObjectId, "providerObjectId");
            requireText(merchantId, "merchantId");
            positiveAmount(amountMinor);
            requireCurrency(currency);
            requireExponent(currencyExponent);
            requireText(businessOrderNo, "businessOrderNo");
        }
    }

    public record OperationResult(State state, boolean finalState, int httpStatus,
            String providerReference, String responseBody) {
        public OperationResult {
            Objects.requireNonNull(state, "state");
            providerReference = providerReference == null ? "" : providerReference;
            responseBody = responseBody == null ? "" : responseBody;
        }
    }

    public record VerifiedWebhook(String eventId, String eventType, String providerObjectId,
            long amountMinor, String currency, byte[] canonicalPayload) {
        public VerifiedWebhook {
            canonicalPayload = canonicalPayload.clone();
        }

        @Override
        public byte[] canonicalPayload() {
            return canonicalPayload.clone();
        }
    }

    /** Transport response whose owned body must be wiped after one attempt. */
    public static final class HttpResult implements AutoCloseable {
        private final int statusCode;
        private byte[] body;
        private boolean closed;

        public HttpResult(int statusCode, byte[] body) {
            this.statusCode = statusCode;
            this.body = Objects.requireNonNull(body, "body").clone();
        }

        public int statusCode() {
            return statusCode;
        }

        public synchronized int bodyLength() {
            ensureOpen();
            return body.length;
        }

        /** Returns an owned copy; the caller must wipe it. */
        public synchronized byte[] body() {
            ensureOpen();
            return body.clone();
        }

        @Override
        public synchronized void close() {
            if (closed) {
                return;
            }
            closed = true;
            Arrays.fill(body, (byte) 0);
            body = new byte[0];
        }

        private void ensureOpen() {
            if (closed) {
                throw new IllegalStateException("PayPal HTTP response is closed");
            }
        }
    }

    @FunctionalInterface
    public interface Transport {
        HttpResult send(HttpRequest request) throws IOException, InterruptedException;
    }

    public static final class JdkTransport implements Transport {
        private final HttpClient client;

        public JdkTransport(Duration connectTimeout) {
            positive(connectTimeout, "connectTimeout");
            SSLParameters tls = new SSLParameters();
            tls.setProtocols(new String[] {"TLSv1.3"});
            tls.setEndpointIdentificationAlgorithm("HTTPS");
            client = HttpClient.newBuilder().connectTimeout(connectTimeout)
                    .sslParameters(tls).followRedirects(HttpClient.Redirect.NEVER).build();
        }

        @Override
        public HttpResult send(HttpRequest request) throws IOException, InterruptedException {
            try (BoundedHttpTransport.Response response = BoundedHttpTransport.send(
                    client, request, MAX_BODY_BYTES)) {
                requireJsonContentType(response.headers(), response.bodyLength());
                byte[] body = response.body();
                try {
                    return new HttpResult(response.statusCode(), body);
                } finally {
                    Arrays.fill(body, (byte) 0);
                }
            }
        }

        private static void requireJsonContentType(HttpHeaders headers, int bodyLength) {
            List<String> values = headers.allValues("Content-Type");
            if (bodyLength == 0 && values.isEmpty()) {
                return;
            }
            if (values.size() != 1) {
                throw new SecurityException("PayPal response Content-Type is missing or ambiguous");
            }
            String value = values.getFirst().trim();
            int separator = value.indexOf(';');
            String mediaType = separator < 0 ? value : value.substring(0, separator).trim();
            if (!"application/json".equalsIgnoreCase(mediaType)
                    || value.indexOf(',') >= 0) {
                throw new SecurityException("PayPal response Content-Type is not application/json");
            }
        }
    }

    private record AccessToken(String value, Instant expiresAt) { }

    private static final class OAuthUnavailableException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        OAuthUnavailableException(String message) {
            super(message);
        }

        OAuthUnavailableException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private final Config config;
    private final Transport transport;
    private volatile AccessToken cachedToken;
    private final AtomicBoolean closed = new AtomicBoolean();

    public PayPalAdapter(Config config, Transport transport) {
        this.config = Objects.requireNonNull(config, "config");
        this.transport = Objects.requireNonNull(transport, "transport");
    }

    public OperationResult createOrder(OrderRequest request) {
        Objects.requireNonNull(request, "request");
        String intent = request.authorizeOnly() ? "AUTHORIZE" : "CAPTURE";
        String body = "{\"intent\":\"" + intent + "\",\"purchase_units\":[{\"reference_id\":\""
                + json(request.merchantReference()) + "\",\"amount\":{\"currency_code\":\""
                + request.currency() + "\",\"value\":\""
                + majorAmount(request.amountMinor(), request.currencyExponent())
                + "\"}}],\"payment_source\":{\"paypal\":{\"experience_context\":{\"return_url\":\""
                + json(config.approvedCheckoutBase().resolve("route/" + request.approvedReturnRouteToken()).toString())
                + "\",\"cancel_url\":\""
                + json(config.approvedCheckoutBase().resolve("route/" + request.approvedCancelRouteToken()).toString())
                + "\"}}}}";
        return execute("POST", "/v2/checkout/orders", body, request.idempotencyKey());
    }

    public OperationResult queryOrder(String orderId) {
        requireProviderId(orderId, "orderId");
        return execute("GET", "/v2/checkout/orders/" + orderId, "", "query-order-" + orderId);
    }

    public OperationResult authorize(String orderId, String idempotencyKey) {
        requireProviderId(orderId, "orderId");
        requireIdempotency(idempotencyKey);
        return execute("POST", "/v2/checkout/orders/" + orderId + "/authorize", "{}", idempotencyKey);
    }

    public OperationResult capture(String orderId, String idempotencyKey) {
        requireProviderId(orderId, "orderId");
        requireIdempotency(idempotencyKey);
        return execute("POST", "/v2/checkout/orders/" + orderId + "/capture", "{}", idempotencyKey);
    }

    public OperationResult voidAuthorization(String authorizationId, String idempotencyKey) {
        requireProviderId(authorizationId, "authorizationId");
        requireIdempotency(idempotencyKey);
        return execute("POST", "/v2/payments/authorizations/" + authorizationId + "/void", "{}",
                idempotencyKey);
    }

    public OperationResult refund(String captureId, long amountMinor, String currency,
            int currencyExponent, String refundReference, String idempotencyKey) {
        requireProviderId(captureId, "captureId");
        positiveAmount(amountMinor);
        requireCurrency(currency);
        requireExponent(currencyExponent);
        requireText(refundReference, "refundReference");
        requireIdempotency(idempotencyKey);
        String body = "{\"amount\":{\"value\":\"" + majorAmount(amountMinor, currencyExponent)
                + "\",\"currency_code\":\"" + currency + "\"},\"invoice_id\":\""
                + json(refundReference) + "\"}";
        return execute("POST", "/v2/payments/captures/" + captureId + "/refund", body, idempotencyKey);
    }

    public OperationResult queryRefund(String refundId) {
        requireProviderId(refundId, "refundId");
        return execute("GET", "/v2/payments/refunds/" + refundId, "", "query-refund-" + refundId);
    }

    public OperationResult createSubscription(String planId, String subscriberReference,
            String approvedReturnRouteToken, String approvedCancelRouteToken, String idempotencyKey) {
        requireProviderId(planId, "planId");
        requireText(subscriberReference, "subscriberReference");
        requireRouteToken(approvedReturnRouteToken, "approvedReturnRouteToken");
        requireRouteToken(approvedCancelRouteToken, "approvedCancelRouteToken");
        requireIdempotency(idempotencyKey);
        String body = "{\"plan_id\":\"" + json(planId) + "\",\"custom_id\":\""
                + json(subscriberReference) + "\",\"application_context\":{\"return_url\":\""
                + json(config.approvedCheckoutBase().resolve("route/" + approvedReturnRouteToken).toString())
                + "\",\"cancel_url\":\""
                + json(config.approvedCheckoutBase().resolve("route/" + approvedCancelRouteToken).toString())
                + "\"}}";
        return execute("POST", "/v1/billing/subscriptions", body, idempotencyKey);
    }

    public OperationResult cancelSubscription(String subscriptionId, String reason, String idempotencyKey) {
        requireProviderId(subscriptionId, "subscriptionId");
        requireText(reason, "reason");
        requireIdempotency(idempotencyKey);
        return execute("POST", "/v1/billing/subscriptions/" + subscriptionId + "/cancel",
                "{\"reason\":\"" + json(reason) + "\"}", idempotencyKey);
    }

    public OperationResult submitDisputeEvidence(String disputeId, String note,
            String evidenceFileReference, String idempotencyKey) {
        requireProviderId(disputeId, "disputeId");
        requireText(note, "note");
        requireText(evidenceFileReference, "evidenceFileReference");
        requireIdempotency(idempotencyKey);
        String body = "{\"evidences\":[{\"notes\":\"" + json(note)
                + "\",\"evidence_info\":{\"tracking_info\":[{\"tracking_number\":\""
                + json(evidenceFileReference) + "\"}]}}]}";
        return execute("POST", "/v1/customer/disputes/" + disputeId + "/provide-evidence", body,
                idempotencyKey);
    }

    /**
     * Uses PayPal's official verify-webhook-signature endpoint. No remote certificate URL is fetched locally.
     */
    public VerifiedWebhook verifyWebhook(Map<String, String> headers, byte[] rawBody,
            ExpectedWebhook expected) {
        ensureOpen();
        Objects.requireNonNull(headers, "headers");
        Objects.requireNonNull(rawBody, "rawBody");
        Objects.requireNonNull(expected, "expected");
        if (rawBody.length == 0 || rawBody.length > MAX_BODY_BYTES) {
            throw new SecurityException("invalid PayPal webhook body size");
        }
        String transmissionId = header(headers, "PAYPAL-TRANSMISSION-ID");
        String transmissionTime = header(headers, "PAYPAL-TRANSMISSION-TIME");
        String certUrl = header(headers, "PAYPAL-CERT-URL");
        String authAlgo = header(headers, "PAYPAL-AUTH-ALGO");
        String transmissionSignature = header(headers, "PAYPAL-TRANSMISSION-SIG");
        URI certificateUri;
        try {
            certificateUri = URI.create(certUrl);
        } catch (IllegalArgumentException exception) {
            throw new SecurityException("invalid PayPal certificate URL", exception);
        }
        requireHttps(certificateUri, "PayPal certificate URL");
        if (!config.certificateHosts().contains(certificateUri.getHost().toLowerCase(Locale.ROOT))) {
            throw new SecurityException("PayPal certificate host is not allowlisted");
        }
        if (!Set.of("SHA256withRSA", "SHA256withECDSA").contains(authAlgo)) {
            throw new SecurityException("unsupported PayPal webhook algorithm");
        }
        String webhookEvent = strictUtf8(rawBody).trim();
        Map<String, Object> event = strictJsonObject(webhookEvent, "webhook event");
        String eventId = requiredWebhookString(event, "id");
        if (!eventId.matches("WH-[A-Za-z0-9_-]{4,128}")) {
            throw new SecurityException("invalid PayPal webhook event id");
        }
        String verificationBody = "{\"auth_algo\":\"" + json(authAlgo)
                + "\",\"cert_url\":\"" + json(certUrl) + "\",\"transmission_id\":\""
                + json(transmissionId) + "\",\"transmission_sig\":\"" + json(transmissionSignature)
                + "\",\"transmission_time\":\"" + json(transmissionTime) + "\",\"webhook_id\":\""
                + json(config.webhookId()) + "\",\"webhook_event\":" + webhookEvent + "}";
        String requestId = "verify-" + sha256(rawBody).substring(0, 32);
        OperationResult verification = execute("POST", "/v1/notifications/verify-webhook-signature",
                verificationBody, requestId);
        if (verification.httpStatus() < 200 || verification.httpStatus() >= 300
                || !"SUCCESS".equals(optionalJsonString(verification.responseBody(), "verification_status"))) {
            throw new SecurityException("PayPal rejected webhook signature");
        }
        String eventType = requiredWebhookString(event, "event_type");
        Map<String, Object> resource = requiredWebhookObject(event, "resource");
        String providerObjectId = requiredWebhookString(resource, "id");
        if (providerObjectId.startsWith("WH-")
                || !providerObjectId.matches("[A-Za-z0-9_-]{6,128}")) {
            throw new SecurityException("invalid PayPal provider object id");
        }
        Map<String, Object> amountObject = requiredWebhookObject(resource, "amount");
        Map<String, Object> payee = requiredWebhookObject(resource, "payee");
        String merchantId = requiredWebhookString(payee, "merchant_id");
        String value = requiredWebhookString(amountObject, "value");
        String currency = requiredWebhookString(amountObject, "currency_code");
        long amount = parseMinor(value, expected.currencyExponent());
        if (!expected.providerObjectId().equals(providerObjectId)
                || !expected.merchantId().equals(merchantId)
                || expected.amountMinor() != amount || !expected.currency().equals(currency)) {
            throw new SecurityException("PayPal webhook binding mismatch");
        }
        String canonical = "{\"event_id\":\"" + json(eventId) + "\",\"event_type\":\""
                + json(eventType) + "\",\"provider_object_id\":\"" + json(providerObjectId)
                + "\",\"amount_minor\":" + amount + ",\"currency\":\"" + currency + "\"}";
        return new VerifiedWebhook(eventId, eventType, providerObjectId, amount, currency,
                canonical.getBytes(StandardCharsets.UTF_8));
    }

    private OperationResult execute(String method, String path, String body, String requestId) {
        ensureOpen();
        int lastStatus = 0;
        for (int attempt = 1; attempt <= config.maxAttempts(); attempt++) {
            try {
                HttpRequest.Builder builder = HttpRequest.newBuilder(config.apiBase().resolve(path))
                        .timeout(config.requestTimeout())
                        .header("Accept", "application/json")
                        .header("Authorization", "Bearer " + accessToken())
                        .header("PayPal-Request-Id", requestId);
                HttpRequest request = "GET".equals(method) ? builder.GET().build()
                        : builder.header("Content-Type", "application/json")
                                .method(method, HttpRequest.BodyPublishers.ofString(body,
                                        StandardCharsets.UTF_8)).build();
                try (HttpResult result = transport.send(request)) {
                    lastStatus = result.statusCode();
                    if (result.bodyLength() > MAX_BODY_BYTES) {
                        return new OperationResult(State.UNKNOWN, false, lastStatus, "", "");
                    }
                    if (lastStatus == 401 && attempt < config.maxAttempts()) {
                        cachedToken = null;
                        continue;
                    }
                    if ((lastStatus < 200 || lastStatus >= 300) && retryable(lastStatus)) {
                        continue;
                    }
                    byte[] responseBytes = result.body();
                    String response;
                    try {
                        response = strictUtf8(responseBytes);
                    } finally {
                        Arrays.fill(responseBytes, (byte) 0);
                    }
                    if (lastStatus >= 200 && lastStatus < 300) {
                        String status = optionalJsonString(response, "status");
                        State state = mapState(status);
                        return new OperationResult(state, isFinal(state), lastStatus,
                                optionalJsonString(response, "id"), response);
                    }
                    return new OperationResult(State.FAILED, true, lastStatus, "", response);
                }
            } catch (IOException exception) {
                lastStatus = 0;
            } catch (OAuthUnavailableException exception) {
                lastStatus = 0;
            } catch (SecurityException exception) {
                return new OperationResult(State.UNKNOWN, false, lastStatus, "", "");
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                return new OperationResult(State.UNKNOWN, false, 0, "", "");
            }
        }
        return new OperationResult(State.UNKNOWN, false, lastStatus, "", "");
    }

    private String accessToken() {
        ensureOpen();
        AccessToken current = cachedToken;
        Instant now = Instant.now(config.clock());
        if (current != null && current.expiresAt().isAfter(now.plusSeconds(30))) {
            return current.value();
        }
        synchronized (this) {
            current = cachedToken;
            if (current != null && current.expiresAt().isAfter(now.plusSeconds(30))) {
                return current.value();
            }
            ClientCredentials credentials = config.credentialProvider().current();
            String basic = Base64.getEncoder().encodeToString(
                    (credentials.clientId() + ":" + credentials.clientSecret()).getBytes(StandardCharsets.UTF_8));
            HttpRequest request = HttpRequest.newBuilder(config.apiBase().resolve("/v1/oauth2/token"))
                    .timeout(config.requestTimeout()).header("Accept", "application/json")
                    .header("Authorization", "Basic " + basic)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials",
                            StandardCharsets.US_ASCII)).build();
            try {
                try (HttpResult result = transport.send(request)) {
                    if (result.statusCode() < 200 || result.statusCode() >= 300
                            || result.bodyLength() > MAX_BODY_BYTES) {
                        throw new OAuthUnavailableException("PayPal OAuth request failed");
                    }
                    byte[] responseBytes = result.body();
                    String response;
                    try {
                        response = strictUtf8(responseBytes);
                    } finally {
                        Arrays.fill(responseBytes, (byte) 0);
                    }
                    String token = requiredJsonString(response, "access_token");
                    long expiresIn = requiredJsonLong(response, "expires_in");
                    if (expiresIn < 60 || expiresIn > 86_400) {
                        throw new OAuthUnavailableException("PayPal OAuth returned an invalid lifetime");
                    }
                    cachedToken = new AccessToken(token, now.plusSeconds(expiresIn));
                    return token;
                }
            } catch (IOException exception) {
                throw new OAuthUnavailableException("PayPal OAuth transport failed", exception);
            } catch (SecurityException exception) {
                throw new OAuthUnavailableException("PayPal OAuth response failed validation", exception);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new OAuthUnavailableException("PayPal OAuth interrupted", exception);
            }
        }
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            cachedToken = null;
        }
    }

    private void ensureOpen() {
        if (closed.get()) {
            throw new IllegalStateException("PayPal credential runtime is closed");
        }
    }

    private static State mapState(String status) {
        return switch (status) {
            case "CREATED", "SAVED" -> State.CREATED;
            case "PAYER_ACTION_REQUIRED", "APPROVAL_PENDING" -> State.APPROVAL_REQUIRED;
            case "APPROVED", "AUTHORIZED", "ACTIVE" -> State.AUTHORIZED;
            case "PENDING" -> State.PROCESSING;
            case "COMPLETED" -> State.SUCCEEDED;
            case "FAILED", "DENIED", "EXPIRED", "SUSPENDED" -> State.FAILED;
            case "VOIDED", "CANCELLED" -> State.VOIDED;
            default -> State.UNKNOWN;
        };
    }

    private static boolean isFinal(State state) {
        return state == State.SUCCEEDED || state == State.FAILED || state == State.VOIDED;
    }

    private static String header(Map<String, String> headers, String name) {
        String result = null;
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (!entry.getKey().equalsIgnoreCase(name)) {
                continue;
            }
            if (result != null || entry.getValue() == null) {
                throw new SecurityException("ambiguous PayPal webhook header: " + name);
            }
            result = entry.getValue();
        }
        if (result == null) {
            throw new SecurityException("missing PayPal webhook header: " + name);
        }
        if (result.isBlank() || result.length() > 4_096
                || result.chars().anyMatch(character -> character < 0x20 || character == 0x7f)) {
            throw new SecurityException("invalid PayPal webhook header: " + name);
        }
        return result;
    }

    private static Map<String, Object> strictJsonObject(String body, String label) {
        try {
            return StrictJson.object(body);
        } catch (IllegalArgumentException exception) {
            throw new SecurityException("invalid PayPal " + label + " JSON", exception);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> requiredWebhookObject(Map<String, Object> source,
            String key) {
        Object value = source.get(key);
        if (!(value instanceof Map<?, ?> map)) {
            throw new SecurityException("missing PayPal webhook object field: " + key);
        }
        return (Map<String, Object>) map;
    }

    private static String requiredWebhookString(Map<String, Object> source, String key) {
        Object value = source.get(key);
        if (!(value instanceof String text) || text.isBlank() || text.length() > 512
                || text.chars().anyMatch(character -> character < 0x20
                        || character == 0x7f)) {
            throw new SecurityException("invalid PayPal webhook string field: " + key);
        }
        return text;
    }

    private static String requiredJsonString(String body, String key) {
        String value = optionalJsonString(body, key);
        if (value.isBlank()) {
            throw new SecurityException("missing PayPal JSON field: " + key);
        }
        return value;
    }

    private static String optionalJsonString(String body, String key) {
        Object value = strictJsonObject(body, "provider response").get(key);
        if (value == null) {
            return "";
        }
        if (!(value instanceof String text) || text.length() > 8_192
                || text.chars().anyMatch(character -> character < 0x20
                        || character == 0x7f)) {
            throw new SecurityException("invalid PayPal JSON string field: " + key);
        }
        return text;
    }

    private static long requiredJsonLong(String body, String key) {
        Object value = strictJsonObject(body, "provider response").get(key);
        if (!(value instanceof Long number) || number < 0) {
            throw new SecurityException("invalid PayPal numeric field: " + key);
        }
        return number;
    }

    private static long parseMinor(String value, int exponent) {
        try {
            return new BigDecimal(value).setScale(exponent, RoundingMode.UNNECESSARY)
                    .movePointRight(exponent).longValueExact();
        } catch (NumberFormatException | ArithmeticException exception) {
            throw new SecurityException("invalid PayPal amount", exception);
        }
    }

    private static String majorAmount(long minor, int exponent) {
        return BigDecimal.valueOf(minor, exponent).setScale(exponent, RoundingMode.UNNECESSARY).toPlainString();
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static String strictUtf8(byte[] value) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value)).toString();
        } catch (CharacterCodingException exception) {
            throw new SecurityException("body is not valid UTF-8", exception);
        }
    }

    private static String json(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\r", "\\r").replace("\n", "\\n");
    }

    private static boolean retryable(int status) {
        return status == 408 || status == 425 || status == 429 || status >= 500;
    }

    private static void requireProviderId(String value, String name) {
        if (value == null || !PROVIDER_ID.matcher(value).matches()) {
            throw new IllegalArgumentException(name + " has an invalid format");
        }
    }

    private static void requireIdempotency(String value) {
        if (value == null || !IDEMPOTENCY_KEY.matcher(value).matches()) {
            throw new IllegalArgumentException("invalid idempotency key");
        }
    }

    private static void requireRouteToken(String value, String name) {
        if (value == null || !value.matches("[A-Za-z0-9_-]{16,128}")) {
            throw new IllegalArgumentException(name + " has an invalid format");
        }
    }

    private static void requireCurrency(String value) {
        if (value == null || !value.matches("[A-Z]{3}")) {
            throw new IllegalArgumentException("currency must be three uppercase letters");
        }
    }

    private static void requireExponent(int exponent) {
        if (exponent < 0 || exponent > 3) {
            throw new IllegalArgumentException("currencyExponent must be between 0 and 3");
        }
    }

    private static void positiveAmount(long amount) {
        if (amount <= 0) {
            throw new IllegalArgumentException("amount must be positive");
        }
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
    }

    private static void requireHttps(URI uri, String name) {
        Objects.requireNonNull(uri, name);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                || uri.getUserInfo() != null || uri.getFragment() != null) {
            throw new IllegalArgumentException(name + " must be an absolute HTTPS URI");
        }
    }

    private static void positive(Duration value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isNegative() || value.isZero()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }
}
