package com.elmpay.connectors.stripe;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Stripe REST adapter for tokenized payments, billing, refunds and disputes. */
public final class StripeAdapter implements AutoCloseable {
    private static final int MAX_BODY_BYTES = 1_048_576;
    private static final Pattern IDEMPOTENCY_KEY = Pattern.compile("[A-Za-z0-9._:-]{16,128}");
    private static final Pattern PROVIDER_ID = Pattern.compile("[A-Za-z][A-Za-z0-9_]{5,128}");
    private static final Pattern PAYMENT_METHOD = Pattern.compile("pm_[A-Za-z0-9]{8,128}");

    public enum State { REQUIRES_ACTION, PROCESSING, REQUIRES_CAPTURE, SUCCEEDED, FAILED, CANCELED, UNKNOWN }

    @FunctionalInterface
    public interface SecretProvider {
        String currentApiKey();
    }

    public record WebhookSecret(String keyId, byte[] secret, Instant validFrom, Instant validUntil) {
        public WebhookSecret {
            requireText(keyId, "keyId");
            secret = Objects.requireNonNull(secret, "secret").clone();
            if (secret.length < 16) {
                throw new IllegalArgumentException("webhook secret is too short");
            }
            Objects.requireNonNull(validFrom, "validFrom");
            Objects.requireNonNull(validUntil, "validUntil");
            if (!validUntil.isAfter(validFrom)) {
                throw new IllegalArgumentException("invalid webhook secret validity window");
            }
        }

        @Override
        public byte[] secret() {
            return secret.clone();
        }

        boolean validAt(Instant instant) {
            return !instant.isBefore(validFrom) && instant.isBefore(validUntil);
        }

        void destroy() {
            java.util.Arrays.fill(secret, (byte) 0);
        }
    }

    public record Config(URI apiBase, URI approvedReturnBase, SecretProvider secretProvider,
            List<WebhookSecret> webhookSecrets, Duration requestTimeout, Duration webhookTolerance,
            int maxAttempts, Clock clock) {
        public Config {
            requireHttps(apiBase, "apiBase");
            requireHttps(approvedReturnBase, "approvedReturnBase");
            if (!approvedReturnBase.getPath().endsWith("/") || approvedReturnBase.getQuery() != null) {
                throw new IllegalArgumentException("approvedReturnBase must end in a path separator");
            }
            Objects.requireNonNull(secretProvider, "secretProvider");
            webhookSecrets = List.copyOf(webhookSecrets);
            if (webhookSecrets.isEmpty()) {
                throw new IllegalArgumentException("at least one webhook secret is required");
            }
            positive(requestTimeout, "requestTimeout");
            positive(webhookTolerance, "webhookTolerance");
            if (maxAttempts < 1 || maxAttempts > 3) {
                throw new IllegalArgumentException("maxAttempts must be between 1 and 3");
            }
            Objects.requireNonNull(clock, "clock");
        }
    }

    public record PaymentRequest(long amountMinor, String currency, String paymentMethodReference,
            boolean captureManually, String merchantReference, String idempotencyKey) {
        public PaymentRequest {
            positiveAmount(amountMinor);
            requireCurrency(currency);
            if (paymentMethodReference != null && !PAYMENT_METHOD.matcher(paymentMethodReference).matches()) {
                throw new IllegalArgumentException("only an opaque Stripe payment-method reference is accepted");
            }
            requireText(merchantReference, "merchantReference");
            requireIdempotency(idempotencyKey);
        }
    }

    public record ExpectedWebhook(String providerObjectId, long amountMinor, String currency) {
        public ExpectedWebhook {
            requireProviderId(providerObjectId, "providerObjectId");
            positiveAmount(amountMinor);
            requireCurrency(currency);
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
            long createdEpochSecond, boolean outOfOrder, String signatureKeyId,
            byte[] canonicalPayload) {
        public VerifiedWebhook {
            canonicalPayload = canonicalPayload.clone();
        }

        @Override
        public byte[] canonicalPayload() {
            return canonicalPayload.clone();
        }
    }

    public record HttpResult(int statusCode, byte[] body) {
        public HttpResult {
            body = Objects.requireNonNull(body, "body").clone();
        }

        @Override
        public byte[] body() {
            return body.clone();
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
            client = HttpClient.newBuilder().connectTimeout(connectTimeout)
                    .followRedirects(HttpClient.Redirect.NEVER).build();
        }

        @Override
        public HttpResult send(HttpRequest request) throws IOException, InterruptedException {
            HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
            return new HttpResult(response.statusCode(), response.body());
        }
    }

    private final Config config;
    private final Transport transport;
    private final AtomicReference<List<WebhookSecret>> webhookSecrets;
    private final ConcurrentHashMap<String, Long> latestEventTimes = new ConcurrentHashMap<>();
    private final AtomicBoolean closed = new AtomicBoolean();

    public StripeAdapter(Config config, Transport transport) {
        this.config = Objects.requireNonNull(config, "config");
        this.transport = Objects.requireNonNull(transport, "transport");
        this.webhookSecrets = new AtomicReference<>(config.webhookSecrets());
    }

    public void rotateWebhookSecrets(List<WebhookSecret> replacement) {
        ensureOpen();
        List<WebhookSecret> safe = List.copyOf(replacement);
        if (safe.isEmpty()) {
            throw new IllegalArgumentException("replacement secret set is empty");
        }
        List<String> currentIds = webhookSecrets.get().stream().map(WebhookSecret::keyId).toList();
        if (safe.stream().map(WebhookSecret::keyId).noneMatch(currentIds::contains)) {
            throw new IllegalArgumentException("webhook secret rotation requires an overlap");
        }
        webhookSecrets.set(safe);
    }

    public OperationResult createPaymentIntent(PaymentRequest request) {
        ensureOpen();
        Objects.requireNonNull(request, "request");
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put("amount", Long.toString(request.amountMinor()));
        parameters.put("currency", request.currency().toLowerCase(Locale.ROOT));
        parameters.put("capture_method", request.captureManually() ? "manual" : "automatic");
        parameters.put("metadata[merchant_reference]", request.merchantReference());
        if (request.paymentMethodReference() != null) {
            parameters.put("payment_method", request.paymentMethodReference());
            parameters.put("confirm", "true");
        }
        parameters.put("automatic_payment_methods[enabled]", "true");
        return execute("POST", "/v1/payment_intents", parameters, request.idempotencyKey());
    }

    public OperationResult createSetupIntent(String customerId, String idempotencyKey) {
        ensureOpen();
        requireProviderId(customerId, "customerId");
        requireIdempotency(idempotencyKey);
        return execute("POST", "/v1/setup_intents",
                Map.of("customer", customerId, "automatic_payment_methods[enabled]", "true"),
                idempotencyKey);
    }

    public OperationResult confirmPaymentIntent(String paymentIntentId, String paymentMethodReference,
            String idempotencyKey) {
        ensureOpen();
        requireProviderId(paymentIntentId, "paymentIntentId");
        if (!PAYMENT_METHOD.matcher(paymentMethodReference).matches()) {
            throw new IllegalArgumentException("only an opaque Stripe payment-method reference is accepted");
        }
        requireIdempotency(idempotencyKey);
        return execute("POST", "/v1/payment_intents/" + paymentIntentId + "/confirm",
                Map.of("payment_method", paymentMethodReference), idempotencyKey);
    }

    public OperationResult queryPaymentIntent(String paymentIntentId) {
        ensureOpen();
        requireProviderId(paymentIntentId, "paymentIntentId");
        return execute("GET", "/v1/payment_intents/" + paymentIntentId, Map.of(), "query-" + paymentIntentId);
    }

    public OperationResult capturePaymentIntent(String paymentIntentId, long amountMinor,
            String idempotencyKey) {
        ensureOpen();
        requireProviderId(paymentIntentId, "paymentIntentId");
        positiveAmount(amountMinor);
        requireIdempotency(idempotencyKey);
        return execute("POST", "/v1/payment_intents/" + paymentIntentId + "/capture",
                Map.of("amount_to_capture", Long.toString(amountMinor)), idempotencyKey);
    }

    public OperationResult cancelPaymentIntent(String paymentIntentId, String reason,
            String idempotencyKey) {
        ensureOpen();
        requireProviderId(paymentIntentId, "paymentIntentId");
        requireText(reason, "reason");
        requireIdempotency(idempotencyKey);
        return execute("POST", "/v1/payment_intents/" + paymentIntentId + "/cancel",
                Map.of("cancellation_reason", reason), idempotencyKey);
    }

    public OperationResult refund(String paymentIntentId, long amountMinor, String refundReference,
            String idempotencyKey) {
        ensureOpen();
        requireProviderId(paymentIntentId, "paymentIntentId");
        positiveAmount(amountMinor);
        requireText(refundReference, "refundReference");
        requireIdempotency(idempotencyKey);
        return execute("POST", "/v1/refunds", Map.of("payment_intent", paymentIntentId,
                "amount", Long.toString(amountMinor), "metadata[refund_reference]", refundReference),
                idempotencyKey);
    }

    public OperationResult queryRefund(String refundId) {
        ensureOpen();
        requireProviderId(refundId, "refundId");
        return execute("GET", "/v1/refunds/" + refundId, Map.of(), "query-refund-" + refundId);
    }

    public OperationResult submitDisputeEvidence(String disputeId, Map<String, String> evidence,
            String idempotencyKey) {
        ensureOpen();
        requireProviderId(disputeId, "disputeId");
        requireIdempotency(idempotencyKey);
        if (evidence.isEmpty() || evidence.size() > 20) {
            throw new IllegalArgumentException("dispute evidence must contain between 1 and 20 fields");
        }
        Map<String, String> parameters = new LinkedHashMap<>();
        evidence.forEach((key, value) -> parameters.put("evidence[" + safeField(key) + "]", safeValue(value)));
        parameters.put("submit", "true");
        return execute("POST", "/v1/disputes/" + disputeId, parameters, idempotencyKey);
    }

    public OperationResult createSubscription(String customerId, String priceId, int trialDays,
            String idempotencyKey) {
        ensureOpen();
        requireProviderId(customerId, "customerId");
        requireProviderId(priceId, "priceId");
        requireIdempotency(idempotencyKey);
        if (trialDays < 0 || trialDays > 730) {
            throw new IllegalArgumentException("trialDays is outside the supported range");
        }
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put("customer", customerId);
        parameters.put("items[0][price]", priceId);
        parameters.put("payment_behavior", "default_incomplete");
        parameters.put("payment_settings[save_default_payment_method]", "on_subscription");
        parameters.put("expand[0]", "latest_invoice.confirmation_secret");
        if (trialDays > 0) {
            parameters.put("trial_period_days", Integer.toString(trialDays));
        }
        return execute("POST", "/v1/subscriptions", parameters, idempotencyKey);
    }

    public OperationResult recordMeterEvent(String eventName, String customerId, long value,
            String usageReference, String idempotencyKey) {
        ensureOpen();
        requireText(eventName, "eventName");
        requireProviderId(customerId, "customerId");
        positiveAmount(value);
        requireText(usageReference, "usageReference");
        requireIdempotency(idempotencyKey);
        return execute("POST", "/v1/billing/meter_events", Map.of("event_name", eventName,
                "payload[stripe_customer_id]", customerId, "payload[value]", Long.toString(value),
                "identifier", usageReference), idempotencyKey);
    }

    public OperationResult createBillingPortalSession(String customerId, String approvedReturnUrlToken,
            String idempotencyKey) {
        ensureOpen();
        requireProviderId(customerId, "customerId");
        requireText(approvedReturnUrlToken, "approvedReturnUrlToken");
        requireIdempotency(idempotencyKey);
        if (!approvedReturnUrlToken.matches("[A-Za-z0-9_-]{16,128}")) {
            throw new IllegalArgumentException("return URL must be represented by an approved route token");
        }
        return execute("POST", "/v1/billing_portal/sessions",
                Map.of("customer", customerId, "return_url",
                        config.approvedReturnBase().resolve("route/" + approvedReturnUrlToken).toString()),
                idempotencyKey);
    }

    public VerifiedWebhook verifyWebhook(String stripeSignature, byte[] rawBody,
            Instant receivedAt, ExpectedWebhook expected) {
        ensureOpen();
        requireText(stripeSignature, "stripeSignature");
        Objects.requireNonNull(rawBody, "rawBody");
        Objects.requireNonNull(receivedAt, "receivedAt");
        Objects.requireNonNull(expected, "expected");
        if (rawBody.length == 0 || rawBody.length > MAX_BODY_BYTES) {
            throw new SecurityException("invalid Stripe webhook body size");
        }
        SignatureHeader parsed = parseSignature(stripeSignature);
        long difference = receivedAt.getEpochSecond() - parsed.timestamp();
        if (difference > config.webhookTolerance().toSeconds()
                || difference < -config.webhookTolerance().toSeconds()) {
            throw new SecurityException("stale Stripe webhook");
        }
        byte[] signed = concat(Long.toString(parsed.timestamp()).getBytes(StandardCharsets.US_ASCII),
                new byte[] {'.'}, rawBody);
        String keyId = null;
        for (WebhookSecret candidate : webhookSecrets.get()) {
            if (!candidate.validAt(receivedAt)) {
                continue;
            }
            byte[] expectedSignature = hmac(candidate.secret(), signed);
            for (byte[] supplied : parsed.signatures()) {
                if (MessageDigest.isEqual(expectedSignature, supplied)) {
                    keyId = candidate.keyId();
                    break;
                }
            }
            if (keyId != null) {
                break;
            }
        }
        if (keyId == null) {
            throw new SecurityException("invalid Stripe webhook signature");
        }
        String body = strictUtf8(rawBody);
        String eventId = stringWithPrefix(body, "id", "evt_");
        String eventType = requiredJsonString(body, "type");
        long created = requiredJsonLong(body, "created");
        String objectId = firstProviderObjectId(body);
        long amount = requiredJsonLong(body, "amount");
        String currency = requiredJsonString(body, "currency").toUpperCase(Locale.ROOT);
        if (!expected.providerObjectId().equals(objectId) || expected.amountMinor() != amount
                || !expected.currency().equals(currency)) {
            throw new SecurityException("Stripe webhook binding mismatch");
        }
        Long previous = latestEventTimes.putIfAbsent(objectId, created);
        boolean outOfOrder = previous != null && created < previous;
        if (previous != null && created > previous) {
            latestEventTimes.replace(objectId, previous, created);
        }
        String canonical = "{\"event_id\":\"" + json(eventId) + "\",\"event_type\":\""
                + json(eventType) + "\",\"provider_object_id\":\"" + json(objectId)
                + "\",\"amount_minor\":" + amount + ",\"currency\":\"" + currency
                + "\",\"out_of_order\":" + outOfOrder + "}";
        return new VerifiedWebhook(eventId, eventType, objectId, created, outOfOrder, keyId,
                canonical.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        webhookSecrets.getAndSet(List.of()).forEach(WebhookSecret::destroy);
        latestEventTimes.clear();
    }

    private void ensureOpen() {
        if (closed.get()) {
            throw new IllegalStateException("Stripe credential runtime is closed");
        }
    }

    private OperationResult execute(String method, String path, Map<String, String> parameters,
            String idempotencyKey) {
        validateNoCardData(parameters);
        String body = form(parameters);
        HttpResult last = null;
        for (int attempt = 1; attempt <= config.maxAttempts(); attempt++) {
            String apiKey = config.secretProvider().currentApiKey();
            requireText(apiKey, "Stripe API key");
            HttpRequest.Builder builder = HttpRequest.newBuilder(config.apiBase().resolve(path))
                    .timeout(config.requestTimeout())
                    .header("Accept", "application/json")
                    .header("Authorization", "Bearer " + apiKey)
                    .header("Idempotency-Key", idempotencyKey);
            HttpRequest request = "GET".equals(method)
                    ? builder.GET().build()
                    : builder.header("Content-Type", "application/x-www-form-urlencoded")
                            .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build();
            try {
                last = transport.send(request);
                if (last.body().length > MAX_BODY_BYTES) {
                    return new OperationResult(State.UNKNOWN, false, last.statusCode(), "", "");
                }
                String response = strictUtf8(last.body());
                if (last.statusCode() >= 200 && last.statusCode() < 300) {
                    String status = optionalJsonString(response, "status");
                    State state = mapState(status);
                    return new OperationResult(state, state == State.SUCCEEDED || state == State.FAILED
                            || state == State.CANCELED, last.statusCode(), optionalJsonString(response, "id"),
                            response);
                }
                if (!retryable(last.statusCode())) {
                    return new OperationResult(State.FAILED, true, last.statusCode(), "", response);
                }
            } catch (IOException exception) {
                last = null;
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                return new OperationResult(State.UNKNOWN, false, 0, "", "");
            }
        }
        return new OperationResult(State.UNKNOWN, false, last == null ? 0 : last.statusCode(), "",
                last == null ? "" : strictUtf8(last.body()));
    }

    private static State mapState(String status) {
        return switch (status) {
            case "requires_action", "requires_source_action" -> State.REQUIRES_ACTION;
            case "processing", "requires_payment_method", "requires_confirmation", "incomplete", "trialing",
                    "active", "past_due" -> State.PROCESSING;
            case "requires_capture" -> State.REQUIRES_CAPTURE;
            case "succeeded", "paid", "complete" -> State.SUCCEEDED;
            case "canceled" -> State.CANCELED;
            case "failed", "uncollectible", "incomplete_expired" -> State.FAILED;
            default -> State.UNKNOWN;
        };
    }

    private static void validateNoCardData(Map<String, String> parameters) {
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            String key = entry.getKey().toLowerCase(Locale.ROOT);
            if (key.contains("card[number]") || key.contains("cvc") || key.contains("cvv")
                    || key.contains("track") || key.equals("pan") || key.contains("payment_method_data")) {
                throw new IllegalArgumentException("raw card data is forbidden");
            }
            String digits = entry.getValue().replaceAll("[ -]", "");
            if (digits.matches("[0-9]{12,19}") && luhn(digits)) {
                throw new IllegalArgumentException("PAN-like value is forbidden");
            }
        }
    }

    private static boolean luhn(String digits) {
        int sum = 0;
        boolean doubleDigit = false;
        for (int index = digits.length() - 1; index >= 0; index--) {
            int digit = digits.charAt(index) - '0';
            if (doubleDigit && (digit *= 2) > 9) {
                digit -= 9;
            }
            sum += digit;
            doubleDigit = !doubleDigit;
        }
        return sum % 10 == 0;
    }

    private static SignatureHeader parseSignature(String value) {
        Long timestamp = null;
        List<byte[]> signatures = new ArrayList<>();
        for (String part : value.split(",")) {
            String[] pair = part.trim().split("=", 2);
            if (pair.length != 2) {
                throw new SecurityException("invalid Stripe-Signature header");
            }
            if ("t".equals(pair[0])) {
                if (timestamp != null) {
                    throw new SecurityException("duplicate Stripe timestamp");
                }
                try {
                    timestamp = Long.parseLong(pair[1]);
                } catch (NumberFormatException exception) {
                    throw new SecurityException("invalid Stripe timestamp", exception);
                }
            } else if ("v1".equals(pair[0])) {
                try {
                    signatures.add(HexFormat.of().parseHex(pair[1]));
                } catch (IllegalArgumentException exception) {
                    throw new SecurityException("invalid Stripe signature encoding", exception);
                }
            }
        }
        if (timestamp == null || signatures.isEmpty()) {
            throw new SecurityException("missing Stripe signature components");
        }
        return new SignatureHeader(timestamp, List.copyOf(signatures));
    }

    private record SignatureHeader(long timestamp, List<byte[]> signatures) {
        private SignatureHeader {
            signatures = signatures.stream().map(byte[]::clone).toList();
        }
    }

    private static byte[] hmac(byte[] key, byte[] value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(value);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("HMAC-SHA256 is unavailable", exception);
        }
    }

    private static byte[] concat(byte[]... values) {
        int length = 0;
        for (byte[] value : values) {
            length = Math.addExact(length, value.length);
        }
        ByteBuffer result = ByteBuffer.allocate(length);
        for (byte[] value : values) {
            result.put(value);
        }
        return result.array();
    }

    private static String firstProviderObjectId(String body) {
        for (String prefix : List.of("pi_", "seti_", "ch_", "re_", "dp_", "sub_", "in_")) {
            String value = stringWithPrefix(body, "id", prefix);
            if (!value.isBlank()) {
                return value;
            }
        }
        throw new SecurityException("missing Stripe provider object id");
    }

    private static String stringWithPrefix(String body, String key, String prefix) {
        String needle = "\"" + key + "\"";
        int from = 0;
        while (true) {
            int keyIndex = body.indexOf(needle, from);
            if (keyIndex < 0) {
                return "";
            }
            int colon = body.indexOf(':', keyIndex + needle.length());
            int quote = colon < 0 ? -1 : body.indexOf('"', colon + 1);
            int end = quote < 0 ? -1 : body.indexOf('"', quote + 1);
            if (quote >= 0 && end > quote) {
                String value = body.substring(quote + 1, end);
                if (value.startsWith(prefix)) {
                    return value;
                }
            }
            from = keyIndex + needle.length();
        }
    }

    private static String requiredJsonString(String body, String key) {
        String value = optionalJsonString(body, key);
        if (value.isBlank()) {
            throw new SecurityException("missing Stripe JSON field: " + key);
        }
        return value;
    }

    private static String optionalJsonString(String body, String key) {
        String needle = "\"" + key + "\"";
        int keyIndex = body.indexOf(needle);
        if (keyIndex < 0) {
            return "";
        }
        int colon = body.indexOf(':', keyIndex + needle.length());
        int quote = colon < 0 ? -1 : body.indexOf('"', colon + 1);
        int end = quote < 0 ? -1 : body.indexOf('"', quote + 1);
        return end > quote ? body.substring(quote + 1, end) : "";
    }

    private static long requiredJsonLong(String body, String key) {
        String needle = "\"" + key + "\"";
        int keyIndex = body.indexOf(needle);
        int colon = keyIndex < 0 ? -1 : body.indexOf(':', keyIndex + needle.length());
        if (colon < 0) {
            throw new SecurityException("missing Stripe JSON field: " + key);
        }
        int start = colon + 1;
        while (start < body.length() && Character.isWhitespace(body.charAt(start))) {
            start++;
        }
        int end = start;
        while (end < body.length() && Character.isDigit(body.charAt(end))) {
            end++;
        }
        try {
            return Long.parseLong(body.substring(start, end));
        } catch (NumberFormatException exception) {
            throw new SecurityException("invalid Stripe numeric field: " + key, exception);
        }
    }

    private static String form(Map<String, String> parameters) {
        return parameters.entrySet().stream().sorted(Map.Entry.comparingByKey())
                .map(entry -> url(entry.getKey()) + "=" + url(entry.getValue()))
                .collect(java.util.stream.Collectors.joining("&"));
    }

    private static String url(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String safeField(String value) {
        if (value == null || !value.matches("[a-z_]{1,64}")) {
            throw new IllegalArgumentException("invalid evidence field");
        }
        return value;
    }

    private static String safeValue(String value) {
        requireText(value, "evidence value");
        if (value.length() > 2_000) {
            throw new IllegalArgumentException("evidence value is too long");
        }
        return value;
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

    private static void requireCurrency(String value) {
        if (value == null || !value.matches("[A-Z]{3}")) {
            throw new IllegalArgumentException("currency must be three uppercase letters");
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
