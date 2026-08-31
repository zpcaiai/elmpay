package com.elmpay.connectors.wechatpay;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLParameters;

import com.elmpay.security.BoundedHttpTransport;

/**
 * A narrow WeChat Pay APIv3 adapter. It implements the public APIv3 signing and
 * notification rules with JCA and deliberately owns no business-order state.
 */
public final class WechatPayAdapter implements AutoCloseable {
    private static final int MAX_BODY_BYTES = 1_048_576;
    private static final Pattern PROVIDER_ID = Pattern.compile("[A-Za-z0-9_-]{6,64}");
    private static final Pattern IDEMPOTENCY_KEY = Pattern.compile("[A-Za-z0-9._:-]{16,128}");
    private static final Pattern CURRENCY = Pattern.compile("[A-Z]{3}");

    public enum Channel { JSAPI, MINI_PROGRAM, NATIVE, H5, APP }

    public enum State { PENDING, SUCCEEDED, FAILED, CLOSED, UNKNOWN }

    public record Config(
            URI apiBase,
            URI notifyUri,
            String merchantId,
            String appId,
            String merchantSerial,
            PrivateKey merchantPrivateKey,
            byte[] apiV3Key,
            Map<String, PublicKey> platformKeys,
            Duration requestTimeout,
            Duration webhookTolerance,
            int maxAttempts,
            Clock clock) {
        public Config {
            requireHttps(apiBase, "apiBase");
            requireHttps(notifyUri, "notifyUri");
            requireText(merchantId, "merchantId");
            requireText(appId, "appId");
            requireText(merchantSerial, "merchantSerial");
            Objects.requireNonNull(merchantPrivateKey, "merchantPrivateKey");
            apiV3Key = Objects.requireNonNull(apiV3Key, "apiV3Key").clone();
            if (apiV3Key.length != 32) {
                throw new IllegalArgumentException("apiV3Key must be 32 bytes");
            }
            platformKeys = Map.copyOf(platformKeys);
            if (platformKeys.isEmpty()) {
                throw new IllegalArgumentException("at least one platform key is required");
            }
            positive(requestTimeout, "requestTimeout");
            positive(webhookTolerance, "webhookTolerance");
            if (webhookTolerance.compareTo(Duration.ofHours(1)) > 0) {
                throw new IllegalArgumentException("webhookTolerance must not exceed one hour");
            }
            if (maxAttempts < 1 || maxAttempts > 3) {
                throw new IllegalArgumentException("maxAttempts must be between 1 and 3");
            }
            Objects.requireNonNull(clock, "clock");
        }

        @Override
        public byte[] apiV3Key() {
            return apiV3Key.clone();
        }
    }

    public record PaymentRequest(
            String outTradeNo,
            long amountMinor,
            String currency,
            String description,
            Channel channel,
            String openId,
            String clientIp,
            String h5Type,
            String idempotencyKey) {
        public PaymentRequest(String outTradeNo, long amountMinor, String currency, String description,
                Channel channel, String openId, String idempotencyKey) {
            this(outTradeNo, amountMinor, currency, description, channel, openId, null, null,
                    idempotencyKey);
        }

        public PaymentRequest {
            requireProviderId(outTradeNo, "outTradeNo");
            positiveAmount(amountMinor);
            requireCurrency(currency);
            requireText(description, "description");
            if (description.length() > 127) {
                throw new IllegalArgumentException("description is too long");
            }
            Objects.requireNonNull(channel, "channel");
            requireIdempotency(idempotencyKey);
            if ((channel == Channel.JSAPI || channel == Channel.MINI_PROGRAM)
                    && (openId == null || openId.isBlank())) {
                throw new IllegalArgumentException("openId is required for JSAPI and mini-program payments");
            }
            if (channel == Channel.H5) {
                if (clientIp == null || !clientIp.matches("[0-9A-Fa-f:.]{3,45}")) {
                    throw new IllegalArgumentException("clientIp is required for H5 payments");
                }
                if (h5Type == null || !h5Type.matches("[A-Za-z0-9_-]{2,32}")) {
                    throw new IllegalArgumentException("h5Type is required for H5 payments");
                }
            }
        }
    }

    public record ClientAction(Channel channel, Map<String, String> parameters) {
        public ClientAction {
            Objects.requireNonNull(channel, "channel");
            parameters = Map.copyOf(parameters);
        }
    }

    public record ExpectedWebhook(
            String merchantId,
            String appId,
            String outTradeNo,
            String transactionId,
            long amountMinor,
            String currency) {
        public ExpectedWebhook {
            requireText(merchantId, "merchantId");
            requireText(appId, "appId");
            requireProviderId(outTradeNo, "outTradeNo");
            positiveAmount(amountMinor);
            requireCurrency(currency);
        }
    }

    /** Cryptographically verified and decrypted identity used only to locate server-side facts. */
    public record WebhookIdentity(String merchantId, String appId, String outTradeNo,
            String transactionId) {
        public WebhookIdentity {
            requireText(merchantId, "merchantId");
            requireText(appId, "appId");
            requireProviderId(outTradeNo, "outTradeNo");
            requireProviderId(transactionId, "transactionId");
        }
    }

    public record OperationResult(State state, boolean finalState, int httpStatus,
            String providerReference, String responseBody) {
        public OperationResult {
            Objects.requireNonNull(state, "state");
            responseBody = responseBody == null ? "" : responseBody;
        }
    }

    public record VerifiedWebhook(String eventId, String eventType, String transactionId,
            String outTradeNo, long amountMinor, String currency, String signatureSerial,
            byte[] canonicalPayload) {
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
        private final Map<String, List<String>> headers;
        private byte[] body;
        private boolean closed;

        public HttpResult(int statusCode, byte[] body) {
            this(statusCode, Map.of(), body);
        }

        public HttpResult(int statusCode, Map<String, List<String>> headers, byte[] body) {
            this.statusCode = statusCode;
            Objects.requireNonNull(headers, "headers");
            Map<String, List<String>> safeHeaders = new LinkedHashMap<>();
            headers.forEach((name, values) -> safeHeaders.put(Objects.requireNonNull(name, "header name"),
                    List.copyOf(Objects.requireNonNull(values, "header values"))));
            this.headers = Map.copyOf(safeHeaders);
            this.body = Objects.requireNonNull(body, "body").clone();
        }

        public int statusCode() {
            return statusCode;
        }

        public Map<String, List<String>> headers() {
            return headers;
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
                throw new IllegalStateException("WeChat HTTP response is closed");
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
            this.client = HttpClient.newBuilder()
                    .connectTimeout(connectTimeout)
                    .sslParameters(tls)
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
        }

        @Override
        public HttpResult send(HttpRequest request) throws IOException, InterruptedException {
            try (BoundedHttpTransport.Response response = BoundedHttpTransport.send(
                    client, request, MAX_BODY_BYTES)) {
                requireJsonContentType(response.headers(), response.bodyLength());
                byte[] body = response.body();
                try {
                    return new HttpResult(response.statusCode(), response.headers().map(), body);
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
                throw new SecurityException("WeChat response Content-Type is missing or ambiguous");
            }
            String value = values.getFirst().trim();
            int separator = value.indexOf(';');
            String mediaType = separator < 0 ? value : value.substring(0, separator).trim();
            if (!"application/json".equalsIgnoreCase(mediaType)
                    || value.indexOf(',') >= 0) {
                throw new SecurityException("WeChat response Content-Type is not application/json");
            }
        }
    }

    private final Config config;
    private final Transport transport;
    private final AtomicReference<Map<String, PublicKey>> platformKeys;
    private final AtomicBoolean closed = new AtomicBoolean();

    public WechatPayAdapter(Config config, Transport transport) {
        this.config = Objects.requireNonNull(config, "config");
        this.transport = Objects.requireNonNull(transport, "transport");
        this.platformKeys = new AtomicReference<>(config.platformKeys());
    }

    /** A rotation must retain at least one old key, preventing a gap in callback verification. */
    public void rotatePlatformKeys(Map<String, PublicKey> replacement) {
        ensureOpen();
        Map<String, PublicKey> safe = Map.copyOf(replacement);
        if (safe.isEmpty()) {
            throw new IllegalArgumentException("replacement platform key ring is empty");
        }
        Map<String, PublicKey> current = platformKeys.get();
        if (current.keySet().stream().noneMatch(safe::containsKey)) {
            throw new IllegalArgumentException("platform key rotation requires an overlap");
        }
        platformKeys.set(safe);
    }

    public OperationResult createPayment(PaymentRequest request) {
        ensureOpen();
        Objects.requireNonNull(request, "request");
        String path = switch (request.channel()) {
            case JSAPI, MINI_PROGRAM -> "/v3/pay/transactions/jsapi";
            case NATIVE -> "/v3/pay/transactions/native";
            case H5 -> "/v3/pay/transactions/h5";
            case APP -> "/v3/pay/transactions/app";
        };
        String payer = request.openId() == null || request.openId().isBlank()
                ? "" : ",\"payer\":{\"openid\":\"" + json(request.openId()) + "\"}";
        String scene = request.channel() == Channel.H5
                ? ",\"scene_info\":{\"payer_client_ip\":\"" + json(request.clientIp())
                        + "\",\"h5_info\":{\"type\":\"" + json(request.h5Type()) + "\"}}"
                : "";
        String body = "{\"appid\":\"" + json(config.appId()) + "\",\"mchid\":\""
                + json(config.merchantId()) + "\",\"description\":\"" + json(request.description())
                + "\",\"out_trade_no\":\"" + json(request.outTradeNo()) + "\",\"notify_url\":\""
                + json(config.notifyUri().toString()) + "\",\"amount\":{\"total\":"
                + request.amountMinor() + ",\"currency\":\"" + request.currency() + "\"}" + payer
                + scene + "}";
        OperationResult result = execute("POST", path, body, request.idempotencyKey());
        if (result.state() == State.PENDING && result.providerReference().isBlank()) {
            String reference = firstPresent(result.responseBody(), "prepay_id", "code_url", "h5_url");
            return new OperationResult(result.state(), result.finalState(), result.httpStatus(), reference,
                    result.responseBody());
        }
        return result;
    }

    /** Builds official client-side action fields from a server-issued prepay or redirect reference. */
    public ClientAction buildClientAction(Channel channel, String providerReference) {
        ensureOpen();
        Objects.requireNonNull(channel, "channel");
        requireText(providerReference, "providerReference");
        return switch (channel) {
            case JSAPI, MINI_PROGRAM -> {
                String timestamp = Long.toString(Instant.now(config.clock()).getEpochSecond());
                String nonce = UUID.randomUUID().toString().replace("-", "");
                String packageValue = "prepay_id=" + providerReference;
                String message = config.appId() + "\n" + timestamp + "\n" + nonce + "\n"
                        + packageValue + "\n";
                yield new ClientAction(channel, Map.of("appId", config.appId(), "timeStamp", timestamp,
                        "nonceStr", nonce, "package", packageValue, "signType", "RSA",
                        "paySign", rsaSign(message)));
            }
            case APP -> {
                String timestamp = Long.toString(Instant.now(config.clock()).getEpochSecond());
                String nonce = UUID.randomUUID().toString().replace("-", "");
                String packageValue = "Sign=WXPay";
                String message = config.appId() + "\n" + config.merchantId() + "\n" + providerReference
                        + "\n" + packageValue + "\n" + nonce + "\n" + timestamp + "\n";
                yield new ClientAction(channel, Map.of("appid", config.appId(), "partnerid",
                        config.merchantId(), "prepayid", providerReference, "package", packageValue,
                        "noncestr", nonce, "timestamp", timestamp, "sign", rsaSign(message)));
            }
            case NATIVE -> new ClientAction(channel, Map.of("code_url", providerReference));
            case H5 -> new ClientAction(channel, Map.of("h5_url", providerReference));
        };
    }

    public OperationResult queryPayment(String outTradeNo, String idempotencyKey) {
        ensureOpen();
        requireProviderId(outTradeNo, "outTradeNo");
        requireIdempotency(idempotencyKey);
        String path = "/v3/pay/transactions/out-trade-no/" + outTradeNo + "?mchid=" + config.merchantId();
        OperationResult result = execute("GET", path, "", idempotencyKey);
        if (result.httpStatus() >= 200 && result.httpStatus() < 300) {
            String tradeState = optionalString(result.responseBody(), "trade_state");
            State state = switch (tradeState) {
                case "SUCCESS" -> State.SUCCEEDED;
                case "CLOSED", "REVOKED", "PAYERROR" -> State.FAILED;
                case "NOTPAY", "USERPAYING", "ACCEPT" -> State.PENDING;
                default -> State.UNKNOWN;
            };
            return new OperationResult(state, state == State.SUCCEEDED || state == State.FAILED,
                    result.httpStatus(), optionalString(result.responseBody(), "transaction_id"),
                    result.responseBody());
        }
        return result;
    }

    public OperationResult closePayment(String outTradeNo, String idempotencyKey) {
        ensureOpen();
        requireProviderId(outTradeNo, "outTradeNo");
        requireIdempotency(idempotencyKey);
        String path = "/v3/pay/transactions/out-trade-no/" + outTradeNo + "/close";
        String body = "{\"mchid\":\"" + json(config.merchantId()) + "\"}";
        OperationResult result = execute("POST", path, body, idempotencyKey);
        if (result.httpStatus() == 204) {
            return new OperationResult(State.CLOSED, true, 204, outTradeNo, "");
        }
        return result;
    }

    public OperationResult refund(String transactionId, String outRefundNo, long refundAmountMinor,
            long totalAmountMinor, String currency, String idempotencyKey) {
        ensureOpen();
        requireProviderId(transactionId, "transactionId");
        requireProviderId(outRefundNo, "outRefundNo");
        positiveAmount(refundAmountMinor);
        positiveAmount(totalAmountMinor);
        if (refundAmountMinor > totalAmountMinor) {
            throw new IllegalArgumentException("refund exceeds original amount");
        }
        requireCurrency(currency);
        requireIdempotency(idempotencyKey);
        String body = "{\"transaction_id\":\"" + json(transactionId) + "\",\"out_refund_no\":\""
                + json(outRefundNo) + "\",\"amount\":{\"refund\":" + refundAmountMinor
                + ",\"total\":" + totalAmountMinor + ",\"currency\":\"" + currency + "\"}}";
        return execute("POST", "/v3/refund/domestic/refunds", body, idempotencyKey);
    }

    public OperationResult queryRefund(String outRefundNo, String idempotencyKey) {
        ensureOpen();
        requireProviderId(outRefundNo, "outRefundNo");
        requireIdempotency(idempotencyKey);
        return execute("GET", "/v3/refund/domestic/refunds/" + outRefundNo, "", idempotencyKey);
    }

    public OperationResult requestBill(String billDate, String billType, String idempotencyKey) {
        ensureOpen();
        requireBillDate(billDate);
        if (!Set.of("ALL", "SUCCESS", "REFUND").contains(billType)) {
            throw new IllegalArgumentException("billType must be ALL, SUCCESS, or REFUND");
        }
        requireIdempotency(idempotencyKey);
        String path = "/v3/bill/tradebill?bill_date=" + billDate + "&bill_type=" + billType;
        return execute("GET", path, "", idempotencyKey);
    }

    public static void verifyBillDigest(byte[] bill, String expectedSha256Hex) {
        Objects.requireNonNull(bill, "bill");
        requireText(expectedSha256Hex, "expectedSha256Hex");
        try {
            byte[] expected = HexFormat.of().parseHex(expectedSha256Hex);
            byte[] actual = MessageDigest.getInstance("SHA-256").digest(bill);
            if (!MessageDigest.isEqual(expected, actual)) {
                throw new SecurityException("bill digest mismatch");
            }
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new SecurityException("invalid bill digest", exception);
        }
    }

    public VerifiedWebhook verifyWebhook(Map<String, String> headers, byte[] rawBody,
            Instant receivedAt, ExpectedWebhook expected) {
        Objects.requireNonNull(expected, "expected");
        return verifyWebhook(headers, rawBody, receivedAt, ignored -> expected);
    }

    /**
     * Verifies the envelope and decrypts the resource before consulting durable expected facts.
     * The resolver must treat the supplied identity only as a lookup key; amounts and merchant
     * bindings still come from server-owned state.
     */
    public VerifiedWebhook verifyWebhook(Map<String, String> headers, byte[] rawBody,
            Instant receivedAt, Function<WebhookIdentity, ExpectedWebhook> expectationResolver) {
        ensureOpen();
        Objects.requireNonNull(headers, "headers");
        Objects.requireNonNull(rawBody, "rawBody");
        Objects.requireNonNull(receivedAt, "receivedAt");
        Objects.requireNonNull(expectationResolver, "expectationResolver");
        if (rawBody.length == 0 || rawBody.length > MAX_BODY_BYTES) {
            throw new SecurityException("invalid webhook body size");
        }
        String timestampText = header(headers, "Wechatpay-Timestamp");
        String nonce = header(headers, "Wechatpay-Nonce");
        String serial = header(headers, "Wechatpay-Serial");
        String signatureText = header(headers, "Wechatpay-Signature");
        long timestamp;
        try {
            timestamp = Long.parseLong(timestampText);
        } catch (NumberFormatException exception) {
            throw new SecurityException("invalid webhook timestamp", exception);
        }
        long skew;
        try {
            long difference = Math.subtractExact(receivedAt.getEpochSecond(), timestamp);
            skew = Math.abs(difference);
            if (skew < 0) {
                throw new ArithmeticException("timestamp difference overflow");
            }
        } catch (ArithmeticException exception) {
            throw new SecurityException("invalid webhook timestamp", exception);
        }
        if (skew > config.webhookTolerance().toSeconds()) {
            throw new SecurityException("stale webhook");
        }
        if (nonce.isBlank() || nonce.length() > 128 || nonce.indexOf('\n') >= 0 || nonce.indexOf('\r') >= 0) {
            throw new SecurityException("invalid webhook nonce");
        }
        PublicKey platformKey = platformKeys.get().get(serial);
        if (platformKey == null) {
            throw new SecurityException("unknown platform key serial");
        }
        String body = strictUtf8(rawBody);
        byte[] message = (timestampText + "\n" + nonce + "\n" + body + "\n")
                .getBytes(StandardCharsets.UTF_8);
        byte[] supplied = null;
        try {
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(platformKey);
            verifier.update(message);
            supplied = Base64.getDecoder().decode(signatureText);
            if (!verifier.verify(supplied)) {
                throw new SecurityException("invalid webhook signature");
            }
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new SecurityException("invalid webhook signature", exception);
        } finally {
            Arrays.fill(message, (byte) 0);
            if (supplied != null) {
                Arrays.fill(supplied, (byte) 0);
            }
        }

        String eventId = requiredString(body, "id");
        String eventType = requiredString(body, "event_type");
        String ciphertext = requiredString(body, "ciphertext");
        String resourceNonce = requiredString(body, "nonce");
        String associatedData = optionalString(body, "associated_data");
        String resource = decryptResource(ciphertext, resourceNonce, associatedData);

        String merchantId = requiredString(resource, "mchid");
        String appId = requiredString(resource, "appid");
        String outTradeNo = requiredString(resource, "out_trade_no");
        String transactionId = requiredString(resource, "transaction_id");
        long amount = requiredLong(resource, "total");
        String currency = requiredString(resource, "currency");
        ExpectedWebhook expected = Objects.requireNonNull(expectationResolver.apply(
                new WebhookIdentity(merchantId, appId, outTradeNo, transactionId)),
                "expected webhook facts");
        if (!expected.merchantId().equals(merchantId)
                || !expected.appId().equals(appId)
                || !expected.outTradeNo().equals(outTradeNo)
                || (expected.transactionId() != null && !expected.transactionId().isBlank()
                        && !expected.transactionId().equals(transactionId))
                || expected.amountMinor() != amount
                || !expected.currency().equals(currency)) {
            throw new SecurityException("webhook binding mismatch");
        }
        String canonical = "{\"event_id\":\"" + json(eventId) + "\",\"event_type\":\""
                + json(eventType) + "\",\"transaction_id\":\"" + json(transactionId)
                + "\",\"out_trade_no\":\"" + json(outTradeNo) + "\",\"amount_minor\":"
                + amount + ",\"currency\":\"" + currency + "\"}";
        return new VerifiedWebhook(eventId, eventType, transactionId, outTradeNo, amount, currency,
                serial, canonical.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        java.util.Arrays.fill(config.apiV3Key, (byte) 0);
        platformKeys.set(Map.of());
    }

    private void ensureOpen() {
        if (closed.get()) {
            throw new IllegalStateException("WeChat credential runtime is closed");
        }
    }

    private OperationResult execute(String method, String path, String body, String idempotencyKey) {
        int lastStatus = 0;
        for (int attempt = 1; attempt <= config.maxAttempts(); attempt++) {
            HttpRequest request = signedRequest(method, path, body, idempotencyKey);
            try (HttpResult result = transport.send(request)) {
                lastStatus = result.statusCode();
                if (result.bodyLength() > MAX_BODY_BYTES) {
                    return new OperationResult(State.UNKNOWN, false, lastStatus, "", "");
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
                    verifySynchronousResponse(result.headers(), response, Instant.now(config.clock()));
                    return new OperationResult(State.PENDING, false, lastStatus,
                            optionalString(response, "transaction_id"), response);
                }
                return new OperationResult(State.FAILED, true, lastStatus, "", response);
            } catch (IOException exception) {
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

    private void verifySynchronousResponse(Map<String, List<String>> headers, String body,
            Instant receivedAt) {
        String timestampText = responseHeader(headers, "Wechatpay-Timestamp");
        String nonce = responseHeader(headers, "Wechatpay-Nonce");
        String serial = responseHeader(headers, "Wechatpay-Serial");
        String suppliedSignature = responseHeader(headers, "Wechatpay-Signature");
        long timestamp;
        try {
            timestamp = Long.parseLong(timestampText);
            long difference = Math.subtractExact(receivedAt.getEpochSecond(), timestamp);
            if (difference == Long.MIN_VALUE
                    || Math.abs(difference) > config.webhookTolerance().toSeconds()) {
                throw new SecurityException("stale WeChat response signature");
            }
        } catch (NumberFormatException | ArithmeticException exception) {
            throw new SecurityException("invalid WeChat response timestamp", exception);
        }
        if (nonce.isBlank() || nonce.length() > 128 || nonce.indexOf('\n') >= 0
                || nonce.indexOf('\r') >= 0) {
            throw new SecurityException("invalid WeChat response nonce");
        }
        PublicKey key = platformKeys.get().get(serial);
        if (key == null) {
            throw new SecurityException("unknown WeChat response key serial");
        }
        byte[] message = (timestampText + "\n" + nonce + "\n" + body + "\n")
                .getBytes(StandardCharsets.UTF_8);
        byte[] supplied = null;
        try {
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(key);
            verifier.update(message);
            supplied = Base64.getDecoder().decode(suppliedSignature);
            if (!verifier.verify(supplied)) {
                throw new SecurityException("invalid WeChat response signature");
            }
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new SecurityException("invalid WeChat response signature", exception);
        } finally {
            Arrays.fill(message, (byte) 0);
            if (supplied != null) {
                Arrays.fill(supplied, (byte) 0);
            }
        }
    }

    private static String responseHeader(Map<String, List<String>> headers, String expected) {
        String result = null;
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (!entry.getKey().equalsIgnoreCase(expected)) {
                continue;
            }
            if (result != null || entry.getValue().size() != 1
                    || entry.getValue().getFirst() == null) {
                throw new SecurityException("ambiguous WeChat response header: " + expected);
            }
            result = entry.getValue().getFirst();
        }
        if (result == null) {
            throw new SecurityException("missing WeChat response header: " + expected);
        }
        return requireSafeHeaderValue(result, "WeChat response header: " + expected);
    }

    private HttpRequest signedRequest(String method, String path, String body, String idempotencyKey) {
        String timestamp = Long.toString(Instant.now(config.clock()).getEpochSecond());
        String nonce = UUID.randomUUID().toString().replace("-", "");
        String message = method + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + body + "\n";
        String signature = rsaSign(message);
        String authorization = "WECHATPAY2-SHA256-RSA2048 mchid=\"" + config.merchantId()
                + "\",nonce_str=\"" + nonce + "\",timestamp=\"" + timestamp
                + "\",serial_no=\"" + config.merchantSerial() + "\",signature=\"" + signature + "\"";
        HttpRequest.Builder builder = HttpRequest.newBuilder(config.apiBase().resolve(path))
                .timeout(config.requestTimeout())
                .header("Accept", "application/json")
                .header("Authorization", authorization)
                .header("X-Elmpay-Idempotency-Key", idempotencyKey);
        if ("GET".equals(method)) {
            return builder.GET().build();
        }
        return builder.header("Content-Type", "application/json; charset=utf-8")
                .method(method, HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build();
    }

    private String rsaSign(String message) {
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(config.merchantPrivateKey());
            signer.update(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signer.sign());
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("unable to create WeChat RSA signature", exception);
        }
    }

    private String decryptResource(String ciphertext, String nonce, String associatedData) {
        byte[] encrypted = null;
        byte[] cleartext = null;
        byte[] keyBytes = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            keyBytes = config.apiV3Key();
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            cipher.init(Cipher.DECRYPT_MODE, key,
                    new GCMParameterSpec(128, nonce.getBytes(StandardCharsets.UTF_8)));
            cipher.updateAAD(associatedData.getBytes(StandardCharsets.UTF_8));
            encrypted = Base64.getDecoder().decode(ciphertext);
            cleartext = cipher.doFinal(encrypted);
            return strictUtf8(cleartext);
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new SecurityException("unable to decrypt webhook resource", exception);
        } finally {
            if (encrypted != null) {
                Arrays.fill(encrypted, (byte) 0);
            }
            if (cleartext != null) {
                Arrays.fill(cleartext, (byte) 0);
            }
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
            }
        }
    }

    private static boolean retryable(int status) {
        return status == 408 || status == 425 || status == 429 || status >= 500;
    }

    private static String header(Map<String, String> headers, String name) {
        String result = null;
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (!entry.getKey().equalsIgnoreCase(name)) {
                continue;
            }
            if (result != null || entry.getValue() == null) {
                throw new SecurityException("ambiguous webhook header: " + name);
            }
            result = entry.getValue();
        }
        if (result == null) {
            throw new SecurityException("missing webhook header: " + name);
        }
        return requireSafeHeaderValue(result, "webhook header: " + name);
    }

    private static String requireSafeHeaderValue(String value, String name) {
        if (value.isBlank() || value.length() > 4_096
                || value.chars().anyMatch(character -> character < 0x20 || character == 0x7f)) {
            throw new SecurityException("invalid " + name);
        }
        return value;
    }

    private static void requireBillDate(String value) {
        requireText(value, "billDate");
        try {
            if (!LocalDate.parse(value).toString().equals(value)) {
                throw new DateTimeParseException("non-canonical bill date", value, 0);
            }
        } catch (DateTimeParseException exception) {
            throw new IllegalArgumentException("billDate must be a canonical ISO date", exception);
        }
    }

    private static String firstPresent(String json, String... names) {
        for (String name : names) {
            String value = optionalString(json, name);
            if (!value.isBlank()) {
                return value;
            }
        }
        return "";
    }

    private static String requiredString(String source, String key) {
        String value = optionalString(source, key);
        if (value.isBlank()) {
            throw new SecurityException("missing JSON field: " + key);
        }
        return value;
    }

    private static String optionalString(String source, String key) {
        int start = findValue(source, key);
        if (start < 0 || source.charAt(start) != '"') {
            return "";
        }
        StringBuilder result = new StringBuilder();
        for (int index = start + 1; index < source.length(); index++) {
            char value = source.charAt(index);
            if (value == '"') {
                return result.toString();
            }
            if (value != '\\') {
                if (value < 0x20) {
                    throw new SecurityException("invalid JSON control character");
                }
                result.append(value);
                continue;
            }
            if (++index >= source.length()) {
                throw new SecurityException("invalid JSON escape");
            }
            char escaped = source.charAt(index);
            switch (escaped) {
                case '"', '\\', '/' -> result.append(escaped);
                case 'b' -> result.append('\b');
                case 'f' -> result.append('\f');
                case 'n' -> result.append('\n');
                case 'r' -> result.append('\r');
                case 't' -> result.append('\t');
                case 'u' -> {
                    if (index + 4 >= source.length()) {
                        throw new SecurityException("invalid JSON unicode escape");
                    }
                    try {
                        result.append((char) Integer.parseInt(source.substring(index + 1, index + 5), 16));
                    } catch (NumberFormatException exception) {
                        throw new SecurityException("invalid JSON unicode escape", exception);
                    }
                    index += 4;
                }
                default -> throw new SecurityException("invalid JSON escape");
            }
        }
        throw new SecurityException("unterminated JSON string");
    }

    private static long requiredLong(String source, String key) {
        int start = findValue(source, key);
        if (start < 0) {
            throw new SecurityException("missing JSON field: " + key);
        }
        int end = start;
        if (source.charAt(end) == '-') {
            end++;
        }
        while (end < source.length() && Character.isDigit(source.charAt(end))) {
            end++;
        }
        if (end == start) {
            throw new SecurityException("invalid numeric JSON field: " + key);
        }
        try {
            return Long.parseLong(source.substring(start, end));
        } catch (NumberFormatException exception) {
            throw new SecurityException("invalid numeric JSON field: " + key, exception);
        }
    }

    private static int findValue(String source, String key) {
        String needle = "\"" + key + "\"";
        int from = 0;
        int found = -1;
        while (true) {
            int candidate = source.indexOf(needle, from);
            if (candidate < 0) {
                return found;
            }
            int colon = candidate + needle.length();
            while (colon < source.length() && Character.isWhitespace(source.charAt(colon))) {
                colon++;
            }
            if (colon < source.length() && source.charAt(colon) == ':') {
                if (found >= 0) {
                    throw new SecurityException("duplicate JSON field: " + key);
                }
                int value = colon + 1;
                while (value < source.length() && Character.isWhitespace(source.charAt(value))) {
                    value++;
                }
                if (value >= source.length()) {
                    throw new SecurityException("missing JSON value: " + key);
                }
                found = value;
            }
            from = candidate + needle.length();
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
        StringBuilder escaped = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"' -> escaped.append("\\\"");
                case '\\' -> escaped.append("\\\\");
                case '\b' -> escaped.append("\\b");
                case '\f' -> escaped.append("\\f");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> {
                    if (character < 0x20) {
                        escaped.append(String.format(Locale.ROOT, "\\u%04x", (int) character));
                    } else {
                        escaped.append(character);
                    }
                }
            }
        }
        return escaped.toString();
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
        if (value == null || !CURRENCY.matcher(value).matches()) {
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

    private static void requireHttps(URI value, String name) {
        Objects.requireNonNull(value, name);
        if (!"https".equalsIgnoreCase(value.getScheme()) || value.getHost() == null
                || value.getUserInfo() != null || value.getFragment() != null) {
            throw new IllegalArgumentException(name + " must be an absolute HTTPS URI");
        }
    }

    private static void positive(Duration value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }
}
