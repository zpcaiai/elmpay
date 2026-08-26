package com.elmpay.connectors.alipay;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.RoundingMode;
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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/** Certificate-mode Alipay adapter using the public RSA2 protocol and JCA. */
public final class AlipayAdapter {
    private static final int MAX_BODY_BYTES = 1_048_576;
    private static final Pattern ORDER_ID = Pattern.compile("[A-Za-z0-9_-]{6,64}");
    private static final Pattern IDEMPOTENCY_KEY = Pattern.compile("[A-Za-z0-9._:-]{16,128}");
    private static final DateTimeFormatter ALIPAY_TIME = DateTimeFormatter
            .ofPattern("yyyy-MM-dd HH:mm:ss", Locale.ROOT).withZone(ZoneOffset.ofHours(8));

    public enum Channel { WEB, WAP, APP, QR, MINI_PROGRAM }

    public enum State { PENDING, SUCCEEDED, FAILED, CLOSED, UNKNOWN }

    public record VerificationKey(String certificateSerial, PublicKey publicKey,
            Instant validFrom, Instant validUntil) {
        public VerificationKey {
            requireText(certificateSerial, "certificateSerial");
            Objects.requireNonNull(publicKey, "publicKey");
            Objects.requireNonNull(validFrom, "validFrom");
            Objects.requireNonNull(validUntil, "validUntil");
            if (!validUntil.isAfter(validFrom)) {
                throw new IllegalArgumentException("invalid certificate validity window");
            }
        }

        boolean validAt(Instant instant) {
            return !instant.isBefore(validFrom) && instant.isBefore(validUntil);
        }
    }

    public record Config(
            URI gateway,
            URI notifyUri,
            Set<String> approvedReturnHosts,
            String appId,
            String sellerId,
            String appCertificateSerial,
            String rootCertificateSerial,
            PrivateKey appPrivateKey,
            List<VerificationKey> alipayCertificateKeys,
            Duration requestTimeout,
            int maxAttempts,
            Clock clock) {
        public Config {
            requireHttps(gateway, "gateway");
            requireHttps(notifyUri, "notifyUri");
            approvedReturnHosts = approvedReturnHosts.stream()
                    .map(host -> host.toLowerCase(Locale.ROOT)).collect(java.util.stream.Collectors.toUnmodifiableSet());
            if (approvedReturnHosts.isEmpty()) {
                throw new IllegalArgumentException("approvedReturnHosts is empty");
            }
            requireText(appId, "appId");
            requireText(sellerId, "sellerId");
            requireText(appCertificateSerial, "appCertificateSerial");
            requireText(rootCertificateSerial, "rootCertificateSerial");
            Objects.requireNonNull(appPrivateKey, "appPrivateKey");
            alipayCertificateKeys = List.copyOf(alipayCertificateKeys);
            if (alipayCertificateKeys.isEmpty()) {
                throw new IllegalArgumentException("at least one Alipay certificate key is required");
            }
            positive(requestTimeout, "requestTimeout");
            if (maxAttempts < 1 || maxAttempts > 3) {
                throw new IllegalArgumentException("maxAttempts must be between 1 and 3");
            }
            Objects.requireNonNull(clock, "clock");
        }
    }

    public record PaymentRequest(String outTradeNo, long amountMinor, String currency,
            String subject, Channel channel, String storeId, String idempotencyKey) {
        public PaymentRequest {
            requireOrderId(outTradeNo, "outTradeNo");
            positiveAmount(amountMinor);
            if (!"CNY".equals(currency)) {
                throw new IllegalArgumentException("this Alipay adapter requires CNY minor units");
            }
            requireText(subject, "subject");
            if (subject.length() > 128) {
                throw new IllegalArgumentException("subject is too long");
            }
            Objects.requireNonNull(channel, "channel");
            requireIdempotency(idempotencyKey);
            if ((channel == Channel.QR || channel == Channel.MINI_PROGRAM)
                    && (storeId == null || storeId.isBlank())) {
                throw new IllegalArgumentException("storeId is required for offline channels");
            }
        }
    }

    public record ExpectedNotify(String appId, String sellerId, String outTradeNo,
            long amountMinor, String currency) {
        public ExpectedNotify {
            requireText(appId, "appId");
            requireText(sellerId, "sellerId");
            requireOrderId(outTradeNo, "outTradeNo");
            positiveAmount(amountMinor);
            if (!"CNY".equals(currency)) {
                throw new IllegalArgumentException("currency must be CNY");
            }
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

    public record VerifiedNotify(String eventId, String tradeNo, String outTradeNo,
            String tradeStatus, long amountMinor, String currency, String certificateSerial,
            byte[] canonicalPayload) {
        public VerifiedNotify {
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
    private final AtomicReference<List<VerificationKey>> verificationKeys;

    public AlipayAdapter(Config config, Transport transport) {
        this.config = Objects.requireNonNull(config, "config");
        this.transport = Objects.requireNonNull(transport, "transport");
        this.verificationKeys = new AtomicReference<>(config.alipayCertificateKeys());
    }

    /** Enforces an overlapping certificate window so delayed notifications remain verifiable. */
    public void rotateVerificationKeys(List<VerificationKey> replacement) {
        List<VerificationKey> safe = List.copyOf(replacement);
        if (safe.isEmpty()) {
            throw new IllegalArgumentException("replacement key set is empty");
        }
        Set<String> oldSerials = verificationKeys.get().stream()
                .map(VerificationKey::certificateSerial).collect(java.util.stream.Collectors.toSet());
        if (safe.stream().map(VerificationKey::certificateSerial).noneMatch(oldSerials::contains)) {
            throw new IllegalArgumentException("certificate rotation requires an overlap");
        }
        verificationKeys.set(safe);
    }

    public OperationResult createOrder(PaymentRequest request, URI approvedReturnUri) {
        Objects.requireNonNull(request, "request");
        if (approvedReturnUri != null) {
            validateReturnUri(approvedReturnUri);
        }
        String method = switch (request.channel()) {
            case WEB -> "alipay.trade.page.pay";
            case WAP -> "alipay.trade.wap.pay";
            case APP -> "alipay.trade.app.pay";
            case QR -> "alipay.trade.precreate";
            case MINI_PROGRAM -> "alipay.trade.create";
        };
        String productCode = switch (request.channel()) {
            case WEB -> "FAST_INSTANT_TRADE_PAY";
            case WAP -> "QUICK_WAP_WAY";
            case APP -> "QUICK_MSECURITY_PAY";
            case QR, MINI_PROGRAM -> "FACE_TO_FACE_PAYMENT";
        };
        String store = request.storeId() == null || request.storeId().isBlank()
                ? "" : ",\"store_id\":\"" + json(request.storeId()) + "\"";
        String biz = "{\"out_trade_no\":\"" + json(request.outTradeNo()) + "\",\"total_amount\":\""
                + majorAmount(request.amountMinor()) + "\",\"subject\":\"" + json(request.subject())
                + "\",\"product_code\":\"" + productCode + "\"" + store + "}";
        return execute(method, biz, request.idempotencyKey(), approvedReturnUri);
    }

    public OperationResult query(String outTradeNo, String idempotencyKey) {
        requireOrderId(outTradeNo, "outTradeNo");
        requireIdempotency(idempotencyKey);
        OperationResult result = execute("alipay.trade.query",
                "{\"out_trade_no\":\"" + json(outTradeNo) + "\"}", idempotencyKey, null);
        if (result.httpStatus() >= 200 && result.httpStatus() < 300) {
            String status = optionalJsonString(result.responseBody(), "trade_status");
            State state = switch (status) {
                case "TRADE_SUCCESS", "TRADE_FINISHED" -> State.SUCCEEDED;
                case "TRADE_CLOSED" -> State.CLOSED;
                case "WAIT_BUYER_PAY" -> State.PENDING;
                default -> State.UNKNOWN;
            };
            return new OperationResult(state, state == State.SUCCEEDED || state == State.CLOSED,
                    result.httpStatus(), optionalJsonString(result.responseBody(), "trade_no"),
                    result.responseBody());
        }
        return result;
    }

    public OperationResult close(String outTradeNo, String idempotencyKey) {
        requireOrderId(outTradeNo, "outTradeNo");
        requireIdempotency(idempotencyKey);
        return execute("alipay.trade.close", "{\"out_trade_no\":\"" + json(outTradeNo) + "\"}",
                idempotencyKey, null);
    }

    public OperationResult refund(String outTradeNo, String refundRequestNo, long amountMinor,
            String idempotencyKey) {
        requireOrderId(outTradeNo, "outTradeNo");
        requireOrderId(refundRequestNo, "refundRequestNo");
        positiveAmount(amountMinor);
        requireIdempotency(idempotencyKey);
        String biz = "{\"out_trade_no\":\"" + json(outTradeNo) + "\",\"refund_amount\":\""
                + majorAmount(amountMinor) + "\",\"out_request_no\":\"" + json(refundRequestNo) + "\"}";
        return execute("alipay.trade.refund", biz, idempotencyKey, null);
    }

    public OperationResult queryRefund(String outTradeNo, String refundRequestNo,
            String idempotencyKey) {
        requireOrderId(outTradeNo, "outTradeNo");
        requireOrderId(refundRequestNo, "refundRequestNo");
        requireIdempotency(idempotencyKey);
        String biz = "{\"out_trade_no\":\"" + json(outTradeNo) + "\",\"out_request_no\":\""
                + json(refundRequestNo) + "\"}";
        return execute("alipay.trade.fastpay.refund.query", biz, idempotencyKey, null);
    }

    public OperationResult requestBill(String billType, String billDate, String idempotencyKey) {
        requireText(billType, "billType");
        requireText(billDate, "billDate");
        requireIdempotency(idempotencyKey);
        String biz = "{\"bill_type\":\"" + json(billType) + "\",\"bill_date\":\""
                + json(billDate) + "\"}";
        return execute("alipay.data.dataservice.bill.downloadurl.query", biz, idempotencyKey, null);
    }

    public VerifiedNotify verifyNotify(byte[] rawFormBody, Instant receivedAt, ExpectedNotify expected) {
        Objects.requireNonNull(rawFormBody, "rawFormBody");
        Objects.requireNonNull(receivedAt, "receivedAt");
        Objects.requireNonNull(expected, "expected");
        if (rawFormBody.length == 0 || rawFormBody.length > MAX_BODY_BYTES) {
            throw new SecurityException("invalid notify body size");
        }
        Map<String, String> parameters = parseForm(rawFormBody);
        String signatureText = required(parameters, "sign");
        if (!"RSA2".equals(required(parameters, "sign_type"))) {
            throw new SecurityException("Alipay notification must use RSA2");
        }
        String serial = required(parameters, "alipay_cert_sn");
        VerificationKey key = verificationKeys.get().stream()
                .filter(candidate -> candidate.certificateSerial().equals(serial))
                .filter(candidate -> candidate.validAt(receivedAt))
                .findFirst().orElseThrow(() -> new SecurityException("unknown or expired Alipay certificate"));
        String canonical = canonical(parameters, Set.of("sign", "sign_type"));
        try {
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(key.publicKey());
            verifier.update(canonical.getBytes(StandardCharsets.UTF_8));
            if (!verifier.verify(Base64.getDecoder().decode(signatureText))) {
                throw new SecurityException("invalid Alipay notification signature");
            }
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new SecurityException("invalid Alipay notification signature", exception);
        }
        String appId = required(parameters, "app_id");
        String sellerId = required(parameters, "seller_id");
        String outTradeNo = required(parameters, "out_trade_no");
        String tradeNo = required(parameters, "trade_no");
        String status = required(parameters, "trade_status");
        if (!Set.of("WAIT_BUYER_PAY", "TRADE_SUCCESS", "TRADE_FINISHED", "TRADE_CLOSED").contains(status)) {
            throw new SecurityException("unknown Alipay trade status");
        }
        long amount = parseCnyMinor(required(parameters, "total_amount"));
        if (!expected.appId().equals(appId) || !expected.sellerId().equals(sellerId)
                || !expected.outTradeNo().equals(outTradeNo) || expected.amountMinor() != amount) {
            throw new SecurityException("Alipay notification binding mismatch");
        }
        String eventId = required(parameters, "notify_id");
        String safe = "{\"event_id\":\"" + json(eventId) + "\",\"trade_no\":\"" + json(tradeNo)
                + "\",\"out_trade_no\":\"" + json(outTradeNo) + "\",\"trade_status\":\""
                + status + "\",\"amount_minor\":" + amount + ",\"currency\":\"CNY\"}";
        return new VerifiedNotify(eventId, tradeNo, outTradeNo, status, amount, "CNY", serial,
                safe.getBytes(StandardCharsets.UTF_8));
    }

    private OperationResult execute(String method, String bizContent, String idempotencyKey,
            URI returnUri) {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put("app_id", config.appId());
        parameters.put("method", method);
        parameters.put("format", "JSON");
        parameters.put("charset", "utf-8");
        parameters.put("sign_type", "RSA2");
        parameters.put("timestamp", ALIPAY_TIME.format(Instant.now(config.clock())));
        parameters.put("version", "1.0");
        parameters.put("notify_url", config.notifyUri().toString());
        parameters.put("app_cert_sn", config.appCertificateSerial());
        parameters.put("alipay_root_cert_sn", config.rootCertificateSerial());
        if (returnUri != null) {
            parameters.put("return_url", returnUri.toString());
        }
        parameters.put("biz_content", bizContent);
        String content = canonical(parameters, Set.of());
        parameters.put("sign", sign(content));
        String body = encodeForm(parameters);
        HttpResult last = null;
        for (int attempt = 1; attempt <= config.maxAttempts(); attempt++) {
            HttpRequest request = HttpRequest.newBuilder(config.gateway())
                    .timeout(config.requestTimeout())
                    .header("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                    .header("Accept", "application/json")
                    .header("X-Elmpay-Idempotency-Key", idempotencyKey)
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build();
            try {
                last = transport.send(request);
                if (last.body().length > MAX_BODY_BYTES) {
                    return new OperationResult(State.UNKNOWN, false, last.statusCode(), "", "");
                }
                String response = strictUtf8(last.body());
                if (last.statusCode() >= 200 && last.statusCode() < 300) {
                    String businessCode = optionalJsonString(response, "code");
                    if (!businessCode.isBlank() && !"10000".equals(businessCode)) {
                        if ("20000".equals(businessCode)) {
                            continue;
                        }
                        return new OperationResult(State.FAILED, true, last.statusCode(), "", response);
                    }
                    return new OperationResult(State.PENDING, false, last.statusCode(),
                            optionalJsonString(response, "trade_no"), response);
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

    private String sign(String content) {
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(config.appPrivateKey());
            signer.update(content.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signer.sign());
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("unable to sign Alipay request", exception);
        }
    }

    private void validateReturnUri(URI uri) {
        requireHttps(uri, "returnUri");
        if (!config.approvedReturnHosts().contains(uri.getHost().toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException("returnUri host is not registered");
        }
    }

    private static Map<String, String> parseForm(byte[] body) {
        String raw = strictUtf8(body);
        Map<String, String> result = new LinkedHashMap<>();
        for (String pair : raw.split("&", -1)) {
            if (pair.isEmpty()) {
                continue;
            }
            int separator = pair.indexOf('=');
            String key = decodeForm(separator < 0 ? pair : pair.substring(0, separator));
            String value = decodeForm(separator < 0 ? "" : pair.substring(separator + 1));
            if (key.isBlank() || result.putIfAbsent(key, value) != null) {
                throw new SecurityException("duplicate or empty form parameter");
            }
        }
        return Map.copyOf(result);
    }

    private static String decodeForm(String value) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(value.length());
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (current == '+') {
                bytes.write(' ');
            } else if (current == '%') {
                if (index + 2 >= value.length()) {
                    throw new SecurityException("invalid percent encoding");
                }
                int high = Character.digit(value.charAt(++index), 16);
                int low = Character.digit(value.charAt(++index), 16);
                if (high < 0 || low < 0) {
                    throw new SecurityException("invalid percent encoding");
                }
                bytes.write((high << 4) | low);
            } else if (current <= 0x7f) {
                bytes.write(current);
            } else {
                byte[] encoded = String.valueOf(current).getBytes(StandardCharsets.UTF_8);
                bytes.writeBytes(encoded);
            }
        }
        return strictUtf8(bytes.toByteArray());
    }

    private static String encodeForm(Map<String, String> values) {
        return values.entrySet().stream().sorted(Map.Entry.comparingByKey())
                .map(entry -> url(entry.getKey()) + "=" + url(entry.getValue()))
                .collect(java.util.stream.Collectors.joining("&"));
    }

    private static String canonical(Map<String, String> values, Set<String> exclusions) {
        return values.entrySet().stream()
                .filter(entry -> !exclusions.contains(entry.getKey()))
                .filter(entry -> entry.getValue() != null && !entry.getValue().isEmpty())
                .sorted(Comparator.comparing(Map.Entry::getKey))
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(java.util.stream.Collectors.joining("&"));
    }

    private static String url(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String required(Map<String, String> values, String name) {
        String value = values.get(name);
        if (value == null || value.isBlank()) {
            throw new SecurityException("missing Alipay parameter: " + name);
        }
        return value;
    }

    private static long parseCnyMinor(String value) {
        try {
            return new BigDecimal(value).setScale(2, RoundingMode.UNNECESSARY)
                    .movePointRight(2).longValueExact();
        } catch (ArithmeticException | NumberFormatException exception) {
            throw new SecurityException("invalid CNY amount", exception);
        }
    }

    private static String majorAmount(long amountMinor) {
        return BigDecimal.valueOf(amountMinor, 2).setScale(2, RoundingMode.UNNECESSARY).toPlainString();
    }

    private static String optionalJsonString(String source, String key) {
        String needle = "\"" + key + "\"";
        int keyIndex = source.indexOf(needle);
        if (keyIndex < 0 || source.indexOf(needle, keyIndex + needle.length()) >= 0) {
            return "";
        }
        int colon = source.indexOf(':', keyIndex + needle.length());
        if (colon < 0) {
            return "";
        }
        int quote = source.indexOf('"', colon + 1);
        if (quote < 0) {
            return "";
        }
        int end = quote + 1;
        StringBuilder result = new StringBuilder();
        boolean escaped = false;
        while (end < source.length()) {
            char character = source.charAt(end++);
            if (escaped) {
                if (character != '"' && character != '\\' && character != '/') {
                    return "";
                }
                result.append(character);
                escaped = false;
            } else if (character == '\\') {
                escaped = true;
            } else if (character == '"') {
                return result.toString();
            } else {
                result.append(character);
            }
        }
        return "";
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

    private static void requireOrderId(String value, String name) {
        if (value == null || !ORDER_ID.matcher(value).matches()) {
            throw new IllegalArgumentException(name + " has an invalid format");
        }
    }

    private static void requireIdempotency(String value) {
        if (value == null || !IDEMPOTENCY_KEY.matcher(value).matches()) {
            throw new IllegalArgumentException("invalid idempotency key");
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
