package com.elmpay.sdk;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.net.URI;
import java.net.URISyntaxException;
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
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Dependency-free Java client with bounded retries and fail-closed typed responses. */
public final class ElmpayClient {
    public static final int MAX_RESPONSE_BYTES = 1_048_576;

    public record CheckoutRequest(String businessOrderNo, long amount, String currency,
            String returnRouteId) {}
    public record ConfirmRequest(String paymentMethodType, String paymentMethodReference,
            String fingerprint) {}
    public record CheckoutSession(String checkoutSessionId, String expiresAt, String checkoutUrl) {}
    public record ApiProblem(String type, String title, int status, String code, String traceId,
            String detail) {}
    public record ApiResponse(int statusCode, CheckoutSession data, String requestId) {}
    public record SdkRequest(String method, URI uri, Map<String, String> headers, String body) {
        public SdkRequest { headers = Map.copyOf(headers); }
    }
    public record RawResponse(int statusCode, String contentType, long contentLength,
            String requestId, InputStream body) implements AutoCloseable {
        public RawResponse {
            contentType = contentType == null ? "" : contentType;
            requestId = requestId == null ? "" : requestId;
            Objects.requireNonNull(body, "body");
        }
        @Override public void close() throws IOException { body.close(); }
    }

    public static class InvalidResponseException extends IOException {
        private final String requestId;
        public InvalidResponseException(String message, String requestId) {
            super("Invalid ElmPay response: " + message); this.requestId = requestId;
        }
        public InvalidResponseException(String message, String requestId, Throwable cause) {
            super("Invalid ElmPay response: " + message, cause); this.requestId = requestId;
        }
        public String requestId() { return requestId; }
    }
    public static final class ResponseTooLargeException extends InvalidResponseException {
        public ResponseTooLargeException(String requestId) {
            super("body exceeds 1 MiB limit", requestId);
        }
    }
    public static final class ApiException extends IOException {
        private final ApiProblem problem;
        private final String requestId;
        public ApiException(ApiProblem problem, String requestId) {
            super("ElmPay API error " + problem.status() + ": " + problem.code());
            this.problem = problem; this.requestId = requestId;
        }
        public ApiProblem problem() { return problem; }
        public String requestId() { return requestId; }
        public int statusCode() { return problem.status(); }
    }

    @FunctionalInterface
    public interface Transport {
        RawResponse execute(SdkRequest request, Duration timeout)
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
        if (baseUri == null || !"https".equalsIgnoreCase(baseUri.getScheme())
                || baseUri.getHost() == null || baseUri.getUserInfo() != null
                || baseUri.getQuery() != null || baseUri.getFragment() != null)
            throw new IllegalArgumentException("base URI must be an origin-form HTTPS URL");
        if (bearerToken == null || bearerToken.isBlank())
            throw new IllegalArgumentException("bearer token required");
        if (projectId == null || projectId.isBlank() || projectId.length() > 64)
            throw new IllegalArgumentException("project ID required");
        if (timeout == null || timeout.isZero() || timeout.isNegative()
                || timeout.compareTo(Duration.ofMinutes(5)) > 0)
            throw new IllegalArgumentException("timeout must be positive and at most five minutes");
        if (maximumAttempts < 1 || maximumAttempts > 5)
            throw new IllegalArgumentException("maximumAttempts must be 1..5");
        this.baseUri = baseUri; this.bearerToken = bearerToken; this.projectId = projectId;
        this.timeout = timeout; this.maximumAttempts = maximumAttempts;
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
        return send("POST", "/v1/checkout-sessions", body, idempotencyKey, 201);
    }

    public ApiResponse getCheckoutSession(String sessionId) throws IOException, InterruptedException {
        return send("GET", "/v1/checkout-sessions/" + encodePath(sessionId), null, null, 200);
    }

    public ApiResponse confirmCheckoutSession(String sessionId, ConfirmRequest value,
            String idempotencyKey) throws IOException, InterruptedException {
        if (value.paymentMethodType() == null || value.paymentMethodType().isBlank()
                || idempotencyKey == null || idempotencyKey.isBlank())
            throw new IllegalArgumentException("payment method and idempotency key required");
        String body = "{\"payment_method_type\":\"" + json(value.paymentMethodType()) + "\""
                + (value.paymentMethodReference() == null ? "" : ",\"payment_method_reference\":\""
                + json(value.paymentMethodReference()) + "\"")
                + (value.fingerprint() == null ? "" : ",\"fingerprint\":\""
                + json(value.fingerprint()) + "\"") + "}";
        return send("POST", "/v1/checkout-sessions/" + encodePath(sessionId) + "/confirm",
                body, idempotencyKey, 200);
    }

    private ApiResponse send(String method, String path, String body, String idempotencyKey,
            int expectedStatus) throws IOException, InterruptedException {
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
            try (RawResponse response = transport.execute(new SdkRequest(method,
                    baseUri.resolve(path), headers, body), timeout)) {
                try {
                    return decodeResponse(response, expectedStatus);
                } catch (ApiException error) {
                    if (!retrySafe || attempt == maximumAttempts || !retryable(error.statusCode()))
                        throw error;
                }
            } catch (ApiException | InvalidResponseException protocolFailure) {
                throw protocolFailure;
            } catch (IOException failure) {
                lastTransport = failure;
                if (!retrySafe || attempt == maximumAttempts) throw failure;
            }
            Thread.sleep(Math.min(1000L, 100L << (attempt - 1)));
        }
        throw Objects.requireNonNull(lastTransport);
    }

    private static ApiResponse decodeResponse(RawResponse response, int expectedStatus)
            throws IOException {
        String requestId = response.requestId();
        String mediaType = response.contentType().split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
        if (!mediaType.equals("application/json") && !mediaType.equals("application/problem+json"))
            throw new InvalidResponseException("Content-Type must be JSON", requestId);
        byte[] raw = readBounded(response.body(), response.contentLength(), requestId);
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(raw)).toString();
        } catch (CharacterCodingException error) {
            throw new InvalidResponseException("body is not valid UTF-8", requestId, error);
        }
        Object parsed;
        try { parsed = new JsonParser(text).parse(); }
        catch (IllegalArgumentException error) {
            throw new InvalidResponseException("body is not strict JSON", requestId, error);
        }
        if (!(parsed instanceof Map<?, ?>))
            throw new InvalidResponseException("JSON body must be an object", requestId);
        @SuppressWarnings("unchecked")
        Map<String, Object> object = (Map<String, Object>) parsed;
        if (response.statusCode() == expectedStatus) {
            if (!mediaType.equals("application/json"))
                throw new InvalidResponseException("success response must use application/json", requestId);
            return new ApiResponse(response.statusCode(), decodeCheckoutSession(object, requestId),
                    requestId);
        }
        if (response.statusCode() >= 400 && response.statusCode() <= 599) {
            if (!mediaType.equals("application/problem+json"))
                throw new InvalidResponseException(
                        "error response must use application/problem+json", requestId);
            throw new ApiException(decodeProblem(object, response.statusCode(), requestId), requestId);
        }
        throw new InvalidResponseException("unexpected HTTP status " + response.statusCode(),
                requestId);
    }

    private static byte[] readBounded(InputStream stream, long contentLength, String requestId)
            throws IOException {
        if (contentLength < -1)
            throw new InvalidResponseException("invalid Content-Length", requestId);
        if (contentLength > MAX_RESPONSE_BYTES) throw new ResponseTooLargeException(requestId);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[64 * 1024];
        int total = 0;
        while (true) {
            int allowed = Math.min(buffer.length, MAX_RESPONSE_BYTES + 1 - total);
            int read = stream.read(buffer, 0, allowed);
            if (read < 0) break;
            if (read == 0) throw new InvalidResponseException(
                    "response stream made no progress", requestId);
            total += read;
            if (total > MAX_RESPONSE_BYTES) throw new ResponseTooLargeException(requestId);
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }

    private static CheckoutSession decodeCheckoutSession(Map<String, Object> value,
            String requestId) throws InvalidResponseException {
        String id = requiredString(value, "checkout_session_id", requestId);
        String expiresAt = requiredString(value, "expires_at", requestId);
        String checkoutUrl = requiredString(value, "checkout_url", requestId);
        try { OffsetDateTime.parse(expiresAt); }
        catch (DateTimeParseException error) {
            throw new InvalidResponseException(
                    "expires_at must be an RFC 3339 date-time", requestId, error);
        }
        try {
            URI parsed = new URI(checkoutUrl);
            if (!"https".equalsIgnoreCase(parsed.getScheme()) || parsed.getHost() == null)
                throw new InvalidResponseException(
                        "checkout_url must be an absolute HTTPS URL", requestId);
        } catch (URISyntaxException error) {
            throw new InvalidResponseException(
                    "checkout_url must be an absolute HTTPS URL", requestId, error);
        }
        return new CheckoutSession(id, expiresAt, checkoutUrl);
    }

    private static ApiProblem decodeProblem(Map<String, Object> value, int status,
            String requestId) throws InvalidResponseException {
        String type = requiredString(value, "type", requestId);
        try {
            if (!new URI(type).isAbsolute())
                throw new InvalidResponseException("problem type must be an absolute URI", requestId);
        } catch (URISyntaxException error) {
            throw new InvalidResponseException("problem type must be an absolute URI", requestId,
                    error);
        }
        String title = requiredString(value, "title", requestId);
        Object rawStatus = value.get("status");
        int problemStatus;
        try {
            if (!(rawStatus instanceof BigDecimal)) throw new ArithmeticException("not a number");
            problemStatus = ((BigDecimal) rawStatus).intValueExact();
        } catch (ArithmeticException error) {
            throw new InvalidResponseException("problem status must be an integer", requestId, error);
        }
        if (problemStatus != status)
            throw new InvalidResponseException("problem status must match HTTP status", requestId);
        String code = requiredString(value, "code", requestId);
        String traceId = requiredString(value, "trace_id", requestId);
        String detail = null;
        if (value.containsKey("detail")) {
            Object rawDetail = value.get("detail");
            if (!(rawDetail instanceof String))
                throw new InvalidResponseException("problem detail must be a string", requestId);
            detail = (String) rawDetail;
        }
        return new ApiProblem(type, title, problemStatus, code, traceId, detail);
    }

    private static String requiredString(Map<String, Object> value, String name, String requestId)
            throws InvalidResponseException {
        Object field = value.get(name);
        if (!(field instanceof String) || ((String) field).isBlank())
            throw new InvalidResponseException(
                    "field " + name + " must be a non-empty string", requestId);
        return (String) field;
    }

    public static boolean verifyWebhook(byte[] secret, byte[] rawBody, String signatureHeader,
            Clock clock, Duration tolerance) {
        if (secret == null || secret.length < 32 || rawBody == null || signatureHeader == null
                || signatureHeader.length() > 4096 || clock == null || tolerance == null
                || tolerance.isNegative()) return false;
        Map<String, String> parts = new LinkedHashMap<>();
        for (String part : signatureHeader.split(",")) {
            String[] pair = part.trim().split("=", 2);
            if (pair.length != 2) return false;
            String key = pair[0].trim();
            String value = pair[1].trim();
            if ((!key.equals("t") && !key.equals("v1")) || value.isEmpty()
                    || value.chars().anyMatch(Character::isWhitespace) || parts.putIfAbsent(key, value) != null)
                return false;
        }
        if (parts.size() != 2 || !parts.containsKey("t") || !parts.containsKey("v1")
                || !asciiDigits(parts.get("t")) || parts.get("t").length() > 19
                || !rawUrlSignature(parts.get("v1"))) return false;
        long timestamp;
        try {
            timestamp = Long.parseLong(parts.get("t"));
            if (timestamp < 0 || Duration.between(Instant.ofEpochSecond(timestamp), clock.instant())
                    .abs().compareTo(tolerance) > 0) return false;
        } catch (RuntimeException invalidTimestamp) {
            return false;
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            mac.update(Long.toString(timestamp).getBytes(StandardCharsets.US_ASCII));
            mac.update((byte) '.'); mac.update(rawBody);
            byte[] supplied = Base64.getUrlDecoder().decode(parts.get("v1"));
            return supplied.length == 32 && MessageDigest.isEqual(mac.doFinal(), supplied);
        } catch (GeneralSecurityException | IllegalArgumentException invalid) { return false; }
    }

    private static boolean asciiDigits(String value) {
        if (value.isEmpty()) return false;
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character < '0' || character > '9') return false;
        }
        return true;
    }

    private static boolean rawUrlSignature(String value) {
        if (value.length() != 43) return false;
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z')
                    || (character >= '0' && character <= '9') || character == '-' || character == '_'))
                return false;
        }
        return true;
    }

    public static String newIdempotencyKey() { return UUID.randomUUID().toString(); }
    private static boolean retryable(int status) {
        return status == 408 || status == 429 || status >= 500;
    }
    private static String encodePath(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
    private static String json(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r");
    }

    private static final class JdkTransport implements Transport {
        private final HttpClient http;
        private JdkTransport(Duration timeout) {
            http = HttpClient.newBuilder().connectTimeout(timeout)
                    .followRedirects(HttpClient.Redirect.NEVER).build();
        }
        @Override
        public RawResponse execute(SdkRequest value, Duration timeout)
                throws IOException, InterruptedException {
            HttpRequest.Builder builder = HttpRequest.newBuilder(value.uri()).timeout(timeout);
            value.headers().forEach(builder::header);
            builder.method(value.method(), value.body() == null
                    ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofString(value.body(), StandardCharsets.UTF_8));
            HttpResponse<InputStream> response = http.send(builder.build(),
                    HttpResponse.BodyHandlers.ofInputStream());
            long contentLength;
            try { contentLength = response.headers().firstValueAsLong("content-length").orElse(-1L); }
            catch (NumberFormatException error) {
                response.body().close();
                throw new IOException("invalid response Content-Length", error);
            }
            return new RawResponse(response.statusCode(),
                    response.headers().firstValue("content-type").orElse(""), contentLength,
                    response.headers().firstValue("x-request-id").orElse(""), response.body());
        }
    }

    /** Small strict JSON parser used to keep the server SDK dependency-free. */
    private static final class JsonParser {
        private final String input;
        private int index;
        private int depth;
        JsonParser(String input) { this.input = input; }

        Object parse() {
            skipWhitespace();
            Object value = value();
            skipWhitespace();
            if (index != input.length()) fail("trailing data");
            return value;
        }

        private Object value() {
            if (index >= input.length()) return fail("unexpected end");
            char current = input.charAt(index);
            if (current == '{') return object();
            if (current == '[') return array();
            if (current == '"') return string();
            if (current == 't') { literal("true"); return Boolean.TRUE; }
            if (current == 'f') { literal("false"); return Boolean.FALSE; }
            if (current == 'n') { literal("null"); return null; }
            if (current == '-' || current >= '0' && current <= '9') return number();
            return fail("unexpected token");
        }

        private Map<String, Object> object() {
            enter(); index++; skipWhitespace();
            Map<String, Object> result = new LinkedHashMap<>();
            if (consume('}')) { leave(); return result; }
            while (true) {
                if (index >= input.length() || input.charAt(index) != '"') fail("object key expected");
                String key = string();
                if (result.containsKey(key)) fail("duplicate object key");
                skipWhitespace(); expect(':'); skipWhitespace();
                result.put(key, value()); skipWhitespace();
                if (consume('}')) { leave(); return result; }
                expect(','); skipWhitespace();
            }
        }

        private List<Object> array() {
            enter(); index++; skipWhitespace();
            List<Object> result = new ArrayList<>();
            if (consume(']')) { leave(); return result; }
            while (true) {
                result.add(value()); skipWhitespace();
                if (consume(']')) { leave(); return result; }
                expect(','); skipWhitespace();
            }
        }

        private String string() {
            expect('"'); StringBuilder result = new StringBuilder();
            while (index < input.length()) {
                char current = input.charAt(index++);
                if (current == '"') {
                    validateSurrogates(result);
                    return result.toString();
                }
                if (current < 0x20) fail("control character in string");
                if (current != '\\') { result.append(current); continue; }
                if (index >= input.length()) fail("unterminated escape");
                char escaped = input.charAt(index++);
                switch (escaped) {
                    case '"': result.append('"'); break;
                    case '\\': result.append('\\'); break;
                    case '/': result.append('/'); break;
                    case 'b': result.append('\b'); break;
                    case 'f': result.append('\f'); break;
                    case 'n': result.append('\n'); break;
                    case 'r': result.append('\r'); break;
                    case 't': result.append('\t'); break;
                    case 'u': result.append(unicode()); break;
                    default: fail("invalid escape");
                }
            }
            return fail("unterminated string");
        }

        private char unicode() {
            if (index + 4 > input.length()) return fail("short unicode escape");
            int value = 0;
            for (int count = 0; count < 4; count++) {
                int digit = Character.digit(input.charAt(index++), 16);
                if (digit < 0) return fail("invalid unicode escape");
                value = value * 16 + digit;
            }
            return (char) value;
        }

        private BigDecimal number() {
            int start = index;
            if (consume('-') && index >= input.length()) return fail("incomplete number");
            if (consume('0')) {
                if (index < input.length() && Character.isDigit(input.charAt(index)))
                    return fail("leading zero");
            } else {
                digits();
            }
            if (consume('.')) digits();
            if (index < input.length() && (input.charAt(index) == 'e' || input.charAt(index) == 'E')) {
                index++;
                if (index < input.length() && (input.charAt(index) == '+' || input.charAt(index) == '-')) index++;
                digits();
            }
            try { return new BigDecimal(input.substring(start, index)); }
            catch (NumberFormatException error) { return fail("invalid number"); }
        }

        private void digits() {
            int start = index;
            while (index < input.length() && Character.isDigit(input.charAt(index))) index++;
            if (start == index) fail("digits expected");
        }

        private void literal(String literal) {
            if (!input.startsWith(literal, index)) fail("invalid literal");
            index += literal.length();
        }
        private void skipWhitespace() {
            while (index < input.length()) {
                char value = input.charAt(index);
                if (value != ' ' && value != '\n' && value != '\r' && value != '\t') break;
                index++;
            }
        }
        private boolean consume(char expected) {
            if (index < input.length() && input.charAt(index) == expected) { index++; return true; }
            return false;
        }
        private void expect(char expected) {
            if (!consume(expected)) fail("expected " + expected);
        }
        private void enter() {
            if (++depth > 64) fail("maximum depth exceeded");
        }
        private void leave() { depth--; }
        private static void validateSurrogates(CharSequence value) {
            for (int i = 0; i < value.length(); i++) {
                char current = value.charAt(i);
                if (Character.isHighSurrogate(current)) {
                    if (++i >= value.length() || !Character.isLowSurrogate(value.charAt(i)))
                        fail("unpaired high surrogate");
                } else if (Character.isLowSurrogate(current)) fail("unpaired low surrogate");
            }
        }
        private static <T> T fail(String message) {
            throw new IllegalArgumentException("invalid JSON: " + message);
        }
    }
}
