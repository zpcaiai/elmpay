package com.elmpay.security;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;

/** HTTPS+mTLS client for a deployment-owned KMS/HSM data-key gateway. */
public final class HttpsKmsClient implements KmsClient {
    public interface Transport {
        Response post(URI endpoint, Map<String, String> headers, byte[] body, Duration timeout);
    }

    public record Response(int statusCode, byte[] body) {
        public Response {
            body = body.clone();
        }
        @Override public byte[] body() { return body.clone(); }
    }

    private static final class JdkTransport implements Transport {
        private final HttpClient client;

        private JdkTransport(SSLContext sslContext, Duration connectTimeout) {
            client = HttpClient.newBuilder().sslContext(sslContext)
                    .connectTimeout(connectTimeout).followRedirects(HttpClient.Redirect.NEVER).build();
        }

        @Override
        public Response post(URI endpoint, Map<String, String> headers, byte[] body,
                Duration timeout) {
            HttpRequest.Builder builder = HttpRequest.newBuilder(endpoint).timeout(timeout)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body));
            headers.forEach(builder::header);
            try {
                HttpResponse<byte[]> response = client.send(builder.build(),
                        HttpResponse.BodyHandlers.ofByteArray());
                return new Response(response.statusCode(), response.body());
            } catch (IOException exception) {
                throw new IllegalStateException("KMS gateway is unavailable", exception);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("KMS request was interrupted", exception);
            }
        }
    }

    private final URI endpoint;
    private final Transport transport;
    private final Supplier<String> accessToken;
    private final Duration timeout;

    public static HttpsKmsClient create(URI endpoint, SSLContext mutualTlsContext,
            Supplier<String> accessToken, Duration timeout) {
        return new HttpsKmsClient(endpoint,
                new JdkTransport(Objects.requireNonNull(mutualTlsContext, "mutualTlsContext"),
                        timeout), accessToken, timeout);
    }

    public HttpsKmsClient(URI endpoint, Transport transport, Supplier<String> accessToken,
            Duration timeout) {
        this.endpoint = requireHttpsBase(endpoint);
        this.transport = Objects.requireNonNull(transport, "transport");
        this.accessToken = Objects.requireNonNull(accessToken, "accessToken");
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        if (timeout.isZero() || timeout.isNegative() || timeout.compareTo(Duration.ofSeconds(10)) > 0) {
            throw new IllegalArgumentException("KMS timeout must be 1ms..10s");
        }
    }

    @Override
    public GeneratedDataKey generateDataKey(String keyReference,
            Map<String, String> encryptionContext, Duration maximumPlaintextLifetime) {
        Map<String, String> response = call("data-keys/generate", Map.of(
                "keyReference", requireText(keyReference, "keyReference"),
                "contextDigest", contextDigest(encryptionContext),
                "maximumPlaintextLifetimeSeconds", Long.toString(maximumPlaintextLifetime.toSeconds())));
        if (!keyReference.equals(response.get("keyReference"))) {
            throw new SecurityException("KMS response key reference mismatch");
        }
        return new GeneratedDataKey(keyReference, required(response, "keyVersion"),
                decode(response, "plaintextKey"), decode(response, "wrappedDataKey"),
                parseInstant(response, "plaintextExpiresAt"));
    }

    @Override
    public UnwrappedDataKey unwrapDataKey(String keyReference, String keyVersion,
            byte[] wrappedDataKey, Map<String, String> encryptionContext,
            Duration maximumPlaintextLifetime) {
        Map<String, String> response = call("data-keys/unwrap", Map.of(
                "keyReference", requireText(keyReference, "keyReference"),
                "keyVersion", requireText(keyVersion, "keyVersion"),
                "wrappedDataKey", Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(wrappedDataKey),
                "contextDigest", contextDigest(encryptionContext),
                "maximumPlaintextLifetimeSeconds", Long.toString(maximumPlaintextLifetime.toSeconds())));
        return new UnwrappedDataKey(decode(response, "plaintextKey"),
                parseInstant(response, "plaintextExpiresAt"));
    }

    private Map<String, String> call(String path, Map<String, String> document) {
        String token = requireText(accessToken.get(), "KMS access token");
        if (token.length() > 8_192 || token.indexOf('\r') >= 0 || token.indexOf('\n') >= 0) {
            throw new SecurityException("KMS access token is malformed");
        }
        URI target = endpoint.resolve(path);
        Response response = transport.post(target, Map.of(
                "Authorization", "Bearer " + token,
                "Content-Type", "application/json",
                "Accept", "application/json",
                "X-Elmpay-Request-Id", java.util.UUID.randomUUID().toString()),
                encode(document), timeout);
        if (response.statusCode() != 200 || response.body().length > 65_536) {
            throw new IllegalStateException("KMS gateway returned an unsafe response");
        }
        return parseFlatJson(response.body());
    }

    private static byte[] encode(Map<String, String> values) {
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : new TreeMap<>(values).entrySet()) {
            if (!first) json.append(',');
            first = false;
            json.append('"').append(escape(entry.getKey())).append("\":\"")
                    .append(escape(entry.getValue())).append('"');
        }
        return json.append('}').toString().getBytes(StandardCharsets.UTF_8);
    }

    private static Map<String, String> parseFlatJson(byte[] raw) {
        String input = new String(raw, StandardCharsets.UTF_8);
        int[] cursor = {0};
        skipWhitespace(input, cursor);
        expect(input, cursor, '{');
        Map<String, String> result = new LinkedHashMap<>();
        skipWhitespace(input, cursor);
        if (peek(input, cursor) == '}') {
            cursor[0]++;
        } else {
            while (true) {
                String key = jsonString(input, cursor);
                skipWhitespace(input, cursor);
                expect(input, cursor, ':');
                skipWhitespace(input, cursor);
                String value = jsonString(input, cursor);
                if (result.putIfAbsent(key, value) != null) {
                    throw new SecurityException("KMS response has duplicate JSON key");
                }
                skipWhitespace(input, cursor);
                char next = peek(input, cursor);
                if (next == '}') {
                    cursor[0]++;
                    break;
                }
                expect(input, cursor, ',');
                skipWhitespace(input, cursor);
            }
        }
        skipWhitespace(input, cursor);
        if (cursor[0] != input.length()) {
            throw new SecurityException("KMS response has trailing data");
        }
        return Map.copyOf(result);
    }

    private static String jsonString(String input, int[] cursor) {
        expect(input, cursor, '"');
        StringBuilder result = new StringBuilder();
        while (cursor[0] < input.length()) {
            char value = input.charAt(cursor[0]++);
            if (value == '"') return result.toString();
            if (value == '\\') {
                if (cursor[0] >= input.length()) throw new SecurityException("invalid KMS JSON escape");
                char escaped = input.charAt(cursor[0]++);
                switch (escaped) {
                    case '"', '\\', '/' -> result.append(escaped);
                    case 'b' -> result.append('\b');
                    case 'f' -> result.append('\f');
                    case 'n' -> result.append('\n');
                    case 'r' -> result.append('\r');
                    case 't' -> result.append('\t');
                    default -> throw new SecurityException("unsupported KMS JSON escape");
                }
            } else if (value < 0x20) {
                throw new SecurityException("control character in KMS JSON");
            } else {
                result.append(value);
            }
        }
        throw new SecurityException("unterminated KMS JSON string");
    }

    private static void skipWhitespace(String input, int[] cursor) {
        while (cursor[0] < input.length() && Character.isWhitespace(input.charAt(cursor[0]))) {
            cursor[0]++;
        }
    }

    private static char peek(String input, int[] cursor) {
        if (cursor[0] >= input.length()) throw new SecurityException("truncated KMS JSON");
        return input.charAt(cursor[0]);
    }

    private static void expect(String input, int[] cursor, char expected) {
        if (peek(input, cursor) != expected) throw new SecurityException("invalid KMS JSON");
        cursor[0]++;
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\r", "\\r").replace("\n", "\\n");
    }

    private static URI requireHttpsBase(URI value) {
        Objects.requireNonNull(value, "endpoint");
        if (!"https".equalsIgnoreCase(value.getScheme()) || value.getHost() == null
                || value.getUserInfo() != null || value.getQuery() != null || value.getFragment() != null) {
            throw new IllegalArgumentException("KMS endpoint must be an HTTPS origin/path");
        }
        String normalized = value.toString();
        return normalized.endsWith("/") ? value : URI.create(normalized + "/");
    }

    private static String contextDigest(Map<String, String> context) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            new TreeMap<>(context).forEach((key, value) -> {
                digest.update(requireText(key, "context key").getBytes(StandardCharsets.UTF_8));
                digest.update((byte) 0);
                digest.update(requireText(value, "context value").getBytes(StandardCharsets.UTF_8));
                digest.update((byte) 0xff);
            });
            return java.util.HexFormat.of().formatHex(digest.digest());
        } catch (java.security.GeneralSecurityException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static String required(Map<String, String> values, String key) {
        return requireText(values.get(key), "KMS response " + key);
    }

    private static byte[] decode(Map<String, String> values, String key) {
        try {
            return Base64.getUrlDecoder().decode(required(values, key));
        } catch (IllegalArgumentException exception) {
            throw new SecurityException("KMS response contains invalid key material", exception);
        }
    }

    private static Instant parseInstant(Map<String, String> values, String key) {
        try {
            return Instant.parse(required(values, key));
        } catch (java.time.format.DateTimeParseException exception) {
            throw new SecurityException("KMS response expiry is invalid", exception);
        }
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required");
        return value;
    }
}
