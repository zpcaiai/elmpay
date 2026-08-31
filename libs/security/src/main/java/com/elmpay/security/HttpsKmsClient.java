package com.elmpay.security;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/** HTTPS+mTLS client for a deployment-owned KMS/HSM data-key gateway. */
public final class HttpsKmsClient implements KmsClient {
    public interface Transport {
        Response post(URI endpoint, Map<String, String> headers, byte[] body, Duration timeout);
    }

    public static final class Response implements AutoCloseable {
        private final int statusCode;
        private final HttpHeaders headers;
        private byte[] body;
        private boolean closed;

        public Response(int statusCode, HttpHeaders headers, byte[] body) {
            this.statusCode = statusCode;
            this.headers = Objects.requireNonNull(headers, "headers");
            this.body = Objects.requireNonNull(body, "body").clone();
        }

        public int statusCode() {
            return statusCode;
        }

        public HttpHeaders headers() {
            return headers;
        }

        public synchronized int bodyLength() {
            ensureOpen();
            return body.length;
        }

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
                throw new IllegalStateException("KMS response is closed");
            }
        }
    }

    private static final class JdkTransport implements Transport {
        private final HttpClient client;

        private JdkTransport(SSLContext sslContext, Duration connectTimeout) {
            SSLParameters tls = new SSLParameters();
            tls.setProtocols(new String[] {"TLSv1.3"});
            tls.setEndpointIdentificationAlgorithm("HTTPS");
            client = HttpClient.newBuilder().sslContext(sslContext)
                    .sslParameters(tls).connectTimeout(connectTimeout)
                    .followRedirects(HttpClient.Redirect.NEVER).build();
        }

        private JdkTransport(HttpClient client) {
            this.client = Objects.requireNonNull(client, "client");
            BoundedHttpTransport.requireHttpsClient(client);
        }

        @Override
        public Response post(URI endpoint, Map<String, String> headers, byte[] body,
                Duration timeout) {
            HttpRequest.Builder builder = HttpRequest.newBuilder(endpoint).timeout(timeout)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body));
            headers.forEach(builder::header);
            try (BoundedHttpTransport.Response response = BoundedHttpTransport.send(
                    client, builder.build(), 65_536)) {
                byte[] received = response.body();
                try {
                    return new Response(response.statusCode(), response.headers(), received);
                } finally {
                    Arrays.fill(received, (byte) 0);
                }
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

    /**
     * Production composition from the exact {@code kms-client} projected-secret mount.
     *
     * <p>Required settings are {@code ELMPAY_KMS_ENDPOINT},
     * {@code ELMPAY_KMS_TIMEOUT_MILLISECONDS} and the four mounted-file variables documented by
     * {@link MountedHttpsClient#fromEnvironment}. Inline access tokens are rejected.
     */
    public static HttpsKmsClient fromEnvironment(Map<String, String> environment, Clock clock) {
        Objects.requireNonNull(environment, "environment");
        if (environment.containsKey("ELMPAY_KMS_ACCESS_TOKEN")) {
            throw new IllegalStateException("inline KMS access tokens are forbidden");
        }
        Duration timeout = milliseconds(environment, "ELMPAY_KMS_TIMEOUT_MILLISECONDS", 2_000);
        MountedHttpsClient.Client mounted = MountedHttpsClient.fromEnvironment(environment,
                "ELMPAY_KMS", "kms-client", clock, timeout);
        URI endpoint;
        try {
            endpoint = URI.create(required(environment, "ELMPAY_KMS_ENDPOINT"));
        } catch (IllegalArgumentException failure) {
            throw new IllegalStateException("ELMPAY_KMS_ENDPOINT is invalid", failure);
        }
        return new HttpsKmsClient(endpoint, new JdkTransport(mounted.httpClient()),
                mounted.accessToken(), timeout);
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
        long maximumLifetimeSeconds = lifetimeSeconds(maximumPlaintextLifetime);
        byte[] plaintext = null;
        byte[] wrapped = null;
        try (WipeableFlatJson response = call("data-keys/generate", Map.of(
                "keyReference", requireText(keyReference, "keyReference"),
                "contextDigest", contextDigest(encryptionContext),
                "maximumPlaintextLifetimeSeconds", Long.toString(maximumLifetimeSeconds)))) {
            requireExactFields(response, Set.of("keyReference", "keyVersion", "plaintextKey",
                    "wrappedDataKey", "plaintextExpiresAt"));
            response.requireBound("keyReference", keyReference);
            String keyVersion = response.requireMetadata("keyVersion", 256);
            plaintext = response.requireBase64Url("plaintextKey", 32, 32);
            wrapped = response.requireBase64Url("wrappedDataKey", 32, 65_536);
            return new GeneratedDataKey(keyReference, keyVersion, plaintext, wrapped,
                    response.requireInstant("plaintextExpiresAt"));
        } finally {
            wipe(plaintext);
            wipe(wrapped);
        }
    }

    @Override
    public UnwrappedDataKey unwrapDataKey(String keyReference, String keyVersion,
            byte[] wrappedDataKey, Map<String, String> encryptionContext,
            Duration maximumPlaintextLifetime) {
        long maximumLifetimeSeconds = lifetimeSeconds(maximumPlaintextLifetime);
        byte[] plaintext = null;
        byte[] request = encodeUnwrapRequest(
                requireText(keyReference, "keyReference"),
                requireText(keyVersion, "keyVersion"), wrappedDataKey,
                contextDigest(encryptionContext), maximumLifetimeSeconds);
        try (WipeableFlatJson response = call("data-keys/unwrap", request)) {
            requireExactFields(response, Set.of("plaintextKey", "plaintextExpiresAt"));
            plaintext = response.requireBase64Url("plaintextKey", 32, 32);
            return new UnwrappedDataKey(plaintext,
                    response.requireInstant("plaintextExpiresAt"));
        } finally {
            wipe(plaintext);
        }
    }

    private WipeableFlatJson call(String path, Map<String, String> document) {
        return call(path, encode(document));
    }

    private WipeableFlatJson call(String path, byte[] request) {
        try {
            String token = requireText(accessToken.get(), "KMS access token");
            if (token.length() > 8_192
                    || !token.matches("[A-Za-z0-9\\-._~+/]+=*")) {
                throw new SecurityException("KMS access token is malformed");
            }
            URI target = endpoint.resolve(path);
            try (Response response = transport.post(target, Map.of(
                    "Authorization", "Bearer " + token,
                    "Content-Type", "application/json",
                    "Accept", "application/json",
                    "X-Elmpay-Request-Id", java.util.UUID.randomUUID().toString()),
                        request, timeout)) {
                if (response.statusCode() != 200 || response.bodyLength() == 0
                        || response.bodyLength() > 65_536) {
                    throw new IllegalStateException("KMS gateway returned an unsafe response");
                }
                requireJsonContentType(response.headers());
                byte[] received = response.body();
                try {
                    return WipeableFlatJson.parse(received);
                } finally {
                    Arrays.fill(received, (byte) 0);
                }
            }
        } finally {
            Arrays.fill(request, (byte) 0);
        }
    }

    private static byte[] encodeUnwrapRequest(String keyReference, String keyVersion,
            byte[] wrappedDataKey, String contextDigest, long maximumLifetimeSeconds) {
        Objects.requireNonNull(wrappedDataKey, "wrappedDataKey");
        byte[] wrapped = null;
        byte[] prefix = null;
        byte[] suffix = null;
        byte[] result = null;
        try {
            wrapped = Base64.getUrlEncoder().withoutPadding().encode(wrappedDataKey);
            prefix = ("{\"contextDigest\":\"" + escape(contextDigest)
                    + "\",\"keyReference\":\"" + escape(keyReference)
                    + "\",\"keyVersion\":\"" + escape(keyVersion)
                    + "\",\"maximumPlaintextLifetimeSeconds\":\""
                    + maximumLifetimeSeconds + "\",\"wrappedDataKey\":\"")
                    .getBytes(StandardCharsets.UTF_8);
            suffix = new byte[] {'"', '}'};
            result = new byte[Math.addExact(Math.addExact(prefix.length,
                    wrapped.length), suffix.length)];
            System.arraycopy(prefix, 0, result, 0, prefix.length);
            System.arraycopy(wrapped, 0, result, prefix.length, wrapped.length);
            System.arraycopy(suffix, 0, result, prefix.length + wrapped.length,
                    suffix.length);
            byte[] owned = result;
            result = null;
            return owned;
        } finally {
            wipe(wrapped);
            wipe(prefix);
            wipe(suffix);
            wipe(result);
        }
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

    private static void requireExactFields(WipeableFlatJson response, Set<String> expected) {
        if (!response.keys().equals(expected)) {
            throw new SecurityException("KMS response fields are not exact");
        }
    }

    private static void requireJsonContentType(HttpHeaders headers) {
        var values = headers.allValues("Content-Type");
        if (values.size() != 1 || !"application/json".equalsIgnoreCase(values.getFirst())) {
            throw new SecurityException("KMS response content type is unsafe");
        }
    }

    private static void wipe(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required");
        return value;
    }

    private static String required(Map<String, String> environment, String key) {
        String value = environment.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(key + " is required");
        }
        return value;
    }

    private static Duration milliseconds(Map<String, String> environment, String key,
            long fallback) {
        String configured = environment.get(key);
        long value = fallback;
        if (configured != null) {
            if (!configured.matches("(?:[1-9][0-9]{0,3}|10000)")) {
                throw new IllegalStateException(key + " must be 1..10000");
            }
            value = Long.parseLong(configured);
        }
        return Duration.ofMillis(value);
    }

    private static long lifetimeSeconds(Duration value) {
        Objects.requireNonNull(value, "maximumPlaintextLifetime");
        if (value.compareTo(Duration.ofSeconds(1)) < 0
                || value.compareTo(Duration.ofSeconds(30)) > 0) {
            throw new IllegalArgumentException(
                    "maximum plaintext data-key lifetime must be 1..30 seconds");
        }
        return value.toSeconds();
    }
}
