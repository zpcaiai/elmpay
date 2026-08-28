package com.elmpay.payment.provider;

import com.elmpay.security.SecretReference;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.UUID;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;

/** HTTPS+mTLS boundary for exact, short-lived provider credential leases. */
public final class HttpsProviderCredentialResolver implements ProviderCredentialResolver {
    public interface Transport {
        Response post(URI endpoint, Map<String, String> headers, byte[] body, Duration timeout);
    }

    public record Response(int statusCode, byte[] body) {
        public Response {
            body = Objects.requireNonNull(body, "body").clone();
        }

        @Override
        public byte[] body() {
            return body.clone();
        }
    }

    private static final class JdkMutualTlsTransport implements Transport {
        private final HttpClient client;

        private JdkMutualTlsTransport(SSLContext mutualTlsContext, Duration connectTimeout) {
            client = HttpClient.newBuilder().sslContext(
                    Objects.requireNonNull(mutualTlsContext, "mutualTlsContext"))
                    .connectTimeout(connectTimeout).followRedirects(HttpClient.Redirect.NEVER)
                    .build();
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
                throw new IllegalStateException("credential gateway is unavailable", exception);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("credential gateway request was interrupted", exception);
            }
        }
    }

    private record Configuration(URI endpoint, Transport transport, Supplier<String> token,
            Duration timeout, Duration maximumLease, Clock clock, boolean configured) {
        private Configuration {
            Objects.requireNonNull(timeout, "timeout");
            Objects.requireNonNull(maximumLease, "maximumLease");
            Objects.requireNonNull(clock, "clock");
        }
    }

    private final URI endpoint;
    private final Transport transport;
    private final Supplier<String> accessToken;
    private final Duration timeout;
    private final Duration maximumLease;
    private final Clock clock;
    private final boolean configured;

    /** ServiceLoader constructor. Configuration is read once; token material is read per request. */
    public HttpsProviderCredentialResolver() {
        this(systemConfiguration());
    }

    public HttpsProviderCredentialResolver(URI endpoint, Transport transport,
            Supplier<String> accessToken, Duration timeout, Duration maximumLease, Clock clock) {
        this(new Configuration(requireHttpsBase(endpoint), Objects.requireNonNull(transport, "transport"),
                Objects.requireNonNull(accessToken, "accessToken"), timeout, maximumLease, clock, true));
    }

    private HttpsProviderCredentialResolver(Configuration configuration) {
        endpoint = configuration.endpoint();
        transport = configuration.transport();
        accessToken = configuration.token();
        timeout = configuration.timeout();
        maximumLease = configuration.maximumLease();
        clock = configuration.clock();
        configured = configuration.configured();
        if (timeout.isZero() || timeout.isNegative() || timeout.compareTo(Duration.ofSeconds(10)) > 0) {
            throw new IllegalArgumentException("credential timeout must be 1ms..10s");
        }
        if (maximumLease.compareTo(Duration.ofSeconds(5)) < 0
                || maximumLease.compareTo(Duration.ofMinutes(15)) > 0) {
            throw new IllegalArgumentException("credential maximum lease must be 5s..15m");
        }
    }

    @Override
    public boolean configured() {
        return configured;
    }

    @Override
    public ProviderCredential resolve(UUID tenantId, UUID providerAccountId,
            SecretReference reference, String credentialVersion) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(providerAccountId, "providerAccountId");
        Objects.requireNonNull(reference, "reference");
        requireText(credentialVersion, "credentialVersion");
        if (!configured) {
            throw new IllegalStateException("provider credential resolver is not configured");
        }
        String token = token();
        Map<String, String> request = Map.of(
                "tenantId", tenantId.toString(),
                "providerAccountId", providerAccountId.toString(),
                "secretReference", reference.uri().toString(),
                "credentialVersion", credentialVersion,
                "maximumLeaseSeconds", Long.toString(maximumLease.toSeconds()));
        Response response = transport.post(endpoint.resolve("v1/provider-credentials/lease"),
                headers(token), encode(request), timeout);
        if (response.statusCode() != 200 || response.body().length == 0
                || response.body().length > 524_288) {
            throw new IllegalStateException("credential gateway returned an unsafe response");
        }
        Map<String, String> document = parseFlatJson(response.body());
        requireBound(document, "tenantId", tenantId.toString());
        requireBound(document, "providerAccountId", providerAccountId.toString());
        requireBound(document, "secretReference", reference.uri().toString());
        requireBound(document, "credentialVersion", credentialVersion);
        String leaseId = requireText(document.get("leaseId"), "leaseId");
        Instant expiresAt = parseInstant(document.get("expiresAt"));
        Instant now = clock.instant();
        if (!expiresAt.isAfter(now) || expiresAt.isAfter(now.plus(maximumLease))) {
            throw new SecurityException("credential lease expiration is outside the requested bound");
        }
        Map<String, byte[]> material = decodeMaterial(document);
        Runnable revoker = () -> revoke(token, tenantId, providerAccountId, reference,
                credentialVersion, leaseId);
        return new SecretMaterialProviderCredential(credentialVersion, leaseId, expiresAt,
                material, revoker);
    }

    private void revoke(String token, UUID tenantId, UUID providerAccountId,
            SecretReference reference, String version, String leaseId) {
        Response response = transport.post(endpoint.resolve("v1/provider-credentials/revoke"),
                headers(token), encode(Map.of(
                        "tenantId", tenantId.toString(),
                        "providerAccountId", providerAccountId.toString(),
                        "secretReference", reference.uri().toString(),
                        "credentialVersion", version,
                        "leaseId", leaseId)), timeout);
        if (response.statusCode() != 204 || response.body().length != 0) {
            throw new IllegalStateException("credential lease revocation was not acknowledged");
        }
    }

    private String token() {
        String value = requireText(accessToken.get(), "credential gateway access token");
        if (value.length() > 8_192 || value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
            throw new SecurityException("credential gateway access token is malformed");
        }
        return value;
    }

    private static Map<String, String> headers(String token) {
        return Map.of(
                "Authorization", "Bearer " + token,
                "Content-Type", "application/json",
                "Accept", "application/json",
                "X-Elmpay-Request-Id", UUID.randomUUID().toString());
    }

    private static Map<String, byte[]> decodeMaterial(Map<String, String> document) {
        Map<String, byte[]> result = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : document.entrySet()) {
            if (!entry.getKey().startsWith("material.")) {
                continue;
            }
            String field = entry.getKey().substring("material.".length());
            if (!field.matches("[a-z][a-z0-9_.-]{0,63}")) {
                wipe(result);
                throw new SecurityException("credential response has an invalid material field");
            }
            try {
                byte[] value = Base64.getUrlDecoder().decode(entry.getValue());
                if (result.putIfAbsent(field, value) != null) {
                    java.util.Arrays.fill(value, (byte) 0);
                    wipe(result);
                    throw new SecurityException("credential response has duplicate material");
                }
            } catch (IllegalArgumentException exception) {
                wipe(result);
                throw new SecurityException("credential response material is malformed", exception);
            }
        }
        if (result.isEmpty()) {
            throw new SecurityException("credential response contains no secret material");
        }
        return result;
    }

    private static void wipe(Map<String, byte[]> values) {
        values.values().forEach(value -> java.util.Arrays.fill(value, (byte) 0));
    }

    private static Configuration systemConfiguration() {
        Map<String, String> environment = System.getenv();
        String endpointValue = environment.get("ELMPAY_PROVIDER_CREDENTIAL_ENDPOINT");
        String tokenFileValue = environment.get("ELMPAY_PROVIDER_CREDENTIAL_TOKEN_FILE");
        boolean mutualTls = "true".equalsIgnoreCase(
                environment.get("ELMPAY_PROVIDER_CREDENTIAL_MTLS"));
        Duration timeout = duration(environment.get("ELMPAY_PROVIDER_CREDENTIAL_TIMEOUT_MS"),
                2_000, "timeout");
        Duration lease = duration(environment.get("ELMPAY_PROVIDER_CREDENTIAL_MAX_LEASE_SECONDS"),
                300, "lease");
        if (endpointValue == null || endpointValue.isBlank() || tokenFileValue == null
                || tokenFileValue.isBlank() || !mutualTls) {
            return new Configuration(null, null, null, timeout, lease, Clock.systemUTC(), false);
        }
        URI endpoint = requireHttpsBase(URI.create(endpointValue));
        Path tokenFile = Path.of(tokenFileValue).toAbsolutePath().normalize();
        Supplier<String> token = () -> readToken(tokenFile);
        try {
            SSLContext context = SSLContext.getDefault();
            return new Configuration(endpoint, new JdkMutualTlsTransport(context, timeout), token,
                    timeout, lease, Clock.systemUTC(), true);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("default mutual TLS context is unavailable", exception);
        }
    }

    private static Duration duration(String value, long fallback, String kind) {
        long number = fallback;
        if (value != null && !value.isBlank()) {
            try {
                number = Long.parseLong(value);
            } catch (NumberFormatException exception) {
                throw new IllegalStateException("provider credential " + kind + " is invalid", exception);
            }
        }
        return "lease".equals(kind) ? Duration.ofSeconds(number) : Duration.ofMillis(number);
    }

    private static String readToken(Path path) {
        try {
            if (!Files.isRegularFile(path) || Files.isSymbolicLink(path) || Files.size(path) > 8_192) {
                throw new SecurityException("credential token file is unsafe");
            }
            return Files.readString(path, StandardCharsets.UTF_8).strip();
        } catch (IOException exception) {
            throw new IllegalStateException("credential token file is unavailable", exception);
        }
    }

    private static URI requireHttpsBase(URI value) {
        Objects.requireNonNull(value, "endpoint");
        if (!"https".equalsIgnoreCase(value.getScheme()) || value.getHost() == null
                || value.getUserInfo() != null || value.getQuery() != null
                || value.getFragment() != null) {
            throw new IllegalArgumentException("credential endpoint must be an HTTPS origin/path");
        }
        String normalized = value.toString();
        return normalized.endsWith("/") ? value : URI.create(normalized + "/");
    }

    private static void requireBound(Map<String, String> values, String field, String expected) {
        String actual = requireText(values.get(field), field);
        if (!java.security.MessageDigest.isEqual(actual.getBytes(StandardCharsets.UTF_8),
                expected.getBytes(StandardCharsets.UTF_8))) {
            throw new SecurityException("credential response binding mismatch");
        }
    }

    private static Instant parseInstant(String value) {
        try {
            return Instant.parse(requireText(value, "expiresAt"));
        } catch (DateTimeParseException exception) {
            throw new SecurityException("credential response expiration is invalid", exception);
        }
    }

    private static byte[] encode(Map<String, String> values) {
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : new TreeMap<>(values).entrySet()) {
            if (!first) {
                json.append(',');
            }
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
                    throw new SecurityException("credential response has duplicate JSON key");
                }
                skipWhitespace(input, cursor);
                if (peek(input, cursor) == '}') {
                    cursor[0]++;
                    break;
                }
                expect(input, cursor, ',');
                skipWhitespace(input, cursor);
            }
        }
        skipWhitespace(input, cursor);
        if (cursor[0] != input.length()) {
            throw new SecurityException("credential response has trailing data");
        }
        return Map.copyOf(result);
    }

    private static String jsonString(String input, int[] cursor) {
        expect(input, cursor, '"');
        StringBuilder value = new StringBuilder();
        while (cursor[0] < input.length()) {
            char next = input.charAt(cursor[0]++);
            if (next == '"') {
                return value.toString();
            }
            if (next == '\\') {
                if (cursor[0] >= input.length()) {
                    throw new SecurityException("invalid credential JSON escape");
                }
                char escaped = input.charAt(cursor[0]++);
                switch (escaped) {
                    case '"', '\\', '/' -> value.append(escaped);
                    case 'b' -> value.append('\b');
                    case 'f' -> value.append('\f');
                    case 'n' -> value.append('\n');
                    case 'r' -> value.append('\r');
                    case 't' -> value.append('\t');
                    default -> throw new SecurityException("unsupported credential JSON escape");
                }
            } else if (next < 0x20) {
                throw new SecurityException("control character in credential JSON");
            } else {
                value.append(next);
            }
        }
        throw new SecurityException("unterminated credential JSON string");
    }

    private static void skipWhitespace(String input, int[] cursor) {
        while (cursor[0] < input.length() && Character.isWhitespace(input.charAt(cursor[0]))) {
            cursor[0]++;
        }
    }

    private static char peek(String input, int[] cursor) {
        if (cursor[0] >= input.length()) {
            throw new SecurityException("truncated credential JSON");
        }
        return input.charAt(cursor[0]);
    }

    private static void expect(String input, int[] cursor, char expected) {
        if (peek(input, cursor) != expected) {
            throw new SecurityException("invalid credential JSON");
        }
        cursor[0]++;
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\r", "\\r").replace("\n", "\\n");
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank() || value.length() > 8_192
                || value.chars().anyMatch(character -> character < 0x20)) {
            throw new SecurityException(field + " has an invalid format");
        }
        return value;
    }
}
