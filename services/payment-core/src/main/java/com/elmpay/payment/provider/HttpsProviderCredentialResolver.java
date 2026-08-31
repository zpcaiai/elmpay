package com.elmpay.payment.provider;

import com.elmpay.security.BoundedHttpTransport;
import com.elmpay.security.MountedHttpsClient;
import com.elmpay.security.SecretReference;
import com.elmpay.security.WipeableFlatJson;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/** HTTPS+mTLS boundary for exact, short-lived provider credential leases. */
public final class HttpsProviderCredentialResolver implements ProviderCredentialResolver {
    public interface Transport {
        Response post(URI endpoint, Map<String, String> headers, byte[] body, Duration timeout);
    }

    private static final int MAX_RESPONSE_BYTES = 524_288;
    private static final Set<String> RESPONSE_BINDING_FIELDS = Set.of(
            "tenantId", "providerAccountId", "secretReference", "credentialVersion",
            "leaseId", "expiresAt");

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
                throw new IllegalStateException("credential response is closed");
            }
        }
    }

    private static final class JdkMutualTlsTransport implements Transport {
        private final HttpClient client;

        private JdkMutualTlsTransport(SSLContext mutualTlsContext, Duration connectTimeout) {
            SSLParameters tls = new SSLParameters();
            tls.setProtocols(new String[] {"TLSv1.3"});
            tls.setEndpointIdentificationAlgorithm("HTTPS");
            client = HttpClient.newBuilder().sslContext(
                    Objects.requireNonNull(mutualTlsContext, "mutualTlsContext"))
                    .sslParameters(tls).connectTimeout(connectTimeout)
                    .followRedirects(HttpClient.Redirect.NEVER).build();
        }

        private JdkMutualTlsTransport(HttpClient client) {
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
                    client, builder.build(), MAX_RESPONSE_BYTES)) {
                byte[] received = response.body();
                try {
                    return new Response(response.statusCode(), response.headers(), received);
                } finally {
                    Arrays.fill(received, (byte) 0);
                }
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

    /**
     * Production composition from the exact {@code provider-credential-client} projected-secret
     * mount. Construction validates the mTLS identity, trust bundle and rotating token before the
     * resolver can be used.
     */
    public static HttpsProviderCredentialResolver fromEnvironment(
            Map<String, String> environment, Clock clock) {
        return new HttpsProviderCredentialResolver(
                productionConfiguration(environment, clock, false));
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
        byte[] requestBody = encode(request);
        try (Response response = transport.post(
                    endpoint.resolve("v1/provider-credentials/lease"), headers(token),
                    requestBody, timeout)) {
            if (response.statusCode() != 200 || response.bodyLength() == 0
                    || response.bodyLength() > MAX_RESPONSE_BYTES) {
                throw new IllegalStateException("credential gateway returned an unsafe response");
            }
            requireJsonContentType(response.headers());
            byte[] raw = response.body();
            try (WipeableFlatJson document = parse(raw)) {
                validateResponseFields(document);
                document.requireBound("tenantId", tenantId.toString());
                document.requireBound("providerAccountId", providerAccountId.toString());
                document.requireBound("secretReference", reference.uri().toString());
                document.requireBound("credentialVersion", credentialVersion);
                String leaseId = document.requireMetadata("leaseId", 256);
                Instant expiresAt = document.requireInstant("expiresAt");
                Instant now = clock.instant();
                if (!expiresAt.isAfter(now) || expiresAt.isAfter(now.plus(maximumLease))) {
                    throw new SecurityException(
                            "credential lease expiration is outside the requested bound");
                }
                Map<String, byte[]> material = decodeMaterial(document);
                try {
                    Runnable revoker = () -> revoke(token(), tenantId, providerAccountId,
                            reference, credentialVersion, leaseId);
                    return new SecretMaterialProviderCredential(credentialVersion, leaseId,
                            expiresAt, material, revoker);
                } finally {
                    wipe(material);
                }
            } finally {
                Arrays.fill(raw, (byte) 0);
            }
        } finally {
            Arrays.fill(requestBody, (byte) 0);
        }
    }

    private void revoke(String token, UUID tenantId, UUID providerAccountId,
            SecretReference reference, String version, String leaseId) {
        byte[] requestBody = encode(Map.of(
                        "tenantId", tenantId.toString(),
                        "providerAccountId", providerAccountId.toString(),
                        "secretReference", reference.uri().toString(),
                        "credentialVersion", version,
                        "leaseId", leaseId));
        try (Response response = transport.post(
                    endpoint.resolve("v1/provider-credentials/revoke"), headers(token),
                    requestBody, timeout)) {
            if (response.statusCode() != 204 || response.bodyLength() != 0) {
                throw new IllegalStateException(
                        "credential lease revocation was not acknowledged");
            }
        } finally {
            Arrays.fill(requestBody, (byte) 0);
        }
    }

    private String token() {
        String value = requireText(accessToken.get(), "credential gateway access token");
        if (value.length() > 8_192
                || !value.matches("[A-Za-z0-9\\-._~+/]+=*")) {
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

    private static Map<String, byte[]> decodeMaterial(WipeableFlatJson document) {
        Map<String, byte[]> result = new LinkedHashMap<>();
        long total = 0;
        for (String key : document.keys()) {
            if (!key.startsWith("material.")) {
                continue;
            }
            String field = key.substring("material.".length());
            if (!field.matches("[a-z][a-z0-9_.-]{0,63}")) {
                wipe(result);
                throw new SecurityException("credential response has an invalid material field");
            }
            byte[] value = null;
            try {
                value = document.requireBase64Url(key, 1, 65_536);
                total += value.length;
                if (result.size() == 64 || total > 262_144) {
                    throw new SecurityException("credential response material exceeds its bound");
                }
                if (result.putIfAbsent(field, value) != null) {
                    throw new SecurityException("credential response material is ambiguous");
                }
                value = null;
            } catch (RuntimeException | Error exception) {
                if (value != null) {
                    Arrays.fill(value, (byte) 0);
                }
                wipe(result);
                throw exception;
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
        return productionConfiguration(System.getenv(), Clock.systemUTC(), true);
    }

    private static Configuration productionConfiguration(Map<String, String> environment,
            Clock clock, boolean allowAbsent) {
        Objects.requireNonNull(environment, "environment");
        Objects.requireNonNull(clock, "clock");
        Duration timeout = duration(environment.get(
                        "ELMPAY_PROVIDER_CREDENTIAL_TIMEOUT_MILLISECONDS"),
                2_000, "timeout");
        Duration lease = duration(environment.get("ELMPAY_PROVIDER_CREDENTIAL_MAX_LEASE_SECONDS"),
                300, "lease");
        boolean any = environment.keySet().stream()
                .anyMatch(key -> key.startsWith("ELMPAY_PROVIDER_CREDENTIAL_"));
        if (!any && allowAbsent) {
            return new Configuration(null, null, null, timeout, lease, clock, false);
        }
        if (environment.containsKey("ELMPAY_PROVIDER_CREDENTIAL_ACCESS_TOKEN")
                || environment.containsKey("ELMPAY_PROVIDER_CREDENTIAL_TOKEN_FILE")
                || environment.containsKey("ELMPAY_PROVIDER_CREDENTIAL_TIMEOUT_MS")) {
            throw new IllegalStateException(
                    "legacy or inline provider credential configuration is forbidden");
        }
        URI endpoint;
        try {
            endpoint = requireHttpsBase(URI.create(required(environment,
                    "ELMPAY_PROVIDER_CREDENTIAL_ENDPOINT")));
        } catch (IllegalArgumentException failure) {
            throw new IllegalStateException(
                    "ELMPAY_PROVIDER_CREDENTIAL_ENDPOINT is invalid", failure);
        }
        MountedHttpsClient.Client mounted = MountedHttpsClient.fromEnvironment(environment,
                "ELMPAY_PROVIDER_CREDENTIAL", "provider-credential-client", clock, timeout);
        return new Configuration(endpoint, new JdkMutualTlsTransport(mounted.httpClient()),
                mounted.accessToken(), timeout, lease, clock, true);
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
        long minimum = "lease".equals(kind) ? 5 : 1;
        long maximum = "lease".equals(kind) ? 900 : 10_000;
        if (number < minimum || number > maximum) {
            throw new IllegalStateException("provider credential " + kind
                    + " is outside its production bound");
        }
        return "lease".equals(kind) ? Duration.ofSeconds(number) : Duration.ofMillis(number);
    }

    static String readToken(Path path) {
        byte[] encoded = null;
        try {
            Path configured = path.toAbsolutePath().normalize();
            Path mount = configured.getParent().toRealPath();
            Path resolved = configured.toRealPath();
            long size = Files.size(resolved);
            if (!resolved.startsWith(mount) || !Files.isRegularFile(resolved)
                    || size < 1 || size > 8_192
                    || Files.getPosixFilePermissions(resolved).stream().anyMatch(permission ->
                            permission == java.nio.file.attribute.PosixFilePermission.OWNER_WRITE
                            || permission == java.nio.file.attribute.PosixFilePermission.GROUP_WRITE
                            || permission == java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE)) {
                throw new SecurityException("credential token file is unsafe");
            }
            try (var input = Files.newInputStream(resolved)) {
                encoded = input.readNBytes(8_193);
            }
            int length = encoded.length;
            if (length > 0 && encoded[length - 1] == '\n') {
                length--;
                if (length > 0 && encoded[length - 1] == '\r') {
                    length--;
                }
            }
            if (length < 16 || length > 8_192 || !token68(encoded, length)) {
                throw new SecurityException("credential token file has an invalid value");
            }
            return new String(encoded, 0, length, StandardCharsets.US_ASCII);
        } catch (IOException | UnsupportedOperationException exception) {
            throw new IllegalStateException("credential token file is unavailable", exception);
        } finally {
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
        }
    }

    private static boolean token68(byte[] value, int length) {
        int paddingStart = length;
        while (paddingStart > 0 && value[paddingStart - 1] == '=') {
            paddingStart--;
        }
        if (paddingStart == 0) {
            return false;
        }
        for (int index = 0; index < length; index++) {
            int character = Byte.toUnsignedInt(value[index]);
            boolean core = character >= 'A' && character <= 'Z'
                    || character >= 'a' && character <= 'z'
                    || character >= '0' && character <= '9'
                    || character == '-' || character == '.' || character == '_'
                    || character == '~' || character == '+' || character == '/';
            if (index < paddingStart ? !core : character != '=') {
                return false;
            }
        }
        return true;
    }

    private static String required(Map<String, String> environment, String key) {
        String value = environment.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(key + " is required");
        }
        return value;
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

    private static WipeableFlatJson parse(byte[] raw) {
        return WipeableFlatJson.parse(raw);
    }

    private static void validateResponseFields(WipeableFlatJson document) {
        if (!document.keys().containsAll(RESPONSE_BINDING_FIELDS)) {
            throw new SecurityException("credential response is missing required fields");
        }
        for (String key : document.keys()) {
            if (!RESPONSE_BINDING_FIELDS.contains(key) && !key.startsWith("material.")) {
                throw new SecurityException("credential response has an unexpected field");
            }
        }
    }

    private static void requireJsonContentType(HttpHeaders headers) {
        var values = headers.allValues("Content-Type");
        if (values.size() != 1 || !"application/json".equalsIgnoreCase(values.getFirst())) {
            throw new SecurityException("credential response content type is unsafe");
        }
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
