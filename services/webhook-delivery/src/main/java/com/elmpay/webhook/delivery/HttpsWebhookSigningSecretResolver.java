package com.elmpay.webhook.delivery;

import com.elmpay.security.BoundedHttpTransport;
import com.elmpay.security.MountedHttpsClient;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

/** HTTPS+mTLS client for short-lived, exactly bound webhook signing-secret leases. */
public final class HttpsWebhookSigningSecretResolver
        implements WebhookDeliveryRuntime.SigningSecretResolver {
    private static final int MAX_SECRET_BYTES = 128;
    private final HttpClient mutualTlsClient;
    private final URI endpoint;
    private final Supplier<String> accessToken;
    private final Duration timeout;
    private final Clock clock;

    public HttpsWebhookSigningSecretResolver(HttpClient mutualTlsClient, URI endpoint,
            Supplier<String> accessToken, Duration timeout) {
        this(mutualTlsClient, endpoint, accessToken, timeout, Clock.systemUTC());
    }

    HttpsWebhookSigningSecretResolver(HttpClient mutualTlsClient, URI endpoint,
            Supplier<String> accessToken, Duration timeout, Clock clock) {
        this.mutualTlsClient = Objects.requireNonNull(mutualTlsClient, "mutualTlsClient");
        if (mutualTlsClient.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("signing-secret client must reject redirects");
        }
        BoundedHttpTransport.requireHttpsClient(mutualTlsClient);
        this.endpoint = requireHttps(endpoint);
        this.accessToken = Objects.requireNonNull(accessToken, "accessToken");
        this.timeout = positive(timeout, "timeout");
        if (timeout.compareTo(Duration.ofSeconds(10)) > 0) {
            throw new IllegalArgumentException("timeout must not exceed 10 seconds");
        }
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Production composition from the exact {@code webhook-signing-client} secret mount. */
    public static HttpsWebhookSigningSecretResolver fromEnvironment(
            Map<String, String> environment, Clock clock) {
        Objects.requireNonNull(environment, "environment");
        if (environment.containsKey("ELMPAY_WEBHOOK_SIGNING_SECRET_ACCESS_TOKEN")) {
            throw new IllegalStateException("inline signing-secret access tokens are forbidden");
        }
        Duration timeout = milliseconds(environment,
                "ELMPAY_WEBHOOK_SIGNING_SECRET_TIMEOUT_MILLISECONDS", 2_000);
        MountedHttpsClient.Client mounted = MountedHttpsClient.fromEnvironment(environment,
                "ELMPAY_WEBHOOK_SIGNING_SECRET", "webhook-signing-client", clock, timeout);
        URI endpoint;
        try {
            endpoint = URI.create(required(environment,
                    "ELMPAY_WEBHOOK_SIGNING_SECRET_ENDPOINT"));
        } catch (IllegalArgumentException failure) {
            throw new IllegalStateException(
                    "ELMPAY_WEBHOOK_SIGNING_SECRET_ENDPOINT is invalid", failure);
        }
        return new HttpsWebhookSigningSecretResolver(mounted.httpClient(), endpoint,
                mounted.accessToken(), timeout, clock);
    }

    @Override
    public WebhookDeliveryRuntime.SecretLease lease(String tenantId,
            WebhookDeliveryRuntime.KeyDescriptor descriptor, Duration maximumLifetime) {
        Objects.requireNonNull(descriptor, "descriptor");
        requireId(tenantId, "tenantId");
        positive(maximumLifetime, "maximumLifetime");
        if (maximumLifetime.compareTo(Duration.ofSeconds(1)) < 0
                || maximumLifetime.compareTo(Duration.ofMinutes(5)) > 0) {
            throw new IllegalArgumentException("maximumLifetime must be 1 second..5 minutes");
        }
        String token = requireToken(accessToken.get());
        byte[] requestBody = requestBody(tenantId, descriptor, maximumLifetime);
        try {
            HttpRequest request = HttpRequest.newBuilder(endpoint).timeout(timeout)
                    .header("Authorization", "Bearer " + token)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/octet-stream")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(requestBody))
                    .build();
            try (BoundedHttpTransport.Response response = BoundedHttpTransport.send(
                        mutualTlsClient, request, MAX_SECRET_BYTES)) {
                byte[] responseSecret = response.body();
                try {
                    if (response.statusCode() != 200 || responseSecret.length < 32) {
                        throw new SecurityException(
                                "signing-secret gateway returned an unsafe response");
                    }
                    requireContentType(response, "application/octet-stream");
                    String responseTenant = header(response, "X-Elmpay-Tenant-Id");
                    String responseProject = header(response, "X-Elmpay-Project-Id");
                    String responseKey = header(response, "X-Elmpay-Key-Id");
                    String responseReference = header(response, "X-Elmpay-Secret-Reference");
                    if (!tenantId.equals(responseTenant)
                            || !descriptor.projectId().equals(responseProject)
                            || !descriptor.keyId().equals(responseKey)
                            || !descriptor.secretReference().equals(responseReference)) {
                        throw new SecurityException("signing-secret response binding mismatch");
                    }
                    Instant expiresAt = Instant.parse(header(response, "X-Elmpay-Expires-At"));
                    Instant now = clock.instant();
                    if (!expiresAt.isAfter(now) || expiresAt.isAfter(now.plus(maximumLifetime))) {
                        throw new SecurityException(
                                "signing-secret lease lifetime is outside the requested bound");
                    }
                    return new WebhookDeliveryRuntime.SecretLease(responseTenant,
                            responseProject, responseKey, responseReference,
                            header(response, "X-Elmpay-Lease-Id"),
                            expiresAt, responseSecret);
                } finally {
                    Arrays.fill(responseSecret, (byte) 0);
                }
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("signing-secret lease was interrupted", exception);
        } catch (IOException exception) {
            throw new IllegalStateException("signing-secret lease failed", exception);
        } finally {
            Arrays.fill(requestBody, (byte) 0);
        }
    }

    private static byte[] requestBody(String tenantId,
            WebhookDeliveryRuntime.KeyDescriptor descriptor, Duration maximumLifetime) {
        String value = "{\"tenant_id\":\"" + escape(tenantId)
                + "\",\"project_id\":\"" + escape(descriptor.projectId())
                + "\",\"key_id\":\"" + escape(descriptor.keyId())
                + "\",\"secret_reference\":\"" + escape(descriptor.secretReference())
                + "\",\"maximum_lifetime_seconds\":\"" + maximumLifetime.toSeconds()
                + "\"}";
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static String header(BoundedHttpTransport.Response response, String name) {
        List<String> values = response.headers().allValues(name);
        if (values.size() != 1 || values.getFirst().isBlank()
                || values.getFirst().length() > 320
                || values.getFirst().chars().anyMatch(
                        character -> character < 0x20 || character == 0x7f)) {
            throw new SecurityException("signing-secret response header is missing or ambiguous");
        }
        return values.getFirst();
    }

    static void requireContentType(BoundedHttpTransport.Response response,
            String expected) {
        List<String> values = response.headers().allValues("Content-Type");
        if (values.size() != 1 || !expected.equalsIgnoreCase(values.getFirst())) {
            throw new SecurityException("signing-secret response content type is unsafe");
        }
    }

    private static String escape(String value) {
        Objects.requireNonNull(value, "value");
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\r", "\\r").replace("\n", "\\n");
    }

    private static URI requireHttps(URI value) {
        Objects.requireNonNull(value, "endpoint");
        if (!"https".equalsIgnoreCase(value.getScheme()) || value.getHost() == null
                || value.getUserInfo() != null || value.getQuery() != null
                || value.getFragment() != null) {
            throw new IllegalArgumentException("signing-secret endpoint must be exact HTTPS");
        }
        return value;
    }

    private static Duration positive(Duration value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(field + " must be positive");
        }
        return value;
    }

    private static void requireId(String value, String field) {
        if (value == null || !value.matches("[A-Za-z0-9._:-]{3,160}")) {
            throw new IllegalArgumentException(field + " has an invalid format");
        }
    }

    private static String requireToken(String value) {
        if (value == null || value.length() < 32 || value.length() > 8_192
                || !value.matches("[A-Za-z0-9\\-._~+/]+=*")) {
            throw new SecurityException("signing-secret access token is malformed");
        }
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
}
