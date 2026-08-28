package com.elmpay.webhook.delivery;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

/** HTTPS+mTLS client for short-lived, exactly bound webhook signing-secret leases. */
public final class HttpsWebhookSigningSecretResolver
        implements WebhookDeliveryRuntime.SigningSecretResolver {
    private final HttpClient mutualTlsClient;
    private final URI endpoint;
    private final Supplier<String> accessToken;
    private final Duration timeout;

    public HttpsWebhookSigningSecretResolver(HttpClient mutualTlsClient, URI endpoint,
            Supplier<String> accessToken, Duration timeout) {
        this.mutualTlsClient = Objects.requireNonNull(mutualTlsClient, "mutualTlsClient");
        if (mutualTlsClient.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("signing-secret client must reject redirects");
        }
        this.endpoint = requireHttps(endpoint);
        this.accessToken = Objects.requireNonNull(accessToken, "accessToken");
        this.timeout = positive(timeout, "timeout");
    }

    @Override
    public WebhookDeliveryRuntime.SecretLease lease(String tenantId,
            WebhookDeliveryRuntime.KeyDescriptor descriptor, Duration maximumLifetime) {
        Objects.requireNonNull(descriptor, "descriptor");
        positive(maximumLifetime, "maximumLifetime");
        String token = Objects.requireNonNull(accessToken.get(), "accessToken");
        if (token.length() < 32 || token.length() > 8_192
                || token.chars().anyMatch(Character::isWhitespace)) {
            throw new SecurityException("signing-secret access token is malformed");
        }
        HttpRequest request = HttpRequest.newBuilder(endpoint).timeout(timeout)
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .header("Accept", "application/octet-stream")
                .POST(HttpRequest.BodyPublishers.ofByteArray(requestBody(tenantId, descriptor,
                        maximumLifetime)))
                .build();
        HttpResponse<byte[]> response;
        try {
            response = mutualTlsClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("signing-secret lease was interrupted", exception);
        } catch (IOException exception) {
            throw new IllegalStateException("signing-secret lease failed", exception);
        }
        byte[] responseSecret = response.body();
        if (response.statusCode() != 200 || responseSecret == null
                || responseSecret.length < 32 || responseSecret.length > 128) {
            throw new SecurityException("signing-secret gateway returned an unsafe response");
        }
        try {
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
            return new WebhookDeliveryRuntime.SecretLease(responseTenant, responseProject,
                    responseKey, responseReference, header(response, "X-Elmpay-Lease-Id"),
                    Instant.parse(header(response, "X-Elmpay-Expires-At")), responseSecret);
        } finally {
            java.util.Arrays.fill(responseSecret, (byte) 0);
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

    private static String header(HttpResponse<?> response, String name) {
        List<String> values = response.headers().allValues(name);
        if (values.size() != 1 || values.getFirst().isBlank()
                || values.getFirst().length() > 320
                || values.getFirst().indexOf('\r') >= 0 || values.getFirst().indexOf('\n') >= 0) {
            throw new SecurityException("signing-secret response header is missing or ambiguous");
        }
        return values.getFirst();
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
}
