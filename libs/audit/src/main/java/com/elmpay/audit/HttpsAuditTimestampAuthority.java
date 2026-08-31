package com.elmpay.audit;

import com.elmpay.security.BoundedHttpTransport;
import com.elmpay.security.MountedHttpsClient;
import com.elmpay.security.WipeableFlatJson;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

/** HTTPS transport for an independently operated, Ed25519-signing timestamp authority. */
public final class HttpsAuditTimestampAuthority implements AuditAnchorWorker.TimestampAuthority {
    private static final int MAX_RESPONSE_BYTES = 64 * 1024;
    private static final Set<String> RESPONSE_FIELDS = Set.of(
            "authority_id", "receipt_id", "tenant_id", "through_sequence",
            "chain_hash", "anchored_at", "signature");
    private final HttpClient mutualTlsClient;
    private final URI endpoint;
    private final Duration requestTimeout;
    private final Supplier<String> bearerToken;

    public HttpsAuditTimestampAuthority(HttpClient mutualTlsClient, URI endpoint,
            Duration requestTimeout, String bearerToken) {
        this(mutualTlsClient, endpoint, requestTimeout, () -> bearerToken, true);
    }

    HttpsAuditTimestampAuthority(HttpClient mutualTlsClient, URI endpoint,
            Duration requestTimeout, Supplier<String> bearerToken) {
        this(mutualTlsClient, endpoint, requestTimeout, bearerToken, true);
    }

    private HttpsAuditTimestampAuthority(HttpClient mutualTlsClient, URI endpoint,
            Duration requestTimeout, Supplier<String> bearerToken,
            boolean validateSupplierImmediately) {
        this.mutualTlsClient = Objects.requireNonNull(mutualTlsClient, "mutualTlsClient");
        if (mutualTlsClient.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("timestamp authority client must reject redirects");
        }
        BoundedHttpTransport.requireHttpsClient(mutualTlsClient);
        this.endpoint = requireHttpsEndpoint(endpoint);
        this.requestTimeout = positive(requestTimeout, "requestTimeout");
        if (requestTimeout.compareTo(Duration.ofSeconds(10)) > 0) {
            throw new IllegalArgumentException("requestTimeout must not exceed 10 seconds");
        }
        this.bearerToken = Objects.requireNonNull(bearerToken, "bearerToken");
        if (validateSupplierImmediately) {
            requireToken(bearerToken.get());
        }
    }

    /** Production composition from the exact {@code audit-timestamp-client} secret mount. */
    public static HttpsAuditTimestampAuthority fromEnvironment(Map<String, String> environment,
            java.time.Clock clock) {
        Objects.requireNonNull(environment, "environment");
        if (environment.containsKey("ELMPAY_AUDIT_TIMESTAMP_AUTHORITY_ACCESS_TOKEN")) {
            throw new IllegalStateException("inline timestamp-authority access tokens are forbidden");
        }
        Duration timeout = milliseconds(environment,
                "ELMPAY_AUDIT_TIMESTAMP_AUTHORITY_TIMEOUT_MILLISECONDS", 2_000);
        MountedHttpsClient.Client mounted = MountedHttpsClient.fromEnvironment(environment,
                "ELMPAY_AUDIT_TIMESTAMP_AUTHORITY", "audit-timestamp-client", clock, timeout);
        URI endpoint;
        try {
            endpoint = URI.create(required(environment,
                    "ELMPAY_AUDIT_TIMESTAMP_AUTHORITY_ENDPOINT"));
        } catch (IllegalArgumentException failure) {
            throw new IllegalStateException(
                    "ELMPAY_AUDIT_TIMESTAMP_AUTHORITY_ENDPOINT is invalid", failure);
        }
        return new HttpsAuditTimestampAuthority(mounted.httpClient(), endpoint, timeout,
                mounted.accessToken(), false);
    }

    @Override
    public AuditAnchorWorker.Receipt anchor(AuditAnchorWorker.Candidate candidate) {
        Objects.requireNonNull(candidate, "candidate");
        byte[] requestBody = requestBody(candidate);
        try {
            String token = requireToken(bearerToken.get());
            HttpRequest request = HttpRequest.newBuilder(endpoint)
                    .timeout(requestTimeout)
                    .header("Authorization", "Bearer " + token)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(requestBody))
                    .build();
            try (BoundedHttpTransport.Response response = BoundedHttpTransport.send(
                        mutualTlsClient, request, MAX_RESPONSE_BYTES)) {
                if (response.statusCode() != 200 || response.bodyLength() == 0) {
                    throw new IllegalStateException(
                            "timestamp authority returned an unsafe response");
                }
                requireContentType(response, "application/json");
                byte[] body = response.body();
                try (WipeableFlatJson values = WipeableFlatJson.parse(body)) {
                    if (!values.keys().equals(RESPONSE_FIELDS)) {
                        throw new SecurityException(
                                "timestamp authority response fields are not exact");
                    }
                    try {
                        byte[] signature = values.requireBase64Url("signature", 64, 64);
                        try {
                            return new AuditAnchorWorker.Receipt(
                                    values.requireMetadata("authority_id", 256),
                                    values.requireMetadata("receipt_id", 256),
                                    UUID.fromString(values.requireMetadata("tenant_id", 64)),
                                    Long.parseLong(values.requireMetadata(
                                            "through_sequence", 32)),
                                    values.requireMetadata("chain_hash", 128),
                                    values.requireInstant("anchored_at"), signature);
                        } finally {
                            Arrays.fill(signature, (byte) 0);
                        }
                    } catch (IllegalArgumentException exception) {
                        throw new SecurityException(
                                "timestamp authority response is malformed", exception);
                    }
                } finally {
                    Arrays.fill(body, (byte) 0);
                }
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("timestamp authority request was interrupted", exception);
        } catch (IOException exception) {
            throw new IllegalStateException("timestamp authority request failed", exception);
        } finally {
            Arrays.fill(requestBody, (byte) 0);
        }
    }

    private static byte[] requestBody(AuditAnchorWorker.Candidate candidate) {
        String json = "{\"schema\":\"elmpay-audit-anchor-v1\",\"anchor_id\":\""
                + candidate.anchorId() + "\",\"tenant_id\":\"" + candidate.tenantId()
                + "\",\"through_sequence\":\"" + candidate.throughSequence()
                + "\",\"chain_hash\":\"" + candidate.chainHash() + "\"}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    static void requireContentType(BoundedHttpTransport.Response response,
            String expected) {
        List<String> values = response.headers().allValues("Content-Type");
        if (values.size() != 1 || !expected.equalsIgnoreCase(values.getFirst())) {
            throw new SecurityException("timestamp authority content type is unsafe");
        }
    }

    private static URI requireHttpsEndpoint(URI endpoint) {
        Objects.requireNonNull(endpoint, "endpoint");
        if (!"https".equalsIgnoreCase(endpoint.getScheme()) || endpoint.getHost() == null
                || endpoint.getUserInfo() != null || endpoint.getFragment() != null
                || endpoint.getQuery() != null) {
            throw new IllegalArgumentException("timestamp authority endpoint must be an exact HTTPS URI");
        }
        return endpoint;
    }

    private static Duration positive(Duration value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(field + " must be positive");
        }
        return value;
    }

    private static String requireToken(String value) {
        if (value == null || value.length() < 32 || value.length() > 4_096
                || !value.matches("[A-Za-z0-9\\-._~+/]+=*")) {
            throw new IllegalArgumentException("bearerToken has an invalid format");
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
