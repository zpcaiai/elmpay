package com.elmpay.audit;

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
import java.util.Set;
import java.util.UUID;

/** HTTPS transport for an independently operated, Ed25519-signing timestamp authority. */
public final class HttpsAuditTimestampAuthority implements AuditAnchorWorker.TimestampAuthority {
    private static final int MAX_RESPONSE_BYTES = 64 * 1024;
    private static final Set<String> RESPONSE_FIELDS = Set.of(
            "authority_id", "receipt_id", "tenant_id", "through_sequence",
            "chain_hash", "anchored_at", "signature");
    private final HttpClient mutualTlsClient;
    private final URI endpoint;
    private final Duration requestTimeout;
    private final String bearerToken;

    public HttpsAuditTimestampAuthority(HttpClient mutualTlsClient, URI endpoint,
            Duration requestTimeout, String bearerToken) {
        this.mutualTlsClient = Objects.requireNonNull(mutualTlsClient, "mutualTlsClient");
        if (mutualTlsClient.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("timestamp authority client must reject redirects");
        }
        this.endpoint = requireHttpsEndpoint(endpoint);
        this.requestTimeout = positive(requestTimeout, "requestTimeout");
        if (bearerToken == null || bearerToken.length() < 32 || bearerToken.length() > 4096
                || bearerToken.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("bearerToken has an invalid format");
        }
        this.bearerToken = bearerToken;
    }

    @Override
    public AuditAnchorWorker.Receipt anchor(AuditAnchorWorker.Candidate candidate) {
        Objects.requireNonNull(candidate, "candidate");
        HttpRequest request = HttpRequest.newBuilder(endpoint)
                .timeout(requestTimeout)
                .header("Authorization", "Bearer " + bearerToken)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(requestBody(candidate)))
                .build();
        HttpResponse<byte[]> response;
        try {
            response = mutualTlsClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("timestamp authority request was interrupted", exception);
        } catch (IOException exception) {
            throw new IllegalStateException("timestamp authority request failed", exception);
        }
        if (response.statusCode() != 200) {
            throw new IllegalStateException("timestamp authority returned status "
                    + response.statusCode());
        }
        byte[] body = response.body();
        if (body == null || body.length == 0 || body.length > MAX_RESPONSE_BYTES) {
            throw new SecurityException("timestamp authority response size is invalid");
        }
        Map<String, String> values = parseFlatJson(new String(body, StandardCharsets.UTF_8));
        if (!values.keySet().equals(RESPONSE_FIELDS)) {
            throw new SecurityException("timestamp authority response fields are not exact");
        }
        try {
            return new AuditAnchorWorker.Receipt(required(values, "authority_id"),
                    required(values, "receipt_id"), UUID.fromString(required(values, "tenant_id")),
                    Long.parseLong(required(values, "through_sequence")),
                    required(values, "chain_hash"), Instant.parse(required(values, "anchored_at")),
                    Base64.getUrlDecoder().decode(required(values, "signature")));
        } catch (IllegalArgumentException exception) {
            throw new SecurityException("timestamp authority response is malformed", exception);
        }
    }

    private static byte[] requestBody(AuditAnchorWorker.Candidate candidate) {
        String json = "{\"schema\":\"elmpay-audit-anchor-v1\",\"anchor_id\":\""
                + candidate.anchorId() + "\",\"tenant_id\":\"" + candidate.tenantId()
                + "\",\"through_sequence\":\"" + candidate.throughSequence()
                + "\",\"chain_hash\":\"" + candidate.chainHash() + "\"}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    private static Map<String, String> parseFlatJson(String source) {
        Map<String, String> result = new LinkedHashMap<>();
        int[] at = {0};
        skipWhitespace(source, at);
        expect(source, at, '{');
        skipWhitespace(source, at);
        if (peek(source, at) == '}') {
            at[0]++;
            return result;
        }
        while (true) {
            String key = string(source, at);
            skipWhitespace(source, at);
            expect(source, at, ':');
            skipWhitespace(source, at);
            String value = string(source, at);
            if (result.putIfAbsent(key, value) != null) {
                throw new IllegalArgumentException("duplicate JSON field");
            }
            skipWhitespace(source, at);
            char next = peek(source, at);
            if (next == '}') {
                at[0]++;
                break;
            }
            expect(source, at, ',');
            skipWhitespace(source, at);
        }
        skipWhitespace(source, at);
        if (at[0] != source.length()) {
            throw new IllegalArgumentException("trailing JSON data");
        }
        return Map.copyOf(result);
    }

    private static String string(String source, int[] at) {
        expect(source, at, '"');
        StringBuilder result = new StringBuilder();
        while (at[0] < source.length()) {
            char value = source.charAt(at[0]++);
            if (value == '"') {
                return result.toString();
            }
            if (value == '\\') {
                if (at[0] >= source.length()) {
                    throw new IllegalArgumentException("unterminated JSON escape");
                }
                char escaped = source.charAt(at[0]++);
                result.append(switch (escaped) {
                    case '"', '\\', '/' -> escaped;
                    case 'b' -> '\b';
                    case 'f' -> '\f';
                    case 'n' -> '\n';
                    case 'r' -> '\r';
                    case 't' -> '\t';
                    default -> throw new IllegalArgumentException("unsupported JSON escape");
                });
            } else if (value < 0x20) {
                throw new IllegalArgumentException("control character in JSON string");
            } else {
                result.append(value);
            }
        }
        throw new IllegalArgumentException("unterminated JSON string");
    }

    private static void skipWhitespace(String source, int[] at) {
        while (at[0] < source.length() && Character.isWhitespace(source.charAt(at[0]))) {
            at[0]++;
        }
    }

    private static void expect(String source, int[] at, char expected) {
        if (peek(source, at) != expected) {
            throw new IllegalArgumentException("malformed JSON");
        }
        at[0]++;
    }

    private static char peek(String source, int[] at) {
        if (at[0] >= source.length()) {
            throw new IllegalArgumentException("unexpected end of JSON");
        }
        return source.charAt(at[0]);
    }

    private static String required(Map<String, String> values, String field) {
        String value = values.get(field);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("missing response field " + field);
        }
        return value;
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
}
