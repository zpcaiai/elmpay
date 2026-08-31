package com.elmpay.risk.runtime;

import com.elmpay.security.BoundedHttpTransport;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/** TLS 1.3-only transport with no redirects and bounded streaming response bodies. */
public final class StrictHttpsTransport {
    private static final Set<String> RESERVED_REQUEST_HEADERS = Set.of(
            "accept", "authorization", "connection", "content-length", "content-type",
            "expect", "host", "proxy-authorization", "te", "trailer", "transfer-encoding",
            "upgrade");
    public static final class Response implements AutoCloseable {
        private final int status;
        private final String contentType;
        private byte[] body;

        public Response(int status, String contentType, byte[] body) {
            this.status = status;
            this.contentType = Objects.requireNonNull(contentType, "contentType");
            this.body = Objects.requireNonNull(body, "body").clone();
        }

        public int status() {
            return status;
        }

        public String contentType() {
            return contentType;
        }

        public synchronized byte[] body() {
            if (body == null) {
                throw new IllegalStateException("HTTPS response is closed");
            }
            return body.clone();
        }

        @Override
        public synchronized void close() {
            if (body != null) {
                java.util.Arrays.fill(body, (byte) 0);
                body = null;
            }
        }
    }

    private final HttpClient client;
    private final Duration timeout;
    private final int maximumResponseBytes;

    public StrictHttpsTransport(SSLContext context, Duration timeout, int maximumResponseBytes) {
        Objects.requireNonNull(context, "context");
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        if (timeout.isZero() || timeout.isNegative() || timeout.compareTo(Duration.ofSeconds(5)) > 0
                || maximumResponseBytes < 1 || maximumResponseBytes > 1024 * 1024) {
            throw new IllegalArgumentException("HTTPS timeout or response bound is invalid");
        }
        this.maximumResponseBytes = maximumResponseBytes;
        SSLParameters parameters = new SSLParameters();
        parameters.setProtocols(new String[] {"TLSv1.3"});
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        this.client = HttpClient.newBuilder().sslContext(context).sslParameters(parameters)
                .connectTimeout(timeout).followRedirects(HttpClient.Redirect.NEVER)
                .version(HttpClient.Version.HTTP_1_1).build();
    }

    public Response post(URI endpoint, byte[] body, Map<String, String> headers) {
        return post(endpoint, body, headers, timeout);
    }

    /**
     * Send with a caller-owned remaining budget that may only tighten this transport's bound.
     * This is used by multi-hop protocols so each hop cannot restart the complete deadline.
     */
    public Response post(URI endpoint, byte[] body, Map<String, String> headers,
            Duration remainingTimeout) {
        Duration requestTimeout = boundedRequestTimeout(remainingTimeout);
        HttpRequest.Builder request = HttpRequest.newBuilder(exactHttps(endpoint))
                .timeout(requestTimeout)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        headers.forEach((name, value) -> {
            if (name == null || !name.matches("[A-Za-z0-9-]{1,64}") || value == null
                    || RESERVED_REQUEST_HEADERS.contains(name.toLowerCase(java.util.Locale.ROOT))
                    || value.length() > 1024 || value.indexOf('\r') >= 0
                    || value.indexOf('\n') >= 0) {
                throw new IllegalArgumentException("unsafe HTTPS request header");
            }
            request.header(name, value);
        });
        return send(request.build());
    }

    public Response get(URI endpoint) {
        return send(HttpRequest.newBuilder(exactHttps(endpoint)).timeout(timeout)
                .header("Accept", "application/json").GET().build());
    }

    private Duration boundedRequestTimeout(Duration value) {
        Objects.requireNonNull(value, "remainingTimeout");
        if (value.isZero() || value.isNegative() || value.compareTo(timeout) > 0) {
            throw new IllegalArgumentException(
                    "HTTPS request timeout must tighten the configured transport bound");
        }
        return value;
    }

    private Response send(HttpRequest request) {
        try (BoundedHttpTransport.Response response = BoundedHttpTransport.send(
                    client, request, maximumResponseBytes)) {
            byte[] received = response.body();
            try {
                return new Response(response.statusCode(), exactContentType(response.headers()),
                        received);
            } finally {
                java.util.Arrays.fill(received, (byte) 0);
            }
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("HTTPS request was interrupted", failure);
        } catch (IOException failure) {
            throw new IllegalStateException("HTTPS dependency is unavailable", failure);
        }
    }

    static String exactContentType(HttpHeaders headers) {
        Objects.requireNonNull(headers, "headers");
        List<String> values = headers.allValues("Content-Type");
        if (values.size() != 1
                || !"application/json".equalsIgnoreCase(values.getFirst())) {
            return "";
        }
        return "application/json";
    }

    public static URI exactHttps(URI endpoint) {
        Objects.requireNonNull(endpoint, "endpoint");
        int port = endpoint.getPort();
        if (!"https".equals(endpoint.getScheme()) || endpoint.getHost() == null
                || endpoint.getUserInfo() != null || endpoint.getQuery() != null
                || endpoint.getFragment() != null || endpoint.getRawPath() == null
                || (port != -1 && (port < 1 || port > 65_535))
                || endpoint.getRawPath().isBlank()
                || !endpoint.getRawPath().equals(endpoint.getPath())
                || !endpoint.getRawPath().matches("/[A-Za-z0-9._~/-]+")
                || endpoint.getRawPath().contains("//") || !endpoint.normalize().equals(endpoint)) {
            throw new IllegalArgumentException("dependency endpoint must be an exact HTTPS URI");
        }
        return endpoint;
    }
}
