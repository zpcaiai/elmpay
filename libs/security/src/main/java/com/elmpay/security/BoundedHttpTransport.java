package com.elmpay.security;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;
import javax.net.ssl.SSLParameters;

/**
 * Bounded JDK HTTP response transport with an explicitly wipeable response lifecycle.
 *
 * <p>The returned response owns a defensive copy of the received bytes and must be closed.
 * JDK-owned socket, TLS, HPACK and {@link ByteBuffer} storage is outside this class's erasure
 * boundary. Internal heap byte arrays are wiped on terminal paths; a copy returned by
 * {@link Response#body()} is caller-owned and cannot be erased by this class.
 */
public final class BoundedHttpTransport {
    private static final int MAX_CONFIGURED_BODY_BYTES = 16 * 1024 * 1024;
    private static final int MAX_RESPONSE_HEADER_NAMES = 64;
    private static final int MAX_RESPONSE_HEADER_CHARS = 32 * 1024;

    private BoundedHttpTransport() {
    }

    /** Sends one request without redirects beyond the policy configured on {@code client}. */
    public static Response send(HttpClient client, HttpRequest request, int maximumBodyBytes)
            throws IOException, InterruptedException {
        requireHttpsClient(client);
        Objects.requireNonNull(request, "request");
        if (!"https".equalsIgnoreCase(request.uri().getScheme())
                || request.uri().getHost() == null || request.uri().getUserInfo() != null
                || request.uri().getFragment() != null) {
            throw new SecurityException("HTTP transport requires an exact HTTPS request URI");
        }
        requireMaximum(maximumBodyBytes);
        BoundedBodyHandler handler = new BoundedBodyHandler(maximumBodyBytes);
        byte[] received = null;
        try {
            HttpResponse<byte[]> response = client.send(request, handler);
            received = Objects.requireNonNull(response.body(), "HTTP response body");
            return new Response(response.statusCode(), response.headers(), received);
        } finally {
            if (received != null) {
                Arrays.fill(received, (byte) 0);
            }
            handler.close();
        }
    }

    /** Verifies the caller supplied the exact TLS/redirect policy required by this transport. */
    public static void requireHttpsClient(HttpClient client) {
        Objects.requireNonNull(client, "client");
        SSLParameters parameters = client.sslParameters();
        if (client.followRedirects() != HttpClient.Redirect.NEVER
                || !Arrays.equals(parameters.getProtocols(), new String[] {"TLSv1.3"})
                || !"HTTPS".equals(parameters.getEndpointIdentificationAlgorithm())) {
            throw new SecurityException(
                    "HTTP client must pin TLSv1.3, HTTPS endpoint identity, and no redirects");
        }
    }

    /** Wipeable immutable-metadata response. */
    public static final class Response implements AutoCloseable {
        private final int statusCode;
        private final HttpHeaders headers;
        private byte[] body;
        private boolean closed;

        public Response(int statusCode, HttpHeaders headers, byte[] body) {
            if (statusCode < 100 || statusCode > 599) {
                throw new IllegalArgumentException("HTTP response status is invalid");
            }
            this.statusCode = statusCode;
            this.headers = Objects.requireNonNull(headers, "headers");
            validateResponseHeaders(headers);
            byte[] supplied = Objects.requireNonNull(body, "body");
            if (supplied.length > MAX_CONFIGURED_BODY_BYTES) {
                throw new IllegalArgumentException("HTTP response body is outside its hard bound");
            }
            this.body = supplied.clone();
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

        /** Returns an owned copy which the caller must wipe. */
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
                throw new IllegalStateException("HTTP response is closed");
            }
        }
    }

    static final class BoundedBodyHandler
            implements HttpResponse.BodyHandler<byte[]>, AutoCloseable {
        private final int maximumBodyBytes;
        private BoundedBodySubscriber subscriber;
        private boolean applied;
        private boolean closed;

        BoundedBodyHandler(int maximumBodyBytes) {
            requireMaximum(maximumBodyBytes);
            this.maximumBodyBytes = maximumBodyBytes;
        }

        @Override
        public synchronized HttpResponse.BodySubscriber<byte[]> apply(
                HttpResponse.ResponseInfo responseInfo) {
            Objects.requireNonNull(responseInfo, "responseInfo");
            if (closed || applied) {
                throw new SecurityException("HTTP body handler was reused");
            }
            applied = true;
            validateResponseHeaders(responseInfo.headers());
            validateContentLength(responseInfo.headers(), maximumBodyBytes);
            subscriber = new BoundedBodySubscriber(maximumBodyBytes);
            return subscriber;
        }

        @Override
        public synchronized void close() {
            if (closed) {
                return;
            }
            closed = true;
            if (subscriber != null) {
                subscriber.close();
            }
        }
    }

    static final class BoundedBodySubscriber
            implements HttpResponse.BodySubscriber<byte[]>, AutoCloseable {
        private final CompletableFuture<byte[]> body = new CompletableFuture<>();
        private final int maximumBodyBytes;
        private byte[] buffer;
        private byte[] completedBody;
        private int size;
        private Flow.Subscription subscription;
        private boolean subscribed;
        private boolean terminal;
        private boolean closed;

        BoundedBodySubscriber(int maximumBodyBytes) {
            requireMaximum(maximumBodyBytes);
            this.maximumBodyBytes = maximumBodyBytes;
            buffer = new byte[Math.min(maximumBodyBytes, 8 * 1024)];
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return body;
        }

        @Override
        public synchronized void onSubscribe(Flow.Subscription next) {
            Objects.requireNonNull(next, "subscription");
            if (closed || terminal || subscribed) {
                Throwable duplicateCancellation = cancel(next, null);
                if (!closed && !terminal) {
                    SecurityException failure = new SecurityException(
                            "HTTP body publisher subscribed more than once");
                    if (duplicateCancellation != null) {
                        failure.addSuppressed(duplicateCancellation);
                    }
                    fail(failure);
                }
                return;
            }
            subscribed = true;
            subscription = next;
            try {
                next.request(Long.MAX_VALUE);
            } catch (RuntimeException | Error exception) {
                fail(exception);
            }
        }

        @Override
        public synchronized void onNext(List<ByteBuffer> chunks) {
            Objects.requireNonNull(chunks, "chunks");
            if (closed || terminal) {
                return;
            }
            if (!subscribed) {
                fail(new SecurityException("HTTP body arrived before subscription"));
                return;
            }
            long incoming = 0;
            try {
                for (ByteBuffer chunk : chunks) {
                    incoming = Math.addExact(incoming,
                            Objects.requireNonNull(chunk, "body chunk").remaining());
                }
                if (incoming > maximumBodyBytes - size) {
                    fail(new SecurityException("HTTP response body exceeds configured limit"));
                    return;
                }
                ensureCapacity(Math.addExact(size, Math.toIntExact(incoming)));
                for (ByteBuffer chunk : chunks) {
                    int length = chunk.remaining();
                    chunk.get(buffer, size, length);
                    size += length;
                }
            } catch (RuntimeException | Error exception) {
                fail(exception);
            }
        }

        @Override
        public synchronized void onError(Throwable failure) {
            fail(Objects.requireNonNull(failure, "failure"));
        }

        @Override
        public synchronized void onComplete() {
            if (closed || terminal) {
                return;
            }
            if (!subscribed) {
                fail(new SecurityException("HTTP body completed before subscription"));
                return;
            }
            terminal = true;
            byte[] result = Arrays.copyOf(buffer, size);
            clearBuffer();
            completedBody = result;
            if (!body.complete(result)) {
                Arrays.fill(result, (byte) 0);
                completedBody = null;
            }
        }

        @Override
        public synchronized void close() {
            if (closed) {
                return;
            }
            closed = true;
            Throwable cancellationFailure = cancel(subscription, null);
            subscription = null;
            clearBuffer();
            if (completedBody != null) {
                Arrays.fill(completedBody, (byte) 0);
                completedBody = null;
            }
            if (!terminal) {
                terminal = true;
                SecurityException exception = new SecurityException(
                        "HTTP response body was closed before completion");
                if (cancellationFailure != null) {
                    exception.addSuppressed(cancellationFailure);
                }
                body.completeExceptionally(exception);
            }
        }

        private void fail(Throwable failure) {
            if (closed || terminal) {
                return;
            }
            terminal = true;
            Throwable cancellationFailure = cancel(subscription, failure);
            subscription = null;
            clearBuffer();
            if (cancellationFailure != null && cancellationFailure != failure) {
                failure.addSuppressed(cancellationFailure);
            }
            body.completeExceptionally(failure);
        }

        private void clearBuffer() {
            Arrays.fill(buffer, (byte) 0);
            buffer = new byte[0];
            size = 0;
        }

        private void ensureCapacity(int required) {
            if (required <= buffer.length) {
                return;
            }
            int nextLength = Math.min(maximumBodyBytes,
                    Math.max(required, Math.multiplyExact(buffer.length, 2)));
            byte[] expanded = Arrays.copyOf(buffer, nextLength);
            Arrays.fill(buffer, (byte) 0);
            buffer = expanded;
        }
    }

    private static void validateContentLength(HttpHeaders headers, int maximumBodyBytes) {
        List<String> values = headers.allValues("Content-Length");
        if (values.isEmpty()) {
            return;
        }
        if (values.size() != 1) {
            throw new SecurityException("HTTP Content-Length is ambiguous");
        }
        String value = values.getFirst();
        if (value.isEmpty() || value.length() > 10
                || (value.length() > 1 && value.charAt(0) == '0')
                || value.chars().anyMatch(character -> character < '0' || character > '9')) {
            throw new SecurityException("HTTP Content-Length is invalid");
        }
        try {
            long length = Long.parseLong(value);
            if (length > maximumBodyBytes) {
                throw new SecurityException("HTTP response body exceeds configured limit");
            }
        } catch (NumberFormatException exception) {
            throw new SecurityException("HTTP Content-Length is invalid", exception);
        }
    }

    private static void validateResponseHeaders(HttpHeaders headers) {
        Map<String, List<String>> values = headers.map();
        if (values.size() > MAX_RESPONSE_HEADER_NAMES) {
            throw new SecurityException("HTTP response has too many header names");
        }
        long characters = 0;
        int headerValues = 0;
        java.util.Set<String> normalizedNames = new HashSet<>();
        for (Map.Entry<String, List<String>> entry : values.entrySet()) {
            String name = entry.getKey();
            if (name == null || !name.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}")) {
                throw new SecurityException("HTTP response header name is invalid");
            }
            if (!normalizedNames.add(name.toLowerCase(Locale.ROOT))) {
                throw new SecurityException("HTTP response header name is duplicated");
            }
            characters = Math.addExact(characters, name.length());
            for (String value : entry.getValue()) {
                headerValues = Math.addExact(headerValues, 1);
                if (headerValues > 128) {
                    throw new SecurityException("HTTP response has too many header values");
                }
                if (value == null || value.length() > 8_192
                        || value.chars().anyMatch(character -> character < 0x20
                                && character != '\t' || character == 0x7f)) {
                    throw new SecurityException("HTTP response header value is invalid");
                }
                characters = Math.addExact(characters, value.length());
            }
            if (characters > MAX_RESPONSE_HEADER_CHARS) {
                throw new SecurityException("HTTP response headers exceed their configured bound");
            }
        }
    }

    private static Throwable cancel(Flow.Subscription subscription, Throwable original) {
        if (subscription == null) {
            return null;
        }
        try {
            subscription.cancel();
            return null;
        } catch (RuntimeException | Error exception) {
            return exception == original ? null : exception;
        }
    }

    private static void requireMaximum(int maximumBodyBytes) {
        if (maximumBodyBytes < 1 || maximumBodyBytes > MAX_CONFIGURED_BODY_BYTES) {
            throw new IllegalArgumentException("maximumBodyBytes must be 1..16777216");
        }
    }
}
