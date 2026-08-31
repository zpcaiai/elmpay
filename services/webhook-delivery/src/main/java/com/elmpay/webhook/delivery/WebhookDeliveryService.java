package com.elmpay.webhook.delivery;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.IDN;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/** Signed, persistently retried business-project webhook delivery worker. */
public final class WebhookDeliveryService {
    private static final int MAX_PAYLOAD_BYTES = 1_048_576;

    public enum Outcome { IDLE, DELIVERED, RETRY_SCHEDULED, DEAD_LETTERED }

    public record SigningKey(String projectId, String keyId, byte[] secret,
            Instant validFrom, Instant validUntil) implements AutoCloseable {
        public SigningKey {
            requireId(projectId, "projectId");
            requireText(keyId, "keyId");
            byte[] supplied = Objects.requireNonNull(secret, "secret");
            if (supplied.length < 32 || supplied.length > 128) {
                throw new IllegalArgumentException(
                        "webhook signing secret must contain 32..128 bytes");
            }
            secret = supplied.clone();
            Objects.requireNonNull(validFrom, "validFrom");
            Objects.requireNonNull(validUntil, "validUntil");
            if (!validUntil.isAfter(validFrom)) {
                throw new IllegalArgumentException("invalid signing-key validity window");
            }
        }

        @Override
        public synchronized byte[] secret() {
            return secret.clone();
        }

        boolean validAt(Instant at) {
            return !at.isBefore(validFrom) && at.isBefore(validUntil);
        }

        @Override
        public synchronized void close() {
            java.util.Arrays.fill(secret, (byte) 0);
        }
    }

    public record Delivery(long deliveryId, String tenantId, String projectId, String endpointId,
            URI endpoint, String eventId, String eventType, byte[] payload,
            int attemptCount, int maxAttempts, String leaseOwner, long fencingToken)
            implements AutoCloseable {
        public Delivery {
            if (deliveryId <= 0) {
                throw new IllegalArgumentException("deliveryId must be positive");
            }
            requireId(tenantId, "tenantId");
            requireId(projectId, "projectId");
            requireId(endpointId, "endpointId");
            Objects.requireNonNull(endpoint, "endpoint");
            requireText(eventId, "eventId");
            requireText(eventType, "eventType");
            payload = Objects.requireNonNull(payload, "payload").clone();
            if (payload.length == 0 || payload.length > MAX_PAYLOAD_BYTES) {
                throw new IllegalArgumentException("payload has an invalid size");
            }
            if (attemptCount < 0 || maxAttempts < 1 || maxAttempts > 20 || attemptCount >= maxAttempts) {
                throw new IllegalArgumentException("invalid delivery attempt counters");
            }
            requireId(leaseOwner, "leaseOwner");
            if (fencingToken <= 0) {
                throw new IllegalArgumentException("fencingToken must be positive");
            }
        }

        @Override
        public synchronized byte[] payload() {
            return payload.clone();
        }

        @Override
        public synchronized void close() {
            java.util.Arrays.fill(payload, (byte) 0);
        }
    }

    public record HttpResult(int statusCode, Map<String, List<String>> headers) {
        public HttpResult {
            if (statusCode < 100 || statusCode > 599) {
                throw new IllegalArgumentException("webhook response status is invalid");
            }
            headers = Map.copyOf(headers);
        }
    }

    @FunctionalInterface
    public interface Transport {
        HttpResult send(OutboundRequest request) throws IOException, InterruptedException;
    }

    /** Immutable request plus the DNS answers validated for this exact delivery attempt. */
    public record OutboundRequest(EndpointPolicy.ValidatedEndpoint target,
            Map<String, String> headers, byte[] body, Duration timeout)
            implements AutoCloseable {
        public OutboundRequest {
            Objects.requireNonNull(target, "target");
            Objects.requireNonNull(headers, "headers");
            Map<String, String> safeHeaders = new LinkedHashMap<>();
            headers.forEach((name, value) -> {
                if (name == null || !name.matches("[A-Za-z0-9-]{1,128}")
                        || name.equalsIgnoreCase("Host")
                        || name.equalsIgnoreCase("Content-Length")
                        || name.equalsIgnoreCase("Connection") || value == null
                        || !value.matches("[\\x20-\\x7e]{0,4096}")) {
                    throw new SecurityException("invalid outbound webhook header");
                }
                safeHeaders.put(name, value);
            });
            headers = Map.copyOf(safeHeaders);
            body = Objects.requireNonNull(body, "body").clone();
            positive(timeout, "timeout");
        }

        @Override
        public synchronized byte[] body() {
            return body.clone();
        }

        public URI endpoint() {
            return target.endpoint();
        }

        @Override
        public synchronized void close() {
            java.util.Arrays.fill(body, (byte) 0);
        }
    }

    public static final class JdkTransport implements Transport {
        private static final int MAX_RESPONSE_HEADER_BYTES = 65_536;
        private final Duration connectTimeout;
        private final SSLSocketFactory socketFactory;

        public JdkTransport(Duration connectTimeout) {
            positive(connectTimeout, "connectTimeout");
            this.connectTimeout = connectTimeout;
            this.socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        }

        @Override
        public HttpResult send(OutboundRequest request) throws IOException {
            Objects.requireNonNull(request, "request");
            IOException failure = null;
            for (InetAddress address : request.target().addresses()) {
                if (!EndpointPolicy.isPublic(address)) {
                    throw new SecurityException(
                            "validated webhook address became non-public before connect");
                }
                try {
                    return sendPinned(request, address);
                } catch (IOException exception) {
                    if (failure == null) {
                        failure = exception;
                    } else {
                        failure.addSuppressed(exception);
                    }
                }
            }
            throw failure == null ? new IOException("webhook endpoint has no pinned addresses")
                    : failure;
        }

        private HttpResult sendPinned(OutboundRequest request, InetAddress address)
                throws IOException {
            EndpointPolicy.ValidatedEndpoint target = request.target();
            int connectMilliseconds = timeoutMilliseconds(connectTimeout);
            int requestMilliseconds = timeoutMilliseconds(request.timeout());
            try (Socket connection = new Socket()) {
                connection.connect(new InetSocketAddress(address, target.port()),
                        connectMilliseconds);
                connection.setSoTimeout(requestMilliseconds);
                try (SSLSocket tls = (SSLSocket) socketFactory.createSocket(connection,
                        target.host(), target.port(), true)) {
                    tls.setEnabledProtocols(new String[] {"TLSv1.3"});
                    SSLParameters parameters = tls.getSSLParameters();
                    parameters.setEndpointIdentificationAlgorithm("HTTPS");
                    parameters.setServerNames(List.of(new SNIHostName(target.host())));
                    parameters.setApplicationProtocols(new String[] {"http/1.1"});
                    tls.setSSLParameters(parameters);
                    tls.setUseClientMode(true);
                    tls.startHandshake();
                    writeRequest(tls.getOutputStream(), request);
                    return readResponse(tls.getInputStream());
                }
            }
        }

        private static void writeRequest(OutputStream output, OutboundRequest request)
                throws IOException {
            byte[] body = request.body();
            try {
                StringBuilder head = new StringBuilder();
                head.append("POST ").append(requestTarget(request.endpoint()))
                        .append(" HTTP/1.1\r\nHost: ").append(request.target().host())
                        .append("\r\nConnection: close\r\nContent-Length: ")
                        .append(body.length).append("\r\n");
                request.headers().forEach((name, value) -> head.append(name).append(": ")
                        .append(value).append("\r\n"));
                head.append("\r\n");
                output.write(head.toString().getBytes(StandardCharsets.US_ASCII));
                output.write(body);
                output.flush();
            } finally {
                java.util.Arrays.fill(body, (byte) 0);
            }
        }

        private static HttpResult readResponse(InputStream input) throws IOException {
            int[] consumed = {0};
            String statusLine = readLine(input, consumed);
            if (!statusLine.matches("HTTP/1\\.[01] [0-9]{3}( .*)?")) {
                throw new IOException("invalid webhook HTTP response status line");
            }
            int statusCode = Integer.parseInt(statusLine.substring(9, 12));
            Map<String, List<String>> headers = new LinkedHashMap<>();
            while (true) {
                String line = readLine(input, consumed);
                if (line.isEmpty()) {
                    return new HttpResult(statusCode, headers);
                }
                int separator = line.indexOf(':');
                if (separator < 1) {
                    throw new IOException("invalid webhook HTTP response header");
                }
                String name = line.substring(0, separator).strip().toLowerCase(Locale.ROOT);
                String value = line.substring(separator + 1).strip();
                if (!name.matches("[a-z0-9-]{1,128}")) {
                    throw new IOException("invalid webhook HTTP response header name");
                }
                headers.computeIfAbsent(name, ignored -> new java.util.ArrayList<>()).add(value);
            }
        }

        private static String readLine(InputStream input, int[] consumed) throws IOException {
            StringBuilder line = new StringBuilder();
            boolean carriageReturn = false;
            while (true) {
                int next = input.read();
                if (next < 0) {
                    throw new IOException("truncated webhook HTTP response");
                }
                consumed[0]++;
                if (consumed[0] > MAX_RESPONSE_HEADER_BYTES) {
                    throw new IOException("webhook HTTP response headers are too large");
                }
                if (carriageReturn) {
                    if (next == '\n') {
                        return line.toString();
                    }
                    line.append('\r');
                    carriageReturn = false;
                }
                if (next == '\r') {
                    carriageReturn = true;
                } else if (next == '\n' || next < 0x20 && next != '\t') {
                    throw new IOException("invalid webhook HTTP response line ending");
                } else {
                    line.append((char) next);
                }
            }
        }

        private static String requestTarget(URI endpoint) {
            URI ascii = URI.create(endpoint.toASCIIString());
            String path = ascii.getRawPath();
            String target = path == null || path.isEmpty() ? "/" : path;
            return ascii.getRawQuery() == null ? target : target + "?" + ascii.getRawQuery();
        }

        private static int timeoutMilliseconds(Duration timeout) {
            long raw;
            try {
                raw = timeout.toMillis();
            } catch (ArithmeticException exception) {
                raw = Integer.MAX_VALUE;
            }
            long milliseconds = Math.max(1, raw);
            return Math.toIntExact(Math.min(milliseconds, Integer.MAX_VALUE));
        }
    }

    @FunctionalInterface
    public interface HostResolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    public interface Outbox {
        Optional<Delivery> claim(String tenantId, Instant now, Instant leaseUntil);

        void markDelivered(Delivery delivery, int statusCode, Instant deliveredAt);

        void reschedule(Delivery delivery, int statusCode, String errorCode,
                Instant nextAttemptAt);

        void deadLetter(Delivery delivery, int statusCode, String errorCode, Instant failedAt);
    }

    public static final class RotatingKeyRing implements AutoCloseable {
        private final AtomicReference<List<SigningKey>> keys;

        public RotatingKeyRing(List<SigningKey> initial) {
            List<SigningKey> safe = List.copyOf(initial);
            if (safe.isEmpty()) {
                throw new IllegalArgumentException("at least one signing key is required");
            }
            keys = new AtomicReference<>(safe);
        }

        public SigningKey current(String projectId, Instant at) {
            requireId(projectId, "projectId");
            return keys.get().stream().filter(key -> projectId.equals(key.projectId()))
                    .filter(key -> key.validAt(at))
                    .max(java.util.Comparator.comparing(SigningKey::validFrom))
                    .orElseThrow(() -> new SecurityException(
                            "no active webhook signing key for delivery project"));
        }

        public void rotate(List<SigningKey> replacement) {
            List<SigningKey> safe = List.copyOf(replacement);
            if (safe.isEmpty()) {
                throw new IllegalArgumentException("replacement key set is empty");
            }
            Map<String, List<String>> replacementIds = safe.stream().collect(
                    java.util.stream.Collectors.groupingBy(SigningKey::projectId,
                            java.util.stream.Collectors.mapping(SigningKey::keyId,
                                    java.util.stream.Collectors.toList())));
            Map<String, List<String>> currentIds = keys.get().stream().collect(
                    java.util.stream.Collectors.groupingBy(SigningKey::projectId,
                            java.util.stream.Collectors.mapping(SigningKey::keyId,
                                    java.util.stream.Collectors.toList())));
            for (Map.Entry<String, List<String>> current : currentIds.entrySet()) {
                if (replacementIds.getOrDefault(current.getKey(), List.of()).stream()
                        .noneMatch(current.getValue()::contains)) {
                    throw new IllegalArgumentException(
                            "signing-key rotation requires a per-project overlap");
                }
            }
            List<SigningKey> previous = keys.getAndSet(safe);
            previous.stream().filter(key -> safe.stream().noneMatch(candidate -> candidate == key))
                    .forEach(SigningKey::close);
        }

        @Override
        public void close() {
            keys.getAndSet(List.of()).forEach(SigningKey::close);
        }
    }

    public static final class EndpointPolicy {
        private final Set<String> approvedHosts;
        private final HostResolver resolver;

        public EndpointPolicy(Set<String> approvedHosts, HostResolver resolver) {
            this.approvedHosts = approvedHosts.stream()
                    .map(host -> normalizeHost(host, "approved host"))
                    .collect(java.util.stream.Collectors.toUnmodifiableSet());
            if (this.approvedHosts.isEmpty()) {
                throw new IllegalArgumentException("approvedHosts is empty");
            }
            this.resolver = Objects.requireNonNull(resolver, "resolver");
        }

        public record ValidatedEndpoint(URI endpoint, String host, int port,
                List<InetAddress> addresses) {
            public ValidatedEndpoint {
                Objects.requireNonNull(endpoint, "endpoint");
                requireText(host, "host");
                if (port != 443) {
                    throw new IllegalArgumentException("webhook endpoint port must be 443");
                }
                addresses = List.copyOf(addresses);
                if (addresses.isEmpty()) {
                    throw new IllegalArgumentException("validated addresses are empty");
                }
            }
        }

        public ValidatedEndpoint validate(URI endpoint) {
            Objects.requireNonNull(endpoint, "endpoint");
            if (endpoint.isOpaque() || !endpoint.isAbsolute()
                    || !"https".equalsIgnoreCase(endpoint.getScheme()) || endpoint.getHost() == null
                    || endpoint.getUserInfo() != null || endpoint.getFragment() != null
                    || (endpoint.getPort() != -1 && endpoint.getPort() != 443)) {
                throw new SecurityException("webhook endpoint must be an absolute HTTPS URI on port 443");
            }
            String host;
            try {
                host = normalizeHost(endpoint.getHost(), "endpoint host");
            } catch (IllegalArgumentException exception) {
                throw new SecurityException("webhook endpoint host is not canonical", exception);
            }
            String authority = endpoint.getRawAuthority();
            if (authority == null || authority.contains("%") || authority.contains("\\")
                    || !(authority.equalsIgnoreCase(host)
                            || authority.equalsIgnoreCase(host + ":443"))) {
                throw new SecurityException("webhook endpoint authority is not canonical");
            }
            if (!approvedHosts.contains(host)) {
                throw new SecurityException("webhook endpoint host is not allowlisted");
            }
            InetAddress[] addresses;
            try {
                addresses = resolver.resolve(host);
            } catch (UnknownHostException exception) {
                throw new SecurityException("webhook endpoint DNS resolution failed", exception);
            }
            if (addresses == null || addresses.length == 0) {
                throw new SecurityException("webhook endpoint resolved to no addresses");
            }
            for (InetAddress address : addresses) {
                if (address == null || !isPublic(address)) {
                    throw new SecurityException("webhook endpoint resolved to a non-public address");
                }
            }
            return new ValidatedEndpoint(endpoint, host, 443, List.of(addresses));
        }

        static boolean isPublic(InetAddress address) {
            if (address == null) {
                return false;
            }
            if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                    || address.isSiteLocalAddress() || address.isMulticastAddress()) {
                return false;
            }
            byte[] bytes = address.getAddress();
            if (bytes.length == 16) {
                int first = Byte.toUnsignedInt(bytes[0]);
                int second = Byte.toUnsignedInt(bytes[1]);
                int third = Byte.toUnsignedInt(bytes[2]);
                int fourth = Byte.toUnsignedInt(bytes[3]);
                boolean globalUnicast = (first & 0xe0) == 0x20;
                boolean special2001 = first == 0x20 && second == 0x01 && third <= 0x01;
                boolean documentation = first == 0x20 && second == 0x01
                        && third == 0x0d && fourth == 0xb8;
                boolean sixToFour = first == 0x20 && second == 0x02;
                boolean documentationV2 = first == 0x3f && (second & 0xf0) == 0xf0;
                return globalUnicast && !special2001 && !documentation && !sixToFour
                        && !documentationV2;
            }
            if (bytes.length != 4) {
                return false;
            }
            int first = Byte.toUnsignedInt(bytes[0]);
            int second = Byte.toUnsignedInt(bytes[1]);
            int third = Byte.toUnsignedInt(bytes[2]);
            return first != 0 && first != 10 && first != 127 && first < 224
                    && !(first == 100 && second >= 64 && second <= 127)
                    && !(first == 169 && second == 254)
                    && !(first == 172 && second >= 16 && second <= 31)
                    && !(first == 192 && second == 0 && third == 0)
                    && !(first == 192 && second == 0 && third == 2)
                    && !(first == 192 && second == 31 && third == 196)
                    && !(first == 192 && second == 52 && third == 193)
                    && !(first == 192 && second == 88 && third == 99)
                    && !(first == 192 && second == 175 && third == 48)
                    && !(first == 192 && second == 168)
                    && !(first == 198 && (second == 18 || second == 19))
                    && !(first == 198 && second == 51 && third == 100)
                    && !(first == 203 && second == 0 && third == 113);
        }
    }

    private final String tenantId;
    private final Outbox outbox;
    private final Transport transport;
    private final EndpointPolicy endpointPolicy;
    private final RotatingKeyRing keyRing;
    private final Duration requestTimeout;
    private final Duration leaseDuration;
    private final Duration baseBackoff;
    private final Duration maximumBackoff;
    private final Clock clock;

    public WebhookDeliveryService(String tenantId, Outbox outbox, Transport transport,
            EndpointPolicy endpointPolicy, RotatingKeyRing keyRing, Duration requestTimeout,
            Duration leaseDuration, Duration baseBackoff, Duration maximumBackoff, Clock clock) {
        requireId(tenantId, "tenantId");
        this.tenantId = tenantId;
        this.outbox = Objects.requireNonNull(outbox, "outbox");
        this.transport = Objects.requireNonNull(transport, "transport");
        this.endpointPolicy = Objects.requireNonNull(endpointPolicy, "endpointPolicy");
        this.keyRing = Objects.requireNonNull(keyRing, "keyRing");
        positive(requestTimeout, "requestTimeout");
        positive(leaseDuration, "leaseDuration");
        positive(baseBackoff, "baseBackoff");
        positive(maximumBackoff, "maximumBackoff");
        if (baseBackoff.compareTo(maximumBackoff) > 0) {
            throw new IllegalArgumentException("baseBackoff exceeds maximumBackoff");
        }
        this.requestTimeout = requestTimeout;
        this.leaseDuration = leaseDuration;
        this.baseBackoff = baseBackoff;
        this.maximumBackoff = maximumBackoff;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public Outcome deliverNext() {
        Instant now = Instant.now(clock);
        Optional<Delivery> claimed = outbox.claim(tenantId, now, now.plus(leaseDuration));
        if (claimed.isEmpty()) {
            return Outcome.IDLE;
        }
        Delivery delivery = claimed.orElseThrow();
        if (!tenantId.equals(delivery.tenantId())) {
            delivery.close();
            throw new SecurityException("outbox returned a cross-tenant delivery");
        }
        try {
            EndpointPolicy.ValidatedEndpoint endpoint = endpointPolicy.validate(delivery.endpoint());
            SigningKey key = keyRing.current(delivery.projectId(), now);
            String timestamp = Long.toString(now.getEpochSecond());
            byte[] payload = delivery.payload();
            HttpResult response;
            try {
                byte[] signingSecret = key.secret();
                String signatureHeader;
                try {
                    signatureHeader = signingHeader(now.getEpochSecond(), signingSecret,
                            payload);
                } finally {
                    java.util.Arrays.fill(signingSecret, (byte) 0);
                }
                Map<String, String> headers = new LinkedHashMap<>();
                headers.put("Content-Type", "application/json");
                headers.put("User-Agent", "elmpay-webhook-delivery/1");
                headers.put("X-Elmpay-Event-Id", delivery.eventId());
                headers.put("X-Elmpay-Event-Type", delivery.eventType());
                headers.put("X-Elmpay-Timestamp", timestamp);
                headers.put("X-Elmpay-Key-Id", key.keyId());
                headers.put("X-Elmpay-Signature", signatureHeader);
                try (OutboundRequest request = new OutboundRequest(endpoint, headers, payload,
                        requestTimeout)) {
                    response = transport.send(request);
                }
            } finally {
                java.util.Arrays.fill(payload, (byte) 0);
            }
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                outbox.markDelivered(delivery, response.statusCode(), now);
                return Outcome.DELIVERED;
            }
            if (response.statusCode() >= 300 && response.statusCode() < 400) {
                outbox.deadLetter(delivery, response.statusCode(), "HTTP_REDIRECT_FORBIDDEN", now);
                return Outcome.DEAD_LETTERED;
            }
            if (!retryable(response.statusCode())) {
                outbox.deadLetter(delivery, response.statusCode(), "HTTP_TERMINAL", now);
                return Outcome.DEAD_LETTERED;
            }
            return retryOrDeadLetter(delivery, response.statusCode(), "HTTP_RETRYABLE", now);
        } catch (SecurityException exception) {
            outbox.deadLetter(delivery, 0, "SECURITY_POLICY", now);
            return Outcome.DEAD_LETTERED;
        } catch (IOException exception) {
            return retryOrDeadLetter(delivery, 0, "TRANSPORT_IO", now);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return retryOrDeadLetter(delivery, 0, "TRANSPORT_INTERRUPTED", now);
        } finally {
            delivery.close();
        }
    }

    private Outcome retryOrDeadLetter(Delivery delivery, int statusCode, String errorCode, Instant now) {
        int attempted = delivery.attemptCount() + 1;
        if (attempted >= delivery.maxAttempts()) {
            outbox.deadLetter(delivery, statusCode, errorCode, now);
            return Outcome.DEAD_LETTERED;
        }
        long multiplier = 1L << Math.min(delivery.attemptCount(), 20);
        Duration delay;
        try {
            delay = baseBackoff.multipliedBy(multiplier);
        } catch (ArithmeticException exception) {
            delay = maximumBackoff;
        }
        if (delay.compareTo(maximumBackoff) > 0) {
            delay = maximumBackoff;
        }
        outbox.reschedule(delivery, statusCode, errorCode, now.plus(delay));
        return Outcome.RETRY_SCHEDULED;
    }

    private static byte[] hmac(byte[] key, byte[] value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(value);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("HMAC-SHA256 is unavailable", exception);
        }
    }

    /**
     * Canonical SDK-compatible webhook signature. The signature binds the exact raw payload
     * bytes and uses unpadded Base64URL so every supported SDK parses the same wire value.
     */
    public static String signingHeader(long timestamp, byte[] secret, byte[] rawPayload) {
        if (timestamp <= 0) {
            throw new IllegalArgumentException("webhook timestamp must be positive");
        }
        byte[] safeSecret = Objects.requireNonNull(secret, "secret").clone();
        byte[] safePayload = Objects.requireNonNull(rawPayload, "rawPayload").clone();
        if (safeSecret.length < 32) {
            throw new IllegalArgumentException("webhook signing secret must be at least 32 bytes");
        }
        if (safePayload.length == 0 || safePayload.length > MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("payload has an invalid size");
        }
        byte[] signatureInput = null;
        byte[] signatureBytes = null;
        try {
            signatureInput = concat(Long.toString(timestamp)
                    .getBytes(StandardCharsets.US_ASCII), new byte[] {'.'}, safePayload);
            signatureBytes = hmac(safeSecret, signatureInput);
            String signature = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(signatureBytes);
            return "t=" + timestamp + ",v1=" + signature;
        } finally {
            java.util.Arrays.fill(safeSecret, (byte) 0);
            java.util.Arrays.fill(safePayload, (byte) 0);
            if (signatureInput != null) {
                java.util.Arrays.fill(signatureInput, (byte) 0);
            }
            if (signatureBytes != null) {
                java.util.Arrays.fill(signatureBytes, (byte) 0);
            }
        }
    }

    private static byte[] concat(byte[]... values) {
        int length = 0;
        for (byte[] value : values) {
            length = Math.addExact(length, value.length);
        }
        ByteBuffer result = ByteBuffer.allocate(length);
        for (byte[] value : values) {
            result.put(value);
        }
        return result.array();
    }

    private static String normalizeHost(String host, String name) {
        if (host == null || host.isBlank() || host.contains("*") || host.contains("/")
                || host.contains(":") || !host.chars().allMatch(character -> character < 128)) {
            throw new IllegalArgumentException(name + " has an invalid format");
        }
        String normalized = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
        if (normalized.length() > 253 || normalized.endsWith(".")
                || normalized.equals("localhost") || normalized.endsWith(".localhost")
                || !normalized.contains(".") || !normalized.matches("[a-z0-9.-]+")
                || !normalized.matches(".*[a-z].*")
                || java.util.Arrays.stream(normalized.split("\\.", -1))
                        .anyMatch(label -> label.isEmpty() || label.length() > 63)) {
            throw new IllegalArgumentException(name + " has an invalid format");
        }
        return normalized;
    }

    private static boolean retryable(int status) {
        return status == 0 || status == 408 || status == 409 || status == 425 || status == 429 || status >= 500;
    }

    private static void requireId(String value, String name) {
        if (value == null || !value.matches("[A-Za-z0-9_-]{3,64}")) {
            throw new IllegalArgumentException(name + " has an invalid format");
        }
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank() || value.length() > 160
                || value.chars().anyMatch(character -> character < 0x20)) {
            throw new IllegalArgumentException(name + " has an invalid format");
        }
    }

    private static void positive(Duration value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isNegative() || value.isZero()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }
}
