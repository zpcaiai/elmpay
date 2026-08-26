package com.elmpay.webhook.delivery;

import java.io.IOException;
import java.net.IDN;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Signed, persistently retried business-project webhook delivery worker. */
public final class WebhookDeliveryService {
    private static final int MAX_PAYLOAD_BYTES = 1_048_576;

    public enum Outcome { IDLE, DELIVERED, RETRY_SCHEDULED, DEAD_LETTERED }

    public record SigningKey(String keyId, byte[] secret, Instant validFrom, Instant validUntil) {
        public SigningKey {
            requireText(keyId, "keyId");
            secret = Objects.requireNonNull(secret, "secret").clone();
            if (secret.length < 32) {
                throw new IllegalArgumentException("webhook signing secret must be at least 32 bytes");
            }
            Objects.requireNonNull(validFrom, "validFrom");
            Objects.requireNonNull(validUntil, "validUntil");
            if (!validUntil.isAfter(validFrom)) {
                throw new IllegalArgumentException("invalid signing-key validity window");
            }
        }

        @Override
        public byte[] secret() {
            return secret.clone();
        }

        boolean validAt(Instant at) {
            return !at.isBefore(validFrom) && at.isBefore(validUntil);
        }
    }

    public record Delivery(long deliveryId, String tenantId, String projectId, String endpointId,
            URI endpoint, String eventId, String eventType, byte[] payload,
            int attemptCount, int maxAttempts) {
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
        }

        @Override
        public byte[] payload() {
            return payload.clone();
        }
    }

    public record HttpResult(int statusCode, Map<String, List<String>> headers) {
        public HttpResult {
            headers = Map.copyOf(headers);
        }
    }

    @FunctionalInterface
    public interface Transport {
        HttpResult send(HttpRequest request) throws IOException, InterruptedException;
    }

    public static final class JdkTransport implements Transport {
        private final HttpClient client;

        public JdkTransport(Duration connectTimeout) {
            positive(connectTimeout, "connectTimeout");
            client = HttpClient.newBuilder().connectTimeout(connectTimeout)
                    .followRedirects(HttpClient.Redirect.NEVER).build();
        }

        @Override
        public HttpResult send(HttpRequest request) throws IOException, InterruptedException {
            HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
            return new HttpResult(response.statusCode(), response.headers().map());
        }
    }

    @FunctionalInterface
    public interface HostResolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    public interface Outbox {
        Optional<Delivery> claim(String tenantId, Instant now, Instant leaseUntil);

        void markDelivered(String tenantId, long deliveryId, int statusCode, Instant deliveredAt);

        void reschedule(String tenantId, long deliveryId, int statusCode, String errorCode,
                Instant nextAttemptAt);

        void deadLetter(String tenantId, long deliveryId, int statusCode, String errorCode, Instant failedAt);
    }

    public static final class RotatingKeyRing {
        private final AtomicReference<List<SigningKey>> keys;

        public RotatingKeyRing(List<SigningKey> initial) {
            List<SigningKey> safe = List.copyOf(initial);
            if (safe.isEmpty()) {
                throw new IllegalArgumentException("at least one signing key is required");
            }
            keys = new AtomicReference<>(safe);
        }

        public SigningKey current(Instant at) {
            return keys.get().stream().filter(key -> key.validAt(at))
                    .max(java.util.Comparator.comparing(SigningKey::validFrom))
                    .orElseThrow(() -> new SecurityException("no active webhook signing key"));
        }

        public void rotate(List<SigningKey> replacement) {
            List<SigningKey> safe = List.copyOf(replacement);
            if (safe.isEmpty()) {
                throw new IllegalArgumentException("replacement key set is empty");
            }
            List<String> oldIds = keys.get().stream().map(SigningKey::keyId).toList();
            if (safe.stream().map(SigningKey::keyId).noneMatch(oldIds::contains)) {
                throw new IllegalArgumentException("signing-key rotation requires an overlap");
            }
            keys.set(safe);
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

        public URI validate(URI endpoint) {
            Objects.requireNonNull(endpoint, "endpoint");
            if (!"https".equalsIgnoreCase(endpoint.getScheme()) || endpoint.getHost() == null
                    || endpoint.getUserInfo() != null || endpoint.getFragment() != null
                    || (endpoint.getPort() != -1 && endpoint.getPort() != 443)) {
                throw new SecurityException("webhook endpoint must be an absolute HTTPS URI on port 443");
            }
            String host = normalizeHost(endpoint.getHost(), "endpoint host");
            if (!approvedHosts.contains(host)) {
                throw new SecurityException("webhook endpoint host is not allowlisted");
            }
            InetAddress[] addresses;
            try {
                addresses = resolver.resolve(host);
            } catch (UnknownHostException exception) {
                throw new SecurityException("webhook endpoint DNS resolution failed", exception);
            }
            if (addresses.length == 0) {
                throw new SecurityException("webhook endpoint resolved to no addresses");
            }
            for (InetAddress address : addresses) {
                if (!isPublic(address)) {
                    throw new SecurityException("webhook endpoint resolved to a non-public address");
                }
            }
            return endpoint;
        }

        private static boolean isPublic(InetAddress address) {
            if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                    || address.isSiteLocalAddress() || address.isMulticastAddress()) {
                return false;
            }
            if (address instanceof Inet6Address) {
                byte first = address.getAddress()[0];
                return (first & 0xfe) != 0xfc;
            }
            byte[] bytes = address.getAddress();
            int first = Byte.toUnsignedInt(bytes[0]);
            int second = Byte.toUnsignedInt(bytes[1]);
            int third = Byte.toUnsignedInt(bytes[2]);
            return first != 0 && first != 10 && first != 127 && first < 224
                    && !(first == 100 && second >= 64 && second <= 127)
                    && !(first == 169 && second == 254)
                    && !(first == 172 && second >= 16 && second <= 31)
                    && !(first == 192 && second == 0 && third == 0)
                    && !(first == 192 && second == 0 && third == 2)
                    && !(first == 192 && second == 88 && third == 99)
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
            throw new SecurityException("outbox returned a cross-tenant delivery");
        }
        try {
            URI endpoint = endpointPolicy.validate(delivery.endpoint());
            SigningKey key = keyRing.current(now);
            String timestamp = Long.toString(now.getEpochSecond());
            byte[] signatureInput = concat(timestamp.getBytes(StandardCharsets.US_ASCII),
                    new byte[] {'.'}, delivery.payload());
            String signature = Base64.getEncoder().encodeToString(hmac(key.secret(), signatureInput));
            HttpRequest request = HttpRequest.newBuilder(endpoint).timeout(requestTimeout)
                    .header("Content-Type", "application/json")
                    .header("User-Agent", "elmpay-webhook-delivery/1")
                    .header("X-Elmpay-Event-Id", delivery.eventId())
                    .header("X-Elmpay-Event-Type", delivery.eventType())
                    .header("X-Elmpay-Timestamp", timestamp)
                    .header("X-Elmpay-Key-Id", key.keyId())
                    .header("X-Elmpay-Signature", "v1=" + signature)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(delivery.payload())).build();
            HttpResult response = transport.send(request);
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                outbox.markDelivered(tenantId, delivery.deliveryId(), response.statusCode(), now);
                return Outcome.DELIVERED;
            }
            if (!retryable(response.statusCode())) {
                outbox.deadLetter(tenantId, delivery.deliveryId(), response.statusCode(),
                        "HTTP_TERMINAL", now);
                return Outcome.DEAD_LETTERED;
            }
            return retryOrDeadLetter(delivery, response.statusCode(), "HTTP_RETRYABLE", now);
        } catch (SecurityException exception) {
            outbox.deadLetter(tenantId, delivery.deliveryId(), 0, "SECURITY_POLICY", now);
            return Outcome.DEAD_LETTERED;
        } catch (IOException exception) {
            return retryOrDeadLetter(delivery, 0, "TRANSPORT_IO", now);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return retryOrDeadLetter(delivery, 0, "TRANSPORT_INTERRUPTED", now);
        }
    }

    private Outcome retryOrDeadLetter(Delivery delivery, int statusCode, String errorCode, Instant now) {
        int attempted = delivery.attemptCount() + 1;
        if (attempted >= delivery.maxAttempts()) {
            outbox.deadLetter(tenantId, delivery.deliveryId(), statusCode, errorCode, now);
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
        outbox.reschedule(tenantId, delivery.deliveryId(), statusCode, errorCode, now.plus(delay));
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
        if (host == null || host.isBlank() || host.contains("*") || host.contains("/") || host.contains(":")) {
            throw new IllegalArgumentException(name + " has an invalid format");
        }
        String normalized = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
        if (normalized.equals("localhost") || normalized.endsWith(".localhost") || !normalized.contains(".")) {
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
