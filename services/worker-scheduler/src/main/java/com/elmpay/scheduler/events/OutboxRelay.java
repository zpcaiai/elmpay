package com.elmpay.scheduler.events;

import java.io.Serial;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Claims one durable outbox row, waits for a broker acknowledgement, then marks it published.
 *
 * <p>A process crash after the broker acknowledgement and before {@code markPublished} causes a
 * duplicate publication after the lease expires. That is intentional at-least-once delivery;
 * {@link JdbcEventDeliveryStore#consume} supplies the durable inbox that gives consumers one
 * committed business effect.
 */
public final class OutboxRelay {
    private static final Duration MAXIMUM_BACKOFF = Duration.ofMinutes(15);

    public enum Outcome {
        IDLE,
        PUBLISHED,
        RETRY_SCHEDULED
    }

    /** Exact canonical payload and lease identity read from the transactional outbox. */
    public record Message(long sequenceNo, UUID eventId, UUID tenantId, UUID projectId,
            String aggregateType, UUID aggregateId, String eventType, int eventVersion,
            String payloadJson, String correlationId, Instant createdAt, int deliveryAttempt,
            String leaseOwner, long fencingToken) {
        public Message {
            Objects.requireNonNull(eventId, "eventId");
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(projectId, "projectId");
            requireText(aggregateType, "aggregateType");
            Objects.requireNonNull(aggregateId, "aggregateId");
            requireText(eventType, "eventType");
            requireText(payloadJson, "payloadJson");
            requireText(correlationId, "correlationId");
            Objects.requireNonNull(createdAt, "createdAt");
            requireText(leaseOwner, "leaseOwner");
            if (sequenceNo <= 0 || eventVersion <= 0 || deliveryAttempt <= 0 || fencingToken <= 0) {
                throw new IllegalArgumentException("invalid outbox message identity");
            }
        }
    }

    public interface Store {
        Optional<Message> claim(UUID tenantId, String workerId, Instant now, Duration leaseTtl);

        void markPublished(Message message, Instant acknowledgedAt);

        void recordFailure(Message message, Instant failedAt, Duration retryDelay,
                String failureCode);
    }

    /** Implementations return only after the broker durably acknowledges this exact event id. */
    @FunctionalInterface
    public interface Publisher {
        void publish(Message message) throws Exception;
    }

    private final Store store;
    private final Publisher publisher;
    private final Duration leaseTtl;
    private final Duration baseBackoff;

    public OutboxRelay(Store store, Publisher publisher, Duration leaseTtl,
            Duration baseBackoff) {
        this.store = Objects.requireNonNull(store, "store");
        this.publisher = Objects.requireNonNull(publisher, "publisher");
        this.leaseTtl = requirePositive(leaseTtl, "leaseTtl");
        this.baseBackoff = requirePositive(baseBackoff, "baseBackoff");
        if (baseBackoff.compareTo(MAXIMUM_BACKOFF) > 0) {
            throw new IllegalArgumentException("baseBackoff exceeds the bounded maximum");
        }
    }

    public Outcome runOnce(UUID tenantId, String workerId, Instant now) {
        Objects.requireNonNull(tenantId, "tenantId");
        requireText(workerId, "workerId");
        Objects.requireNonNull(now, "now");
        Optional<Message> claimed = store.claim(tenantId, workerId, now, leaseTtl);
        if (claimed.isEmpty()) {
            return Outcome.IDLE;
        }
        Message message = claimed.orElseThrow();
        try {
            publisher.publish(message);
        } catch (Exception failure) {
            store.recordFailure(message, now, backoff(message.deliveryAttempt()),
                    failure.getClass().getSimpleName());
            return Outcome.RETRY_SCHEDULED;
        }
        // publisher.publish returns only after ACK. Never move this marker before that call.
        store.markPublished(message, now);
        return Outcome.PUBLISHED;
    }

    Duration backoff(int attempt) {
        if (attempt <= 0) {
            throw new IllegalArgumentException("attempt must be positive");
        }
        int exponent = Math.min(attempt - 1, 20);
        long multiplier = 1L << exponent;
        Duration candidate;
        try {
            candidate = baseBackoff.multipliedBy(multiplier);
        } catch (ArithmeticException overflow) {
            return MAXIMUM_BACKOFF;
        }
        return candidate.compareTo(MAXIMUM_BACKOFF) > 0 ? MAXIMUM_BACKOFF : candidate;
    }

    public static final class LeaseLostException extends IllegalStateException {
        @Serial
        private static final long serialVersionUID = 1L;

        public LeaseLostException(String message) {
            super(message);
        }
    }

    private static Duration requirePositive(Duration value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(field + " must be positive");
        }
        return value;
    }

    static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
