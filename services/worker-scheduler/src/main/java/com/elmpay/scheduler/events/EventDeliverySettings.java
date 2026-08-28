package com.elmpay.scheduler.events;

import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.Map;
import java.util.Objects;

/** Fail-fast runtime configuration for the durable outbox and inbox workers. */
public record EventDeliverySettings(Duration outboxLeaseTtl, Duration publisherBaseBackoff,
        Duration inboxLeaseTtl, Duration inboxRetryDelay) {
    public static final String OUTBOX_LEASE_TTL = "ELMPAY_EVENT_OUTBOX_LEASE_TTL";
    public static final String PUBLISHER_BASE_BACKOFF = "ELMPAY_EVENT_PUBLISHER_BASE_BACKOFF";
    public static final String INBOX_LEASE_TTL = "ELMPAY_EVENT_INBOX_LEASE_TTL";
    public static final String INBOX_RETRY_DELAY = "ELMPAY_EVENT_INBOX_RETRY_DELAY";

    public EventDeliverySettings {
        requirePositive(outboxLeaseTtl, OUTBOX_LEASE_TTL);
        requirePositive(publisherBaseBackoff, PUBLISHER_BASE_BACKOFF);
        requirePositive(inboxLeaseTtl, INBOX_LEASE_TTL);
        requirePositive(inboxRetryDelay, INBOX_RETRY_DELAY);
        if (publisherBaseBackoff.compareTo(Duration.ofMinutes(15)) > 0) {
            throw new IllegalArgumentException(PUBLISHER_BASE_BACKOFF
                    + " must not exceed the relay backoff ceiling");
        }
    }

    /** Parse ISO-8601 durations; missing or malformed production configuration fails closed. */
    public static EventDeliverySettings from(Map<String, String> environment) {
        Objects.requireNonNull(environment, "environment");
        return new EventDeliverySettings(duration(environment, OUTBOX_LEASE_TTL),
                duration(environment, PUBLISHER_BASE_BACKOFF),
                duration(environment, INBOX_LEASE_TTL),
                duration(environment, INBOX_RETRY_DELAY));
    }

    public OutboxRelay relay(OutboxRelay.Store store, OutboxRelay.Publisher publisher) {
        return new OutboxRelay(store, publisher, outboxLeaseTtl, publisherBaseBackoff);
    }

    private static Duration duration(Map<String, String> environment, String key) {
        String value = environment.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(key + " is required");
        }
        try {
            return Duration.parse(value);
        } catch (DateTimeParseException exception) {
            throw new IllegalStateException(key + " must be an ISO-8601 duration", exception);
        }
    }

    private static void requirePositive(Duration value, String key) {
        Objects.requireNonNull(value, key);
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(key + " must be positive");
        }
    }
}
